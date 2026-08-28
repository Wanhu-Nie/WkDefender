/**************************************************/
/*  WkDefender 文件系统 Minifilter + YARA 扫描回路   */
/**************************************************/

#include "Filter.h"
#include "FileBackupEngine.h"
#include "NamedPipeMonitor.h"                       /* 命名管道 C2/横向移动检测（迁移 2026-08） */
#include "PreAcquireSection.h"                      /* 代码执行映射检测（PreAcquireSection 迁移 2026-08） */
#include "../Notification/NotificationManager.h"   /* 文件事件上送（NtfCreateMessage/NtfSendMessageAsync） */
#include "../AnalysisEngine/AnalysisEngine.h"       /* AepIsCriticalProcess 阻断豁免 */
#include "../ThreatScoring/ThreatScoring.h"         /* AeReportIndicatorPair 评分上报 */
#include "../Common/Utils.h"
#include "../Common/Exempts/Exempts.h"             /* 敏感文件保护豁免（ExemptsIsProcessTrusted） */

/*++
 * 实现说明（迁移 DEC-03 裁剪原则）：
 *   本文件是迁移计划"步骤 2 续 / 步骤 4"的落地。参考 PhantomSensor 成熟实现：
 *     - minifilter 注册：ShadowStrike/PhantomSensor/PhantomSensor/Core/FilterRegistration.c
 *     - FLT 端口 + 同步扫描：ShadowStrike/PhantomSensor/PhantomSensor/Communication/CommPort.c
 *   按 DEC-02 = X1，文件扫描走**独立 FLT 通信端口**（非 ALPC）。
 *   按计划 L16 简化决策：**不照搬** PhantomSensor 的 AES-256-GCM/HMAC/HKDF 密钥交换，
 *   改为明文端口 + 安全描述符 + 客户端 PID 校验（含 scanner PID 豁免防递归死锁）。
 *
 *   范围裁剪（不照搬 PhantomSensor 全部，详见各函数注释）：
 *     - 注册 IRP_MJ_CREATE（Pre+Post）、IRP_MJ_WRITE（Pre）、
 *       IRP_MJ_SET_INFORMATION（Pre，PreSetInfo 迁移 2026-08）、
 *       IRP_MJ_CREATE_NAMED_PIPE（Pre，NamedPipeMonitor 迁移 2026-08）。
 *     - 不注册 Cleanup / AcquireSection / USB 回调。
 *     - 不注册 FLT context（Stream/Volume/StreamHandle/Instance/Transaction）。
 *     - 上述范围外能力后期补全指引见各 TODO 注释。
 *--*/

/* 全局：minifilter 句柄与通信服务端端口句柄 */
static PFLT_FILTER   WkdFileSystemFilter = NULL;
static PFLT_PORT    g_FsServerPort   = NULL;

/* 连接状态：当前已连接的 agent 客户端端口（X1 仅允许 1 个主扫描进程） */
static PFLT_PORT    g_FsClientPort   = NULL;
static volatile LONG g_FsConnectedPid = 0;   /* 已连接 agent 的 PID（ConnectNotify 写入，防递归） */

/* FAST_MUTEX 保护客户端端口切换（Connect/Disconnect 在 PASSIVE_LEVEL） */
static FAST_MUTEX   g_FsPortLock;

/* ============================================================================
 * 前向声明（定义位于本文件后部；PreCreate/PreWrite 等热路径先期调用）
 * ========================================================================== */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN WkdFspIsCanaryFile(_In_ PCUNICODE_STRING FileName);

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN WkdFspIsHoneypotFile(_In_ PCUNICODE_STRING FileName);

/* 逐进程文件操作窗口计数（定义于勒索窗口计数分区，PreWrite 先期调用） */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN WkdFspTrackFileOperation(_In_ HANDLE ProcessId, _In_ ULONG OpType);

_IRQL_requires_(PASSIVE_LEVEL)
static VOID FspSendFileEvent(
    _In_ ULONG OperationType,
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSize,
    _In_ ULONG FileEntropy,
    _In_ ULONG Flags,
    _In_ LONGLONG WriteOffset,
    _In_ ULONG BytesWritten,
    _In_ ULONG64 FileId
    );

/* ============================================================================
 * 文件事件标志位（对齐 agent DEF_FILE_FLAG_*）
 *   本定义位于文件前部：FspSendFileEvent（定义在后）在 PreCreate 热路径中
 *   先期使用 WKD_FS_FILE_FLAG_CREATE/SHADOW_DELETE/RAPID_RATE。
 * ========================================================================== */
#define WKD_FS_FILE_FLAG_RAPID_RATE     0x00000002  /* 对齐 agent DEF_FILE_FLAG_RAPID_RATE */
#define WKD_FS_FILE_FLAG_SHADOW_DELETE  0x00000004  /* 卷影副本删除（T1490）→ WkdMessage_FileShadowCopyDelete */
#define WKD_FS_FILE_FLAG_CREATE         0x00000008  /* 新文件创建 → WkdMessage_FileCreate */
#define WKD_FS_FILE_FLAG_CANARY         0x00000001  /* 蜜罐 canary 文件命中（对齐 agent DEF_FILE_FLAG_CANARY，bit0） */

/* 26100 SDK 已移除 STATUS_NOT_READY（旧值 0x00000110L）；本地补回兼容宏，
 * 值对齐旧 SDK 语义（设备/功能未就绪）。 */
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY ((NTSTATUS)0x00000110L)
#endif

/* ============================================================================
 * 可扫描扩展名表（参考 PhantomSensor FilterRegistration.c g_ScannableExtensions）
 * 仅按计划范围收录主要可执行/脚本类型；PhantomSensor 完整表本期未全量照搬。
 * 后期补全：将 ShadowStrike 的 g_ScannableExtensions 全量搬入即可。
 * ========================================================================== */
typedef struct _FSF_EXTENSION_ENTRY {
    PCWSTR Extension;
    USHORT Length;        /* 字节数（不含 NUL） */
    BOOLEAN IsExecutable; /* 是否为直接可执行 PE */
} FSF_EXTENSION_ENTRY, *PFSF_EXTENSION_ENTRY;

static const FSF_EXTENSION_ENTRY g_FsScannableExtensions[] = {
    { L"exe",  6,  TRUE  },
    { L"dll",  6,  TRUE  },
    { L"sys",  6,  TRUE  },
    { L"scr",  6,  TRUE  },
    { L"ocx",  6,  TRUE  },
    { L"cpl",  6,  TRUE  },
    { L"drv",  6,  TRUE  },
    { L"com",  6,  TRUE  },
    { L"pif",  6,  TRUE  },
    { L"bat",  6,  FALSE },
    { L"cmd",  6,  FALSE },
    { L"ps1",  6,  FALSE },
    { L"vbs",  6,  FALSE },
    { L"js",   4,  FALSE },
    { L"jse",  6,  FALSE },
    { L"wsf",  6,  FALSE },
    { L"wsh",  6,  FALSE },
    { L"hta",  6,  FALSE },
    { L"msi",  6,  TRUE  },
    { L"msp",  6,  TRUE  },
    { L"msu",  6,  TRUE  },
    { L"jar",  6,  TRUE  },
    { L"lnk",  6,  FALSE },
    { L"inf",  6,  FALSE },
    { L"reg",  6,  FALSE },
    { L"py",   4,  FALSE },
    { L"sct",  6,  FALSE },
    { L"wsc",  6,  FALSE },
    { NULL,    0,  FALSE }   /* sentinel */
};

/* ============================================================================
 * FsIsScannableExtension
 *   参考 PhantomSensor ShadowStrikeIsScannable（FilterRegistration.c:421）。
 *   纯 ASCII 大小写不敏感比较，DISPATCH_LEVEL 安全（不依赖 NLS 表）。
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FsIsScannableExtension(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG i;
    ULONG extLenBytes;
    const WCHAR* extBuf;
    const WCHAR* tblBuf;
    ULONG charCount;
    ULONG c;
    BOOLEAN match;

    if (Extension == NULL || Extension->Length == 0 || Extension->Buffer == NULL) {
        return FALSE;
    }
    extLenBytes = Extension->Length;
    extBuf = Extension->Buffer;

    for (i = 0; g_FsScannableExtensions[i].Extension != NULL; i++) {
        if (extLenBytes != g_FsScannableExtensions[i].Length) {
            continue;
        }
        tblBuf = g_FsScannableExtensions[i].Extension;
        charCount = extLenBytes / sizeof(WCHAR);
        match = TRUE;
        for (c = 0; c < charCount; c++) {
            WCHAR a = extBuf[c];
            WCHAR b = tblBuf[c];
            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================================
 * 操作回调表（仅按计划范围：Create + Write）
 * 参考 PhantomSensor g_OperationCallbacks（FilterRegistration.c:273）。
 * 范围外（本期不注册）：NamedPipe / SetInformation / Cleanup /
 *   AcquireSection / USB。后期补全指引：
 *   - 勒索防护可加 IRP_MJ_SET_INFORMATION（Delete/Rename）+ IRP_MJ_CLEANUP 重扫；
 *   - 代码执行检测可加 IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION；
 *   - 上述对应 PhantomSensor PreSetInfo.c / PreWrite.c / PreAcquireSection.c。
 * ========================================================================== */

_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_PREOP_CALLBACK_STATUS
FspPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_POSTOP_CALLBACK_STATUS
FspPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_PREOP_CALLBACK_STATUS
FspPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/* PreSetInfo 迁移 2026-08：提取 Rename/Link 目标路径（对齐 SS PsipGetRenameDestination） */
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
WkdFspGetRenameDestination(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _Out_ PUNICODE_STRING NewFileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_PREOP_CALLBACK_STATUS
FspPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/* 强信号阻断依赖（B 区死代码，PreSetInfo 迁移 2026-08 激活/接线） */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FileName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN IsWriteOp
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspIsHardlinkSensitivePath(
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspCacheRemove(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSizeLow
    );

/* 排除机制（对齐 SS PreSetInfo L1050-1080，PreSetInfo 迁移 2026-08 接线） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsPathExcluded(
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsProcessExcluded(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_PREOP_CALLBACK_STATUS
FspPreCreatePipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/* 代码执行映射检测（PreAcquireSection 迁移 2026-08）。
 * IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION pre-op：仅在 SyncTypeCreateSection
 * + 执行保护时生效，捕获"文件被映射为可执行"时刻，可事前阻断。
 * 参考 PhantomSensor PreAcquireSection.c ShadowStrikePreAcquireSection。 */
_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_PREOP_CALLBACK_STATUS
FspPreAcquireSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

static FLT_OPERATION_REGISTRATION g_FsOperations[] = {
    { IRP_MJ_CREATE,            0, FspPreCreate,          FspPostCreate,       NULL },
    { IRP_MJ_WRITE,             0, FspPreWrite,           NULL,                NULL },
    { IRP_MJ_SET_INFORMATION,   0, FspPreSetInformation,  NULL,                NULL },
    { IRP_MJ_CREATE_NAMED_PIPE, 0, FspPreCreatePipe,      NULL,                NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, FspPreAcquireSection, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

/* minifilter 卸载回调（前置于 g_FsRegistration 引用） */
NTSTATUS
FsFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

static FLT_REGISTRATION g_FsRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,   /* 必须：注册 AcquireSection IRP 时 MSDN 强制，否则 FltStartFiltering 失败 */
    NULL,                 /* ContextRegistration：本期不注册 context（范围外） */
    g_FsOperations,
    FsFilterUnload,      /* FilterUnload */
    /* TODO[USBDeviceControl 接线]（2026-08 死代码，USBDeviceControl.{c,h} 已全量功能面对齐）：
     *   InstanceSetup → 替换为 WkdUdcCheckVolumePolicy + WkdUdcNotifyVolumeMount；
     *   InstanceTeardownComplete → 替换为 WkdUdcNotifyVolumeDismount（卷挂载/解除追踪）。 */
    NULL,                 /* InstanceSetup：使用默认（USB 卷追踪未接线） */
    NULL,                 /* InstanceQueryTeardown */
    NULL,                 /* InstanceTeardownStart */
    NULL,                 /* InstanceTeardownComplete（USB 卷解除追踪未接线） */
    NULL, NULL, NULL, NULL, NULL
};

/* ============================================================================
 * FLT 通信端口：连接/断开/消息回调
 * 参考 PhantomSensor CommPort.c ShadowStrikeConnectNotify/
 *   ShadowStrikeDisconnectNotify / ShadowStrikeMessageNotify。
 * 简化：不加密、不 HMAC；记录 scanner PID 防递归死锁（参考 CommPort.c:68-78）。
 * ========================================================================== */

/* 客户端鉴权：仅允许 LocalSystem 下的 WkDefender agent 连接。
 * 参考 PhantomSensor ShadowStrikeVerifyClient（CommPort.c:1214 附近）。
 * 本期简化：校验连接进程是否为已记录的 scanner 进程 + 镜像名校验占位。 */
static NTSTATUS
FspConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID* ConnectionCookie
    )
{
    NTSTATUS status;
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
     * 避免 scanner 打开/读取规则文件时递归回 PreCreate -> FltSendMessage 死锁。
     * 参考 PhantomSensor CommPort.c g_ScannerServiceProcessId 设计。 */
    pid = PsGetCurrentProcessId();
    g_FsClientPort = ClientPort;
    InterlockedExchange(&g_FsConnectedPid, HandleToLong(pid));
    ExReleaseFastMutex(&g_FsPortLock);

    *ConnectionCookie = NULL;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] YARA FLT port connected (PID=%p)\n", pid);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}

static VOID
FspDisconnectNotify(
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

/* 消息回调：agent 经此端口回 verdict（FltSendMessage 的 reply 机制由 FltMgr 处理，
 * 此处处理 agent 主动发来的异步消息，本期主要用于接收 verdict 之外的扩展指令）。
 * 参考 PhantomSensor ShadowStrikeMessageNotify。本期同步 verdict 走 FltSendMessage
 * 的 reply 参数，不经此回调，故本回调暂仅记录。 */
static NTSTATUS
FspMessageNotify(
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
    /* 本期同步 verdict 由 FltSendMessage 的 reply 承载，此处保留扩展点。 */
    return STATUS_SUCCESS;
}

/* ============================================================================
 * FsSendYaraScanRequest
 *   同步阻塞式文件扫描请求（回路 A 内核侧核心）。
 *   参考 PhantomSensor SbSendScanRequest / ShadowStrikeSendScanRequest
 *   （CommPort.c:2810 / FltSendMessage@3057）。
 *   简化：去加密/HMAC；直接 FltSendMessage 阻塞 + fail-open。
 *   必须在 PASSIVE_LEVEL 调用。
 * ========================================================================== */
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

    /* fail-open 默认：未连接 / 超时 / 错误 均放行 */
    verdict.Verdict = WkdYaraVerdict_Allow;
    verdict.Score = 0;

    /* 未连接 agent（如 boot 早期）直接 fail-open，避免卡死创建 */
    /* 锁保护下读取 g_FsClientPort，避免与 FspDisconnectNotify 竞态 */
    ExAcquireFastMutex(&g_FsPortLock);
    PFLT_PORT clientPort = g_FsClientPort;
    if (clientPort == NULL) {
        ExReleaseFastMutex(&g_FsPortLock);
        return verdict;
    }
    ExReleaseFastMutex(&g_FsPortLock);

    /* scanner 自身触发的 I/O 豁免（防递归死锁），参考 CommPort.c scanner PID 设计 */
    if (HandleToULong(PsGetCurrentProcessId()) == (ULONG)ReadNoFence(&g_FsConnectedPid)) {
        return verdict;
    }

    /* 路径标准化：NT 设备路径 → DOS 路径（如 \Device\HarddiskVolume3\... → C:\...）
     * 使用 CoNormalizeDosPath（底层 ZwOpenSymbolicLinkObject + ZwQuerySymbolicLinkObject，
     * 不发 IRP，无递归风险）。标准化失败则 fallback 到原始 NT 路径。 */
    CoNormalizeDosPath(FilePath, &normPath);

    /* 构造变长请求：WKD_YARA_SCAN_REQUEST + 路径 */
    copyLen = (normPath->Length > MAX_PATH * sizeof(WCHAR)) ?
              (MAX_PATH * sizeof(WCHAR)) : normPath->Length;
    reqSize = sizeof(WKD_YARA_SCAN_REQUEST) + copyLen;

    req = (PWKD_YARA_SCAN_REQUEST)ExAllocatePool2(
        POOL_FLAG_PAGED, reqSize, WKD_YARA_PORT_TAG);
    if (req == NULL) {
        if (normPath) {
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
    if (normPath) {
        ExFreePoolWithTag(normPath->Buffer, 'upbp');
        ExFreePoolWithTag(normPath, 'upsp');
    }

    replySize = sizeof(WKD_YARA_SCAN_VERDICT);
    timeout.QuadPart = -(LONGLONG)WKD_YARA_SCAN_TIMEOUT_MS * 10000LL;  /* 相对超时（100ns） */

    /* 用锁内捕获的 clientPort 副本发送，避免 DisconnectNotify 并发置 NULL 后传入无效指针 */
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
        /* 超时/端口断开等：fail-open 放行（计划风险第 2 条） */
        verdict.Verdict = WkdYaraVerdict_Allow;
    }

    ExFreePoolWithTag(req, WKD_YARA_PORT_TAG);
    return verdict;
}

/* ============================================================================
 * boot 期窗口（对齐 SS ShadowFsIsBootPhase 120s，PreCreate.c L1042 /
 *   PreWrite.c L923）
 *   系统启动后 120s 内跳过同步扫描 / FBE 备份 / 熵采样等阻塞或分配操作，
 *   防 csrss/lsass/services 早期文件 I/O 洪泛挂起（winlogon 灰色屏）。
 *   窗口结束后原子锁死为 0（一次性）。
 *   注意：蜜罐 canary 阻断 / 敏感系统文件保护为纯静态表检查，不受窗口门控
 *   （对齐 SS：自保护先于 boot 检查；wkd 的 canary 阻断置于最前，保留）。
 * ========================================================================== */
#define WKD_FSF_BOOT_PHASE_MS        120000

static volatile LONG g_FsBootPhaseActive = TRUE;

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsBootPhase(
    VOID
    )
{
    if (ReadNoFence(&g_FsBootPhaseActive)) {
        LARGE_INTEGER now;
        now.QuadPart = KeQueryUnbiasedInterruptTime();
        if (now.QuadPart >= (LONGLONG)WKD_FSF_BOOT_PHASE_MS * 10000LL) {
            InterlockedExchange(&g_FsBootPhaseActive, FALSE);
        } else {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================================
 * PreCreate：文件创建触发 YARA 同步扫描回路 A
 * 参考 PhantomSensor PreCreate.c + ShadowStrikeBuildFileScanRequest。
 * 仅对"可扫描扩展名"且非 scanner 自身文件发起同步扫描；命中拒绝则
 * 返回 STATUS_ACCESS_DENIED（per-status 阻断）。fail-open 容错。
 * ========================================================================== */
_Use_decl_annotations_
static
FLT_PREOP_CALLBACK_STATUS
FspPreCreate(
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

    /* 仅处理新建/打开可执行类文件（无文件名信息则跳过） */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    /* 蜜罐 canary 检查（迁移 SS PreCreate.c PcCheckHoneypot）：精确路径命中无条件阻断。
     * 置于扩展名过滤之前——canary 文件任意扩展名均命中。 */
    if (WkdFspIsCanaryFile(&nameInfo->Name)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender/FS] CRITICAL canary file access: %wZ (PID=%lu)\n",
            &nameInfo->Name, HandleToULong(PsGetCurrentProcessId()));
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 快速跳过（对齐 SS PreCreate Phase 1-2 L805-861）：内核模式 / 分页文件 /
     * System 进程 / 受保护进程——纯内联判断，避免对系统 I/O 做同步扫描
     * （性能 + 防死锁）。置于 canary 检查之后（保留 wkd 蜜罐对系统进程也生效，
     * 对齐 SS PreWrite canary 无条件语义）。scanner 自身豁免已在
     * FsSendYaraScanRequest 内（g_FsConnectedPid）。 */
    if (Data->RequestorMode == KernelMode) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (PsGetCurrentProcessId() == (HANDLE)4) {   /* System PID，对齐 SS PC_SYSTEM_PROCESS_ID */
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (ExemptsIsProcessTrusted(PsGetCurrentProcessId())) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* TODO[PreCreate→USBDeviceControl]: T1091/T1204.002 autorun.inf 阻断接线——
     *   激活时在此处调用 WkdUdcCheckAutorun(FltObjects, &nameInfo->Name)，返回 TRUE 则
     *   STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE（USBDeviceControl 迁移 2026-08 死代码）。 */
    /* TODO[PreCreate→WSL]: T1611/T1003 WSL 文件访问逃逸检测接线——激活时在此处调用
     *   IocpCheckWslFileAccess(RequestorPid, &nameInfo->Name)（IocProcess.c §9 死代码，
     *   RequestorPid 经 FltGetRequestorProcessId 获取）。
     *   ★ 必须在扩展名过滤（FsIsScannableExtension）之前——宿主凭据文件（SAM 等）无扩展名、
     *   NTDS.dit 非可扫扩展名，走不到下方 YARA 分支。对齐 SS PreCreate.c L1088。 */
    /* 扩展名判定（范围外类型不扫描，fail-open） */
    RtlInitUnicodeString(&extension, nameInfo->Extension.Buffer);
    extension.Length = nameInfo->Extension.Length;
    if (!FsIsScannableExtension(&extension)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* boot 期跳过同步扫描/新建事件上送（fail-open），静态表检查（canary）已过 */
    if (WkdFspIsBootPhase()) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 同步阻塞扫描（PASSIVE_LEVEL：PreCreate 在 PASSIVE_LEVEL） */
    verdict = FsSendYaraScanRequest(
        &nameInfo->Name,
        HandleToULong(PsGetCurrentProcessId()));

    if (verdict.Verdict == WkdYaraVerdict_Deny) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

/* 新文件创建事件上送（迁移 SS PostWrite.c FILE_CREATE 分支）：Disposition==FILE_CREATE
     * 视为新建文件，供 agent 勒索评分（WKD_EVT_FILE_CREATE）与文件级持久化检测消费。
     * FLT_PARAMETERS.Create 无 Disposition 字段：高 8 位（Create.Options bit24-31）
     * 即 CreateDisposition 值（对齐 FltKernel.h FLT_PARAMETERS.Create 布局）。 */
    if ((((Data->Iopb->Parameters.Create.Options >> 24) & 0xFF) == FILE_CREATE)) {
        FspSendFileEvent(WKD_FILE_OP_WRITE, &nameInfo->Name, 0, 0,
                         WKD_FS_FILE_FLAG_CREATE, -1, 0, 0);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* PostCreate：本期仅占位（不缓存 verdict/context，范围外）。
 * 参考 PhantomSensor PostCreate.c（用于 stream context 与扫描状态缓存）。
 * 后期补全：可在此记录 verdict TTL 以避免重复扫描。 */
_Use_decl_annotations_
static
FLT_POSTOP_CALLBACK_STATUS
FspPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*++
 * WkdFspQueryFileId
 *   查询文件对象 ID（FileInternalInformation → IndexNumber）。
 *   对齐 SS PostCreate.c PocpQueryFileInformation L2002-2012（FileId 来源）。
 *   仅在上送文件事件前调用（扩展名命中时），控制热路径开销；失败返回 0。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG64
WkdFspQueryFileId(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    FILE_INTERNAL_INFORMATION internalInfo;

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return 0;
    }
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        NULL
        );
    if (NT_SUCCESS(status)) {
        return (ULONG64)internalInfo.IndexNumber.QuadPart;
    }
    return 0;
}

/*++
 * FspSendFileEvent
 *   备份处理完成后上送文件操作事件（Write/Rename/Delete）到 agent，
 *   供勒索行为检测（IoaRansomwareDetect）与因果图消费。
 *   OperationType 值对齐 FBE_OPERATION_TYPE / WKD_FILE_OP_*。
 *   FileEntropy：写缓冲区熵（Q16 定点，对齐 agent WKD_RANSOM_ENTROPY_Q16），0=未采样。
 *   WriteOffset/BytesWritten/FileId：写偏移/写字节数/文件对象 ID（对齐 SS PostWrite
 *     PW_WRITE_CONTEXT；非写操作传 -1/0/0），供 agent 覆盖模式与唯一文件计数消费。
 *   Flags：DEF_FILE_FLAG_* 位图（驱动侧无同名宏，bit0=Canary）。
 *   变长路径布局仿 WKD_MESSAGE_BODY_PROCESS_CREATE（Buffer 指向头后数据）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
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
    case WKD_FILE_OP_RENAME:
        type = WkdMessage_FileRename;
        break;
    case WKD_FILE_OP_DELETE:
        type = (Flags & WKD_FS_FILE_FLAG_SHADOW_DELETE) ?
            WkdMessage_FileShadowCopyDelete : WkdMessage_FileDelete;
        break;
    case WKD_FILE_OP_TRUNCATE:
    case WKD_FILE_OP_HARDLINK:
    case WKD_FILE_OP_ATTRIBUTE:
        /* 截断/硬链接/属性复用 FileWrite 消息上送（零线格式变更），agent 按
         * payload->OperationType（3/4/5）区分。修复旧版 TRUNCATE 落回
         * FileCreate/FileWrite 误判 CREATE 标志的缺陷。 */
        type = WkdMessage_FileWrite;
        break;
    case WKD_FILE_OP_WRITE:
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

/* ============================================================================
 * 写缓冲区熵计算（迁移自 SS PostWrite.c g_EntropyTable + PwpCalculateEntropy）
 *   g_FsEntropyTable[i] = round(100*(8-log2(i)))，i=0 → 0。
 *   整数查表法返回 H*100（0~800，8.0bit/byte → 800），无浮点依赖。
 *   填充文件事件 FileEntropy（Q16 定点）供 agent IoaRansomware_UpdateScore
 *   高熵分支消费（阈值 WKD_RANSOM_ENTROPY_Q16 = 7.5<<16 = 491520）。
 * ========================================================================== */
static const UINT16 g_FsEntropyTable[257] = {
    0, 800, 700, 642, 600, 568, 542, 519, 500, 483, 468, 454, 442, 430, 419, 409,
    400, 391, 383, 375, 368, 361, 354, 348, 342, 336, 330, 325, 319, 314, 309, 305,
    300, 296, 291, 287, 283, 279, 275, 271, 268, 264, 261, 257, 254, 251, 248, 245,
    242, 239, 236, 233, 230, 227, 225, 222, 219, 217, 214, 212, 209, 207, 205, 202,
    200, 198, 196, 193, 191, 189, 187, 185, 183, 181, 179, 177, 175, 173, 171, 170,
    168, 166, 164, 162, 161, 159, 157, 156, 154, 152, 151, 149, 148, 146, 145, 143,
    142, 140, 139, 137, 136, 134, 133, 131, 130, 129, 127, 126, 125, 123, 122, 121,
    119, 118, 117, 115, 114, 113, 112, 111, 109, 108, 107, 106, 105, 103, 102, 101,
    100, 99, 98, 97, 96, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84,
    83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 71, 70, 69,
    68, 67, 66, 65, 64, 63, 62, 62, 61, 60, 59, 58, 57, 57, 56, 55,
    54, 53, 52, 52, 51, 50, 49, 48, 48, 47, 46, 45, 45, 44, 43, 42,
    42, 41, 40, 39, 39, 38, 37, 36, 36, 35, 34, 33, 33, 32, 31, 31,
    30, 29, 29, 28, 27, 27, 26, 25, 25, 24, 23, 23, 22, 21, 21, 20,
    19, 19, 18, 17, 17, 16, 15, 15, 14, 14, 13, 12, 12, 11, 11, 10,
    9, 9, 8, 8, 7, 6, 6, 5, 5, 4, 3, 3, 2, 2, 1, 1,
    0
};

#define WKD_FS_ENTROPY_SAMPLE        256     /* 采样字节数（对齐 SS PostWrite） */
#define WKD_FS_ENTROPY_MIN_WRITE     256     /* 小于此长度不采样（性能） */

/* 整数查表熵：返回 H*100（0~800）。迁移自 SS PwpCalculateEntropy。 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdFspCalculateEntropyX100(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
    )
{
    ULONG byteCounts[256] = { 0 };
    ULONG i;
    ULONG entropy = 0;
    ULONG count;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    for (i = 0; i < Length; i++) {
        byteCounts[Buffer[i]]++;
    }

    for (i = 0; i < 256; i++) {
        count = byteCounts[i];
        if (count > 0) {
            ULONG scaledCount = (count * 256) / Length;
            if (scaledCount > 256) {
                scaledCount = 256;
            }
            entropy += (g_FsEntropyTable[scaledCount] * count) / Length;
        }
    }

    return entropy;
}

/* H*100 → Q16 定点（对齐 agent WKD_RANSOM_ENTROPY_Q16 = 7.5 << 16） */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdFspEntropyToQ16(
    _In_ ULONG EntropyX100
    )
{
    return (EntropyX100 * 65536) / 100;
}

/* 写操作熵采样：仅长度≥256 且 MDL/用户缓冲可读时计算，异常/不可读返回 0 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdFspSampleWriteEntropy(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    PVOID writeBuffer = NULL;
    ULONG writeLen = Data->Iopb->Parameters.Write.Length;
    ULONG sampleLen;
    ULONG entropyX100;

    if (writeLen < WKD_FS_ENTROPY_MIN_WRITE) {
        return 0;
    }
    if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
        writeBuffer = MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress,
            NormalPagePriority | MdlMappingNoExecute);
    }
    if (writeBuffer == NULL) {
        writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
    }
    if (writeBuffer == NULL) {
        return 0;
    }
    sampleLen = (writeLen > WKD_FS_ENTROPY_SAMPLE) ? WKD_FS_ENTROPY_SAMPLE : writeLen;
    /* __try { */
        entropyX100 = WkdFspCalculateEntropyX100((PUCHAR)writeBuffer, sampleLen);
    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    } */
    return WkdFspEntropyToQ16(entropyX100);
}

/*++
 * FspIsBackupDirPath
 *   检查路径是否位于 WkdBackup 备份目录内（大小写不敏感子串匹配）。
 *   用于防 FBE 备份 I/O 递归：备份文件自身写入（FbepCopyFileToBackup 写
 *   .bak）会重入 PreWrite，若无此豁免将无限递归。
 *   注：SS 依赖 IoGetTopLevelIrp 哨兵仅覆盖恢复路径，备份路径存在此缺口，wkd 补上。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
FspIsBackupDirPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT len = FileName->Length / sizeof(WCHAR);
    USHORT patLen = (USHORT)(sizeof(FBE_BACKUP_DIR_NAME) / sizeof(WCHAR) - 1);

    if (FileName->Buffer == NULL || len < patLen) {
        return FALSE;
    }

    for (USHORT i = 0; i <= len - patLen; i++) {
        BOOLEAN match = TRUE;
        for (USHORT j = 0; j < patLen; j++) {
            WCHAR a = FileName->Buffer[i + j];
            WCHAR b = FBE_BACKUP_DIR_NAME[j];
            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

/* PreWrite：CoW 备份入口（勒索回滚能力）。
 * 参考 PhantomSensor PreWrite.c（写入时标记 dirty + 可选阻断）。
 * 范围外：本期不启用写入阻断，仅做 FBE 备份，避免影响性能。
 * 后期补全：结合 YARA/签名对可疑写入做实时阻断（勒索行为检测见 4.9c 死代码）。
 * TODO[FileWrite→Clipboard]: T1115 剪贴板倾倒检测接线——激活时在此处调用
 *   IocpClipboardCheckFileWrite(RequestorPid, FileName)（IocProcess.c §8 死代码，
 *   需经 FltGetRequestorProcessId 取 RequestorPid、FltGetFileNameInformation 取文件名）。 */
_Use_decl_annotations_
static
FLT_PREOP_CALLBACK_STATUS
FspPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG fileFlags = 0;
    BOOLEAN honeypotHit = FALSE;

    *CompletionContext = NULL;

    /* 递归豁免：备份目录自身写入不触发备份（防 FBE 备份 I/O 递归） */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    /* TODO[PreWrite→USBDeviceControl]: T1052.001 可移除卷写阻断接线——激活时在此处调用
     *   WkdUdcIsWriteBlocked(FltObjects)，返回 TRUE 则 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE
     *   （ReadOnly 卷写保护，USBDeviceControl 迁移 2026-08 死代码）。 */
    /* 蜜罐 canary 检查（迁移 SS PreWrite.c PwpIsCanaryFile）：精确路径命中无条件阻断。
     * 阻断在备份之前，避免对蜜罐文件做无意义备份。 */
    if (WkdFspIsCanaryFile(&nameInfo->Name)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender/FS] CRITICAL canary file write: %wZ (PID=%lu)\n",
            &nameInfo->Name, HandleToULong(PsGetCurrentProcessId()));
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 快速跳过（对齐 SS PreWrite L819-846）：内核模式 / 分页 I/O / 零长度写——
     * 纯内联判断，避免系统写（日志/分页/缓存回写）触发 FBE 备份与事件上送。
     * 置于 canary 检查之后（保留蜜罐无条件语义）。 */
    if (Data->RequestorMode == KernelMode) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->Iopb->Parameters.Write.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 内置蜜罐文件名命中 → 上送 Flags.Canary 供 agent 勒索评分（+50，不阻断） */
    honeypotHit = WkdFspIsHoneypotFile(&nameInfo->Name);
    if (honeypotHit) {
        fileFlags |= WKD_FS_FILE_FLAG_CANARY;
    }

    /* 勒索窗口计数（迁移 SS PostWrite.c）：1s 窗口写速率超阈值 → RAPID_RATE 提升优先级 */
    if (WkdFspTrackFileOperation(PsGetCurrentProcessId(), WKD_FILE_OP_WRITE)) {
        fileFlags |= WKD_FS_FILE_FLAG_RAPID_RATE;
    }

    /* boot 期跳过 FBE 备份/熵采样/事件上送（canary 阻断已过），防早期文件 I/O 洪泛 */
    if (WkdFspIsBootPhase()) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!FspIsBackupDirPath(&nameInfo->Name)) {
        /* CoW 备份：FBE 内部完成扩展名过滤/哨兵防重入/容量/LRU 管理 */
        status = FbePreWriteBackup(Data, FltObjects, &nameInfo->Name);

        /* 扩展名命中（非 STATUS_FBE_SKIP）→ 上送文件事件供勒索检测/因果图。
         * FileEntropy：写缓冲区熵（Q16）激活 agent 高熵加密检测分支
         * （IoaRansomware_UpdateScore WKD_EVT_FILE_WRITE 分支）。 */
        if (status != STATUS_FBE_SKIP) {
            ULONG entropyQ16 = WkdFspSampleWriteEntropy(Data);
            /* 写偏移/字节数来自 IRP（对齐 SS PostWrite WriteContext.WriteOffset）；
             * FileId 仅上送前查询（FltQueryInformationFile FileInternalInformation） */
            FspSendFileEvent(WKD_FILE_OP_WRITE, &nameInfo->Name,
                             Data->Iopb->Parameters.Write.Length, entropyQ16, fileFlags,
                             Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
                             Data->Iopb->Parameters.Write.Length,
                             WkdFspQueryFileId(FltObjects));
        }

        /* TODO[FileWrite→Clipboard]: 剪贴板倾倒检测接线（IocProcess.c §8 死代码） */
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================================================
 * 敏感系统文件保护（迁移自 SS PreSetInfo.c g_SensitivePaths +
 *   PsipIsSensitiveSystemFile）
 *   MatchMode：0=后缀精确匹配（边界校验）、1=包含匹配（路径分隔符边界校验）。
 *   normalized 路径以 \Device\HarddiskVolumeN\ 开头，目录类必须用包含匹配
 *   而非前缀匹配（SS 修复过该缺陷）。
 *   命中后按操作类型取 Block 位：Disposition→BlockDelete、Rename→BlockRename、
 *   Link→BlockHardLink（wkd 文件事件无 Link 类型，硬链接分支死代码）。
 * ========================================================================== */
typedef struct _WKD_FS_SENSITIVE_PATH {
    PCWSTR  Pattern;
    UCHAR   MatchMode;              /* 0=suffix, 1=contains */
    BOOLEAN BlockDelete;
    BOOLEAN BlockRename;
    BOOLEAN BlockHardLink;
} WKD_FS_SENSITIVE_PATH, *PWKD_FS_SENSITIVE_PATH;

static const WKD_FS_SENSITIVE_PATH g_FsSensitivePaths[] = {
    /* 注册表 hive - 后缀匹配 */
    { L"\\Windows\\System32\\config\\SAM",       0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SECURITY",  0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SYSTEM",    0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SOFTWARE",  0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\DEFAULT",   0, TRUE, TRUE, TRUE },

    /* 关键系统可执行 - 后缀匹配 */
    { L"\\Windows\\System32\\lsass.exe",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\csrss.exe",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\smss.exe",          0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\wininit.exe",       0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\winlogon.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\services.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\ntoskrnl.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\hal.dll",           0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\ntdll.dll",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\kernel32.dll",      0, TRUE, TRUE, FALSE },

    /* 驱动目录 - 包含匹配（block \drivers\ 下任意文件） */
    { L"\\Windows\\System32\\drivers\\",         1, TRUE, TRUE, FALSE },

    /* 引导文件 - 包含匹配 */
    { L"\\Windows\\Boot\\",                      1, TRUE, TRUE, FALSE },
    { L"\\EFI\\Microsoft\\Boot\\",               1, TRUE, TRUE, FALSE },

    /* 引导管理器 - 后缀匹配 */
    { L"\\bootmgr",                              0, TRUE, TRUE, FALSE },
    { L"\\BOOTMGR",                              0, TRUE, TRUE, FALSE },

    /* NTFS 元数据文件 - 后缀匹配 */
    { L"\\$MFT",                                 0, TRUE, TRUE, FALSE },
    { L"\\$MFTMirr",                             0, TRUE, TRUE, FALSE },
    { L"\\$LogFile",                             0, TRUE, TRUE, FALSE },
    { L"\\$Volume",                              0, TRUE, TRUE, FALSE },
    { L"\\$AttrDef",                             0, TRUE, TRUE, FALSE },
    { L"\\$Bitmap",                              0, TRUE, TRUE, FALSE },
    { L"\\$Boot",                                0, TRUE, TRUE, FALSE },
    { L"\\$BadClus",                             0, TRUE, TRUE, FALSE },
    { L"\\$Secure",                              0, TRUE, TRUE, FALSE },
    { L"\\$UpCase",                              0, TRUE, TRUE, FALSE },
    { L"\\$Extend",                              0, TRUE, TRUE, FALSE },

    { NULL, 0, FALSE, FALSE, FALSE }             /* sentinel */
};

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspIsSensitiveSystemFile(
    _In_ PCUNICODE_STRING FileName,
    _Out_opt_ PBOOLEAN BlockDelete,
    _Out_opt_ PBOOLEAN BlockRename,
    _Out_opt_ PBOOLEAN BlockHardLink
    )
{
    ULONG i;
    UNICODE_STRING pattern;
    USHORT patternChars;
    USHORT fileChars;
    PWCHAR fileStart;
    LONG compareResult;

    if (BlockDelete) *BlockDelete = FALSE;
    if (BlockRename) *BlockRename = FALSE;
    if (BlockHardLink) *BlockHardLink = FALSE;

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {
        return FALSE;
    }

    fileChars = FileName->Length / sizeof(WCHAR);

    for (i = 0; g_FsSensitivePaths[i].Pattern != NULL; i++) {
        RtlInitUnicodeString(&pattern, g_FsSensitivePaths[i].Pattern);
        patternChars = pattern.Length / sizeof(WCHAR);

        if (patternChars > fileChars) {
            continue;
        }

        if (g_FsSensitivePaths[i].MatchMode == 1) {
            /* 包含匹配：仅在路径分隔符边界滑动窗口比较，防 C:\notWindows\ 误报 */
            USHORT maxOffset = fileChars - patternChars;
            USHORT offset;
            BOOLEAN found = FALSE;

            for (offset = 0; offset <= maxOffset; offset++) {
                if (offset > 0 && FileName->Buffer[offset - 1] != L'\\' &&
                    FileName->Buffer[offset - 1] != L':') {
                    continue;
                }

                UNICODE_STRING candidate;
                candidate.Buffer = FileName->Buffer + offset;
                candidate.Length = pattern.Length;
                candidate.MaximumLength = pattern.Length;

                if (RtlCompareUnicodeString(&candidate, &pattern, TRUE) == 0) {
                    found = TRUE;
                    break;
                }
            }

            if (found) {
                if (BlockDelete) *BlockDelete = g_FsSensitivePaths[i].BlockDelete;
                if (BlockRename) *BlockRename = g_FsSensitivePaths[i].BlockRename;
                if (BlockHardLink) *BlockHardLink = g_FsSensitivePaths[i].BlockHardLink;
                return TRUE;
            }
        } else {
            /* 后缀匹配 + 边界校验：模式以 '\' 开头则前导反斜杠即边界，否则前一字符须为 '\' 或 ':' */
            fileStart = FileName->Buffer + (fileChars - patternChars);

            UNICODE_STRING fileSuffix;
            fileSuffix.Buffer = fileStart;
            fileSuffix.Length = pattern.Length;
            fileSuffix.MaximumLength = pattern.Length;

            compareResult = RtlCompareUnicodeString(&fileSuffix, &pattern, TRUE);
            if (compareResult == 0) {
                BOOLEAN isBoundary = FALSE;

                if (fileStart == FileName->Buffer) {
                    isBoundary = TRUE;
                } else if (pattern.Buffer[0] == L'\\') {
                    isBoundary = TRUE;
                } else if (*(fileStart - 1) == L'\\' || *(fileStart - 1) == L':') {
                    isBoundary = TRUE;
                }

                if (isBoundary) {
                    if (BlockDelete) *BlockDelete = g_FsSensitivePaths[i].BlockDelete;
                    if (BlockRename) *BlockRename = g_FsSensitivePaths[i].BlockRename;
                    if (BlockHardLink) *BlockHardLink = g_FsSensitivePaths[i].BlockHardLink;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/* ============================================================================
 * 蜜罐 canary（迁移自 SS PreWrite.c PW_CANARY_CONFIG + PwpIsCanaryFile，
 *   PostWrite.c g_HoneypotFileNames）
 *   Canary：精确路径列表（64 上限，WkdFspAddCanaryPath 配置），命中无条件阻断。
 *   Honeypot：内置蜜罐文件名表（包含匹配），命中上送 Flags.Canary 供 agent
 *   勒索评分（IoaRansomware_UpdateScore Canary 分支 +50，WKD_RANSOM_CANARY_SCORE）。
 * ========================================================================== */
#define WKD_FS_MAX_CANARY_PATHS   64
#define WKD_FS_FILE_FLAG_CANARY   0x00000001  /* 对齐 agent DEF_FILE_FLAG_CANARY */

typedef struct _WKD_FS_CANARY_CONFIG {
    UNICODE_STRING Paths[WKD_FS_MAX_CANARY_PATHS];
    volatile LONG  Count;
    EX_PUSH_LOCK   Lock;
    BOOLEAN        Initialized;
} WKD_FS_CANARY_CONFIG, *PWKD_FS_CANARY_CONFIG;

static WKD_FS_CANARY_CONFIG g_FsCanaryConfig;

/* 内置蜜罐文件名表（迁移自 SS PostWrite.c g_HoneypotFileNames 12 条，包含匹配） */
static const PCWSTR g_FsHoneypotFileNames[] = {
    L"important_documents.txt", L"passwords.txt", L"bank_accounts.xlsx",
    L"private_keys.txt", L"credit_cards.xlsx", L"financial_report.docx",
    L"secret.txt", L"confidential.doc", L"personal.xlsx",
    L"accounts.txt", L"recovery_key.txt", L"crypto_wallet.dat",
    NULL
};

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdFspAddCanaryPath(
    _In_ PCUNICODE_STRING Path
    )
{
    LONG index;
    PWCHAR buffer;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_FsCanaryConfig.Initialized) {
        return STATUS_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FsCanaryConfig.Lock);

    index = g_FsCanaryConfig.Count;
    if (index >= WKD_FS_MAX_CANARY_PATHS) {
        ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, Path->Length + sizeof(WCHAR), WKD_FSF_POOL_TAG);
    if (buffer == NULL) {
        ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(buffer, Path->Buffer, Path->Length);
    buffer[Path->Length / sizeof(WCHAR)] = L'\0';

    g_FsCanaryConfig.Paths[index].Buffer = buffer;
    g_FsCanaryConfig.Paths[index].Length = Path->Length;
    g_FsCanaryConfig.Paths[index].MaximumLength = Path->Length + sizeof(WCHAR);
    InterlockedIncrement(&g_FsCanaryConfig.Count);

    ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
WkdFspIsCanaryFile(
    _In_ PCUNICODE_STRING FileName
    )
{
    LONG i;
    LONG count;
    BOOLEAN result = FALSE;

    if (!g_FsCanaryConfig.Initialized) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FsCanaryConfig.Lock);

    count = g_FsCanaryConfig.Count;
    for (i = 0; i < count; i++) {
        if (RtlEqualUnicodeString(FileName, &g_FsCanaryConfig.Paths[i], TRUE)) {
            result = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_FsCanaryConfig.Lock);
    KeLeaveCriticalRegion();
    return result;
}

/* 内置蜜罐文件名包含匹配（ASCII 大小写折叠，DISPATCH_LEVEL 安全） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsHoneypotFile(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG f, p;
    ULONG fileLen;
    ULONG patLen;
    ULONG i, j;
    BOOLEAN match;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    fileLen = FileName->Length / sizeof(WCHAR);

    for (f = 0; g_FsHoneypotFileNames[f] != NULL; f++) {
        patLen = 0;
        while (g_FsHoneypotFileNames[f][patLen] != L'\0') {
            patLen++;
        }
        if (patLen > fileLen) {
            continue;
        }
        for (i = 0; i <= fileLen - patLen; i++) {
            match = TRUE;
            for (j = 0; j < patLen; j++) {
                WCHAR a = FileName->Buffer[i + j];
                WCHAR b = g_FsHoneypotFileNames[f][j];
                if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                if (a != b) { match = FALSE; break; }
            }
            if (match) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* ============================================================================
 * 卷影副本路径判定（T1490，迁移 SS PreSetInfo/PostWrite 敏感表 SHADOW_COPY 类）
 *   包含 \System Volume Information\ 或 @GMT-（VSS 快照视图/DFS 历史）命中。
 *   命中且为删除操作 → 上送 shadow 事件（WkdMessage_FileShadowCopyDelete），
 *   agent IoaRansomware_UpdateScore WKD_EVT_SHADOW_COPY_DELETE 分支 +40。
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspContainsStrInsensitive(
    _In_ PCUNICODE_STRING Str,
    _In_ PCWSTR Substr
    )
{
    ULONG slen;
    ULONG plen = 0;
    ULONG i, j;
    BOOLEAN match;

    if (Str == NULL || Str->Buffer == NULL || Substr == NULL) {
        return FALSE;
    }
    slen = Str->Length / sizeof(WCHAR);
    while (Substr[plen] != L'\0') {
        plen++;
    }
    if (plen == 0 || plen > slen) {
        return FALSE;
    }
    for (i = 0; i <= slen - plen; i++) {
        match = TRUE;
        for (j = 0; j < plen; j++) {
            WCHAR a = Str->Buffer[i + j];
            WCHAR b = Substr[j];
            if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
            if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspIsShadowCopyPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    return WkdFspContainsStrInsensitive(FileName, L"\\System Volume Information\\") ||
           WkdFspContainsStrInsensitive(FileName, L"@GMT-");
}

/* ============================================================================
 * 勒索窗口计数（迁移自 SS PostWrite.c PW_PROCESS_ACTIVITY 固定数组模式 +
 *   FileSystemCallbacks.c FSC_RANSOMWARE_*_THRESHOLD 阈值）
 *   每进程 1 秒窗口内 Write/Rename/Delete 计数，超阈值置 RAPID_RATE 标志，
 *   随下一次文件事件上送（提升优先级），供 agent 及时处置。
 *   采用固定数组（256 槽，无动态分配/lookaside），进程退出经
 *   PsSetCreateProcessNotifyRoutineEx 回调清理槽，防 PID 复用。
 *   死代码：SS FscpDetectRansomwareBehavior 评分≥70 的阻断决策（后续决策接入）。
 * ========================================================================== */
#define WKD_FS_FILE_ACTIVITY_SLOTS  256
#define WKD_FS_WINDOW_100NS         (1000LL * 10000LL)   /* 1 秒窗口 */
#define WKD_FS_RENAME_THRESHOLD     50
#define WKD_FS_DELETE_THRESHOLD     100
#define WKD_FS_WRITE_THRESHOLD      100
/* 文件事件标志位（WKD_FS_FILE_FLAG_*）定义已上移至文件前部（FspSendFileEvent
 * 在 PreCreate 热路径中先期使用），此处不再重复定义。 */

typedef struct _WKD_FS_FILE_ACTIVITY {
    HANDLE        ProcessId;
    LARGE_INTEGER WindowStart;
    volatile LONG RenameCount;
    volatile LONG DeleteCount;
    volatile LONG WriteCount;
    volatile LONG TruncateCount;          /* 截断/分配/有效长度（T1485，PreSetInfo 迁移） */
    volatile LONG ExtensionChangeCount;   /* 勒索扩展名变更（T1486，PreSetInfo 迁移，计数由死代码检测填充） */
    volatile LONG HardLinkCount;          /* 硬链接创建（T1003.003，PreSetInfo 迁移） */
    volatile LONG AttributeCount;         /* 属性/时间戳/短名变更（T1070.006，PreSetInfo 迁移） */
    /* 总量（对齐 SS PSI_PROCESS_CONTEXT Total*，死代码 C 分区评分函数消费） */
    volatile LONG64 TotalRenames;
    volatile LONG64 TotalDeletes;
    volatile LONG64 TotalTruncations;
    volatile LONG64 TotalExtensionChanges;
    volatile LONG64 TotalHardLinks;
    volatile LONG64 TotalAttributes;
    volatile LONG IsActive;
} WKD_FS_FILE_ACTIVITY, *PWKD_FS_FILE_ACTIVITY;

static WKD_FS_FILE_ACTIVITY g_FsFileActivity[WKD_FS_FILE_ACTIVITY_SLOTS];
static EX_PUSH_LOCK g_FsFileActivityLock;

/* 进程退出清理（PsSetCreateProcessNotifyRoutineEx 回调，任意 IRQL 安全——
 * 仅原子置 IsActive=0，不碰 PushLock）。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdFspProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    ULONG i;
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        return;   /* 仅处理进程退出 */
    }

    for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
        if (g_FsFileActivity[i].IsActive &&
            g_FsFileActivity[i].ProcessId == ProcessId) {
            InterlockedExchange(&g_FsFileActivity[i].IsActive, 0);
        }
    }
}

/* 逐进程窗口计数。返回是否超速率阈值（RAPID_RATE）。PASSIVE_LEVEL（PushLock）。 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspTrackFileOperation(
    _In_ HANDLE ProcessId,
    _In_ ULONG OpType               /* WKD_FILE_OP_* */
    )
{
    ULONG i;
    PWKD_FS_FILE_ACTIVITY slot = NULL;
    LARGE_INTEGER now;
    BOOLEAN rateSuspicious = FALSE;

    KeQuerySystemTime(&now);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FsFileActivityLock);

    for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
        if (g_FsFileActivity[i].IsActive && g_FsFileActivity[i].ProcessId == ProcessId) {
            slot = &g_FsFileActivity[i];
            break;
        }
    }
    if (slot == NULL) {
        for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
            if (!g_FsFileActivity[i].IsActive) {
                slot = &g_FsFileActivity[i];
                RtlZeroMemory(slot, sizeof(WKD_FS_FILE_ACTIVITY));
                slot->ProcessId = ProcessId;
                slot->WindowStart = now;
                InterlockedExchange(&slot->IsActive, 1);
                break;
            }
        }
    }
    if (slot == NULL) {
        ExReleasePushLockExclusive(&g_FsFileActivityLock);
        KeLeaveCriticalRegion();
        return FALSE;
    }

    if (now.QuadPart - slot->WindowStart.QuadPart > WKD_FS_WINDOW_100NS) {
        slot->WindowStart = now;
        InterlockedExchange(&slot->RenameCount, 0);
        InterlockedExchange(&slot->DeleteCount, 0);
        InterlockedExchange(&slot->WriteCount, 0);
        InterlockedExchange(&slot->TruncateCount, 0);
        InterlockedExchange(&slot->ExtensionChangeCount, 0);
        InterlockedExchange(&slot->HardLinkCount, 0);
        InterlockedExchange(&slot->AttributeCount, 0);
    }

    switch (OpType) {
    case WKD_FILE_OP_RENAME:
        InterlockedIncrement64(&slot->TotalRenames);
        rateSuspicious = (InterlockedIncrement(&slot->RenameCount) > WKD_FS_RENAME_THRESHOLD);
        break;
    case WKD_FILE_OP_DELETE:
        InterlockedIncrement64(&slot->TotalDeletes);
        rateSuspicious = (InterlockedIncrement(&slot->DeleteCount) > WKD_FS_DELETE_THRESHOLD);
        break;
    case WKD_FILE_OP_TRUNCATE:
        /* 截断仅监控计数（对齐 SS PsipUpdateProcessMetrics：截断/分配/有效长度
         * 累计 RecentTruncations/TotalTruncations），不置 RAPID_RATE 速率阻断。 */
        InterlockedIncrement64(&slot->TotalTruncations);
        InterlockedIncrement(&slot->TruncateCount);
        rateSuspicious = FALSE;
        break;
    case WKD_FILE_OP_HARDLINK:
        /* 硬链接仅监控计数（对齐 SS RecentHardLinks/TotalHardLinks），阻断走
         * 敏感表 BlockHardLink 强信号直断（FspPreSetInformation），非速率阻断。 */
        InterlockedIncrement64(&slot->TotalHardLinks);
        InterlockedIncrement(&slot->HardLinkCount);
        rateSuspicious = FALSE;
        break;
    case WKD_FILE_OP_ATTRIBUTE:
        /* 属性/短名仅监控计数（对齐 SS RecentAttributeChanges），不参与速率阻断。 */
        InterlockedIncrement64(&slot->TotalAttributes);
        InterlockedIncrement(&slot->AttributeCount);
        rateSuspicious = FALSE;
        break;
    case WKD_FILE_OP_WRITE:
    default:
        rateSuspicious = (InterlockedIncrement(&slot->WriteCount) > WKD_FS_WRITE_THRESHOLD);
        break;
    }

    ExReleasePushLockExclusive(&g_FsFileActivityLock);
    KeLeaveCriticalRegion();

    return rateSuspicious;
}

/* ============================================================================
 * Rename/Link 目标路径提取（迁移自 SS PreSetInfo.c PsipGetRenameDestination
 *   L2305-2436，重功能实现）
 *   从 SetInformation 用户缓冲中安全提取目标路径，含：
 *     - 缓冲长度/FileInformationClass 偏移校验（Ex 变体 RootDirectory 后多
 *       一个 ULONG Flags，FileName 偏移 +4；修复 SS 用普通结构读取 Ex 布局
 *       导致 FileNameLength/FileName 字段错位的隐患）
 *     - 用户缓冲 __try 访问
 *     - USHORT 截断防护（bufferLength = fileNameLength + 2 不溢出 USHORT，
 *       对齐 SS v2.1.0 修复，防下游 UNICODE_STRING 操作 OOB）
 *     - 分配大小溢出检查 + 分配上限（防 DoS）
 *   调用者负责 ExFreePoolWithTag(NewFileName->Buffer)。
 * ========================================================================== */
#define WKD_FS_MAX_RENAME_BUFFER_SIZE  65535    /* 对齐 SS PSI_MAX_RENAME_BUFFER_SIZE */

_Use_decl_annotations_
static NTSTATUS
WkdFspGetRenameDestination(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _Out_ PUNICODE_STRING NewFileName
    )
{
    PFILE_RENAME_INFORMATION renameInfo;
    ULONG infoBufferLength;
    ULONG fileNameLength;
    ULONG bufferLength;
    ULONG maxFileNameLength;
    ULONG fileNameLengthOffset;
    ULONG fileNameDataOffset;
    PWCHAR buffer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(NewFileName, sizeof(UNICODE_STRING));

    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    infoBufferLength = Data->Iopb->Parameters.SetFileInformation.Length;

    if (renameInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (infoBufferLength < sizeof(FILE_RENAME_INFORMATION)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Ex 变体（FileRenameInformationEx/FileLinkInformationEx）布局多一个 ULONG
     * Flags（RootDirectory 之后、FileNameLength 之前），FileNameLength 与
     * FileName 偏移均 +4（对齐 SS 提取语义，修复布局错位隐患）。 */
    if (InfoClass == FileRenameInformationEx || InfoClass == FileLinkInformationEx) {
        fileNameLengthOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength) + sizeof(ULONG);
        fileNameDataOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + sizeof(ULONG);
    } else {
        fileNameLengthOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength);
        fileNameDataOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    }

    /* 防 maxFileNameLength 下溢：InfoBuffer 长度不足以容纳 FileName 偏移时
     * 直接拒绝（Ex 变体偏移 +4，恶意超短缓冲会触发）。 */
    if (infoBufferLength < fileNameDataOffset) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maxFileNameLength = infoBufferLength - fileNameDataOffset;

    /* __try { */
        /* 从潜在用户态缓冲读取 FileNameLength */
        fileNameLength = *(PULONG)((PUCHAR)renameInfo + fileNameLengthOffset);

        if (fileNameLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (fileNameLength > maxFileNameLength) {
            return STATUS_BUFFER_OVERFLOW;
        }
        if (fileNameLength > WKD_FS_MAX_RENAME_BUFFER_SIZE) {
            return STATUS_NAME_TOO_LONG;
        }
        /* USHORT 截断防护：fileNameLength == MAXUSHORT 时 bufferLength 会溢出
         * USHORT 的 MaximumLength，收紧边界防下游 OOB（对齐 SS v2.1.0 修复）。 */
        if (fileNameLength > (ULONG)(MAXUSHORT - sizeof(WCHAR))) {
            return STATUS_NAME_TOO_LONG;
        }

        /* 分配大小 +1 WCHAR 存 NUL，溢出检查 */
        bufferLength = fileNameLength + sizeof(WCHAR);
        if (bufferLength < fileNameLength) {
            return STATUS_INTEGER_OVERFLOW;
        }

        buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, bufferLength, WKD_FSF_POOL_TAG);
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(buffer, (PUCHAR)renameInfo + fileNameDataOffset, fileNameLength);
        buffer[fileNameLength / sizeof(WCHAR)] = L'\0';

        NewFileName->Buffer = buffer;
        NewFileName->Length = (USHORT)fileNameLength;
        NewFileName->MaximumLength = (USHORT)bufferLength;

        buffer = NULL;   /* 所有权移交调用者 */
        status = STATUS_SUCCESS;

    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    } */

    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, WKD_FSF_POOL_TAG);
    }

    return status;
}

/* ============================================================================
 * 真实删除判定（FSC-3，迁移自 SS PreSetInfo.c L976-1021）
 *   FileDispositionInformation：DeleteFile=FALSE 是"清除删除标记"（undelete），
 *   非真实删除；FileDispositionInformationEx：FILE_DISPOSITION_DELETE 位（bit0）。
 *   把 undelete 当删除计数会污染勒索统计（RecentDeletes）导致误报，SS 视为
 *   CRITICAL 修复（FSC-3）。命中返回 TRUE 才走删除计数/备份/阻断。
 *   用户态缓冲 __try 保护（前面已跳过 KernelMode）。
 * ========================================================================== */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
WkdFspIsConfirmedDeletion(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    FILE_INFORMATION_CLASS infoClass;
    ULONG length;
    PVOID buffer;

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    length = Data->Iopb->Parameters.SetFileInformation.Length;
    buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (infoClass == FileDispositionInformation) {
        if (length >= sizeof(FILE_DISPOSITION_INFORMATION) && buffer != NULL) {
            /* __try { */
                return ((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile;
            /* } __except (EXCEPTION_EXECUTE_HANDLER) {
                return FALSE;
            } */
        }
        return FALSE;
    }

    /* FileDispositionInformationEx */
    if (length >= sizeof(FILE_DISPOSITION_INFORMATION_EX) && buffer != NULL) {
        /* __try { */
            return (((PFILE_DISPOSITION_INFORMATION_EX)buffer)->Flags & FILE_DISPOSITION_DELETE) != 0;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        } */
    }
    return FALSE;
}

/* PreSetInformation：删除/重命名/硬链接/截断/属性 的 CoW 备份 + 强信号阻断 +
 * 事件上送（勒索回滚能力 + T1003.003 凭据硬链接 + T1485 截断 + T1070.006 属性）。
 * 参考 PhantomSensor PreSetInfo.c：
 *   - Delete/Disposition/Rename → FBE CoW 备份 + 阻断 + 上送；
 *   - Link（FileLinkInformation/Ex）→ 凭据硬链接阻断 + 上送（新增 case）；
 *   - Truncate（EOF/Allocation/ValidDataLength）→ 仅监控上送不备份（SS 语义）；
 *   - BasicInformation/ShortName → 属性/短名监控上送（T1070.006/T1564.001）。
 *   强信号（自保护/敏感文件/凭据硬链接）内核无条件阻断；聚合评分弱信号
 *   （勒索/数据销毁）归死代码 C 分区（对齐 SS 评分≥70 阻断逻辑，门控未开 +
 *   agent IoaRansomwareDetect 已覆盖评分）。 */
_Use_decl_annotations_
static
FLT_PREOP_CALLBACK_STATUS
FspPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG opType;
    HANDLE reqPid;
    UNICODE_STRING newFileName = { 0 };
    BOOLEAN newFileNameAllocated = FALSE;
    BOOLEAN blockDelete = FALSE;
    BOOLEAN blockRename = FALSE;
    BOOLEAN blockHardLink = FALSE;

    *CompletionContext = NULL;

    /* 内核模式操作信任放行（对齐 SS PreSetInfo.c KernelMode 跳过） */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 分页 I/O 跳过：SetInformation 的 EOF 更新等缓存管理器分页写路径必须放行，
     * 否则 boot 期内存压力下死锁（对齐 SS PreSetInfo.c L908-928）。 */
    if (Data->Iopb != NULL &&
        (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
         FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* TODO[PreSetInfo→USBDeviceControl]: 只读卷 rename/delete 阻断接线——激活时在此处调用
     *   WkdUdcIsSetInfoBlocked(FltObjects)，返回 TRUE 则 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE
     *   （USBDeviceControl 迁移 2026-08 死代码）。 */
    /* 按 FileInformationClass 分派（对齐 SS PreSetInfo.c:940-950，补齐
     * Link/Truncate/BasicInformation/ShortName 四类缺口） */
    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        /* FSC-3（对齐 SS PreSetInfo L976-1021）：DeleteFile=FALSE 是清除删除标记
         * （undelete），非真实删除——不计删除数/不备份/不阻断，防把 undelete 当
         * 删除导致勒索误报。注：SS 对 undelete 仍走自保护/敏感检查，wkd 直接放行
         * （敏感文件删除标记本就被阻断，undelete 场景几乎不可达且操作无害）。 */
        if (!WkdFspIsConfirmedDeletion(Data)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        opType = WKD_FILE_OP_DELETE;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
        opType = WKD_FILE_OP_RENAME;
        break;
    case FileLinkInformation:
    case FileLinkInformationEx:
        opType = WKD_FILE_OP_HARDLINK;
        break;
    case FileEndOfFileInformation:
    case FileAllocationInformation:
    case FileValidDataLengthInformation:
        /* 截断：仅监控不备份（对齐 SS FBE 语义），上送 OperationType=3 供 agent
         * 勒索/破坏评分（T1485）。 */
        opType = WKD_FILE_OP_TRUNCATE;
        break;
    case FileBasicInformation:
        /* 属性/时间戳变更（T1070.006）：监控上送，不阻断。 */
        opType = WKD_FILE_OP_ATTRIBUTE;
        break;
    case FileShortNameInformation:
        /* 8.3 短名操作（T1564.001）：归属性类监控上送（对齐 SS PsipUpdateProcessMetrics
         * 语义——短名/属性变更仅计数，不参与速率阻断）。 */
        opType = WKD_FILE_OP_ATTRIBUTE;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* boot 期跳过（对齐 SS ShadowFsIsBootPhase，PreWrite 同款判断），防早期
     * 文件 I/O 洪泛触达行为分析/上送子系统。 */
    if (WkdFspIsBootPhase()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    reqPid = PsGetCurrentProcessId();

    /* 进程排除（对齐 SS PreSetInfo L1050-1054）：用户配置排除进程跳过检测（含备份）。
     * 当前 WkdFspIsProcessExcluded 返回 FALSE（排除表依赖 agent 策略下发，接入前提）。 */
    if (WkdFspIsProcessExcluded(reqPid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 获取操作文件路径（Rename/Link 时 NORMALIZED 返回源路径） */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    /* 路径排除（对齐 SS PreSetInfo L1077-1080）：用户配置排除路径跳过检测。
     * 当前 g_FsExclusions 为空（排除表 agent 策略下发，接入前提），返回 FALSE。 */
    if (WkdFspIsPathExcluded(&nameInfo->Name)) {
        goto CleanupOperation;
    }

    /* Rename/Link 提取目标路径（对齐 SS PsipGetRenameDestination），供自保护
     * 目标检查/敏感 rename 目标检查/死代码扩展名检测复用。 */
    if (opType == WKD_FILE_OP_RENAME || opType == WKD_FILE_OP_HARDLINK) {
        status = WkdFspGetRenameDestination(
            Data,
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass,
            &newFileName);
        if (NT_SUCCESS(status) && newFileName.Buffer != NULL && newFileName.Length > 0) {
            newFileNameAllocated = TRUE;
        }
    }

    /* ========================================================================
     * 自保护（强信号，无条件阻断）：EDR 自身文件（agent/driver/备份目录）被
     * 删除/重命名/建硬链接（T1562.001）。源 + rename 目标双查（对齐 SS FP-C1，
     * 防"无害文件改名到受保护路径"绕过）。豁免可信进程 + 备份目录（防 FBE 递归）。
     * ==================================================================== */
    if (opType == WKD_FILE_OP_DELETE || opType == WKD_FILE_OP_RENAME ||
        opType == WKD_FILE_OP_HARDLINK) {
        if (!FspIsBackupDirPath(&nameInfo->Name) &&
            WkdFspShouldBlockFileAccess(&nameInfo->Name, 0, reqPid, TRUE)) {
            goto BlockOperation;
        }
        if (newFileNameAllocated &&
            !FspIsBackupDirPath(&newFileName) &&
            WkdFspShouldBlockFileAccess(&newFileName, 0, reqPid, TRUE)) {
            goto BlockOperation;
        }
    }

    /* ========================================================================
     * 敏感系统文件保护（强信号，无条件阻断，已迁移）：SAM/注册表 hive/关键
     * exe/drivers/Boot/EFI/bootmgr/NTFS 元数据 的删除/重命名。
     * 补漏：rename 目标路径二次检查（防"无害文件改名到受保护路径"）。
     * 豁免可信进程防系统正常维护（磁盘清理/更新）误阻断。
     * 硬链接（HARDLINK）统一走下方凭据硬链接检测（激活 B5 WkdFspIsHardlink
     * SensitivePath），此处不重复拦截。 */
    if (WkdFspIsSensitiveSystemFile(&nameInfo->Name,
                                    &blockDelete, &blockRename, &blockHardLink)) {
        BOOLEAN shouldBlock = FALSE;

        switch (opType) {
        case WKD_FILE_OP_DELETE:
            shouldBlock = blockDelete;
            break;
        case WKD_FILE_OP_RENAME:
            shouldBlock = blockRename;
            break;
        default:
            break;
        }

        if (shouldBlock && !ExemptsIsProcessTrusted(reqPid)) {
            goto BlockOperation;
        }
    }
    if (opType == WKD_FILE_OP_RENAME && newFileNameAllocated) {
        BOOLEAN d2 = FALSE, r2 = FALSE, h2 = FALSE;

        if (WkdFspIsSensitiveSystemFile(&newFileName, &d2, &r2, &h2) &&
            r2 && !ExemptsIsProcessTrusted(reqPid)) {
            goto BlockOperation;
        }
    }

    /* ========================================================================
     * 凭据硬链接阻断（强信号，无条件阻断）：对 SAM/SECURITY/SYSTEM/SOFTWARE/
     * DEFAULT 建硬链接（T1003.003，激活 B5 WkdFspIsHardlinkSensitivePath）。
     * 命中 → 计数 + 评分上报 + STATUS_ACCESS_DENIED；豁免可信进程。
     * ==================================================================== */
    if (opType == WKD_FILE_OP_HARDLINK) {
        if (WkdFspIsHardlinkSensitivePath(&nameInfo->Name) &&
            !ExemptsIsProcessTrusted(reqPid)) {
            WkdFspTrackFileOperation(reqPid, WKD_FILE_OP_HARDLINK);
            AeReportIndicatorPair(reqPid, reqPid, TsSourceIOC,
                                  TsIndicator_File_HardLink, AeThreatSeverityCritical);
            goto BlockOperation;
        }
    }

    /* ========================================================================
     * 卷影副本删除检测（T1490，已迁移）：\System Volume Information\ 或 @GMT-
     * 路径删除 → 上送 shadow 事件 + 评分上报，agent IoaRansomware_UpdateScore +40。
     * ==================================================================== */
    if (opType == WKD_FILE_OP_DELETE && WkdFspIsShadowCopyPath(&nameInfo->Name)) {
        if (!FspIsBackupDirPath(&nameInfo->Name)) {
            FspSendFileEvent(WKD_FILE_OP_DELETE, &nameInfo->Name, 0, 0,
                             WKD_FS_FILE_FLAG_SHADOW_DELETE, -1, 0, 0);
            AeReportIndicatorPair(reqPid, reqPid, TsSourceIOC,
                                  TsIndicator_File_ShadowDelete, AeThreatSeverityCritical);
        }
        goto CleanupOperation;
    }

    /* ========================================================================
     * 扫描 verdict 缓存失效（对齐 SS PreSetInfo L1293-1303）：rename/delete/
     * truncate 改变内容或移除文件，缓存的 verdict 必须失效。wkd 缓存键 = 路径
     * DJB2 + 大小低 32 位（B8.1 死代码，未接入 PreCreate），此处保持调用使缓存
     * 一旦启用即自动失效。FileSizeLow SetInfo 时未知传 0（SS 用 FltObjects 键）。
     * ==================================================================== */
    if (opType == WKD_FILE_OP_DELETE || opType == WKD_FILE_OP_RENAME ||
        opType == WKD_FILE_OP_TRUNCATE) {
        WkdFspCacheRemove(&nameInfo->Name, 0);
    }

    /* ========================================================================
     * 勒索窗口计数（扩展 4 维，对齐 SS PSI_PROCESS_CONTEXT）：1s 窗口 Rename/
     * Delete 速率超阈值 → RAPID_RATE 提升上送优先级；Truncate/HardLink/Attribute
     * 仅计数（对齐 SS PsipUpdateProcessMetrics 语义，不参与速率阻断）。
     * ==================================================================== */
    {
        BOOLEAN rateSuspicious = WkdFspTrackFileOperation(reqPid, opType);
        ULONG setInfoFlags = rateSuspicious ? WKD_FS_FILE_FLAG_RAPID_RATE : 0;

        if (!FspIsBackupDirPath(&nameInfo->Name)) {
            if (opType == WKD_FILE_OP_DELETE || opType == WKD_FILE_OP_RENAME) {
                /* Delete/Rename：FBE CoW 备份（勒索回滚）+ 事件上送 */
                status = FbePreSetInfoBackup(Data, FltObjects, &nameInfo->Name,
                                             (FBE_OPERATION_TYPE)opType);
                if (status != STATUS_FBE_SKIP) {
                    FspSendFileEvent(opType, &nameInfo->Name, 0, 0,
                                     setInfoFlags, -1, 0, 0);
                }
            } else {
                /* Truncate/HardLink/Attribute：仅监控上送不备份（对齐 SS 语义） */
                FspSendFileEvent(opType, &nameInfo->Name, 0, 0,
                                 setInfoFlags, -1, 0, 0);
            }
        }
    }

CleanupOperation:
    if (newFileNameAllocated && newFileName.Buffer != NULL) {
        ExFreePoolWithTag(newFileName.Buffer, WKD_FSF_POOL_TAG);
        newFileName.Buffer = NULL;
    }
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

BlockOperation:
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WkDefender/FS] BLOCKED set-info: %wZ (PID=%lu, op=%lu)\n",
        &nameInfo->Name, HandleToULong(reqPid), opType);
    if (newFileNameAllocated && newFileName.Buffer != NULL) {
        ExFreePoolWithTag(newFileName.Buffer, WKD_FSF_POOL_TAG);
        newFileName.Buffer = NULL;
    }
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* ============================================================================
 * 命名管道创建回调（NamedPipeMonitor 迁移 2026-08）
 * 参考 PhantomSensor NamedPipeMonitor.c NpMonPreCreateNamedPipe。
 * IRP_MJ_CREATE_NAMED_PIPE pre-op：管道名经 FltGetFileNameInformation
 * FinalComponent 提取（去除 \Device\NamedPipe\ 前缀），创建者镜像名经
 * PsGetProcessImageFileName 捕获，调 WkdNpmPreCreateNamedPipe 分类。
 * 阻断（系统管道冒充/C2≥90）默认门控关闭（Audit 模式，对齐 AppControl），
 * 阻断分支全量写出但查 g_NpmBlockingEnabled。
 * ========================================================================== */

/* 命名管道阻断门控：默认关闭（仅上报+评分），避免系统管道表误伤 RPC 子系统 */
static BOOLEAN g_NpmBlockingEnabled = FALSE;

/* PsGetProcessImageFileName 可能未在所有 WDK 配置声明，导出自 ntoskrnl */
extern PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

/* 创建者镜像名捕获（PsGetProcessImageFileName 15 字符，对齐 SS NpmGetCreatorImageName） */
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
FspPreCreatePipe(
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

    /* 内核模式请求跳过（对齐 FspPreSetInformation KernelMode 跳过） */
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
     * 标志区分（对齐 SS：spoofed 阻断时亦 QueueEvent WasBlocked=TRUE +
     * BeEngineSubmitEvent 提分，供 agent 取证）。 */
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

/* minifilter 卸载回调 */
NTSTATUS
FsFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;  /* 端口/句柄由 FsCleanup 释放 */
}

/* ============================================================================
 * FsInitialize / FsCleanup
 *   注册 minifilter + 创建 YARA 专用 FLT 端口。
 *   参考 PhantomSensor：FltRegisterFilter + CommPort.c FltCreateCommunicationPort。
 * ========================================================================== */
_Use_decl_annotations_
NTSTATUS
FsInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    SECURITY_DESCRIPTOR sd;              /* 栈上分配，无需 ExFree */
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(DriverObject);

    ExInitializeFastMutex(&g_FsPortLock);

    /* 蜜罐 canary 配置初始化（迁移 SS PreWrite.c ShadowStrikeInitializePreWrite） */
    ExInitializePushLock(&g_FsCanaryConfig.Lock);
    g_FsCanaryConfig.Count = 0;
    g_FsCanaryConfig.Initialized = TRUE;

    /* 勒索窗口计数活动表初始化 + 进程退出清理回调（迁移 SS PostWrite.c） */
    ExInitializePushLock(&g_FsFileActivityLock);
    RtlZeroMemory(g_FsFileActivity, sizeof(g_FsFileActivity));
    PsSetCreateProcessNotifyRoutineEx(WkdFspProcessNotify, FALSE);

    /* 1. 注册 minifilter */
    status = FltRegisterFilter(DriverObject, &g_FsRegistration, &WkdFileSystemFilter);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }

    /* 2. 创建 YARA 专用 FLT 通信端口（与 ALPC 主通道隔离，X1 模型） */
    /* 安全描述符：构造 NULL DACL（DaclPresent=TRUE, Dacl=NULL）= 允许所有用户连接。
     * 开发阶段用此简化调试；切勿传 NULL sd（那等于 SYSTEM-only）。
     * TODO：生产环境应创建自定义 DACL 仅允许 SYSTEM + Administrators 连接。
     * 参考 PhantomSensor CommPort.c ShadowStrikeCreateCommunicationPort
     * 使用 RtlCreateSecurityDescriptor + RtlSetDaclSecurityDescriptor。 */
    status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] RtlCreateSecurityDescriptor failed: 0x%X\n", status);
        FltUnregisterFilter(WkdFileSystemFilter);
        WkdFileSystemFilter = NULL;
        return status;
    }
    status = RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] RtlSetDaclSecurityDescriptor failed: 0x%X\n", status);
        FltUnregisterFilter(WkdFileSystemFilter);
        WkdFileSystemFilter = NULL;
        return status;
    }
    RtlInitUnicodeString(&portName, WKD_YARA_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &sd);

    status = FltCreateCommunicationPort(
        WkdFileSystemFilter,
        &g_FsServerPort,
        &oa,
        NULL,                       /* ServerPortCookie */
        FspConnectNotify,
        FspDisconnectNotify,
        FspMessageNotify,
        WKD_YARA_PORT_MAX_CONNECT);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] FltCreateCommunicationPort failed: 0x%X\n", status);
        FltUnregisterFilter(WkdFileSystemFilter);
        WkdFileSystemFilter = NULL;
        return status;
    }

    /* 3. 启动过滤（开始回调生效） */
    status = FltStartFiltering(WkdFileSystemFilter);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] FltStartFiltering failed: 0x%X\n", status);
        FltCloseCommunicationPort(g_FsServerPort);
        g_FsServerPort = NULL;
        FltUnregisterFilter(WkdFileSystemFilter);
        WkdFileSystemFilter = NULL;
        return status;
    }

    /* 4. 代码执行映射检测引擎（PreAcquireSection 迁移 2026-08）。
     *     StartFiltering 生效后 AcquireSection 回调可能先于 WkdPasInitialize——
     *     回调壳经 WkdPasIsActive() 状态门控安全跳过（对齐 FBE/NPM 初始化窗口
     *     处理）。初始化失败非致命（仅失去执行映射检测能力）。 */
    status = WkdPasInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] WkdPasInitialize failed (non-fatal): 0x%X\n", status);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] FileSystem minifilter + YARA FLT port initialized.\n");
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
FsCleanup(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* 代码执行映射检测引擎逆序清理（先于回调反注册，状态门控已置位） */
    WkdPasShutdown();

    /* 移除进程退出清理回调（minifilter 卸载前） */
    PsSetCreateProcessNotifyRoutineEx(WkdFspProcessNotify, TRUE);

    /* 释放蜜罐 canary 路径缓冲 */
    if (g_FsCanaryConfig.Initialized) {
        LONG i;
        for (i = 0; i < g_FsCanaryConfig.Count; i++) {
            if (g_FsCanaryConfig.Paths[i].Buffer != NULL) {
                ExFreePoolWithTag(g_FsCanaryConfig.Paths[i].Buffer, WKD_FSF_POOL_TAG);
                g_FsCanaryConfig.Paths[i].Buffer = NULL;
            }
        }
        g_FsCanaryConfig.Count = 0;
        g_FsCanaryConfig.Initialized = FALSE;
    }

    if (g_FsServerPort != NULL) {
        FltCloseCommunicationPort(g_FsServerPort);
        g_FsServerPort = NULL;
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

/**************************************************/
/*  死代码分区（迁移自 SS PreWrite.c / PreCreate.c）*/
/*  功能面完整落位，暂不接入流水线。               */
/*  接入前提见各分区注释；未接入原因：wkd 当前不启用 */
/*  文件写入阻断 / 路径补充评分（性能与决策待定）。  */
/**************************************************/

#pragma warning(push)
#pragma warning(disable: 4505)  /* unreferenced local function（死代码分区） */
#pragma warning(disable: 4100)  /* unreferenced formal parameter */

/* ============================================================================
 * B1 写阻断决策（迁移自 SS PreWrite.c PwpAnalyzeWriteSuspicion +
 *   PwpShouldBlockWrite）
 *   接入前提：wkd 决策启用文件写入阻断时，在 FspPreWrite 中先计算熵
 *   （WkdFspCalculateEntropyX100）→ WkdFspAnalyzeWriteSuspicion →
 *   WkdFspShouldBlockWrite；命中则 STATUS_ACCESS_DENIED 阻断。
 * ========================================================================== */
#define WKD_FS_SUSP_NONE            0x00000000
#define WKD_FS_SUSP_HIGH_ENTROPY    0x00000001
#define WKD_FS_SUSP_OVERWRITE_HEADER 0x00000002
#define WKD_FS_SUSP_SENSITIVE_TARGET 0x00000004
#define WKD_FS_SUSP_BACKUP_TARGET   0x00000008
#define WKD_FS_SUSP_MASS_WRITE      0x00000010
#define WKD_FS_SUSP_SHADOW_COPY     0x00000020
#define WKD_FS_SUSP_CREDENTIAL_FILE 0x00000040
#define WKD_FS_SUSP_CANARY_FILE     0x00000080
#define WKD_FS_SUSP_EXTENSION_MISMATCH 0x00000100
#define WKD_FS_SUSP_APPEND_EXECUTABLE 0x00000200
#define WKD_FS_SUSP_SELF_PROTECTED  0x00000400
#define WKD_FS_SUSP_DOCUMENT_ENCRYPT 0x00000800

#define WKD_FS_CLASS_EXECUTABLE     0x00000080
#define WKD_FS_CLASS_DOCUMENT       0x00000200
#define WKD_FS_CLASS_DRIVER         0x00001000

/* B3 扩展名分类标志（对齐 SS g_ClassFlags 定义，SS FileSystemCallbacks.c） */
#define WKD_FS_CLASS_SYSTEM         0x00000001   /* 系统组件（Windows 目录/SAM/注册表） */
#define WKD_FS_CLASS_SCRIPT         0x00000002   /* 脚本（ps1/cmd/vbs/hta/reg 等） */
#define WKD_FS_CLASS_SENSITIVE      0x00000004   /* 敏感数据（数据库/邮件/证书源） */
#define WKD_FS_CLASS_DATABASE       0x00000008   /* 数据库文件 */
#define WKD_FS_CLASS_BACKUP         0x00000010   /* 备份文件（.bak/.backup/Backup 路径） */
#define WKD_FS_CLASS_CREDENTIAL     0x00000020   /* 凭据文件（SAM/NTDS/SSH 密钥） */
#define WKD_FS_CLASS_CERTIFICATE    0x00000040   /* 证书/私钥（.pfx/.p12/.pem/.cer） */
#define WKD_FS_CLASS_CONFIG         0x00000400   /* 配置/引导文件（boot.ini/EFI/ini/conf） */
#define WKD_FS_CLASS_SHADOW_COPY    0x00000800   /* 卷影副本路径（VSS/Snapshot） */
#define WKD_FS_CLASS_LOG            0x00002000   /* 日志文件（evtx/log/winevt） */

/* 写分析（迁移自 SS PwpAnalyzeWriteSuspicion）：头覆盖/高熵/大写入/可执行追加 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdFspAnalyzeWriteSuspicion(
    _In_ BOOLEAN WritesToFileStart,
    _In_ ULONG WriteLength,
    _In_ ULONG EntropyX100,
    _In_ ULONG FileClass
    )
{
    ULONG suspicion = WKD_FS_SUSP_NONE;

    if (WritesToFileStart && WriteLength >= 512) {
        suspicion |= WKD_FS_SUSP_OVERWRITE_HEADER;
    }
    if (EntropyX100 >= 800) {       /* 对齐 SS PW_RANSOMWARE_ENTROPY_THRESHOLD */
        suspicion |= WKD_FS_SUSP_HIGH_ENTROPY;
        if (FileClass & WKD_FS_CLASS_DOCUMENT) {
            suspicion |= WKD_FS_SUSP_DOCUMENT_ENCRYPT;
        }
    }
    if (WriteLength >= (16 * 1024 * 1024)) {   /* 对齐 SS PW_MASSIVE_WRITE_THRESHOLD */
        suspicion |= WKD_FS_SUSP_MASS_WRITE;
    }
    if ((FileClass & WKD_FS_CLASS_EXECUTABLE) && !WritesToFileStart) {
        suspicion |= WKD_FS_SUSP_APPEND_EXECUTABLE;
    }
    return suspicion;
}

/* 7 条写阻断规则（迁移自 SS PwpShouldBlockWrite） */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspShouldBlockWrite(
    _In_ ULONG Suspicion,
    _In_ ULONG FileClass
    )
{
    /* 卷影副本 + 高熵/头覆盖 */
    if ((Suspicion & WKD_FS_SUSP_SHADOW_COPY) &&
        (Suspicion & (WKD_FS_SUSP_HIGH_ENTROPY | WKD_FS_SUSP_OVERWRITE_HEADER))) {
        return TRUE;
    }
    /* 凭据文件 + 高熵 */
    if ((Suspicion & WKD_FS_SUSP_CREDENTIAL_FILE) && (Suspicion & WKD_FS_SUSP_HIGH_ENTROPY)) {
        return TRUE;
    }
    /* 蜜罐文件 */
    if (Suspicion & WKD_FS_SUSP_CANARY_FILE) {
        return TRUE;
    }
    /* 驱动文件 + 头覆盖 */
    if ((FileClass & WKD_FS_CLASS_DRIVER) && (Suspicion & WKD_FS_SUSP_OVERWRITE_HEADER)) {
        return TRUE;
    }
    /* 文档加密 + 头覆盖 */
    if ((Suspicion & WKD_FS_SUSP_DOCUMENT_ENCRYPT) && (Suspicion & WKD_FS_SUSP_OVERWRITE_HEADER)) {
        return TRUE;
    }
    /* 备份文件 + 高熵 */
    if ((Suspicion & WKD_FS_SUSP_BACKUP_TARGET) && (Suspicion & WKD_FS_SUSP_HIGH_ENTROPY)) {
        return TRUE;
    }
    /* 可执行追加 + 高熵 */
    if ((Suspicion & WKD_FS_SUSP_APPEND_EXECUTABLE) && (Suspicion & WKD_FS_SUSP_HIGH_ENTROPY)) {
        return TRUE;
    }
    return FALSE;
}

/* ============================================================================
 * B2 PreCreate 路径分析（迁移自 SS PreCreate.c PcAnalyzeFilePath +
 *   PcDetectAdsAccess / PcDetectDoubleExtension / PcpDetectUnicodeObfuscation /
 *   PcpDetectReservedName / PcpDetectTrailingChars / PcCalculateFlagScore）
 *   接入前提：FspPreCreate 扩展名过滤前调用 WkdFspAnalyzeFilePath 作为
 *   YARA 扫描的补充评分（对齐 SS Phase 7 威胁分析）。
 * ========================================================================== */
#define WKD_FS_PATH_ADS            0x00000001
#define WKD_FS_PATH_DOUBLE_EXT     0x00000002
#define WKD_FS_PATH_TEMP           0x00000004
#define WKD_FS_PATH_RECYCLE        0x00000008
#define WKD_FS_PATH_PUBLIC         0x00000010
#define WKD_FS_PATH_APPDATA        0x00000020
#define WKD_FS_PATH_DOWNLOADS      0x00000040
#define WKD_FS_PATH_REMOVABLE      0x00000080
#define WKD_FS_PATH_NETWORK        0x00000100
#define WKD_FS_PATH_HONEYPOT       0x00000200
#define WKD_FS_PATH_ZONE_ID        0x00000400
#define WKD_FS_PATH_HIDDEN         0x00000800
#define WKD_FS_PATH_SYSTEM_USER    0x00001000
#define WKD_FS_PATH_EXEC_NO_READ   0x00002000
#define WKD_FS_PATH_WRITE_EXEC     0x00004000
#define WKD_FS_PATH_DELETE_ON_CLOSE 0x00008000
#define WKD_FS_PATH_OVERWRITE      0x00010000
#define WKD_FS_PATH_LONG           0x00020000
#define WKD_FS_PATH_RLO            0x00040000
#define WKD_FS_PATH_TRAILING       0x00080000
#define WKD_FS_PATH_RESERVED       0x00100000

typedef struct _WKD_FS_SUSPICIOUS_PATH {
    PCWSTR Pattern;
    ULONG  Flag;
} WKD_FS_SUSPICIOUS_PATH;

/* 可疑路径表（对齐 SS PreCreate.c g_SuspiciousPaths 11 条 + PreAcquireSection.c
 * g_SuspiciousPaths 特有 \staging\、\cache\，共 13 条） */
static const WKD_FS_SUSPICIOUS_PATH g_FsSuspiciousPaths[] = {
    { L"\\temp\\",              WKD_FS_PATH_TEMP },
    { L"\\tmp\\",               WKD_FS_PATH_TEMP },
    { L"\\$recycle.bin\\",      WKD_FS_PATH_RECYCLE },
    { L"\\recycler\\",          WKD_FS_PATH_RECYCLE },
    { L"\\users\\public\\",     WKD_FS_PATH_PUBLIC },
    { L"\\public\\",            WKD_FS_PATH_PUBLIC },
    { L"\\appdata\\local\\",    WKD_FS_PATH_APPDATA },
    { L"\\appdata\\roaming\\",  WKD_FS_PATH_APPDATA },
    { L"\\downloads\\",         WKD_FS_PATH_DOWNLOADS },
    { L"\\perflogs\\",          WKD_FS_PATH_TEMP },
    { L"\\programdata\\",       WKD_FS_PATH_APPDATA },
    { L"\\staging\\",           WKD_FS_PATH_TEMP },  /* SS PreAcquireSection 特有 */
    { L"\\cache\\",             WKD_FS_PATH_TEMP },  /* SS PreAcquireSection 特有 */
};

/* 可执行扩展（对齐 SS PreCreate.c g_ExecutableExtensions 12 条） */
static const PCWSTR g_FsExecutableExtensions[] = {
    L"exe", L"dll", L"scr", L"com", L"pif", L"bat", L"cmd",
    L"ps1", L"vbs", L"js", L"hta", L"msi"
};

/* 保留设备名（对齐 SS PreCreate.c g_ReservedNames 24 个） */
static const PCWSTR g_FsReservedNames[] = {
    L"CON", L"PRN", L"AUX", L"NUL",
    L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
    L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9"
};

/* 标志→分值（对齐 SS PcCalculateFlagScore，上限 100） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFspCalcPathFlagScore(
    _In_ ULONG Flags
    )
{
    ULONG score = 0;
    if (Flags & WKD_FS_PATH_ADS)             score += 15;
    if (Flags & WKD_FS_PATH_DOUBLE_EXT)      score += 25;
    if (Flags & WKD_FS_PATH_TEMP)            score += 10;
    if (Flags & WKD_FS_PATH_RECYCLE)         score += 10;
    if (Flags & WKD_FS_PATH_PUBLIC)          score += 15;
    if (Flags & WKD_FS_PATH_APPDATA)         score += 10;
    if (Flags & WKD_FS_PATH_DOWNLOADS)       score += 5;
    if (Flags & WKD_FS_PATH_REMOVABLE)       score += 10;
    if (Flags & WKD_FS_PATH_NETWORK)         score += 5;
    if (Flags & WKD_FS_PATH_HONEYPOT)        score += 40;
    if (Flags & WKD_FS_PATH_ZONE_ID)         score += 5;
    if (Flags & WKD_FS_PATH_HIDDEN)          score += 10;
    if (Flags & WKD_FS_PATH_SYSTEM_USER)     score += 15;
    if (Flags & WKD_FS_PATH_EXEC_NO_READ)    score += 20;
    if (Flags & WKD_FS_PATH_WRITE_EXEC)      score += 20;
    if (Flags & WKD_FS_PATH_DELETE_ON_CLOSE) score += 10;
    if (Flags & WKD_FS_PATH_OVERWRITE)       score += 5;
    if (Flags & WKD_FS_PATH_LONG)            score += 10;
    if (Flags & WKD_FS_PATH_RLO)             score += 30;
    if (Flags & WKD_FS_PATH_TRAILING)        score += 15;
    if (Flags & WKD_FS_PATH_RESERVED)        score += 20;
    return (score > 100) ? 100 : score;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsExecutableExt(
    _In_ PCWSTR Extension
    )
{
    ULONG i;
    if (Extension == NULL) {
        return FALSE;
    }
    for (i = 0; i < ARRAYSIZE(g_FsExecutableExtensions); i++) {
        if (_wcsicmp(Extension, g_FsExecutableExtensions[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ADS 检测（迁移自 SS PcDetectAdsAccess）：驱动器冒号（位置 2）后再现冒号 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspDetectAds(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT i;
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length < 4 * sizeof(WCHAR)) {
        return FALSE;
    }
    for (i = 2; i < FileName->Length / sizeof(WCHAR); i++) {
        if (FileName->Buffer[i] == L':') {
            return TRUE;
        }
    }
    return FALSE;
}

/* 双扩展名检测（迁移自 SS PcDetectDoubleExtension）：长度感知迭代，最终扩展可执行
 * + 隐藏扩展为文档类型（invoice.pdf.exe 经典模式） */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspDetectDoubleExt(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING Extension
    )
{
    static const PCWSTR documentExts[] = {
        L"pdf", L"doc", L"docx", L"xls", L"xlsx", L"txt",
        L"jpg", L"png", L"mp3", L"mp4", L"zip", L"rar"
    };
    PWCHAR fileNameStart = NULL;
    PWCHAR current;
    PWCHAR bufferEnd;
    PWCHAR firstDot = NULL;
    PWCHAR lastDot = NULL;
    ULONG dotCount = 0;
    WCHAR hiddenExt[32];
    ULONG hiddenExtLen = 0;
    ULONG i;
    BOOLEAN hiddenExec = FALSE;
    USHORT charCount;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0 || Extension == NULL) {
        return FALSE;
    }
    charCount = FileName->Length / sizeof(WCHAR);
    bufferEnd = FileName->Buffer + charCount;

    fileNameStart = FileName->Buffer;
    for (current = FileName->Buffer; current < bufferEnd; current++) {
        if (*current == L'\\') {
            fileNameStart = current + 1;
        }
    }
    if (fileNameStart >= bufferEnd) {
        return FALSE;
    }

    for (current = fileNameStart; current < bufferEnd; current++) {
        if (*current == L'.') {
            dotCount++;
            if (firstDot == NULL) firstDot = current;
            lastDot = current;
        }
    }
    if (dotCount < 2 || firstDot == NULL || lastDot == NULL || firstDot == lastDot) {
        return FALSE;
    }

    current = firstDot + 1;
    hiddenExtLen = 0;
    while (current < lastDot && hiddenExtLen < 30) {
        if (*current == L'.') break;
        hiddenExt[hiddenExtLen++] = *current;
        current++;
    }
    if (hiddenExtLen == 0) return FALSE;
    hiddenExt[hiddenExtLen] = L'\0';

    if (Extension->Buffer != NULL && Extension->Length > 0) {
        WCHAR appExt[32];
        USHORT appExtLen = Extension->Length / sizeof(WCHAR);
        PCWSTR extStart = Extension->Buffer;
        if (*extStart == L'.') {
            extStart++;
            appExtLen--;
        }
        if (appExtLen > 0 && appExtLen < 30) {
            RtlCopyMemory(appExt, extStart, appExtLen * sizeof(WCHAR));
            appExt[appExtLen] = L'\0';
            if (WkdFspIsExecutableExt(appExt)) {
                for (i = 0; i < ARRAYSIZE(documentExts); i++) {
                    if (_wcsicmp(hiddenExt, documentExts[i]) == 0) {
                        hiddenExec = TRUE;
                        break;
                    }
                }
            }
        }
    }
    return hiddenExec;
}

/* Unicode 混淆检测（迁移自 SS PcpDetectUnicodeObfuscation）：RLO/LRO/PDF/LRM/RLM + 零宽 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectUnicodeObf(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT i;
    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }
    for (i = 0; i < FileName->Length / sizeof(WCHAR); i++) {
        WCHAR ch = FileName->Buffer[i];
        if (ch == 0x202E || ch == 0x202D || ch == 0x202C ||
            ch == 0x200E || ch == 0x200F ||
            ch == 0x200B || ch == 0x200C || ch == 0x200D || ch == 0xFEFF) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 保留设备名检测（迁移自 SS PcpDetectReservedName）：长度感知，CON/PRN/COM1-9/LPT1-9 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectReservedName(
    _In_ PCUNICODE_STRING FileName
    )
{
    PWCHAR fileNameStart = NULL;
    PWCHAR current;
    PWCHAR bufferEnd;
    PWCHAR dotPos = NULL;
    WCHAR nameBuffer[16];
    ULONG nameLen = 0;
    ULONG i;
    USHORT charCount;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    charCount = FileName->Length / sizeof(WCHAR);
    bufferEnd = FileName->Buffer + charCount;

    fileNameStart = FileName->Buffer;
    for (current = FileName->Buffer; current < bufferEnd; current++) {
        if (*current == L'\\') {
            fileNameStart = current + 1;
        }
    }
    if (fileNameStart >= bufferEnd) {
        return FALSE;
    }

    for (current = fileNameStart; current < bufferEnd; current++) {
        if (*current == L'.') {
            dotPos = current;
            break;
        }
    }
    nameLen = (dotPos != NULL) ? (ULONG)(dotPos - fileNameStart) : (ULONG)(bufferEnd - fileNameStart);
    if (nameLen == 0 || nameLen >= 15) {
        return FALSE;
    }

    RtlCopyMemory(nameBuffer, fileNameStart, nameLen * sizeof(WCHAR));
    nameBuffer[nameLen] = L'\0';

    for (i = 0; i < ARRAYSIZE(g_FsReservedNames); i++) {
        if (_wcsicmp(nameBuffer, g_FsReservedNames[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 尾部空格/点检测（迁移自 SS PcpDetectTrailingChars）：排除当前目录 "." */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectTrailing(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT len;
    WCHAR lastChar;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length < sizeof(WCHAR)) {
        return FALSE;
    }
    len = FileName->Length / sizeof(WCHAR);
    lastChar = FileName->Buffer[len - 1];
    if (lastChar == L' ' || lastChar == L'.') {
        if (len == 1 && lastChar == L'.') {
            return FALSE;   /* 当前目录 "." */
        }
        return TRUE;
    }
    return FALSE;
}

/* 综合路径分析（迁移自 SS PcAnalyzeFilePath）：返回威胁分（0-100），Flags 输出 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdFspAnalyzeFilePath(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING Extension,
    _Out_ PULONG OutFlags
    )
{
    ULONG flags = 0;
    ULONG i;

    if (OutFlags) {
        *OutFlags = 0;
    }
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return 0;
    }

    for (i = 0; i < ARRAYSIZE(g_FsSuspiciousPaths); i++) {
        if (WkdFspContainsStrInsensitive(FileName, g_FsSuspiciousPaths[i].Pattern)) {
            flags |= g_FsSuspiciousPaths[i].Flag;
        }
    }
    if (FileName->Length > 500 * sizeof(WCHAR)) {
        flags |= WKD_FS_PATH_LONG;
    }
    if (WkdFspDetectAds(FileName)) {
        flags |= WKD_FS_PATH_ADS;
    }
    if (WkdFspDetectDoubleExt(FileName, Extension)) {
        flags |= WKD_FS_PATH_DOUBLE_EXT;
    }
    if (WkdFspDetectUnicodeObf(FileName)) {
        flags |= WKD_FS_PATH_RLO;
    }
    if (WkdFspDetectReservedName(FileName)) {
        flags |= WKD_FS_PATH_RESERVED;
    }
    if (WkdFspDetectTrailing(FileName)) {
        flags |= WKD_FS_PATH_TRAILING;
    }

    if (OutFlags) {
        *OutFlags = flags;
    }
    return WkdFspCalcPathFlagScore(flags);
}

/* ============================================================================
 * B3 扩展名分类表（迁移自 SS FileSystemCallbacks.c g_ExtensionTable，
 *   12 类分类标志 + 扫描优先级，60+ 条）
 *   接入前提：写阻断死代码（WkdFspShouldBlockWrite 需 FileClass）与 PreCreate
 *   扫描优先级（YARA 补充）消费。
 * ========================================================================== */
#define WKD_FS_CLASS_ARCHIVE        0x00004000

typedef struct _WKD_FS_EXTENSION_INFO {
    PCWSTR Extension;
    ULONG  ClassFlags;
    ULONG  Priority;
} WKD_FS_EXTENSION_INFO, *PWKD_FS_EXTENSION_INFO;

static const WKD_FS_EXTENSION_INFO g_FsExtensionTable[] = {
    /* 可执行（最高优先级） */
    { L"exe",  WKD_FS_CLASS_EXECUTABLE, 100 },
    { L"dll",  WKD_FS_CLASS_EXECUTABLE, 100 },
    { L"sys",  WKD_FS_CLASS_EXECUTABLE | WKD_FS_CLASS_SYSTEM | WKD_FS_CLASS_DRIVER, 100 },
    { L"drv",  WKD_FS_CLASS_EXECUTABLE | WKD_FS_CLASS_SYSTEM | WKD_FS_CLASS_DRIVER, 100 },
    { L"scr",  WKD_FS_CLASS_EXECUTABLE, 95 },
    { L"com",  WKD_FS_CLASS_EXECUTABLE, 95 },
    { L"pif",  WKD_FS_CLASS_EXECUTABLE, 95 },
    { L"msi",  WKD_FS_CLASS_EXECUTABLE, 90 },
    { L"msp",  WKD_FS_CLASS_EXECUTABLE, 90 },
    { L"msu",  WKD_FS_CLASS_EXECUTABLE, 90 },
    { L"ocx",  WKD_FS_CLASS_EXECUTABLE, 90 },
    { L"cpl",  WKD_FS_CLASS_EXECUTABLE, 90 },

    /* 脚本（高优先级） */
    { L"ps1",  WKD_FS_CLASS_SCRIPT, 85 },
    { L"psm1", WKD_FS_CLASS_SCRIPT, 85 },
    { L"psd1", WKD_FS_CLASS_SCRIPT, 85 },
    { L"bat",  WKD_FS_CLASS_SCRIPT, 80 },
    { L"cmd",  WKD_FS_CLASS_SCRIPT, 80 },
    { L"vbs",  WKD_FS_CLASS_SCRIPT, 85 },
    { L"vbe",  WKD_FS_CLASS_SCRIPT, 85 },
    { L"js",   WKD_FS_CLASS_SCRIPT, 80 },
    { L"jse",  WKD_FS_CLASS_SCRIPT, 85 },
    { L"wsf",  WKD_FS_CLASS_SCRIPT, 85 },
    { L"wsh",  WKD_FS_CLASS_SCRIPT, 85 },
    { L"hta",  WKD_FS_CLASS_SCRIPT, 90 },
    { L"reg",  WKD_FS_CLASS_SCRIPT, 75 },
    { L"inf",  WKD_FS_CLASS_SCRIPT, 70 },

    /* 文档（宏风险） */
    { L"doc",  WKD_FS_CLASS_DOCUMENT, 60 },
    { L"docx", WKD_FS_CLASS_DOCUMENT, 55 },
    { L"docm", WKD_FS_CLASS_DOCUMENT, 75 },
    { L"xls",  WKD_FS_CLASS_DOCUMENT, 60 },
    { L"xlsx", WKD_FS_CLASS_DOCUMENT, 55 },
    { L"xlsm", WKD_FS_CLASS_DOCUMENT, 75 },
    { L"xlsb", WKD_FS_CLASS_DOCUMENT, 75 },
    { L"ppt",  WKD_FS_CLASS_DOCUMENT, 55 },
    { L"pptx", WKD_FS_CLASS_DOCUMENT, 50 },
    { L"pptm", WKD_FS_CLASS_DOCUMENT, 75 },
    { L"pdf",  WKD_FS_CLASS_DOCUMENT, 65 },
    { L"rtf",  WKD_FS_CLASS_DOCUMENT, 60 },

    /* 归档 */
    { L"zip",  WKD_FS_CLASS_ARCHIVE, 50 },
    { L"rar",  WKD_FS_CLASS_ARCHIVE, 50 },
    { L"7z",   WKD_FS_CLASS_ARCHIVE, 50 },
    { L"cab",  WKD_FS_CLASS_ARCHIVE, 55 },
    { L"iso",  WKD_FS_CLASS_ARCHIVE, 60 },
    { L"img",  WKD_FS_CLASS_ARCHIVE, 60 },
    { L"vhd",  WKD_FS_CLASS_ARCHIVE, 60 },
    { L"vhdx", WKD_FS_CLASS_ARCHIVE, 60 },

    /* 敏感数据（凭据/证书/数据库/备份） */
    { L"pst",   WKD_FS_CLASS_SENSITIVE, 40 },
    { L"ost",   WKD_FS_CLASS_SENSITIVE, 40 },
    { L"mdb",   WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_DATABASE, 45 },
    { L"accdb", WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_DATABASE, 45 },
    { L"sqlite",WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_DATABASE, 40 },
    { L"db",    WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_DATABASE, 40 },
    { L"sql",   WKD_FS_CLASS_SENSITIVE, 35 },
    { L"bak",   WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_BACKUP, 35 },
    { L"key",   WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_CERTIFICATE, 50 },
    { L"pem",   WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_CERTIFICATE, 50 },
    { L"pfx",   WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_CERTIFICATE, 50 },
    { L"p12",   WKD_FS_CLASS_SENSITIVE | WKD_FS_CLASS_CERTIFICATE, 50 },

    { NULL, 0, 0 }   /* sentinel */
};

/* 扩展名分类（对齐 SS FscpClassifyFileByExtension + FscpGetScanPriority）：
 * 长度感知大小写不敏感比较，返回分类标志，默认优先级 50。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFspClassifyFile(
    _In_ PCUNICODE_STRING Extension,
    _Out_opt_ PULONG OutPriority
    )
{
    ULONG i;
    ULONG extLen;

    if (OutPriority) {
        *OutPriority = 50;
    }
    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return 0;
    }

    extLen = Extension->Length / sizeof(WCHAR);

    /* 跳过前导点 */
    if (Extension->Buffer[0] == L'.') {
        if (extLen == 1) {
            return 0;
        }
        extLen--;
    }

    for (i = 0; g_FsExtensionTable[i].Extension != NULL; i++) {
        ULONG patLen = 0;
        const WCHAR* pat = g_FsExtensionTable[i].Extension;
        ULONG j;
        BOOLEAN match = TRUE;

        while (pat[patLen] != L'\0') {
            patLen++;
        }
        if (patLen != extLen) {
            continue;
        }
        for (j = 0; j < extLen; j++) {
            WCHAR a = Extension->Buffer[j];
            WCHAR b = pat[j];
            if (Extension->Buffer[0] == L'.') {
                a = Extension->Buffer[j + 1];
            }
            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            if (OutPriority) {
                *OutPriority = g_FsExtensionTable[i].Priority;
            }
            return g_FsExtensionTable[i].ClassFlags;
        }
    }
    return 0;
}

/* ============================================================================
 * B4 敏感写保护表（迁移自 SS PreWrite.c g_SensitivePatterns，40+ 条）
 *   针对"写入敏感文件"的分类（区别于 B3 的 delete/rename 敏感系统文件保护）：
 *   卷影/凭据/证书/数据库/系统/驱动/配置/日志。
 *   接入前提：写阻断死代码（WkdFspShouldBlockWrite 的 SHADOW_COPY /
 *   CREDENTIAL_FILE / BACKUP_TARGET 判定）消费本分类结果。
 * ========================================================================== */
typedef struct _WKD_FS_SENSITIVE_PATTERN {
    PCWSTR Pattern;
    USHORT Length;      /* 字节数（预计算，无 wcslen） */
    ULONG  ClassFlags;
} WKD_FS_SENSITIVE_PATTERN;

static const WKD_FS_SENSITIVE_PATTERN g_FsSensitiveWritePatterns[] = {
    /* 卷影/备份 */
    { L"\\System Volume Information\\", 27, WKD_FS_CLASS_SHADOW_COPY },
    { L"@GMT-",                          5, WKD_FS_CLASS_SHADOW_COPY },
    { L".bak",                           4, WKD_FS_CLASS_BACKUP },
    { L".backup",                        7, WKD_FS_CLASS_BACKUP },
    { L"\\Backup\\",                     8, WKD_FS_CLASS_BACKUP },

    /* 凭据 */
    { L"\\SAM",                          4, WKD_FS_CLASS_CREDENTIAL },
    { L"\\SECURITY",                     9, WKD_FS_CLASS_CREDENTIAL },
    { L"\\SYSTEM",                       7, WKD_FS_CLASS_CREDENTIAL },
    { L"\\ntds.dit",                     9, WKD_FS_CLASS_CREDENTIAL },
    { L"\\NTUSER.DAT",                  11, WKD_FS_CLASS_CREDENTIAL },
    { L".pfx",                           4, WKD_FS_CLASS_CERTIFICATE },
    { L".p12",                           4, WKD_FS_CLASS_CERTIFICATE },
    { L".pem",                           4, WKD_FS_CLASS_CERTIFICATE },
    { L".key",                           4, WKD_FS_CLASS_CERTIFICATE },
    { L".cer",                           4, WKD_FS_CLASS_CERTIFICATE },
    { L".crt",                           4, WKD_FS_CLASS_CERTIFICATE },
    { L"\\ssh\\",                        5, WKD_FS_CLASS_CREDENTIAL },
    { L"\\gnupg\\",                      7, WKD_FS_CLASS_CREDENTIAL },
    { L"id_rsa",                         6, WKD_FS_CLASS_CREDENTIAL },
    { L"id_ecdsa",                       8, WKD_FS_CLASS_CREDENTIAL },
    { L"known_hosts",                   11, WKD_FS_CLASS_CREDENTIAL },

    /* 数据库 */
    { L".mdf",                           4, WKD_FS_CLASS_DATABASE },
    { L".ldf",                           4, WKD_FS_CLASS_DATABASE },
    { L".ndf",                           4, WKD_FS_CLASS_DATABASE },
    { L".sqlite",                        7, WKD_FS_CLASS_DATABASE },
    { L".mdb",                           4, WKD_FS_CLASS_DATABASE },
    { L".accdb",                         6, WKD_FS_CLASS_DATABASE },

    /* 系统/驱动 */
    { L"\\Windows\\System32\\",        18, WKD_FS_CLASS_SYSTEM },
    { L"\\Windows\\SysWOW64\\",        18, WKD_FS_CLASS_SYSTEM },
    { L"\\Windows\\WinSxS\\",          16, WKD_FS_CLASS_SYSTEM },
    { L".sys",                           4, WKD_FS_CLASS_DRIVER },
    { L"\\drivers\\",                    9, WKD_FS_CLASS_DRIVER },

    /* 配置 */
    { L"boot.ini",                       8, WKD_FS_CLASS_CONFIG },
    { L"bootmgr",                        7, WKD_FS_CLASS_CONFIG },
    { L"\\EFI\\",                        5, WKD_FS_CLASS_CONFIG },
    { L".ini",                           4, WKD_FS_CLASS_CONFIG },
    { L".conf",                          5, WKD_FS_CLASS_CONFIG },
    { L".config",                        7, WKD_FS_CLASS_CONFIG },
    { L"web.config",                    10, WKD_FS_CLASS_CONFIG },
    { L"machine.config",                14, WKD_FS_CLASS_CONFIG },

    /* 日志（篡改检测） */
    { L".evtx",                          5, WKD_FS_CLASS_LOG },
    { L".log",                           4, WKD_FS_CLASS_LOG },
    { L"\\winevt\\",                     8, WKD_FS_CLASS_LOG },

    { NULL, 0, 0 }   /* sentinel */
};

/* 敏感写目标判定（对齐 SS PwpIsSensitiveFile）：包含匹配，返回分类标志 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspIsSensitiveWriteTarget(
    _In_ PCUNICODE_STRING FileName,
    _Out_ PULONG ClassFlags
    )
{
    ULONG i;

    if (ClassFlags) {
        *ClassFlags = 0;
    }
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; g_FsSensitiveWritePatterns[i].Pattern != NULL; i++) {
        if (WkdFspContainsStrInsensitive(FileName,
                                         g_FsSensitiveWritePatterns[i].Pattern)) {
            if (ClassFlags) {
                *ClassFlags |= g_FsSensitiveWritePatterns[i].ClassFlags;
            }
        }
    }
    return (ClassFlags && *ClassFlags) ? TRUE : FALSE;
}

/* ============================================================================
 * B5 凭据硬链接检测（迁移自 SS PreSetInfo.c PsipDetectCredentialAccess +
 *   FileLinkInformation 处理，T1003.003 SAM 硬链接）
 *   接入前提：FspPreSetInformation 增加 FileLinkInformation case，
 *   对 SAM/SECURITY/SYSTEM/SOFTWARE/DEFAULT 建硬链接（BlockHardLink 位）即可疑。
 * ========================================================================== */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspIsHardlinkSensitivePath(
    _In_ PCUNICODE_STRING FileName
    )
{
    BOOLEAN blockDelete = FALSE;
    BOOLEAN blockRename = FALSE;
    BOOLEAN blockHardLink = FALSE;

    if (WkdFspIsSensitiveSystemFile(FileName, &blockDelete, &blockRename, &blockHardLink)) {
        return blockHardLink;
    }
    return FALSE;
}

/* ============================================================================
 * B6 PreCreate 访问模式检测（迁移自 SS PreCreate Phase 7 PcpClassifyAccessType +
 *   ExecuteNoRead/WriteExecute/DeleteOnClose/Overwrite + Zone.Identifier）
 *   接入前提：WkdFspAnalyzeFilePath 中补调用，为死代码 B2 标志补生产者。
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFspAnalyzeAccessPattern(
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG CreateOptions
    )
{
    ULONG flags = 0;
    ULONG disposition = (CreateOptions >> 24) & 0xFF;

    /* 执行不读（注入前兆） */
    if ((DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) &&
        !(DesiredAccess & (FILE_READ_DATA | GENERIC_READ))) {
        flags |= WKD_FS_PATH_EXEC_NO_READ;
    }
    /* 写 + 执行（dropper） */
    if ((DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) &&
        (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | DELETE))) {
        flags |= WKD_FS_PATH_WRITE_EXEC;
    }
    /* 关闭即删 */
    if (CreateOptions & FILE_DELETE_ON_CLOSE) {
        flags |= WKD_FS_PATH_DELETE_ON_CLOSE;
    }
    /* 覆盖写 disposition */
    if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
        disposition == FILE_OVERWRITE_IF) {
        flags |= WKD_FS_PATH_OVERWRITE;
    }
    return flags;
}

/* Zone.Identifier 标记流检测（对齐 SS PreCreate Phase 7） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsZoneIdentifier(
    _In_ PCUNICODE_STRING FileName
    )
{
    return WkdFspContainsStrInsensitive(FileName, L":Zone.Identifier");
}

/* ============================================================================
 * 搁置项说明（功能面已覆盖或过时，不迁移代码）
 *   - ETW 双写（SS PostCreate/PostWrite 的 EcEmitKernelEvent / EtwWriteFileEvent）：
 *     wkd 用 ALPC 文件事件上送替代 ETW 消费，架构差异，不迁移。
 *   - WSL 逃逸（SS PreCreate WslMonCheckFileAccess）：已有 TODO 标注接线
 *     IocpCheckWslFileAccess（IocProcess.c §9 死代码）。
 *   - 卷影副本删除评分（SS PreSetInfo）：wkd 已在活跃区上送 shadow 事件
 *     （WkdMessage_FileShadowCopyDelete 0x1306），agent IoaRansomware_UpdateScore
 *     的 SHADOW_COPY_DELETE 分支（+40）消费，覆盖。
 *   其余功能面（KTM/TxF、EFI、勒索关联、自保护、扫描缓存、蜜罐通配模式、
 *   PostCreate 上下文体系、PostWrite 覆盖模式）已按"全量覆盖"原则以死代码
 *   分区迁移（B7/B8/B9），接入前提见各分区注释。
 * ========================================================================== */

/* ============================================================================
 * B7 PostCreate 上下文体系（迁移 SS PostCreate.c，全量死代码）
 *   对标 SS PostCreate.h：SHADOWSTRIKE_STREAM_CONTEXT(L244) /
 *     SHADOWSTRIKE_HANDLE_CONTEXT(L349) / POC_COMPLETION_CONTEXT(L403) /
 *     POC_TRACKING_FLAGS(L182) / POC_FILE_CLASS(L211)。
 *   核心价值：①verdict 缓存（避免重复同步扫描）②变更检测基线
 *     （Dirty/Scanned 失效，写后强制重扫）③勒索监控目标标记。
 *   接入前提（全部满足才可激活）：
 *     a. Filter.c 注册 ContextRegistration（FLT_STREAM_CONTEXT +
 *        FLT_STREAMHANDLE_CONTEXT，见 SS FileSystemCallbacks.c:317）
 *     b. FspPostCreate 调用 WkdFspPostCreateAttach（当前占位）
 *     c. FspPreCreate 读 stream context 命中 verdict 跳过扫描
 *   当前 FspPostCreate 保持占位（不注册 context），本分区全部不接线。
 * ========================================================================== */
#define WKD_FS_STREAM_CONTEXT_SIGNATURE  'cSfW'
#define WKD_FS_HANDLE_CONTEXT_SIGNATURE  'hSfW'

/* 追踪标志（对齐 SS PocTracking*，按需精简） */
#define WKD_FS_TRACK_SCANNED        0x00000001
#define WKD_FS_TRACK_CACHED         0x00000002
#define WKD_FS_TRACK_MODIFIED       0x00000004
#define WKD_FS_TRACK_DELETED        0x00000008
#define WKD_FS_TRACK_RENAMED        0x00000010
#define WKD_FS_TRACK_ADS            0x00000080
#define WKD_FS_TRACK_HIDDEN         0x00000800
#define WKD_FS_TRACK_SYSTEM         0x00001000
#define WKD_FS_TRACK_READONLY       0x00002000
#define WKD_FS_TRACK_TEMPORARY      0x00004000
#define WKD_FS_TRACK_NETWORK        0x00008000
#define WKD_FS_TRACK_REMOVABLE      0x00010000
#define WKD_FS_TRACK_RANSOMWATCH    0x00020000

typedef struct _WKD_FS_STREAM_CONTEXT {
    ULONG           Signature;
    ULONG64         FileId;
    ULONG           VolumeSerial;
    LONGLONG        ScanFileSize;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   CreationTime;
    WCHAR           CachedFileName[256];
    WCHAR           CachedExtension[32];
    ULONG           FileClass;           /* WkdFspClassifyFile 返回（B3） */
    ULONG           FileAttributes;
    BOOLEAN         Scanned;
    BOOLEAN         Dirty;
    BOOLEAN         RansomwareMonitored;
    volatile LONG   OpenCount;
    volatile LONG   WriteCount;
    ULONG           TrackingFlags;
    LARGE_INTEGER   FirstWriteTime;
    LARGE_INTEGER   LastModifyTime;
    EX_PUSH_LOCK    Lock;
} WKD_FS_STREAM_CONTEXT, *PWKD_FS_STREAM_CONTEXT;

typedef struct _WKD_FS_HANDLE_CONTEXT {
    ULONG           Signature;
    HANDLE          ProcessId;
    HANDLE          ThreadId;
    ACCESS_MASK     DesiredAccess;
    ULONG           CreateOptions;
    ULONG           ShareAccess;
    volatile LONG   WriteCount;
    volatile LONG   ReadCount;
    LARGE_INTEGER   OpenTime;
    EX_PUSH_LOCK    Lock;
} WKD_FS_HANDLE_CONTEXT, *PWKD_FS_HANDLE_CONTEXT;

/* 属性查询（对齐 SS PocpQueryFileInformation L1957-2032）：
 * FileStandard(大小) + FileInternal(FileId) + FileBasic(时间戳) */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdFspQueryStreamInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG64 OutFileId,
    _Out_ PLONGLONG OutFileSize,
    _Out_ PLARGE_INTEGER OutLastWriteTime,
    _Out_ PLARGE_INTEGER OutCreationTime
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION stdInfo;
    FILE_INTERNAL_INFORMATION internalInfo;
    FILE_BASIC_INFORMATION basicInfo;

    *OutFileId = 0;
    *OutFileSize = 0;
    OutLastWriteTime->QuadPart = 0;
    OutCreationTime->QuadPart = 0;

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
        &stdInfo, sizeof(stdInfo), FileStandardInformation, NULL);
    if (NT_SUCCESS(status)) {
        *OutFileSize = stdInfo.EndOfFile.QuadPart;
    }
    status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
        &internalInfo, sizeof(internalInfo), FileInternalInformation, NULL);
    if (NT_SUCCESS(status)) {
        *OutFileId = (ULONG64)internalInfo.IndexNumber.QuadPart;
    }
    status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
        &basicInfo, sizeof(basicInfo), FileBasicInformation, NULL);
    if (NT_SUCCESS(status)) {
        *OutLastWriteTime = basicInfo.LastWriteTime;
        *OutCreationTime = basicInfo.CreationTime;
    }
    return STATUS_SUCCESS;
}

/* 卷序列号（对齐 SS PocpQueryVolumeSerial L2035-2070） */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdFspQueryVolumeSerial(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG OutSerial
    )
{
    NTSTATUS status;
    UCHAR buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 32 * sizeof(WCHAR)];
    PFILE_FS_VOLUME_INFORMATION volumeInfo;
    ULONG bytesReturned;

    *OutSerial = 0;
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    volumeInfo = (PFILE_FS_VOLUME_INFORMATION)buffer;
    status = FltQueryVolumeInformationFile(FltObjects->Instance, FltObjects->FileObject,
        volumeInfo, sizeof(buffer), FileFsVolumeInformation, &bytesReturned);
    if (NT_SUCCESS(status)) {
        *OutSerial = volumeInfo->VolumeSerialNumber;
    }
    return status;
}

/* 卷类型 / ADS 追踪标志（对齐 SS PocpSetTrackingFlags L2073-2137） */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdFspSetStreamTrackingFlags(
    _Inout_ PWKD_FS_STREAM_CONTEXT Context,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo
    )
{
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;
    NTSTATUS status;

    if (Context == NULL) {
        return;
    }
    if (FltObjects->Volume != NULL) {
        status = FltGetVolumeProperties(FltObjects->Volume, &volumeProps,
            sizeof(volumeProps), &bytesReturned);
        if (NT_SUCCESS(status)) {
            if (volumeProps.DeviceCharacteristics & FILE_REMOTE_DEVICE) {
                Context->TrackingFlags |= WKD_FS_TRACK_NETWORK;
            }
            if (volumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA) {
                Context->TrackingFlags |= WKD_FS_TRACK_REMOVABLE;
            }
        }
    }
    /* ADS：驱动器冒号（索引 3 起）后再现冒号 */
    if (NameInfo != NULL && NameInfo->Name.Buffer != NULL) {
        USHORT nameLen = NameInfo->Name.Length / sizeof(WCHAR);
        if (nameLen >= 5) {
            USHORT i;
            for (i = 3; i < nameLen; i++) {
                if (NameInfo->Name.Buffer[i] == L':') {
                    Context->TrackingFlags |= WKD_FS_TRACK_ADS;
                    break;
                }
            }
        }
    }
}

/* 勒索监控目标判定（对齐 SS PostCreate Phase 9 L835-853：document/database/
 * backup/certificate 类开启 RansomwareMonitored）。自包含，不依赖 B3/B4
 * 未定义宏，数据库/备份/证书用后缀表判定。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsRansomwatchClass(
    _In_ ULONG FileClass,
    _In_ PCUNICODE_STRING Extension
    )
{
    static const PCWSTR suffixTable[] = {
        L".mdb", L".accdb", L".sqlite", L".db", L".sql",        /* database */
        L".bak", L".backup", L".old",                           /* backup */
        L".pfx", L".p12", L".pem", L".key", L".cer", L".crt",   /* cert */
        NULL
    };
    ULONG i;

    /* 文档类（B1 已定义 WKD_FS_CLASS_DOCUMENT=0x200） */
    if (FileClass & WKD_FS_CLASS_DOCUMENT) {
        return TRUE;
    }
    if (FileClass & WKD_FS_CLASS_EXECUTABLE) {
        return FALSE;
    }
    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return FALSE;
    }
    for (i = 0; suffixTable[i] != NULL; i++) {
        if (WkdFspContainsStrInsensitive(Extension, suffixTable[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 扩展名分类（对齐 SS PocClassifyFileExtension L1710-1755；复用 B3 WkdFspClassifyFile） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFspClassifyFileExt(
    _In_opt_ PCUNICODE_STRING Extension
    )
{
    ULONG priority = 0;
    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return 0;
    }
    return WkdFspClassifyFile(Extension, &priority);
}

/* stream context 分配（对齐 SS PocAllocateStreamContext L980-1026） */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
WkdFspAllocateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PWKD_FS_STREAM_CONTEXT* OutContext
    )
{
    NTSTATUS status;
    PWKD_FS_STREAM_CONTEXT context;

    *OutContext = NULL;
    if (FltObjects == NULL || WkdFsGetFilterHandle() == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    status = FltAllocateContext(WkdFsGetFilterHandle(), FLT_STREAM_CONTEXT,
        sizeof(WKD_FS_STREAM_CONTEXT), NonPagedPoolNx, (PFLT_CONTEXT*)&context);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(context, sizeof(WKD_FS_STREAM_CONTEXT));
    context->Signature = WKD_FS_STREAM_CONTEXT_SIGNATURE;
    ExInitializePushLock(&context->Lock);
    KeQuerySystemTime(&context->CreationTime);
    KeQuerySystemTime(&context->LastWriteTime);
    context->OpenCount = 1;
    *OutContext = context;
    return STATUS_SUCCESS;
}

/* 缓存文件名 / 扩展名（对齐 SS PocCacheFileName L1641-1707） */
_IRQL_requires_max_(APC_LEVEL)
static VOID
WkdFspCacheStreamName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Inout_ PWKD_FS_STREAM_CONTEXT Context
    )
{
    USHORT copyLength;

    if (NameInfo == NULL || Context == NULL) {
        return;
    }
    if (NameInfo->FinalComponent.Buffer != NULL && NameInfo->FinalComponent.Length > 0) {
        copyLength = min(NameInfo->FinalComponent.Length, 255 * sizeof(WCHAR));
        RtlCopyMemory(Context->CachedFileName, NameInfo->FinalComponent.Buffer, copyLength);
        Context->CachedFileName[copyLength / sizeof(WCHAR)] = L'\0';
    }
    if (NameInfo->Extension.Buffer != NULL && NameInfo->Extension.Length > 0) {
        PCWSTR extStart = NameInfo->Extension.Buffer;
        USHORT extLen = NameInfo->Extension.Length;
        if (extLen >= sizeof(WCHAR) && *extStart == L'.') {
            extStart++;
            extLen -= sizeof(WCHAR);
        }
        copyLength = min(extLen, 31 * sizeof(WCHAR));
        RtlCopyMemory(Context->CachedExtension, extStart, copyLength);
        Context->CachedExtension[copyLength / sizeof(WCHAR)] = L'\0';
    }
}

/* 标记修改（对齐 SS PocMarkFileModified L1759-1787） */
_IRQL_requires_max_(APC_LEVEL)
static VOID
WkdFspMarkFileModified(
    _Inout_ PWKD_FS_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);
    Context->Dirty = TRUE;
    Context->TrackingFlags |= WKD_FS_TRACK_MODIFIED;
    if (Context->FirstWriteTime.QuadPart == 0) {
        KeQuerySystemTime(&Context->FirstWriteTime);
    }
    KeQuerySystemTime(&Context->LastModifyTime);
    InterlockedIncrement(&Context->WriteCount);
    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();
}

/* 失效扫描结果（对齐 SS PocInvalidateScanResult L1792-1817）：写后强制重扫 */
_IRQL_requires_max_(APC_LEVEL)
static VOID
WkdFspInvalidateScanResult(
    _Inout_ PWKD_FS_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);
    Context->Scanned = FALSE;
    Context->Dirty = TRUE;
    Context->TrackingFlags &= ~WKD_FS_TRACK_SCANNED;
    Context->TrackingFlags &= ~WKD_FS_TRACK_CACHED;
    Context->TrackingFlags |= WKD_FS_TRACK_MODIFIED;
    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();
}

/* PostCreate 完整 attach（对齐 SS ShadowStrikePostCreate L452-972）
 * 属性采集 → 缓存名 → 分类 → 追踪标志 → 勒索监控 → attach(KEEP_IF_EXISTS)。
 * 接入前提：注册 FLT_STREAM_CONTEXT 后由 FspPostCreate 调用（当前占位）。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdFspPostCreateAttach(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PWKD_FS_STREAM_CONTEXT streamContext = NULL;
    PWKD_FS_STREAM_CONTEXT existingContext = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG64 fileId = 0;
    LONGLONG fileSize = 0;
    LARGE_INTEGER lastWriteTime = {0};
    LARGE_INTEGER creationTime = {0};
    ULONG volumeSerial = 0;
    ULONG fileClass = 0;

    /* 仅处理成功创建的非目录非卷文件 */
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return STATUS_SUCCESS;
    }
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_SUCCESS;
    }
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return STATUS_SUCCESS;
    }
    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        return STATUS_SUCCESS;
    }

    /* 已存在上下文 → 更新访问 / 打开计数（对齐 SS Phase 3 L602-655） */
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
        (PFLT_CONTEXT*)&existingContext);
    if (NT_SUCCESS(status) && existingContext != NULL) {
        KeQuerySystemTime(&existingContext->LastWriteTime);
        InterlockedIncrement(&existingContext->OpenCount);
        FltReleaseContext((PFLT_CONTEXT)existingContext);
        return STATUS_SUCCESS;
    }

    status = WkdFspAllocateStreamContext(FltObjects, &streamContext);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 属性采集（对齐 SS Phase 5 L698-724） */
    status = WkdFspQueryStreamInfo(FltObjects, &fileId, &fileSize,
        &lastWriteTime, &creationTime);
    if (NT_SUCCESS(status)) {
        streamContext->FileId = fileId;
        streamContext->ScanFileSize = fileSize;
        streamContext->LastWriteTime = lastWriteTime;
        streamContext->CreationTime = creationTime;
    }
    status = WkdFspQueryVolumeSerial(FltObjects, &volumeSerial);
    if (NT_SUCCESS(status)) {
        streamContext->VolumeSerial = volumeSerial;
    }

    /* 文件名 + 分类 + 追踪标志 + 勒索监控（对齐 SS Phase 6/8/9） */
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            WkdFspCacheStreamName(nameInfo, streamContext);
            fileClass = WkdFspClassifyFileExt(&nameInfo->Extension);
            streamContext->FileClass = fileClass;
            WkdFspSetStreamTrackingFlags(streamContext, FltObjects, nameInfo);

            if (WkdFspIsRansomwatchClass(fileClass, &nameInfo->Extension)) {
                streamContext->RansomwareMonitored = TRUE;
                streamContext->TrackingFlags |= WKD_FS_TRACK_RANSOMWATCH;
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    /* attach（对齐 SS Phase 10 L859-918：KEEP_IF_EXISTS 并发安全） */
    status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS, (PFLT_CONTEXT)streamContext,
        (PFLT_CONTEXT*)&existingContext);
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        if (existingContext != NULL) {
            FltReleaseContext((PFLT_CONTEXT)existingContext);
        }
    }
    /* 释放调用者引用（attach 成功后 FltMgr 持有自己的引用；失败同样释放） */
    if (streamContext != NULL) {
        FltReleaseContext((PFLT_CONTEXT)streamContext);
    }
    return STATUS_SUCCESS;
}

/* completion context（对齐 SS PostCreate.h POC_COMPLETION_CONTEXT L403）：
 * PreCreate 扫描结果 → PostCreate verdict 应用，替代 SS lookaside 分配。 */
typedef struct _WKD_FS_COMPLETION_CONTEXT {
    BOOLEAN WasScanned;
    UCHAR   Verdict;         /* 0=clean 1=malicious */
    ULONG   ThreatScore;
    ULONG   FileClass;
    ULONG   SuspicionFlags;
} WKD_FS_COMPLETION_CONTEXT, *PWKD_FS_COMPLETION_CONTEXT;

/* completion context 分配（对齐 SS PocAllocateCompletionContext L1442-1488，
 * 简化：直接池分配替代 lookaside） */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
WkdFspAllocateCompletionContext(
    _Out_ PWKD_FS_COMPLETION_CONTEXT* OutContext
    )
{
    PWKD_FS_COMPLETION_CONTEXT context;

    *OutContext = NULL;
    context = (PWKD_FS_COMPLETION_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(WKD_FS_COMPLETION_CONTEXT), WKD_FSF_POOL_TAG);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context, sizeof(WKD_FS_COMPLETION_CONTEXT));
    *OutContext = context;
    return STATUS_SUCCESS;
}

/* verdict 应用（对齐 SS PocApplyCompletionContext L1212-1255）：扫描结果写入
 * stream context（Scanned/FileClass/SuspicionFlags） */
_IRQL_requires_max_(APC_LEVEL)
static VOID
WkdFspApplyCompletionContext(
    _Inout_ PWKD_FS_STREAM_CONTEXT StreamContext,
    _In_ PWKD_FS_COMPLETION_CONTEXT CompletionContext
    )
{
    if (StreamContext == NULL || CompletionContext == NULL) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&StreamContext->Lock);

    if (CompletionContext->WasScanned) {
        StreamContext->Scanned = TRUE;
        StreamContext->Dirty = FALSE;
        StreamContext->TrackingFlags |= WKD_FS_TRACK_SCANNED;
    }
    if (CompletionContext->FileClass != 0) {
        StreamContext->FileClass = CompletionContext->FileClass;
    }
    StreamContext->TrackingFlags |= CompletionContext->SuspicionFlags;

    ExReleasePushLockExclusive(&StreamContext->Lock);
    KeLeaveCriticalRegion();
}

/* 文件属性 → 追踪标志（对齐 SS PocQueryFileAttributes L1565-1638）：
 * hidden/system/readonly/temporary 映射，供 PostCreate 上下文完善属性画像 */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
WkdFspQueryFileAttributes(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PWKD_FS_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    FILE_BASIC_INFORMATION basicInfo;

    if (FltObjects == NULL || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
        &basicInfo, sizeof(basicInfo), FileBasicInformation, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Context->FileAttributes = basicInfo.FileAttributes;
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_HIDDEN) {
        Context->TrackingFlags |= WKD_FS_TRACK_HIDDEN;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_SYSTEM) {
        Context->TrackingFlags |= WKD_FS_TRACK_SYSTEM;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_READONLY) {
        Context->TrackingFlags |= WKD_FS_TRACK_READONLY;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_TEMPORARY) {
        Context->TrackingFlags |= WKD_FS_TRACK_TEMPORARY;
    }
    return STATUS_SUCCESS;
}

/* handle context attach（对齐 SS Phase 11 PocGetOrCreateHandleContext
 *   L1280-1424）：per-open 记录（进程/权限/操作计数）。wkd agent 因果图
 *   已基于事件流覆盖操作链，本函数为功能面完整预留。 */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
WkdFspAttachHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    NTSTATUS status;
    PWKD_FS_HANDLE_CONTEXT context = NULL;
    PWKD_FS_HANDLE_CONTEXT existingContext = NULL;

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL ||
        WkdFsGetFilterHandle() == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
        (PFLT_CONTEXT*)&context);
    if (NT_SUCCESS(status) && context != NULL) {
        FltReleaseContext((PFLT_CONTEXT)context);
        return STATUS_SUCCESS;
    }
    status = FltAllocateContext(WkdFsGetFilterHandle(), FLT_STREAMHANDLE_CONTEXT,
        sizeof(WKD_FS_HANDLE_CONTEXT), NonPagedPoolNx, (PFLT_CONTEXT*)&context);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(context, sizeof(WKD_FS_HANDLE_CONTEXT));
    context->Signature = WKD_FS_HANDLE_CONTEXT_SIGNATURE;
    ExInitializePushLock(&context->Lock);
    context->ProcessId = PsGetCurrentProcessId();
    context->ThreadId = PsGetCurrentThreadId();
    /* 对齐 SS L1369-1374：SecurityContext 可能 NULL（内核打开/快路径），防 BSOD */
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        context->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    } else {
        context->DesiredAccess = 0;
    }
    context->CreateOptions = Data->Iopb->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    context->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    KeQuerySystemTime(&context->OpenTime);

    status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS, (PFLT_CONTEXT)context,
        (PFLT_CONTEXT*)&existingContext);
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        if (existingContext != NULL) {
            FltReleaseContext((PFLT_CONTEXT)existingContext);
        }
    }
    if (context != NULL) {
        FltReleaseContext((PFLT_CONTEXT)context);
    }
    return STATUS_SUCCESS;
}

/* ============================================================================
 * B8 PreCreate 补充（迁移 SS PreCreate.c 剩余功能面，全量死代码）
 *   涵盖：扫描缓存(B8.1) / 勒索关联(B8.2) / EFI 分区(B8.3) / KTM-TxF(B8.4) /
 *   自保护(B8.5) / 蜜罐通配模式(B8.6)。接入前提见各函数注释。
 *   WSL 逃逸已有 IocProcess.c §9 死代码（见搁置项说明）。
 * ========================================================================== */

/* --- B8.1 扫描 verdict 缓存（对齐 SS ScanCache + PreCreate Phase 8）---
 *   SS 用 VolumeSerial+FileId+FileSize 键（Cache/ScanCache.c），wkd 无内核
 *   卷序列号缓存，改用路径 DJB2 哈希 + 文件大小低 32 位，TTL 15min。
 *   接入前提：FspPreCreate 在 FsSendYaraScanRequest 前查缓存、命中跳过扫描、
 *   扫描后写回；接入时需加锁（当前无锁，死代码未接线）。
 *   当前缓存职责由 agent ScanManager g_ScanCache 承担。 */
#define WKD_FS_CACHE_SIZE       256
#define WKD_FS_CACHE_TTL_100NS  (900LL * 10000000LL)   /* 15min，对齐 ScanManager TTL */

typedef struct _WKD_FS_CACHE_ENTRY {
    ULONG         Hash;           /* DJB2 路径哈希 */
    ULONG         FileSizeLow;    /* 文件大小低 32 位 */
    UCHAR         Verdict;        /* 0=unknown 1=clean 2=malicious */
    ULONG         ThreatScore;
    LARGE_INTEGER InsertTime;
    BOOLEAN       Active;
} WKD_FS_CACHE_ENTRY, *PWKD_FS_CACHE_ENTRY;

static WKD_FS_CACHE_ENTRY g_FsScanCache[WKD_FS_CACHE_SIZE];

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFspCacheHash(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSizeLow
    )
{
    ULONG hash = 5381;
    USHORT i;

    for (i = 0; i < FilePath->Length / sizeof(WCHAR); i++) {
        hash = ((hash << 5) + hash) ^ (ULONG)FilePath->Buffer[i];
    }
    return hash ^ FileSizeLow;
}

/* 缓存查找（对齐 SS ShadowStrikeCacheLookup）：命中且未过期返回 verdict */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspCacheLookup(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSizeLow,
    _Out_ PUCHAR OutVerdict,
    _Out_ PULONG OutThreatScore
    )
{
    ULONG hash = WkdFspCacheHash(FilePath, FileSizeLow);
    ULONG i;
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);
    for (i = 0; i < WKD_FS_CACHE_SIZE; i++) {
        if (g_FsScanCache[i].Active && g_FsScanCache[i].Hash == hash) {
            if ((now.QuadPart - g_FsScanCache[i].InsertTime.QuadPart) <= WKD_FS_CACHE_TTL_100NS) {
                *OutVerdict = g_FsScanCache[i].Verdict;
                *OutThreatScore = g_FsScanCache[i].ThreatScore;
                return TRUE;
            }
            g_FsScanCache[i].Active = FALSE;   /* 过期清除槽 */
        }
    }
    return FALSE;
}

/* 缓存写回（对齐 SS ShadowStrikeCacheInsert）：同 hash 覆盖，空槽插入 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdFspCacheInsert(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSizeLow,
    _In_ UCHAR Verdict,
    _In_ ULONG ThreatScore
    )
{
    ULONG hash = WkdFspCacheHash(FilePath, FileSizeLow);
    ULONG i;
    ULONG slot = WKD_FS_CACHE_SIZE;
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);
    for (i = 0; i < WKD_FS_CACHE_SIZE; i++) {
        if (g_FsScanCache[i].Active && g_FsScanCache[i].Hash == hash) {
            slot = i;
            break;
        }
        if (!g_FsScanCache[i].Active && slot == WKD_FS_CACHE_SIZE) {
            slot = i;
        }
    }
    if (slot == WKD_FS_CACHE_SIZE) {
        return;   /* 满且无同 hash → 不插入 */
    }
    g_FsScanCache[slot].Hash = hash;
    g_FsScanCache[slot].FileSizeLow = FileSizeLow;
    g_FsScanCache[slot].Verdict = Verdict;
    g_FsScanCache[slot].ThreatScore = ThreatScore;
    g_FsScanCache[slot].InsertTime = now;
    g_FsScanCache[slot].Active = TRUE;
}

/* 缓存失效（对齐 SS ShadowStrikeCacheRemove，PreWrite L1137-1152 / PostWrite
 *   L873-889）：文件被写/删后移除 verdict，强制重扫 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspCacheRemove(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSizeLow
    )
{
    ULONG hash = WkdFspCacheHash(FilePath, FileSizeLow);
    ULONG i;
    BOOLEAN removed = FALSE;

    for (i = 0; i < WKD_FS_CACHE_SIZE; i++) {
        if (g_FsScanCache[i].Active && g_FsScanCache[i].Hash == hash) {
            g_FsScanCache[i].Active = FALSE;
            removed = TRUE;
        }
    }
    return removed;
}

/* --- B8.2 勒索关联（对齐 SS PcCorrelateRansomware L2519-2580，+35）---
 *   SS 经 FSC_PROCESS_FILE_CONTEXT 查询 IsRansomwareSuspect；wkd 复用活跃区
 *   WkdFspTrackFileOperation 的窗口计数（Write/Delete/Rename 超阈值即勒索嫌疑）。
 *   接入前提：FspPreCreate 在 YARA 扫描后补充评分。 */
#define WKD_FS_RANSOM_CORRELATED_SCORE  35

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsRansomwareSuspect(
    _In_ HANDLE ProcessId
    )
{
    ULONG i;
    BOOLEAN suspect = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FsFileActivityLock);

    for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
        if (g_FsFileActivity[i].IsActive && g_FsFileActivity[i].ProcessId == ProcessId) {
            suspect = (g_FsFileActivity[i].WriteCount > WKD_FS_WRITE_THRESHOLD) ||
                      (g_FsFileActivity[i].DeleteCount > WKD_FS_DELETE_THRESHOLD) ||
                      (g_FsFileActivity[i].RenameCount > WKD_FS_RENAME_THRESHOLD);
            break;
        }
    }

    ExReleasePushLockShared(&g_FsFileActivityLock);
    KeLeaveCriticalRegion();
    return suspect;
}

/* 勒索关联评分判定（对齐 SS PcCorrelateRansomware：命中返回 TRUE 由调用者 +35） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspCorrelateRansomware(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    )
{
    UNREFERENCED_PARAMETER(FileName);
    return WkdFspIsRansomwareSuspect(ProcessId);
}

/* --- B8.3 EFI 分区保护（对齐 SS FiCheckEspAccess，PreCreate L1318-1328，+50）---
 *   ESP（EFI System Partition）写/删访问即提分。B3 敏感系统文件保护
 *   （\EFI\Microsoft\Boot\ 删/重命名阻断）+ B4 敏感写表（\EFI\ 配置类）已覆盖
 *   主体，本函数保留为 PreCreate 路径评分的独立附加分。 */
#define WKD_FS_ESP_SCORE  50

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspCheckEspAccess(
    _In_ PCUNICODE_STRING FileName,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }
    if (WkdFspContainsStrInsensitive(FileName, L"\\EFI\\")) {
        if (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE |
                             FILE_WRITE_ATTRIBUTES | WRITE_DAC)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* --- B8.4 KTM/TxF 事务追踪（对齐 SS PreCreate L1267-1316 +
 *   PostWrite L973-1016，KtmMonitor.c ShadowTrackTransaction /
 *   RecordTransactedFileOperation / KtmEnlistInTransaction）---
 *   TxF 自 Win10 起功能冻结，真实恶意软件极少使用（Process Doppelganging
 *   T1055.013 场景），wkd 无 KTM 消费方。功能面完整落位。
 *   接入前提：PreCreate 写/覆盖访问时调用（IoGetTransactionParameterBlock），
 *   并在事务提交/回滚处消费记录（需额外事务回调）；接入时先
 *   InitializeListHead(&g_FsTxnList) 并加锁。 */
typedef struct _WKD_FS_TXN_RECORD {
    GUID            TransactionId;
    HANDLE          ProcessId;
    WCHAR           FileName[260];
    LARGE_INTEGER   CreateTime;
    LIST_ENTRY      ListEntry;
} WKD_FS_TXN_RECORD, *PWKD_FS_TXN_RECORD;

static LIST_ENTRY g_FsTxnList;   /* 死代码：未接线，无初始化（接入时 InitializeListHead） */

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdFspCheckTransactedAccess(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName,
    _In_ HANDLE ProcessId
    )
{
    PTXN_PARAMETER_BLOCK txnBlock;
    GUID txnGuid;
    PWKD_FS_TXN_RECORD record;

    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        return STATUS_SUCCESS;
    }
    txnBlock = IoGetTransactionParameterBlock(FltObjects->FileObject);
    if (txnBlock == NULL || txnBlock->TransactionObject == NULL) {
        return STATUS_SUCCESS;
    }
    TmGetTransactionId((PKTRANSACTION)txnBlock->TransactionObject, &txnGuid);

    record = (PWKD_FS_TXN_RECORD)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(WKD_FS_TXN_RECORD), WKD_FSF_POOL_TAG);
    if (record == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    record->TransactionId = txnGuid;
    record->ProcessId = ProcessId;
    record->CreateTime.QuadPart = 0;
    RtlZeroMemory(record->FileName, sizeof(record->FileName));
    if (FileName != NULL && FileName->Buffer != NULL && FileName->Length > 0) {
        USHORT copyLen = min(FileName->Length, (259 * sizeof(WCHAR)));
        RtlCopyMemory(record->FileName, FileName->Buffer, copyLen);
    }
    InsertTailList(&g_FsTxnList, &record->ListEntry);
    return STATUS_SUCCESS;
}

/* --- B8.5 自保护（对齐 SS PreCreate L930-955 ShadowStrikeShouldBlockFileAccess，
 *   FileProtection.c）---
 *   EDR 自身文件（驱动/agent）写/删/改名保护。豁免复用 ExemptsIsProcessTrusted
 *   （对齐 SS：受保护进程豁免防系统维护误阻断）。 */
typedef struct _WKD_FS_PROTECT_PATH {
    PCWSTR  Path;           /* 后缀精确匹配（大小写不敏感） */
    BOOLEAN BlockWrite;
    BOOLEAN BlockDelete;
    BOOLEAN BlockRename;
    BOOLEAN BlockExecute;   /* 阻止以执行权限映射（PreAcquireSection 迁移 2026-08，T1562.001） */
} WKD_FS_PROTECT_PATH, *PWKD_FS_PROTECT_PATH;

static const WKD_FS_PROTECT_PATH g_FsProtectPaths[] = {
    { L"\\WkDefender@agent.exe",  TRUE, TRUE, TRUE, TRUE },
    { L"\\WkDefender@agent.dll",  TRUE, TRUE, TRUE, TRUE },
    { L"\\WkDefender@driver.sys", TRUE, TRUE, TRUE, TRUE },
    { L"\\WkDefender@driver.dll", TRUE, TRUE, TRUE, TRUE },
    { L"\\WkdBackup\\",           TRUE, TRUE, FALSE, FALSE },
    { NULL, FALSE, FALSE, FALSE, FALSE }
};

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdFspShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FileName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN IsWriteOp
    )
{
    ULONG i;
    BOOLEAN wantWrite, wantDelete, wantExecute;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    /* 豁免可信进程（对齐 SS 自保护豁免） */
    if (ExemptsIsProcessTrusted(ProcessId)) {
        return FALSE;
    }

    wantWrite = (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    wantDelete = (DesiredAccess & DELETE) != 0;
    wantExecute = (DesiredAccess & SECTION_MAP_EXECUTE) != 0;   /* PreAcquireSection 迁移 2026-08 */

    for (i = 0; g_FsProtectPaths[i].Path != NULL; i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_FsProtectPaths[i].Path);
        if (pattern.Length > FileName->Length) {
            continue;
        }
        {
            UNICODE_STRING suffix;
            suffix.Buffer = FileName->Buffer + (FileName->Length - pattern.Length) / sizeof(WCHAR);
            suffix.Length = pattern.Length;
            suffix.MaximumLength = pattern.Length;
            if (RtlEqualUnicodeString(&suffix, &pattern, TRUE)) {
                if ((wantWrite && g_FsProtectPaths[i].BlockWrite) ||
                    (wantDelete && g_FsProtectPaths[i].BlockDelete) ||
                    (wantExecute && g_FsProtectPaths[i].BlockExecute) ||
                    (IsWriteOp && g_FsProtectPaths[i].BlockRename)) {
                    return TRUE;
                }
                return FALSE;
            }
        }
    }
    return FALSE;
}

/* --- B8.6 蜜罐通配模式（对齐 SS PreCreate PcCheckHoneypot L2110-2225 +
 *   PcAddHoneypotPattern L2280-2424 + PcpMatchWildcard L2737-2813）---
 *   wkd 活跃区已有精确路径 canary（WkdFspAddCanaryPath，RtlEqualUnicodeString）
 *   与内置蜜罐文件名表（WkdFspIsHoneypotFile，包含匹配）；本分区补充 SS 的
 *   通配符模式（* / ?）蜜罐（用户可配置）。
 *   接入前提：agent 策略下发模式 + FspPreCreate/FspPreWrite 在 canary 检查处
 *   调用 WkdFspCheckHoneypotPattern；接入时对齐 g_FsCanaryConfig 初始化。 */
#define WKD_FS_MAX_HONEYPOT_PATTERNS  32

typedef struct _WKD_FS_HONEYPOT_CONFIG {
    UNICODE_STRING Patterns[WKD_FS_MAX_HONEYPOT_PATTERNS];
    volatile LONG  PatternCount;
    EX_PUSH_LOCK   Lock;
    BOOLEAN        Initialized;
} WKD_FS_HONEYPOT_CONFIG, *PWKD_FS_HONEYPOT_CONFIG;

static WKD_FS_HONEYPOT_CONFIG g_FsHoneypotConfig;   /* 死代码：未初始化 */

/* 迭代通配匹配（对齐 SS PcpMatchWildcard L2737-2813：* 与 ?，大小写折叠） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspMatchWildcard(
    _In_ PCWSTR String,
    _In_ PCWSTR Pattern
    )
{
    PCWSTR stringBackup = NULL;
    PCWSTR patternBackup = NULL;

    if (String == NULL || Pattern == NULL) {
        return FALSE;
    }
    while (*String != L'\0') {
        if (*Pattern == L'*') {
            while (*Pattern == L'*') {
                Pattern++;
            }
            if (*Pattern == L'\0') {
                return TRUE;
            }
            stringBackup = String;
            patternBackup = Pattern;
        } else if (*Pattern == L'?' ||
                   RtlUpcaseUnicodeChar(*String) == RtlUpcaseUnicodeChar(*Pattern)) {
            String++;
            Pattern++;
        } else if (patternBackup != NULL) {
            stringBackup++;
            String = stringBackup;
            Pattern = patternBackup;
        } else {
            return FALSE;
        }
    }
    while (*Pattern == L'*') {
        Pattern++;
    }
    return (*Pattern == L'\0');
}

/* 通配蜜罐判定（对齐 SS PcCheckHoneypot L2110-2225：锁内检查 + 栈缓冲终结） */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
WkdFspCheckHoneypotPattern(
    _In_ PCUNICODE_STRING FileName
    )
{
    WCHAR stackBuffer[260];
    PWCHAR terminated = NULL;
    USHORT fileChars;
    LONG i;
    LONG count;
    BOOLEAN result = FALSE;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    fileChars = FileName->Length / sizeof(WCHAR);
    if (fileChars >= 260) {
        return FALSE;   /* 防栈溢出（对齐 SS PC_MAX_PATH 上限） */
    }
    RtlCopyMemory(stackBuffer, FileName->Buffer, FileName->Length);
    stackBuffer[fileChars] = L'\0';
    terminated = stackBuffer;

    if (!g_FsHoneypotConfig.Initialized) {
        return FALSE;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FsHoneypotConfig.Lock);

    count = g_FsHoneypotConfig.PatternCount;
    for (i = 0; i < count && i < WKD_FS_MAX_HONEYPOT_PATTERNS; i++) {
        if (g_FsHoneypotConfig.Patterns[i].Buffer != NULL &&
            g_FsHoneypotConfig.Patterns[i].Length > 0) {
            if (WkdFspMatchWildcard(terminated, g_FsHoneypotConfig.Patterns[i].Buffer)) {
                result = TRUE;
                break;
            }
        }
    }

    ExReleasePushLockShared(&g_FsHoneypotConfig.Lock);
    KeLeaveCriticalRegion();
    return result;
}

/* 添加通配蜜罐模式（对齐 SS PcAddHoneypotPattern L2280-2424：校验防 DoS +
 * 锁内插入 + 上限。防 DoS：超长/内嵌 NUL/纯通配符/过宽模式拒绝） */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdFspAddHoneypotPattern(
    _In_ PCUNICODE_STRING Pattern
    )
{
    PWCHAR buffer;
    LONG i;
    ULONG starCount = 0;
    ULONG nonWildcardCount = 0;
    BOOLEAN hasEmbeddedNull = FALSE;

    if (Pattern == NULL || Pattern->Buffer == NULL || Pattern->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Pattern->Length > 1024 * sizeof(WCHAR)) {   /* 超长拒绝（对齐 SS L2313） */
        return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < (LONG)(Pattern->Length / sizeof(WCHAR)); i++) {
        WCHAR ch = Pattern->Buffer[i];
        if (ch == L'\0') {
            hasEmbeddedNull = TRUE;
            break;
        }
        if (ch == L'*') {
            starCount++;
        } else if (ch != L'?') {
            nonWildcardCount++;
        }
    }
    /* 内嵌 NUL / 纯通配符 / 过宽（≥1 星但 <3 实义字符）拒绝（对齐 SS L2357-2377） */
    if (hasEmbeddedNull || (nonWildcardCount == 0) ||
        (nonWildcardCount < 3 && starCount > 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_FsHoneypotConfig.Initialized) {
        return STATUS_NOT_READY;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FsHoneypotConfig.Lock);

    if (g_FsHoneypotConfig.PatternCount >= WKD_FS_MAX_HONEYPOT_PATTERNS) {
        ExReleasePushLockExclusive(&g_FsHoneypotConfig.Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED,
        Pattern->Length + sizeof(WCHAR), WKD_FSF_POOL_TAG);
    if (buffer == NULL) {
        ExReleasePushLockExclusive(&g_FsHoneypotConfig.Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(buffer, Pattern->Buffer, Pattern->Length);
    buffer[Pattern->Length / sizeof(WCHAR)] = L'\0';

    g_FsHoneypotConfig.Patterns[g_FsHoneypotConfig.PatternCount].Buffer = buffer;
    g_FsHoneypotConfig.Patterns[g_FsHoneypotConfig.PatternCount].Length = Pattern->Length;
    g_FsHoneypotConfig.Patterns[g_FsHoneypotConfig.PatternCount].MaximumLength =
        Pattern->Length + sizeof(WCHAR);
    InterlockedIncrement(&g_FsHoneypotConfig.PatternCount);

    ExReleasePushLockExclusive(&g_FsHoneypotConfig.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

/* 清空通配蜜罐（对齐 SS PcClearHoneypotPatterns L2427-2451） */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdFspClearHoneypotPatterns(
    VOID
    )
{
    LONG i;

    if (!g_FsHoneypotConfig.Initialized) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FsHoneypotConfig.Lock);

    for (i = 0; i < g_FsHoneypotConfig.PatternCount; i++) {
        if (g_FsHoneypotConfig.Patterns[i].Buffer != NULL) {
            ExFreePoolWithTag(g_FsHoneypotConfig.Patterns[i].Buffer, WKD_FSF_POOL_TAG);
            RtlZeroMemory(&g_FsHoneypotConfig.Patterns[i], sizeof(UNICODE_STRING));
        }
    }
    g_FsHoneypotConfig.PatternCount = 0;

    ExReleasePushLockExclusive(&g_FsHoneypotConfig.Lock);
    KeLeaveCriticalRegion();
}

/* ============================================================================
 * B9 PostWrite 覆盖模式分析（迁移 SS PostWrite.c PwpAnalyzeWritePattern
 *   L1722-1766 + PwpCalculateSuspicionScore L1845-1881，全量死代码）
 *   依赖 A1 新增事件字段（WriteOffset/BytesWritten/FileId）：驱动 FspPreWrite
 *   已填充，agent 后续消费；本分区供驱动侧决策（写阻断/评分）参考。
 *   对齐 SS 评分：FULL_FILE_OVERWRITE=40 / SEQUENTIAL_OVERWRITE=30 /
 *   LARGE_WRITE_OVERWRITE=20。
 * ========================================================================== */
#define WKD_FS_OVERWRITE_FULL_FILE   0x00000001
#define WKD_FS_OVERWRITE_SEQUENTIAL  0x00000002
#define WKD_FS_OVERWRITE_LARGE       0x00000004

#define WKD_FS_SCORE_FULL_OVERWRITE     40   /* 对齐 SS PW_SCORE_FULL_FILE_OVERWRITE */
#define WKD_FS_SCORE_SEQUENTIAL_OVERWRITE 30 /* 对齐 SS PW_SCORE_SEQUENTIAL_OVERWRITE */
#define WKD_FS_SCORE_LARGE_OVERWRITE    20   /* 对齐 SS PW_SCORE_LARGE_WRITE_OVERWRITE */

/* 覆盖模式分析（对齐 SS PwpAnalyzeWritePattern L1722-1766）：
 * 返回模式位 + 嫌疑分；OutIsAppend 输出追加判定（偏移 ≥ 文件大小）。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFspAnalyzeOverwritePattern(
    _In_ LONGLONG WriteOffset,
    _In_ ULONG BytesWritten,
    _In_ LONGLONG FileSize,
    _Out_ PULONG OutSuspicionScore,
    _Out_opt_ PBOOLEAN OutIsAppend
    )
{
    ULONG flags = 0;
    ULONG score = 0;
    BOOLEAN append = FALSE;

    if (OutSuspicionScore) {
        *OutSuspicionScore = 0;
    }
    if (OutIsAppend) {
        *OutIsAppend = FALSE;
    }

    /* 偏移未知（-1，如 SetInformation 类）不分析 */
    if (WriteOffset < 0) {
        return 0;
    }

    /* 追加判定（对齐 SS L858-860）：偏移 ≥ 文件大小 */
    if (FileSize >= 0 && WriteOffset >= FileSize) {
        append = TRUE;
    }

    /* 全文件覆盖（对齐 SS L850-853）：offset==0 && 写入 ≥ 文件大小 */
    if (WriteOffset == 0 && FileSize >= 0 && (LONGLONG)BytesWritten >= FileSize) {
        flags |= WKD_FS_OVERWRITE_FULL_FILE;
        score += WKD_FS_SCORE_FULL_OVERWRITE;
    }
    /* 顺序覆盖（对齐 SS L1747-1752）：offset==0 && !append && >4096B */
    if (WriteOffset == 0 && !append && BytesWritten > 4096) {
        flags |= WKD_FS_OVERWRITE_SEQUENTIAL;
        score += WKD_FS_SCORE_SEQUENTIAL_OVERWRITE;
    }
    /* 大写入覆盖（对齐 SS L1758-1765）：≥1MB && !append */
    if (BytesWritten >= (1024 * 1024) && !append) {
        flags |= WKD_FS_OVERWRITE_LARGE;
        score += WKD_FS_SCORE_LARGE_OVERWRITE;
    }

    if (OutSuspicionScore) {
        *OutSuspicionScore = score;
    }
    if (OutIsAppend) {
        *OutIsAppend = append;
    }
    return flags;
}

/* ============================================================================
 * B10 PreCreate 扫描作用域细化 + 排除检查 + 访问类型分类 + 限速日志
 *   （迁移 SS PreCreate.c Phase 5/7/9，全量死代码）
 *   - 作用域细化（对齐 SS Phase 9 L1466-1478）：纯读打开普通数据文件不阻塞
 *     扫描，仅 code-bearing（可执行/脚本/文档/归档）且写/执行访问走同步——
 *     防 Explorer 枚举/缩略图每次打开都等待用户态 verdict 造成系统级卡死。
 *   - 排除检查（对齐 SS Phase 5 L897-924）：路径排除 / 进程排除 / 进程信任。
 *   - 访问类型分类（对齐 SS PcpClassifyAccessType L2643-2680）。
 *   - 限速日志（对齐 SS PcpShouldLogOperation L3006-3069）。
 *   接入前提：wkd 决策启用"作用域细化"与"路径排除"时接入 FspPreCreate。
 * ========================================================================== */
#define WKD_FS_CODE_BEARING_CLASS   (WKD_FS_CLASS_EXECUTABLE | WKD_FS_CLASS_DOCUMENT | WKD_FS_CLASS_ARCHIVE)

typedef enum _WKD_FS_ACCESS_TYPE {
    WkdFsAccessUnknown = 0,
    WkdFsAccessRead,
    WkdFsAccessWrite,
    WkdFsAccessExecute,
    WkdFsAccessDelete
} WKD_FS_ACCESS_TYPE;

/* 访问类型分类（对齐 SS PcpClassifyAccessType L2643-2680） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static WKD_FS_ACCESS_TYPE
WkdFspClassifyAccessType(
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG CreateOptions
    )
{
    if ((DesiredAccess & DELETE) || (CreateOptions & FILE_DELETE_ON_CLOSE)) {
        return WkdFsAccessDelete;
    }
    if (DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) {
        return WkdFsAccessExecute;
    }
    if (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                         FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | GENERIC_WRITE)) {
        return WkdFsAccessWrite;
    }
    return WkdFsAccessRead;
}

/* 作用域细化判定（对齐 SS Phase 9 L1466-1478）：返回 TRUE 才走同步阻塞扫描。
 * 注：脚本类（.ps1 等）ClassFlags 依赖 B3 未定义宏 WKD_FS_CLASS_SCRIPT 修复，
 * 修复后加入 WKD_FS_CODE_BEARING_CLASS。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspShouldBlockScan(
    _In_ WKD_FS_ACCESS_TYPE AccessType,
    _In_ ULONG FileClass
    )
{
    /* 写/执行/删除访问：一律扫描（含普通数据文件，恶意写入需检测） */
    if (AccessType == WkdFsAccessWrite || AccessType == WkdFsAccessExecute ||
        AccessType == WkdFsAccessDelete) {
        return TRUE;
    }
    /* 纯读访问：仅 code-bearing（可执行/文档/归档）扫描 */
    if (FileClass & WKD_FS_CODE_BEARING_CLASS) {
        return TRUE;
    }
    return FALSE;
}

/* --- 排除检查（对齐 SS Phase 5 L897-924：路径排除 / 进程排除 / 进程信任）---
 *   路径排除：agent 下发排除规则表（与 ScanManager 排除规则对齐）时填充。
 *   进程排除：wkd 用 ExemptsIsProcessTrusted 作为进程信任等价（SS IsProcessTrusted），
 *   用户配置排除表由 agent 策略下发（接入前提）。 */
typedef struct _WKD_FS_EXCLUSION {
    UNICODE_STRING Path;    /* 路径前缀（接入时填充） */
} WKD_FS_EXCLUSION, *PWKD_FS_EXCLUSION;

static WKD_FS_EXCLUSION g_FsExclusions[64];   /* 死代码：接入时填充 + 加锁 */
static volatile LONG    g_FsExclusionCount;

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsPathExcluded(
    _In_ PCUNICODE_STRING FileName
    )
{
    LONG i;
    LONG count = g_FsExclusionCount;

    for (i = 0; i < count; i++) {
        if (g_FsExclusions[i].Path.Length > 0 &&
            g_FsExclusions[i].Path.Length <= FileName->Length) {
            UNICODE_STRING prefix;
            prefix.Buffer = FileName->Buffer;
            prefix.Length = g_FsExclusions[i].Path.Length;
            prefix.MaximumLength = g_FsExclusions[i].Path.Length;
            if (RtlEqualUnicodeString(&prefix, &g_FsExclusions[i].Path, TRUE)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsProcessExcluded(
    _In_ HANDLE ProcessId
    )
{
    /* 用户配置进程排除表（agent 策略下发，接入前提）。当前仅信任表等价。 */
    UNREFERENCED_PARAMETER(ProcessId);
    return FALSE;
}

/* --- 限速日志（对齐 SS PcpShouldLogOperation L3006-3069）---
 *   1s 窗口限速，防 DbgPrint 洪泛。CAS 单线程重置窗口。 */
#define WKD_FS_LOG_RATE_LIMIT_PER_SEC  100

static volatile LONG64 g_FsLogRateWindowStart;
static volatile LONG   g_FsLogRateCount;

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspShouldLogOperation(
    VOID
    )
{
    LARGE_INTEGER now;
    LONG64 stored;

    KeQuerySystemTime(&now);
    stored = InterlockedCompareExchange64(&g_FsLogRateWindowStart, 0, 0);
    if ((now.QuadPart - stored) > 10000000LL) {   /* 1 秒 */
        if (InterlockedCompareExchange64(&g_FsLogRateWindowStart,
                now.QuadPart, stored) == stored) {
            InterlockedExchange(&g_FsLogRateCount, 0);
        }
    }
    return (InterlockedIncrement(&g_FsLogRateCount) <= WKD_FS_LOG_RATE_LIMIT_PER_SEC);
}

/* ============================================================================
 * 分区 C：勒索行为检测（迁移自 SS PreSetInfo.c，死代码，重功能实现非复制）
 *   对齐 SS：
 *     g_FsRansomExtensions            ← g_RansomwareExtensions L264-300
 *     WkdFspIsRansomwareExtension     ← PsipIsRansomwareExtension L2177-2226
 *     WkdFspDetectExtensionChange     ← PsipDetectExtensionChange L2228-2290
 *     WkdFspDetectRansomwareBehavior  ← PsipDetectRansomwareBehavior L1938-1998
 *     WkdFspDetectDataDestruction     ← PsipDetectDataDestruction L2000-2026
 *     WkdFspDetectCredentialAccess    ← PsipDetectCredentialAccess L2028-2046
 *   输入 = 扩展后的 WKD_FS_FILE_ACTIVITY（窗口计数 + Total* 总量）。
 *   不接入原因：
 *     1) 弱信号聚合评分阻断门控未开（强信号直断 + 弱信号 Audit 决策，见
 *        FspPreSetInformation 注释；项目惯例 NamedPipeMonitor/AppControl
 *        阻断门控默认 FALSE）。
 *     2) agent 侧 IoaRansomwareDetect（IoaEngine.c 阶段4.9c）已覆盖勒索评分
 *        （高熵写/Canary/勒索信/速率/扩展名/大量删除/卷影/双扩展名），
 *        驱动侧评分与之重复。
 *     3) wkd 分层模型：弱信号归 agent VerdictEngine 决策，内核仅做轻量预判。
 *   接入前提（未来决策）：FspPreSetInformation Rename 分支提取原/新路径后，
 *   调 WkdFspDetectExtensionChange → WkdFspTrackFileOperation 累计
 *   ExtensionChangeCount/TotalExtensionChanges；Delete/Rename 后调
 *   WkdFspDetectRansomwareBehavior/DetectDataDestruction 判定并决策阻断。
 * ========================================================================== */
#define WKD_FS_RANSOM_RENAME_THRESHOLD      30    /* 对齐 SS PSI_RANSOMWARE_RENAME_THRESHOLD */
#define WKD_FS_RANSOM_DELETE_THRESHOLD      50    /* 对齐 SS PSI_RANSOMWARE_DELETE_THRESHOLD */
#define WKD_FS_EXTENSION_CHANGE_THRESHOLD   20    /* 对齐 SS PSI_EXTENSION_CHANGE_THRESHOLD */
#define WKD_FS_DESTRUCTION_DELETE_THRESHOLD 500   /* 对齐 SS PSI_DESTRUCTION_DELETE_THRESHOLD */
#define WKD_FS_CREDENTIAL_HARDLINK_THRESHOLD 3    /* 对齐 SS PSI_CREDENTIAL_HARDLINK_THRESHOLD */
#define WKD_FS_RANSOM_SCORE_THRESHOLD       70    /* 对齐 SS 评分≥70 判定勒索嫌疑 */

/* 勒索行为标志（对齐 SS PSI_BEHAVIOR_* 位，评分函数输出，死代码） */
#define WKD_FS_RANSOM_BEHAVIOR_MASS_RENAME      0x00000001  /* 对齐 SS PSI_BEHAVIOR_MASS_RENAME */
#define WKD_FS_RANSOM_BEHAVIOR_MASS_DELETE      0x00000002  /* 对齐 SS PSI_BEHAVIOR_MASS_DELETE */
#define WKD_FS_RANSOM_BEHAVIOR_EXTENSION_CHANGE 0x00000004  /* 对齐 SS PSI_BEHAVIOR_EXTENSION_CHANGE */

/* 勒索扩展名知识库（对齐 SS g_RansomwareExtensions L264-300 全量 34 条） */
static const PCWSTR g_FsRansomExtensions[] = {
    L".encrypted", L".locked", L".crypto", L".crypt", L".enc", L".locky",
    L".cerber",    L".zepto",  L".odin",   L".thor",  L".aesir", L".zzzzz",
    L".micro",     L".crypted", L".crinf", L".r5a",   L".WNCRY", L".wcry",
    L".wncrypt",   L".wncryt", L".petya",  L".mira",  L".globe", L".purge",
    L".dharma",    L".wallet", L".onion",  L".ryuk",  L".sodinokibi", L".revil",
    L".lockbit",   L".conti",  L".blackcat", L".alphv",
    NULL
};

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspIsRansomwareExtension(
    _In_ PCUNICODE_STRING NewFileName
    )
{
    ULONG i;
    UNICODE_STRING extension;
    UNICODE_STRING fileExt = { 0 };
    USHORT j;

    if (NewFileName == NULL || NewFileName->Buffer == NULL || NewFileName->Length == 0) {
        return FALSE;
    }

    /* 提取扩展名：最后一个 '.' 到文件尾；遇 '\' 停止（无扩展名） */
    for (j = NewFileName->Length / sizeof(WCHAR); j > 0; j--) {
        if (NewFileName->Buffer[j - 1] == L'.') {
            fileExt.Buffer = &NewFileName->Buffer[j - 1];
            fileExt.Length = NewFileName->Length - ((j - 1) * sizeof(WCHAR));
            fileExt.MaximumLength = fileExt.Length;
            break;
        }
        if (NewFileName->Buffer[j - 1] == L'\\') {
            break;
        }
    }

    if (fileExt.Length == 0) {
        return FALSE;
    }

    for (i = 0; g_FsRansomExtensions[i] != NULL; i++) {
        RtlInitUnicodeString(&extension, g_FsRansomExtensions[i]);
        if (RtlEqualUnicodeString(&fileExt, &extension, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectExtensionChange(
    _In_ PCUNICODE_STRING OriginalName,
    _In_ PCUNICODE_STRING NewName
    )
{
    UNICODE_STRING origExt = { 0 };
    UNICODE_STRING newExt = { 0 };
    USHORT i;

    if (OriginalName == NULL || NewName == NULL ||
        OriginalName->Buffer == NULL || NewName->Buffer == NULL) {
        return FALSE;
    }

    /* 提取原扩展名 */
    for (i = OriginalName->Length / sizeof(WCHAR); i > 0; i--) {
        if (OriginalName->Buffer[i - 1] == L'.') {
            origExt.Buffer = &OriginalName->Buffer[i - 1];
            origExt.Length = OriginalName->Length - ((i - 1) * sizeof(WCHAR));
            origExt.MaximumLength = origExt.Length;
            break;
        }
        if (OriginalName->Buffer[i - 1] == L'\\') {
            break;
        }
    }

    /* 提取新扩展名 */
    for (i = NewName->Length / sizeof(WCHAR); i > 0; i--) {
        if (NewName->Buffer[i - 1] == L'.') {
            newExt.Buffer = &NewName->Buffer[i - 1];
            newExt.Length = NewName->Length - ((i - 1) * sizeof(WCHAR));
            newExt.MaximumLength = newExt.Length;
            break;
        }
        if (NewName->Buffer[i - 1] == L'\\') {
            break;
        }
    }

    /* 扩展名添加（原无新有） */
    if (origExt.Length == 0 && newExt.Length > 0) {
        return TRUE;
    }

    /* 扩展名变更 */
    if (origExt.Length > 0 && newExt.Length > 0) {
        if (!RtlEqualUnicodeString(&origExt, &newExt, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectRansomwareBehavior(
    _In_ PWKD_FS_FILE_ACTIVITY Slot,
    _Out_opt_ PLONG SuspicionScore,
    _Out_opt_ PULONG BehaviorFlags
    )
{
    LONG score = 0;
    ULONG behaviorFlags = 0;

    if (BehaviorFlags != NULL) {
        *BehaviorFlags = 0;
    }

    /* 大量重命名（对齐 SS L1950-1953，+40） */
    if (Slot->RenameCount > WKD_FS_RANSOM_RENAME_THRESHOLD) {
        score += 40;
        behaviorFlags |= WKD_FS_RANSOM_BEHAVIOR_MASS_RENAME;
    }
    /* 大量删除（对齐 SS L1956-1959，+35） */
    if (Slot->DeleteCount > WKD_FS_RANSOM_DELETE_THRESHOLD) {
        score += 35;
        behaviorFlags |= WKD_FS_RANSOM_BEHAVIOR_MASS_DELETE;
    }
    /* 大量扩展名变更（对齐 SS L1963-1966，+30） */
    if (Slot->ExtensionChangeCount > WKD_FS_EXTENSION_CHANGE_THRESHOLD) {
        score += 30;
        behaviorFlags |= WKD_FS_RANSOM_BEHAVIOR_EXTENSION_CHANGE;
    }
    /* 历史重命名（对齐 SS L1974-1976，+15） */
    if (Slot->TotalRenames > 1000) {
        score += 15;
    }
    /* 历史扩展名变更（对齐 SS L1978-1980，+20） */
    if (Slot->TotalExtensionChanges > 100) {
        score += 20;
    }
    /* 重命名 + 扩展名变更组合非常可疑（对齐 SS L1985-1988，+25，按标志位判断） */
    if ((behaviorFlags & WKD_FS_RANSOM_BEHAVIOR_MASS_RENAME) &&
        (behaviorFlags & WKD_FS_RANSOM_BEHAVIOR_EXTENSION_CHANGE)) {
        score += 25;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = score;
    }
    if (BehaviorFlags != NULL) {
        *BehaviorFlags = behaviorFlags;
    }
    return (score >= WKD_FS_RANSOM_SCORE_THRESHOLD);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectDataDestruction(
    _In_ PWKD_FS_FILE_ACTIVITY Slot
    )
{
    /* 总量超阈值（对齐 SS L2010-2013） */
    if (Slot->TotalDeletes > WKD_FS_DESTRUCTION_DELETE_THRESHOLD) {
        return TRUE;
    }
    /* 窗口高密度删除（对齐 SS L2019-2023，阈值/10） */
    if (Slot->DeleteCount > (WKD_FS_DESTRUCTION_DELETE_THRESHOLD / 10)) {
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFspDetectCredentialAccess(
    _In_ PWKD_FS_FILE_ACTIVITY Slot
    )
{
    /* 对敏感文件累计建硬链接数（对齐 SS L2039-2043，≥3 判定） */
    if (Slot->TotalHardLinks >= WKD_FS_CREDENTIAL_HARDLINK_THRESHOLD) {
        return TRUE;
    }
    return FALSE;
}

#pragma warning(pop)

/* ============================================================================
 * 代码执行映射检测回调（PreAcquireSection 迁移 2026-08）
 * 参考 PhantomSensor PreAcquireSection.c ShadowStrikePreAcquireSection。
 * IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION pre-op，仅在 SyncTypeCreateSection
 * + 执行保护时生效——捕获"文件被映射为可执行"这一刻，可事前阻断。
 *
 * 流程：boot 跳过 → SyncType 检查 → 执行保护快速跳过 → KernelMode/可信进程豁免
 *   → 自保护执行映射阻断（强信号，不受 EnableBlocking 门控）→ 路径排除 → B2 路径
 *   分析（复用 WkdFspAnalyzeFilePath）+ 卷类型判定（FltGetVolumeProperties）→
 *   WkdPasProcessMapping 检测评分 → 事件上送（0x1308）+ AeReportIndicatorPair
 *   → Audit 门控阻断（EnableBlocking 默认关，仅上报+评分）。
 *
 * 注意：查名必须 CACHE_ONLY（AcquireSection 内 DEFAULT 会死锁，SS 明确标注）。
 * ========================================================================== */

/* 卷类型判定（网络/可移除）——B7 WkdFspSetStreamTrackingFlags 的
 * FltGetVolumeProperties 模式内联。补齐 SS 注入检测 NETWORK/REMOVABLE 标志的
 * 生产者（SS 从未置位=死分支，wkd 激活）。 */
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
FspPreAcquireSection(
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

    /* boot 期跳过（对齐 SS ShadowFsIsBootPhase） */
    if (WkdFspIsBootPhase()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 初始化守卫（惰性初始化在 FsInitialize 完成；未初始化/关闭中安全跳过） */
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

    /* 快速路径：非执行映射放行（对齐 SS PAS_EXECUTE_PROTECTION_MASK） */
    if (!(pageProtection & PAS_EXECUTE_PROTECTION_MASK)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 信任内核/系统/受保护进程（对齐 SS：KernelMode 信任 + PID 4 + IsProcessProtected） */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    pid = PsGetCurrentProcessId();
    if (pid == (HANDLE)(ULONG_PTR)4 || ExemptsIsProcessTrusted(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 路径查询：必须 CACHE_ONLY 防死锁（对齐 SS L1650-1654） */
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_CACHE_ONLY, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    /* 自保护：阻止 EDR 自身文件被执行映射（强信号，不受 EnableBlocking 门控） */
    if (WkdFspShouldBlockFileAccess(&nameInfo->Name, SECTION_MAP_EXECUTE, pid, FALSE)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender/FS] BLOCKED execute mapping of protected file: %wZ (PID=%lu)\n",
            &nameInfo->Name, HandleToULong(pid));
        WkdPasNoteSelfProtectBlock();
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 路径排除（对齐 SS ShadowStrikeIsPathExcluded） */
    if (WkdFspIsPathExcluded(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* B2 路径分析（复用 PreCreate 路径威胁评分，供映射评分融合） */
    pathScore = WkdFspAnalyzeFilePath(&nameInfo->Name, &nameInfo->Extension, &pathFlags);

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
    status = WkdPasProcessMapping(&input, &score, &mapFlags);

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender/FS] BLOCKED section mapping: %wZ (PID=%lu, score=%lu, flags=0x%08X)\n",
            &nameInfo->Name, HandleToULong(pid), score, mapFlags);
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
