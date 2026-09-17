/**************************************************/
/*                                                    */
/*  WkDefender 文件系统子系统——对外公共头             */
/*                                                    */
/*  【唯一对外入口】FileSystem 目录之外的内核模块        */
/*  （薄层 Callbacks\FileSystemNotification、          */
/*   WkdEntry、AlpcService、ProcessNotification 等）    */
/*  一律只允许包含本头，禁止直接包含                   */
/*  FileSystem\FileSystem.h（内部私有头）。             */
/*                                                    */
/*  架构分层：                                         */
/*    Include\FileSystem.h          对外公共头(本文件) */
/*    FileSystem\FileSystem.h       内部私有头          */
/*    FileSystem\FileSystem.c       编排器             */
/*    FileSystem\*.c                分析能力模块        */
/*    Callbacks\FileSystemNotification.{c,h} 薄层      */
/*                                                    */
/*  对外能力：                                         */
/*    - 生命周期：FsInitialize / FsCleanup             */
/*    - 备份服务：FsBackupRollbackProcess /            */
/*      FsBackupCommitProcess（FBE 封装）               */
/*    - 薄层机制导出：FsRegisterFilter /               */
/*      FsUnregisterFilter / FsSendYaraScanRequest /   */
/*      FsIsScannableExtension / FsIsCodeBearingExtension / */
/*      WkdFsGetFilterHandle / WkdFspIsBootPhase        */
/*    - 能力模块 API：FileScan / ProcessFileContext /  */
/*      NamedPipeMonitor / FileBackupEngine /          */
/*      PostCreateContext / PostWrite /            */
/*      PreAcquireSection / USBDeviceControl /         */
/*      PreCreate（Create 前置回调流水线）/             */
/*      PreWrite（Write 前置回调流水线）                */
/*                                                    */
/*  薄层回调壳消费能力模块 API（WkdFs*、Fbe*、         */
/*  WkdNpm*、WkdPoc*、WkdPwc*、WkdPas*、WkdUdc*、      */
/*  WkdPfcp*），故上述函数声明与外部可见类型均在本头。  */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#ifndef _WC_INCLUDE_FILESYSTEM_H_
#define _WC_INCLUDE_FILESYSTEM_H_

#include <ntddk.h>
#include <fltkernel.h>

#include "../../WkDefender@agent/Common/YaraProtocol.h"  /* WKD_YARA_SCAN_VERDICT（薄层 YARA 端口） */

/* ============================================================================
 * 一、外部服务与生命周期（编排器 FileSystem\FileSystem.c 实现）
 * ========================================================================== */

/* 回滚结果枚举（对齐 FileBackupEngine.h 原文，供 ALPC 服务消费方使用） */
typedef enum _FBE_ROLLBACK_RESULT {
    FbeRollback_Success = 0,
    FbeRollback_PartialSuccess,     /* 部分文件已恢复 */
    FbeRollback_NoBackupsFound,
    FbeRollback_IOError,
    FbeRollback_ShuttingDown,
    FbeRollback_InvalidProcess
} FBE_ROLLBACK_RESULT, *PFBE_ROLLBACK_RESULT;

/*++
 * FsInitialize
 *   文件系统子系统统一初始化（编排器入口）：
 *     FileScan（蜜罐/速率/排除/进程退出回调）→ UDC → Pfcp → PostCreate
 *     → PostWrite → 薄层注册（FsRegisterFilter：minifilter + YARA 端口
 *     + StartFiltering）→ WkdPasInitialize（StartFiltering 后）→ FBE → NPM。
 *   失败非致命：各模块能力降级门控，不阻断驱动加载主流程。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FsInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

/*++
 * FsCleanup
 *   文件系统子系统统一卸载（编排器入口），按初始化逆序清理：
 *     NPM → FBE → Pas → PostWrite → PostCreate → Pfcp → UDC → FileScan
 *     → 薄层反注册（FsUnregisterFilter：关 YARA 端口 + FltUnregisterFilter）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FsCleanup(
    _In_ PDRIVER_OBJECT DriverObject
    );

/*++
 * FsBackupRollbackProcess
 *   按进程回滚勒索 CoW 备份（封装 FbeRollbackProcess，语义）。
 *   供 ALPC SERVICE_ROLLBACK 调用。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
FBE_ROLLBACK_RESULT
FsBackupRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    );

/*++
 * FsBackupCommitProcess
 *   进程正常退出时丢弃其全部备份（封装 FbeCommitProcess）。
 *   由进程退出回调（ProcessNotification）调用。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FsBackupCommitProcess(
    _In_ HANDLE ProcessId
    );

/* ============================================================================
 * 二、薄层机制导出（实现于 Callbacks\FileSystemNotification.c）
 * ========================================================================== */

/* YARA FLT 通信端口内存标签（对齐原 Filter.h WKD_YARA_PORT_TAG） */
#define WKD_YARA_PORT_TAG   'pYWK'

/* 文件事件标志（事件上送层语义，对齐 agent DEF_FILE_FLAG_* 位）。
 * 【迁移 2026-10】自薄层上移公共头：薄层 FspSendFileEvent/PreWrite/PreCreate
 * 与能力模块 PreSetInformation（FsPreSetInformationNotifyCallback SHADOW_DELETE/RAPID_RATE）
 * 共用，薄层不再独立定义。 */
#define WKD_FS_FILE_FLAG_CANARY         0x00000001  /* 蜜罐 canary 文件命中（agent bit0） */
#define WKD_FS_FILE_FLAG_RAPID_RATE     0x00000002  /* 1s 窗口速率超阈值 → 高优先级 */
#define WKD_FS_FILE_FLAG_SHADOW_DELETE  0x00000004  /* 卷影副本删除（T1490） */
#define WKD_FS_FILE_FLAG_CREATE         0x00000008  /* 新文件创建 → WkdMessage_FileCreate */
#define WKD_FS_FILE_FLAG_SENSITIVE_WRITE 0x00000010 /* 敏感系统文件/卷影副本 写（T1003/T1490 变体，2026-10） */
#define WKD_FS_FILE_FLAG_CLIPBOARD     0x00000020 /* 剪贴板倾倒快速 temp 写入命中（T1115，2026-10 接线） */

/*++
 * FspSendFileEvent
 *   文件操作事件上送（Write/Rename/Delete/Truncate/HardLink/Attribute）到 agent，
 *   供勒索行为检测与因果图消费。实现在薄层 Callbacks\FileSystemNotification.c
 *   （去 static 导出）；PreWrite/PreCreate/PreSetInformation（能力模块）共用。
 *   OperationType 值对齐 WKD_FLT_OP_*（NotificationManager.h）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
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
    );

/*++
 * FsRegisterFilter
 *   薄层注册：minifilter 注册 + 创建 YARA 专用 FLT 端口 + StartFiltering。
 *   纯注册职责：分析能力模块初始化统一由编排器 FsInitialize 负责
 *   （2026-09-13 整合）。StartFiltering 后由编排器接续 WkdPasInitialize
 *   （回调经 IsActive 门控安全跳过初始化窗口）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FsRegisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
    );

/*++
 * FsUnregisterFilter
 *   薄层反注册：关闭 YARA 端口 + FltUnregisterFilter。
 *   纯反注册职责：能力模块逆序清理由编排器 FsCleanup 负责。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FsUnregisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
    );

/*++
 * FsSendYaraScanRequest
 *   同步阻塞式 YARA 扫描请求（fail-open）。
 *   必须在 PASSIVE_LEVEL 调用；仅 PreCreate/PreCleanup 等 PASSIVE 回调使用。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
WKD_YARA_SCAN_VERDICT
FsSendYaraScanRequest(
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG ProcessId
    );

/*++
 * FsIsScannableExtension
 *   扩展名命中可扫描集合（ASCII 大小写不敏感折叠比较，DISPATCH_LEVEL 安全）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FsIsScannableExtension(
    _In_ PCUNICODE_STRING Extension
    );

/*++
 * FsIsCodeBearingExtension
 *   扩展名是否属 code-bearing 集合（执行/脚本/文档/压缩，对齐 SS
 *   PcClassifyFile Executable/Script/Document/Archive）。
 *   供 G2 扫描范围收敛：纯读 + 非 code-bearing 跳同步扫描（2026-09）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FsIsCodeBearingExtension(
    _In_ PCUNICODE_STRING Extension
    );

/*++
 * WkdFsGetFilterHandle
 *   返回 minifilter 句柄（FileBackupEngine FltCreateFileEx / PostCreate 依赖）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
PFLT_FILTER
WkdFsGetFilterHandle(
    VOID
    );

/*++
 * WkdFspIsBootPhase
 *   一次性锁死的 boot 窗口判断（驱动加载后 120s）。导出供 PostCreateContext
 *   模块（FsPostCreateNotifyCallback boot 防御）与薄层各回调共用。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdFspIsBootPhase(
    VOID
    );

/* ============================================================================
 * 三、FileScan：静态/统计分析能力（蜜罐/速率/排除/熵/路径分析）
 *    原头 FileScan.h（已删除，内容并入本分区）
 * ========================================================================== */

/* 池标签（对齐旧 Filter.h 定义，文件备份引擎等共用） */
#define WKD_FSF_POOL_TAG            'fSWK'  /* 通用文件系统分析缓冲 */

/* 生命周期（编排器 FsInitialize/FsCleanup 内调，PASSIVE_LEVEL） */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdFsScanInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdFsScanCleanup(
    VOID
    );

/* 蜜罐 canary：精确路径无条件阻断（agent 下发的勒索诱饵路径） */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdFsAddCanaryPath(
    _In_ PCUNICODE_STRING Path
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdFsIsCanaryFile(
    _In_ PCUNICODE_STRING FileName
    );

/* 内置蜜罐文件名包含匹配（ASCII 大小写折叠，DISPATCH_LEVEL 安全） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdFsIsHoneypotFile(
    _In_ PCUNICODE_STRING FileName
    );

/* 敏感系统文件判定（BlockDelete/BlockRename/BlockHardLink 仅命中时写回） */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
WkdFsIsSensitiveSystemFile(
    _In_ PCUNICODE_STRING FileName,
    _Out_opt_ PBOOLEAN BlockDelete,
    _Out_opt_ PBOOLEAN BlockRename,
    _Out_opt_ PBOOLEAN BlockHardLink
    );

/* EDR 自保护写/删/改名/执行映射阻断（T1562.001，豁免 ExemptsIsProcessTrusted） */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
WkdFsShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FileName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN IsWriteOp
    );

/* 硬链接目标是否为敏感路径（T1003.003） */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
FspIsHardlinkSensitivePath(
    _In_ PCUNICODE_STRING FileName
    );

/* 卷影副本路径判定（\System Volume Information\ 或 @GMT-，T1490） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FspIsVolumeShadowCopyPath(
    _In_ PCUNICODE_STRING FileName
    );

/* 排除检查（agent 下发规则表填充，当前为空表） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdFsIsPathExcluded(
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdFsIsProcessExcluded(
    _In_ HANDLE ProcessId
    );

/* SetInformation 辅助：从用户缓冲安全提取 Rename/Link 目标路径（Ex 变体布局修正），
 * 调用者负责 ExFreePoolWithTag(NewFileName->Buffer, WKD_FSF_POOL_TAG)。 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdFsGetRenameDestination(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _Out_ PUNICODE_STRING NewFileName
    );

/* 真实删除判定（FSC-3）：FileDispositionInformation 需 DeleteFile=TRUE，
 * 忽略 undete 清除标记操作，防污染勒索统计。 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
BOOLEAN
FspIsConfirmedDeletion(
    _In_ PFLT_CALLBACK_DATA Data
    );

/* 写缓冲区熵（整数查表，Q16 输出，供 agent 高熵加密检测分支） */
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
WkdFsCalculateEntropyX100(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
WkdFsEntropyToQ16(
    _In_ ULONG EntropyX100
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
WkdFsSampleWriteEntropy(
    _In_ PFLT_CALLBACK_DATA Data
    );

/* 勒索窗口计数：1s 窗口 Write/Rename/Delete 速率，返回是否超阈值（RAPID_RATE） */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
WkdFsTrackFileOperation(
    _In_ HANDLE ProcessId,
    _In_ ULONG OpType                /* WKD_FLT_OP_*（NotificationManager.h） */
    );

/* 综合路径分析（B2）：返回威胁分（0-100），Flags 输出供薄层补充评分。
 * 以下两个标志供 CbpPreAcquireSectionNotifyCallback 预映射为 PAS_MAP_FLAG_* 使用 */
#define WKD_FS_PATH_ADS            0x00000001
#define WKD_FS_PATH_TEMP           0x00000004

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
FspAnalyzeFilePath(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING Extension,
    _Out_ PULONG OutFlags
    );

/* ============================================================================
 * 四、ProcessFileContext：进程文件上下文（勒索评分，FileScan 姊妹模块）
 *    原头 ProcessFileContext.h（已删除，内容并入本分区）
 * ========================================================================== */

/* 池标签与常量 */
#define WKD_PFCP_POOL_TAG           'cPFW'  /* WFPc - 进程文件上下文 */

/* 通知操作类型（薄层壳从 WKD_FLT_OP_* 映射，本模块不依赖消息层） */
typedef enum _WKD_PFCP_OP {
    WkdPfcpOp_Write = 0,
    WkdPfcpOp_Rename = 1,
    WkdPfcpOp_Delete = 2,
    WkdPfcpOp_Truncate = 3
} WKD_PFCP_OP;

/* 导出接口 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdPfcpInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdPfcpShutdown(
    VOID
    );

/* 文件操作通知（薄层 FspPreWrite/FsPreSetInformationNotifyCallback 调用）。
 * NewFileName 仅 RENAME 时传入（用于扩展名变更检测，可为 NULL）。 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdPfcpNotifyFileOperation(
    _In_ HANDLE ProcessId,
    _In_ WKD_PFCP_OP OpType,
    _In_ PCUNICODE_STRING FileName,
    _In_opt_ PCUNICODE_STRING NewFileName
    );

/* ============================================================================
 * 五、NamedPipeMonitor：命名管道 C2/横向移动监控
 *    原头 NamedPipeMonitor.h（已删除，内容并入本分区）
 * ========================================================================== */

#define WKD_NPM_POOL_TAG               'mNWK'  /* WkNm */

#define WKD_NPM_MAX_PIPE_NAME_CCH      256
#define WKD_NPM_RATE_LIMIT_WINDOW_MS   1000
#define WKD_NPM_RATE_LIMIT_MAX_CREATES 50
#define WKD_NPM_BOOT_PHASE_MS          120000  /* boot 期跳过窗口（ShadowFsIsBootPhase） */

#define WKD_NPM_STATE_UNINITIALIZED    0
#define WKD_NPM_STATE_INITIALIZING     1
#define WKD_NPM_STATE_READY            2

/* 威胁等级（NpmThreat_*） */
typedef enum _WKD_NPM_THREAT_LEVEL {
    WkdNpmThreat_None      = 0,
    WkdNpmThreat_Low       = 25,
    WkdNpmThreat_Medium    = 50,
    WkdNpmThreat_High      = 75,
    WkdNpmThreat_Critical  = 100
} WKD_NPM_THREAT_LEVEL, *PWKD_NPM_THREAT_LEVEL;

/* 管道分类（NpmClass_* 11 类） */
typedef enum _WKD_NPM_PIPE_CLASS {
    WkdNpmClass_Unknown         = 0,
    WkdNpmClass_System,                 /* Windows 系统管道（lsass 等） */
    WkdNpmClass_KnownApplication,       /* 已知合法应用管道 */
    WkdNpmClass_C2_CobaltStrike,        /* CobaltStrike beacon 模式 */
    WkdNpmClass_C2_Meterpreter,         /* Meterpreter 管道模式 */
    WkdNpmClass_C2_PsExec,              /* PsExec 服务管道 */
    WkdNpmClass_C2_Impacket,            /* Impacket/WMIExec 管道 */
    WkdNpmClass_C2_Generic,             /* 通用 C2 模式 */
    WkdNpmClass_HighEntropy,            /* 可疑随机化名 */
    WkdNpmClass_Suspicious,             /* 其他可疑模式 */
    WkdNpmClass_SpoofedSystem           /* 系统管道名被非预期进程创建（T1036） */
} WKD_NPM_PIPE_CLASS, *PWKD_NPM_PIPE_CLASS;

/* 系统管道验证结果（NpmSysPipe_*） */
typedef enum _WKD_NPM_SYS_PIPE_RESULT {
    WkdNpmSysPipe_NotSystem = 0,
    WkdNpmSysPipe_Validated = 1,
    WkdNpmSysPipe_Spoofed   = 2
} WKD_NPM_SYS_PIPE_RESULT, *PWKD_NPM_SYS_PIPE_RESULT;

/* 统计结构（NPM_STATISTICS 10 计数器） */
typedef struct _WKD_NPM_STATISTICS {
    volatile LONG64 TotalPipesCreated;
    volatile LONG64 TotalPipesConnected;        /* 连接检测未接入（死代码字段），恒 0 */
    volatile LONG64 TotalPipesBlocked;
    volatile LONG64 SuspiciousPipesDetected;
    volatile LONG64 C2PipesDetected;
    volatile LONG64 HighEntropyPipesDetected;
    volatile LONG64 CrossProcessConnections;    /* 连接检测未接入（死代码字段），恒 0 */
    volatile LONG64 SpoofedSystemPipes;
    volatile LONG64 EventsQueued;
    volatile LONG64 EventsDropped;
} WKD_NPM_STATISTICS, *PWKD_NPM_STATISTICS;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WkdNpmInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdNpmShutdown(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdNpmIsActive(
    VOID
    );

/*++
 * WkdNpmPreCreateNamedPipe
 *   命名管道创建分析（纯分类引擎，供 minifilter 回调调用）。
 *   内部编排：系统管道验证（限速豁免）→ 速率限制 → C2 模式/熵分类，
 *   并同步累计统计计数。不执行阻断/上送（接入层职责）。
 *
 * Arguments:
 *   PipeName        - 管道名（去除 \Device\NamedPipe\ 前缀后的最终组件）。
 *   NameLengthBytes - 管道名字节长（不含 NUL）。
 *   CreatorImageName- 创建者进程映像名（PsGetProcessImageFileName，ANSI）。
 *   OutThreatScore  - 输出威胁分 [0,100]。
 *
 * Return Value:
 *   WKD_NPM_PIPE_CLASS 分类；Unknown/System 表示无害。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
WKD_NPM_PIPE_CLASS
WkdNpmPreCreateNamedPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_z_ PCSTR CreatorImageName,
    _Out_ PULONG OutThreatScore
    );

/*++
 * WkdNpmIsBlockworthy
 *   阻断判定：系统管道冒充无条件；C2 类管道威胁分 >= 90（对齐 SS）。
 *
 * Return Value:
 *   TRUE 应阻断 / FALSE 仅上报。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdNpmIsBlockworthy(
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    );

/*++
 * WkdNpmClassToThreatLevel
 *   分类+威胁分 → 威胁等级（分级：>=90 Critical / >=70 High /
 *   >=50 Medium / >=25 Low）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
WKD_NPM_THREAT_LEVEL
WkdNpmClassToThreatLevel(
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    );

/*++
 * WkdNpmNoteBlocked
 *   接入层执行阻断后调用，累计 TotalPipesBlocked 统计。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmNoteBlocked(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmGetStatistics(
    _Out_ PWKD_NPM_STATISTICS Stats
    );

/*++
 * WkdNpmNoteEventQueued / WkdNpmNoteEventDropped
 *   接入层上送命名管道事件成功/失败时调用，NpmQueueEvent 的
 *   EventsQueued / EventsDropped 统计语义（wkd 事件队列由 NotificationManager
 *   承载，此处只累计命名管道模块自身视角的入队/丢弃计数）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmNoteEventQueued(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmNoteEventDropped(
    VOID
    );

/* ============================================================================
 * 六、FileBackupEngine：勒索 CoW 备份/回滚引擎
 *    原头 FileBackupEngine.h（已删除，内容并入本分区）
 * ========================================================================== */

/* 池标签 */
#define WKD_FBE_POOL_TAG            'eBFK'  /* KFBe - 通用 */
#define WKD_FBE_ENTRY_POOL_TAG      'nBFK'  /* KFBn - Backup Entry */
#define WKD_FBE_IO_POOL_TAG         'iBFK'  /* KFBi - I/O Buffer */
#define WKD_FBE_ROLLBACK_POOL_TAG   'rBFK'  /* KFBr - Rollback */
#define WKD_FBE_PATH_POOL_TAG       'pBFK'  /* KFBp - 路径缓冲（死代码：FBE_PATH_POOL_TAG，
                                               SS 亦未使用——路径缓冲内嵌 FBE_BACKUP_ENTRY，无独立分配） */

/* 配置常量（沿用 SS FBE 默认值） */
#define FBE_MAX_BACKUP_SIZE_DEFAULT     ((LONGLONG)10 * 1024 * 1024 * 1024)  /* 10 GB 全局 */
#define FBE_MAX_SINGLE_FILE_SIZE        ((LONGLONG)100 * 1024 * 1024)        /* 100 MB 单文件 */
#define FBE_MAX_TRACKED_PROCESSES       1024
#define FBE_MAX_ENTRIES_PER_PROCESS     4096
#define FBE_MAX_TOTAL_ENTRIES           65536
#define FBE_HASH_BUCKET_COUNT           256
#define FBE_IO_BUFFER_SIZE              (64 * 1024)     /* 64 KB 拷贝缓冲 */
#define FBE_BACKUP_DIR_NAME             L"\\WkdBackup"
#define FBE_MAX_PATH_LENGTH             300             /* 字符，覆盖 99.9% 实际路径 */
#define FBE_BACKUP_PATH_LENGTH          128             /* 字符，备份路径短且确定 */

/* 备份条目状态机：Free→Pending→Valid→RolledBack/Evicted/Failed */
typedef enum _FBE_ENTRY_STATE {
    FbeEntryState_Free = 0,
    FbeEntryState_Pending,          /* 备份进行中 */
    FbeEntryState_Valid,            /* 备份完成，可回滚 */
    FbeEntryState_RolledBack,       /* 已回滚 */
    FbeEntryState_Evicted,          /* LRU 淘汰 */
    FbeEntryState_Failed            /* 备份失败 */
} FBE_ENTRY_STATE;

/* 备份操作类型 */
typedef enum _FBE_OPERATION_TYPE {
    FbeOp_Write = 0,                /* IRP_MJ_WRITE 修改 */
    FbeOp_Rename,                   /* FileRenameInformation */
    FbeOp_Delete,                   /* FileDispositionInformation */
    FbeOp_Truncate,                 /* FileEndOfFileInformation（仅监控不备份，SS 语义） */
    FbeOp_SetAllocation             /* FileAllocationInformation（死代码，SS 亦未接线） */
} FBE_OPERATION_TYPE;

/* 备份条目：三链表嵌入 + 状态机 + 内嵌路径缓冲 */
typedef struct _FBE_BACKUP_ENTRY {
    LIST_ENTRY ProcessLink;         /* 逐进程链表 */
    LIST_ENTRY HashLink;            /* 哈希桶链 */
    LIST_ENTRY LruLink;             /* 全局 LRU 链 */

    volatile LONG State;            /* FBE_ENTRY_STATE（原子访问） */

    HANDLE ProcessId;               /* 归属进程 */
    FBE_OPERATION_TYPE OperationType;
    LARGE_INTEGER Timestamp;        /* 备份创建时间 */

    UNICODE_STRING OriginalPath;    /* 原始完整路径 */
    WCHAR OriginalPathBuffer[FBE_MAX_PATH_LENGTH];
    LARGE_INTEGER OriginalFileSize;

    UNICODE_STRING BackupPath;      /* 备份路径（短而确定） */
    WCHAR BackupPathBuffer[FBE_BACKUP_PATH_LENGTH];
    LARGE_INTEGER BackupFileSize;

    ULONG VolumeSerial;
} FBE_BACKUP_ENTRY, *PFBE_BACKUP_ENTRY;

#define STATUS_FBE_SKIP     ((NTSTATUS)0xE0FB0001L)

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbeInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FbeShutdown(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreWriteBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreSetInfoBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName,
    _In_ FBE_OPERATION_TYPE OpType
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
FBE_ROLLBACK_RESULT
FbeRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FbeCommitProcess(
    _In_ HANDLE ProcessId
    );

/* ============================================================================
 * 七、PostCreateContext：PostCreate verdict 缓存模块
 *    原头 PostCreateContext.h（已删除，内容并入本分区）
 * ========================================================================== */

#define WKD_POC_POOL_TAG                'cCPW'  /* WPcC - PostCreate Context */

/* FLT 上下文注册标签（FltAllocateContext 池标签，对齐 WKD_POC_POOL_TAG 风格） */
#define WKD_POC_STREAM_CONTEXT_TAG      'cSPW'  /* WPcS - Stream Context */
#define WKD_POC_HANDLE_CONTEXT_TAG      'cHPW'  /* WPcH - Handle Context */

#define WKD_POC_MAX_CACHED_NAME         256
#define WKD_POC_MAX_CACHED_EXTENSION    32

#define FLT_STREAM_CONTEXT_SIGNATURE  'tXcS'
#define WKD_POC_HANDLE_CONTEXT_SIGNATURE  'tXcH'
#define WKD_POC_COMPLETION_SIGNATURE      'pCcP'

#define WKD_POC_CONTEXT_COOKIE_SEED     0xDEADBEEFCAFEBABEULL

#define WKD_POC_COMPLETION_LOOKASIDE_DEPTH 64
#define WKD_POC_HANDLE_LOOKASIDE_DEPTH     256

#define WKD_POC_LOG_RATE_LIMIT_PER_SEC  50
#define WKD_POC_ONE_SECOND_100NS        10000000LL

typedef enum _WKD_POC_TRACKING_FLAGS {
    WkdPocTrackingNone        = 0x00000000,
    WkdPocTrackingScanned     = 0x00000001,  /* 已扫描 */
    WkdPocTrackingCached      = 0x00000002,  /* verdict 已缓存 */
    WkdPocTrackingModified    = 0x00000004,  /* 已修改 */
    WkdPocTrackingAds         = 0x00000080,  /* 含备用数据流 */
    WkdPocTrackingEncrypted   = 0x00000100,  /* EFS 加密 */
    WkdPocTrackingCompressed  = 0x00000200,
    WkdPocTrackingSparse      = 0x00000400,
    WkdPocTrackingHidden      = 0x00000800,
    WkdPocTrackingSystem      = 0x00001000,
    WkdPocTrackingReadOnly    = 0x00002000,
    WkdPocTrackingTemporary   = 0x00004000,
    WkdPocTrackingNetwork     = 0x00008000,  /* 网络卷 */
    WkdPocTrackingRemovable   = 0x00010000,  /* 可移除卷 */
} WKD_POC_TRACKING_FLAGS;

typedef enum _WKD_POC_FILE_CLASS {
    WkdPocFileClassUnknown    = 0,
    WkdPocFileClassExecutable = 1,
    WkdPocFileClassScript     = 2,
    WkdPocFileClassDocument   = 3,
    WkdPocFileClassArchive    = 4,
    WkdPocFileClassMedia      = 5,
    WkdPocFileClassData       = 6,
    WkdPocFileClassConfig     = 7,
    WkdPocFileClassCertificate= 8,
    WkdPocFileClassDatabase   = 9,
    WkdPocFileClassBackup     = 10,
    WkdPocFileClassLog        = 11,
    WkdPocFileClassTemporary  = 12,
} WKD_POC_FILE_CLASS;

/*++
 * WKD_POC_STREAM_CONTEXT
 *   挂载于文件流（FLT_STREAM_CONTEXT）的跟踪状态。
 *   核心：verdict 缓存（Scanned/Dirty/ThreatScore）+ 变更检测基线
 *   （ScanFileSize/LastWriteTime/FileId）+ 分类/属性缓存。
 *--*/
typedef struct _WKD_POC_STREAM_CONTEXT {
    ULONG Signature;                 /* FLT_STREAM_CONTEXT_SIGNATURE */
    ULONG64 SecurityCookie;          /* 地址混合防伪 cookie */

    /* 文件标识与变更基线 */
    LONGLONG FileId;
    ULONG VolumeSerial;
    LONGLONG ScanFileSize;           /* 扫描时文件大小（变更检测） */
    LARGE_INTEGER LastWriteTime;     /* 扫描时最后写时间（变更检测） */
    LARGE_INTEGER CreationTime;

    /* 名称缓存（可选，供日志/取证） */
    WCHAR CachedFileName[WKD_POC_MAX_CACHED_NAME];
    USHORT CachedFileNameLength;
    WCHAR CachedExtension[WKD_POC_MAX_CACHED_EXTENSION];
    USHORT CachedExtensionLength;

    /* 分类与属性 */
    WKD_POC_FILE_CLASS FileClass;
    ULONG FileAttributes;

    /* verdict 缓存 */
    BOOLEAN Scanned;                 /* 已扫描且结果有效 */
    BOOLEAN ScanResult;              /* TRUE = clean */
    LARGE_INTEGER ScanTime;
    UINT8 ThreatScore;               /* 0-100（agent 评分，仅记录） */
    ULONG ScanVerdictTTL;            /* 记录 TTL，不驱动失效（wkd 无 ScanCache） */
    UINT8 Reserved1[3];

    /* 变更跟踪 */
    BOOLEAN Dirty;                   /* 已修改 → verdict 失效 */
    UINT8 Reserved2[3];
    volatile LONG OpenCount;
    volatile LONG WriteCount;
    LARGE_INTEGER FirstWriteTime;
    LARGE_INTEGER LastModifyTime;

    /* 跟踪标志（吸附/属性/卷类型） */
    WKD_POC_TRACKING_FLAGS TrackingFlags;

    LARGE_INTEGER ContextCreateTime;
    LARGE_INTEGER LastAccessTime;

    EX_PUSH_LOCK Lock;
} WKD_POC_STREAM_CONTEXT, *PWKD_POC_STREAM_CONTEXT;

/*++
 * WKD_POC_HANDLE_CONTEXT
 *   挂载于流句柄（FLT_STREAMHANDLE_CONTEXT）的 per-open 状态。
 *   本期采集 open 元数据；WritePerformed 等布尔待 PostWrite 迁移时启用。
 *--*/
typedef struct _WKD_POC_HANDLE_CONTEXT {
    ULONG Signature;                 /* WKD_POC_HANDLE_CONTEXT_SIGNATURE */
    ULONG64 SecurityCookie;

    HANDLE ProcessId;
    HANDLE ThreadId;
    ACCESS_MASK DesiredAccess;
    ULONG CreateOptions;
    ULONG ShareAccess;

    LARGE_INTEGER OpenTime;
    EX_PUSH_LOCK Lock;
} WKD_POC_HANDLE_CONTEXT, *PWKD_POC_HANDLE_CONTEXT;

/*++
 * WKD_POC_COMPLETION_CONTEXT
 *   PreCreate → PostCreate verdict 传递（lookaside 分配 + 所有权防双释）。
 *--*/
typedef struct _WKD_POC_COMPLETION_CONTEXT {
    ULONG Signature;                 /* WKD_POC_COMPLETION_SIGNATURE */
    ULONG64 SecurityCookie;          /* 地址混合防伪 cookie */
    volatile LONG OwnershipToken;    /* 1 = owned */

    BOOLEAN WasScanned;              /* 已实际扫描 */
    BOOLEAN ScanResult;              /* TRUE = clean */
    UINT8 ThreatScore;               /* 0-100 */
    UINT8 Reserved1;

    LARGE_INTEGER PreCreateTime;
} WKD_POC_COMPLETION_CONTEXT, *PWKD_POC_COMPLETION_CONTEXT;

FORCEINLINE
ULONG64
WkdPocComputeSecurityCookie(
    _In_ PVOID ContextAddress
    )
{
    ULONG64 addr = (ULONG64)(ULONG_PTR)ContextAddress;
    ULONG64 cookie = addr ^ WKD_POC_CONTEXT_COOKIE_SEED;
    cookie = (cookie >> 17) | (cookie << 47);
    cookie ^= (addr << 13);
    cookie ^= WKD_POC_CONTEXT_COOKIE_SEED;
    return cookie;
}

FORCEINLINE
_Must_inspect_result_
BOOLEAN
FsCheckStreamContextValidity(
    _In_ const PWKD_POC_STREAM_CONTEXT Context
    )
{
    if (!Context || Context->Signature != FLT_STREAM_CONTEXT_SIGNATURE) {
        return FALSE;
    } 
    return (Context->SecurityCookie == WkdPocComputeSecurityCookie(Context));
}

FORCEINLINE
BOOLEAN
WkdPocIsValidHandleContext(
    _In_opt_ PWKD_POC_HANDLE_CONTEXT Context
    )
{
    if (Context == NULL || Context->Signature != WKD_POC_HANDLE_CONTEXT_SIGNATURE) {
        return FALSE;
    }
    return (Context->SecurityCookie == WkdPocComputeSecurityCookie(Context));
}

FORCEINLINE
BOOLEAN
WkdPocIsValidCompletionContext(
    _In_opt_ PWKD_POC_COMPLETION_CONTEXT Context
    )
{
    if (Context == NULL || Context->Signature != WKD_POC_COMPLETION_SIGNATURE) {
        return FALSE;
    }
    return (Context->SecurityCookie == WkdPocComputeSecurityCookie(Context));
}

/*++
 * WkdPocNeedsRescan
 *   verdict 是否失效（PocNeedsRescan：未扫/已修改 → 需重扫）。
 *--*/
FORCEINLINE
BOOLEAN
WkdPocNeedsRescan(
    _In_opt_ PWKD_POC_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return TRUE;
    }
    if (!Context->Scanned) {
        return TRUE;
    }
    if (Context->Dirty) {
        return TRUE;
    }
    return FALSE;
}

/* 初始化 / 关闭（PASSIVE_LEVEL，编排器 FsInitialize/FsCleanup 接线） */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WkdPocInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdPocShutdown(
    VOID
    );

/* 主回调（薄层 FspPostCreate 转发；函数体自带 DRAINING/IRQL 守卫） */
_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
FsPostCreateNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

/* CompletionContext 分配/释放（能力模块 FsPreCreateNotifyCallback 分配；防双释） */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
WkdPocAllocateCompletionContext(
    _Out_ PWKD_POC_COMPLETION_CONTEXT* OutContext
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPocFreeCompletionContext(
    _Inout_ PWKD_POC_COMPLETION_CONTEXT* Context
    );

/* 修改跟踪（薄层 FspPreWrite/FsPreSetInformationNotifyCallback 调用，内部取/验/改/放） */
_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPocMarkFileModified(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPocInvalidateFileVerdict(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

/* 缓存命中判断（能力模块 FsPreCreateNotifyCallback/FspPreCleanup 调用，免重复扫描） */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdPocHasFreshVerdict(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

/* 统计（原子读；精简版，PocGetStatistics/PocGetErrorStatistics） */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPocGetStatistics(
    _Out_opt_ PULONG64 TotalPostCreates,
    _Out_opt_ PULONG64 ContextsCreated,
    _Out_opt_ PULONG64 ContextsReused,
    _Out_opt_ PULONG64 ContextsFailed
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPocGetErrorStatistics(
    _Out_opt_ PULONG64 SignatureMismatches,
    _Out_opt_ PULONG64 InvalidContexts,
    _Out_opt_ PULONG64 DoubleFreeAttempts
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPocResetStatistics(
    VOID
    );

/* ============================================================================
 * 八、PostWrite：post-write 勒索行为检测模块
 *    原头 PostWriteContext.h（已删除，内容并入本分区）；
 *    实现文件 PostWrite.c（2026-10 由 PostWriteContext.c 更名）
 * ========================================================================== */

#define WKD_PWC_POOL_TAG                    'cWPW'  /* WPWc - Post-Write Context */

/*
 * 勒索行为检测阈值（PW_RANSOMWARE_* 系列）
 */
#define WKD_PWC_RANSOMWARE_WRITE_THRESHOLD  50      /* 每窗口写次数 */
#define WKD_PWC_RANSOMWARE_FILE_THRESHOLD   20      /* 每窗口唯一文件数 */
#define WKD_PWC_ENTROPY_HIGH_X100           750     /* 7.50 bits/byte（×100） */
#define WKD_PWC_ENTROPY_SUSPICIOUS_X100     650     /* 6.50 bits/byte（×100） */
#define WKD_PWC_ENTROPY_SAMPLE_SIZE         256     /* 熵采样字节数 */

/*
 * 写模式分析（PW_SMALL/LARGE_WRITE_*）
 */
#define WKD_PWC_SMALL_WRITE_THRESHOLD       4096
#define WKD_PWC_LARGE_WRITE_THRESHOLD       (1024 * 1024)
#define WKD_PWC_RAPID_WRITE_WINDOW_100NS    (1000LL * 10000LL)  /* 1s */
#define WKD_PWC_MAX_TRACKED_PROCESSES       64      /* A2 决策：64 槽轻量 */
#define WKD_PWC_MAX_TRACKED_FILES_PER_PROCESS 64

/*
 * 限速（PW_MAX_LOGS_PER_SECOND）
 */
#define WKD_PWC_MAX_LOGS_PER_SECOND         100

/*
 * 可疑度评分权重（PW_SCORE_*）
 */
#define WKD_PWC_SCORE_HIGH_ENTROPY          100
#define WKD_PWC_SCORE_DOUBLE_EXTENSION      80
#define WKD_PWC_SCORE_RAPID_WRITES          60
#define WKD_PWC_SCORE_HONEYPOT_ACCESS       200
#define WKD_PWC_SCORE_KNOWN_RANSOM_EXT      150
#define WKD_PWC_SCORE_FULL_FILE_OVERWRITE   40
#define WKD_PWC_SCORE_SEQUENTIAL_OVERWRITE  30
#define WKD_PWC_SCORE_LARGE_WRITE_OVERWRITE 20
#define WKD_PWC_SCORE_RAPID_FILE_MODIFICATIONS 70
#define WKD_PWC_ALERT_THRESHOLD             150
#define WKD_PWC_SCORE_DECAY_PER_SECOND      5
#define WKD_PWC_SCORE_MAX_ACCUMULATION      500

/*
 * 活动槽回收（PW_STALE_ENTRY_TIMEOUT_100NS）
 */
#define WKD_PWC_STALE_ENTRY_TIMEOUT_100NS   (60LL * 10000000LL)  /* 60s */

/*++
 * WKD_PWC_FILE_TRACKER
 *   进程活动槽内的唯一文件标识（unique file 计数用）。
 *--*/
typedef struct _WKD_PWC_FILE_TRACKER {
    UINT64 FileId;
    ULONG VolumeSerial;
} WKD_PWC_FILE_TRACKER, *PWKD_PWC_FILE_TRACKER;

/*++
 * WKD_PWC_WRITE_CONTEXT
 *   单次写操作的分析上下文（主回调栈上构造）。PW_WRITE_CONTEXT。
 *--*/
typedef struct _WKD_PWC_WRITE_CONTEXT {
    HANDLE ProcessId;
    HANDLE ThreadId;
    ULONG_PTR BytesWritten;
    LARGE_INTEGER WriteOffset;
    LARGE_INTEGER FileSize;

    ULONG VolumeSerial;
    UINT64 FileId;
    BOOLEAN IsFullOverwrite;
    BOOLEAN IsAppend;
    BOOLEAN IsSequential;
    UINT8 Reserved1;

    LONG SuspicionScore;
    ULONG EntropyX100;
    BOOLEAN IsHighEntropy;
    BOOLEAN IsDoubleExtension;
    BOOLEAN IsKnownRansomwareExt;
    BOOLEAN IsHoneypotFile;
    BOOLEAN IsRapidWrite;
    BOOLEAN IsNewUniqueFile;
    UINT8 Reserved2[2];

    LARGE_INTEGER Timestamp;
} WKD_PWC_WRITE_CONTEXT, *PWKD_PWC_WRITE_CONTEXT;

/* 初始化 / 关闭（PASSIVE_LEVEL，编排器 FsInitialize/FsCleanup 接线） */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WkdPwcInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdPwcShutdown(
    VOID
    );

/* 主回调（实现于 FileSystem\PostWrite.c；函数体自带 DRAINING/IRQL 守卫） */
_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
FsPostWriteNotifyCallabck(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

/* 统计（原子读；精简版，ShadowStrikePostWriteGetStats） */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPwcGetStatistics(
    _Out_opt_ PULONG64 TotalPostWrites,
    _Out_opt_ PULONG64 HighEntropyWrites,
    _Out_opt_ PULONG64 RansomwareAlerts,
    _Out_opt_ PULONG32 ActiveTrackers
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPwcGetErrorStatistics(
    _Out_opt_ PULONG64 InvalidContexts,
    _Out_opt_ PULONG64 MissingStreamContexts,
    _Out_opt_ PULONG64 AllocationFailures
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPwcResetStatistics(
    VOID
    );

/* ============================================================================
 * 九、PreAcquireSection：代码执行映射检测（驱动侧接口）
 *    原头 PreAcquireSection.h（已删除，内容并入本分区）
 * ========================================================================== */

/* 执行保护掩码（文件轨回调快速跳过） */
#define PAS_EXECUTE_PROTECTION_MASK     (PAGE_EXECUTE | PAGE_EXECUTE_READ | \
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

/* 映射分类标志（PAS_MAP_FLAG_* 16 位） */
#define PAS_MAP_FLAG_EXECUTABLE         0x00000001
#define PAS_MAP_FLAG_IMAGE              0x00000002
#define PAS_MAP_FLAG_WRITABLE           0x00000004
#define PAS_MAP_FLAG_CROSS_PROCESS      0x00000008
#define PAS_MAP_FLAG_UNSIGNED           0x00000010
#define PAS_MAP_FLAG_PACKED             0x00000020
#define PAS_MAP_FLAG_SUSPICIOUS_PATH    0x00000040
#define PAS_MAP_FLAG_TEMP_LOCATION      0x00000080
#define PAS_MAP_FLAG_NETWORK            0x00000100
#define PAS_MAP_FLAG_REMOVABLE          0x00000200
#define PAS_MAP_FLAG_ADS                0x00000400
#define PAS_MAP_FLAG_BLOCKED            0x00000800
#define PAS_MAP_FLAG_HOLLOWING_SUSPECT  0x00001000
#define PAS_MAP_FLAG_REFLECTIVE_SUSPECT 0x00002000
#define PAS_MAP_FLAG_EARLY_PROCESS      0x00004000
#define PAS_MAP_FLAG_SUSPENDED_THREAD   0x00008000

/* 行为标志（PAS_BEHAVIOR_* 8 位） */
#define PAS_BEHAVIOR_RAPID_MAPPING      0x00000001
#define PAS_BEHAVIOR_CROSS_PROCESS      0x00000002
#define PAS_BEHAVIOR_UNSIGNED_EXEC      0x00000004
#define PAS_BEHAVIOR_TEMP_EXEC          0x00000008
#define PAS_BEHAVIOR_MULTIPLE_TARGETS   0x00000010
#define PAS_BEHAVIOR_SELF_MODIFICATION  0x00000020
#define PAS_BEHAVIOR_HOLLOWING          0x00000040
#define PAS_BEHAVIOR_REFLECTIVE         0x00000080

/* 评分阈值（PAS_SUSPICION_* / MinBlockScore=85） */
#define PAS_SUSPICION_LOW_DEFAULT       15
#define PAS_SUSPICION_MEDIUM_DEFAULT    30
#define PAS_SUSPICION_HIGH_DEFAULT      65
#define PAS_SUSPICION_CRITICAL_DEFAULT  85
#define PAS_MIN_BLOCK_SCORE             PAS_SUSPICION_CRITICAL_DEFAULT
#define PAS_ANOMALY_THRESHOLD_DEFAULT   10
#define PAS_HOLLOWING_EARLY_WINDOW_MS   5000

/* 单次可执行映射输入（薄层回调壳 → FsAuditMemeoryMapping）。
 * PreMappedFlags 由回调壳把 B2 路径分析结果（WKD_FS_PATH_*）与卷类型
 * 判定预映射为 PAS_MAP_FLAG_* 增量（两宏集合分处不同文件，避免跨文件
 * 宏依赖）。 */
typedef struct _WKD_PAS_INPUT {
    HANDLE           ProcessId;       /* 映射发起进程 */
    ULONG            PageProtection;  /* 请求保护（含 SEC_IMAGE 位） */
    PCUNICODE_STRING FileName;        /* 映射文件路径（CACHE_ONLY 已查，可空） */
    ULONG            PathScore;       /* B2 路径分析分数（0-100，WkdFspCalcPathFlagScore） */
    ULONG            PreMappedFlags;  /* 预映射的 PAS_MAP_FLAG_* 增量 */
} WKD_PAS_INPUT, *PWKD_PAS_INPUT;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WkdPasInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdPasShutdown(
    VOID
    );

/* 处理一次可执行映射：更新进程画像、行为检测、评分融合。
 * 输出 Score（0-100，PAS 基础分 + B2 路径分封顶 +40）与
 * MappingFlags（PAS_MAP_FLAG_* 位图）。
 * 阻断决策由回调壳依据 Score 与 WKD_PAS_CONFIG.EnableBlocking 执行。 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FsAuditMemeoryMapping(
    _In_ PWKD_PAS_INPUT Input,
    _Out_opt_ PULONG Score,
    _Out_opt_ PULONG MappingFlags
    );

/* 状态/配置/统计访问器（薄层回调壳不直接触碰 .c 内 static 全局）。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasIsActive(
    VOID
    );

/* Score 是否达到事件上送门槛（Config.SuspicionMedium） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasShouldReport(
    _In_ ULONG Score
    );

/* Score 是否达到阻断门槛（Config.EnableBlocking && Score>=MinBlockScore） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasShouldBlock(
    _In_ ULONG Score
    );

/* 统计计数（回调壳触发的三类结果） */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteSelfProtectBlock(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteBlocked(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteAllowed(
    VOID
    );

/* 扫描 verdict 缓存统计（PostCreate 迁移 2026-09 补齐生产者后新增：
 * 薄层壳 CbpPreAcquireSectionNotifyCallback 在路径排除后查询 STREAM_CONTEXT verdict，
 * 恶意 verdict 直接强信号阻断，不受 EnableBlocking Audit 门控） */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteCacheHit(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteCacheMiss(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteCacheBlock(
    VOID
    );

/* ============================================================================
 * 十、USBDeviceControl：可移除设备控制
 *    原头 USBDeviceControl.h（已删除，内容并入本分区）
 * ========================================================================== */

#define WKD_UDC_POOL_TAG            'cDUW'  /* WUDc - USB Device Control */
#define WKD_UDC_DEVICE_POOL_TAG     'dDUW'  /* WUDd - Device Entry */

#define WKD_UDC_MAX_WHITELIST_ENTRIES   256
#define WKD_UDC_MAX_BLACKLIST_ENTRIES   256
#define WKD_UDC_MAX_TRACKED_VOLUMES     64
#define WKD_UDC_SERIAL_MAX_LENGTH       128
#define WKD_UDC_MAX_AUTORUN_SIZE        (64 * 1024)     /* 64 KB max autorun.inf */
#define WKD_UDC_STORAGE_QUERY_BUFFER_SIZE 1024
#define WKD_UDC_HARDWARE_ID_BUFFER_SIZE 512
#define WKD_UDC_MAX_PDO_DEPTH           64

/* WKD_UDC-VAL：公开 API/未来 IOCTL 边界校验，防止非法枚举值静默禁用执行 */
#define WKD_UDC_IS_VALID_POLICY(p) \
    ((p) == WkdUdcPolicy_Allow    || (p) == WkdUdcPolicy_ReadOnly || \
     (p) == WkdUdcPolicy_Block    || (p) == WkdUdcPolicy_Audit)

#define WKD_UDC_IS_VALID_CLASS(c) \
    ((ULONG)(c) <= (ULONG)WkdUdcClass_Other)

/* 设备访问策略（UDC_DEVICE_POLICY） */
typedef enum _WKD_UDC_DEVICE_POLICY {
    WkdUdcPolicy_Allow = 0,     /* 完全访问 */
    WkdUdcPolicy_ReadOnly,      /* 只读，写操作阻断 */
    WkdUdcPolicy_Block,         /* 卷附加整体拒绝 */
    WkdUdcPolicy_Audit          /* 仅记录，不阻断 */
} WKD_UDC_DEVICE_POLICY, *PWKD_UDC_DEVICE_POLICY;

/* 设备类型（UDC_DEVICE_CLASS） */
typedef enum _WKD_UDC_DEVICE_CLASS {
    WkdUdcClass_Unknown = 0,
    WkdUdcClass_MassStorage,    /* USB 大容量存储（U 盘/移动硬盘） */
    WkdUdcClass_CDROM,          /* USB CD/DVD */
    WkdUdcClass_HID,            /* 人机接口设备（键盘/鼠标） */
    WkdUdcClass_Network,        /* USB 网卡 */
    WkdUdcClass_Printer,        /* USB 打印机 */
    WkdUdcClass_Other           /* 未分类 */
} WKD_UDC_DEVICE_CLASS, *PWKD_UDC_DEVICE_CLASS;

/* 配置（UDC_CONFIG） */
typedef struct _WKD_UDC_CONFIG {

    WKD_UDC_DEVICE_POLICY DefaultPolicy;    /* 未列入设备的默认策略 */
    BOOLEAN             EnableAutorunBlocking;
    BOOLEAN             EnableWriteProtection;
    BOOLEAN             EnableAuditLogging;
    BOOLEAN             Enabled;            /* 总开关 */

} WKD_UDC_CONFIG, *PWKD_UDC_CONFIG;

/* 统计（UDC_STATISTICS，8 计数） */
typedef struct _WKD_UDC_STATISTICS {

    volatile LONG64     VolumeMounts;
    volatile LONG64     VolumeDismounts;
    volatile LONG64     WritesBlocked;
    volatile LONG64     WritesAllowed;
    volatile LONG64     VolumeAttachRejected;
    volatile LONG64     AutorunDetected;
    volatile LONG64     AutorunBlocked;
    volatile LONG64     PolicyChecks;

} WKD_UDC_STATISTICS, *PWKD_UDC_STATISTICS;

/*
 * 生命周期（UdcInitialize/UdcShutdown）
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdUdcInitialize(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdUdcShutdown(
    VOID
    );

/*
 * 策略检查（minifilter 回调调用，UdcCheckVolumePolicy 等）
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
WkdUdcCheckVolumePolicy(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PWKD_UDC_DEVICE_POLICY Policy
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcIsWriteBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcIsSetInfoBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcCheckAutorun(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    );

/*
 * 卷追踪（InstanceSetup/Teardown 回调调用，UdcNotifyVolumeMount 等）
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdUdcNotifyVolumeMount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ WKD_UDC_DEVICE_POLICY Policy
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdUdcNotifyVolumeDismount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

/*
 * 统计查询（UdcGetStatistics）
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdUdcGetStatistics(
    _Out_ PWKD_UDC_STATISTICS Statistics
    );

/*
 * 规则管理（UdcAddRule/UdcRemoveRule/UdcClearRules/UdcUpdateConfig）
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdUdcAddRule(
    _In_ BOOLEAN IsBlacklist,
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber,
    _In_ WKD_UDC_DEVICE_CLASS DeviceClass,
    _In_ WKD_UDC_DEVICE_POLICY Policy,
    _Out_ PULONG RuleId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WkdUdcRemoveRule(
    _In_ ULONG RuleId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WkdUdcClearRules(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WkdUdcUpdateConfig(
    _In_ PWKD_UDC_CONFIG NewConfig
    );

/* ============================================================================
 * 十一、PreSetInformation：SetInformation 前置回调流水线（2026-10 提取）
 *    原实现位于薄层 Callbacks\FileSystemNotification.c（FsPreSetInformationNotifyCallback
 *    段），static 去除后迁入 FileSystem\PreSetInformation.c。薄层回调表
 *    IRP_MJ_SET_INFORMATION 经本分区声明直接引用；PreWrite 亦经公共头调用
 *    FspIsBackupDirPath（备份目录豁免，薄层→能力模块方向）。
 * ========================================================================== */

/*++
 * FspIsBackupDirPath
 *   检查路径是否位于 WkdBackup 备份目录内（大小写不敏感子串匹配）。
 *   防 FBE 备份 I/O 递归（备份文件自身写入会重入 PreWrite/PreSetInfo）。
 *   实现在 FileSystem\PreSetInformation.c；薄层 PreWrite 共用。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
FspIsBackupDirPath(
    _In_ PCUNICODE_STRING FileName
    );

/*++
 * FsPreSetInformationNotifyCallback
 *   IRP_MJ_SET_INFORMATION Pre 回调：删除/重命名/硬链接/截断/属性 的 CoW 备份
 *   + 强信号阻断（自保护/敏感文件/凭据硬链接）+ 事件上送 + 勒索评分接线。
 *   IRQL：PASSIVE_LEVEL（分页 I/O/KernelMode 快速放行，无需 Post 回调）。
 *   实现在 FileSystem\PreSetInformation.c；薄层回调表直接引用（FLT 注册
 *   签名：PFLT_PREOP_CALLBACK_STATUS）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
FLT_PREOP_CALLBACK_STATUS
FsPreSetInformationNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/* ============================================================================
 * 十二、PreCreate：Create 前置回调流水线（2026-10 提取，与 PreSetInformation 同批）
 *    原实现位于薄层 Callbacks\FileSystemNotification.c（CbpPreCreateNotifyCallback
 *    段），static 去除后迁入 FileSystem\PreCreate.c。薄层回调表
 *    IRP_MJ_CREATE 经本分区声明直接引用；事件上送原语 FspSendFileEvent
 *    保留于薄层（见二分区）。
 * ========================================================================== */

/*++
 * FsPreCreateNotifyCallback
 *   IRP_MJ_CREATE Pre 回调：补齐后的完整检测流水线（对齐 SS
 *   ShadowStrikePreCreate 语义 + wkd 模块化裁剪）：
 *     蜜罐 canary → 快速跳过（内核/分页/System/可信）→ 进程/路径排除
 *     → USB autorun 阻断 → EDR 自保护阻断 → 扩展名判定 → G2 收敛
 *     （纯读+非 code-bearing）→ verdict 缓存命中 → 速率/敏感 flag
 *     → boot 期跳过 → 本地威胁评分（≥75 阻断/≥50 上报）→ 同步 YARA
 *     扫描（fail-open）→ FILE_CREATE 创建事件 → PostCreate verdict 传递。
 *   阻断统一 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE；全部 fail-open。
 *   实现在 FileSystem\PreCreate.c；薄层回调表直接引用（FLT 注册
 *   签名：PFLT_PREOP_CALLBACK_STATUS）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
FLT_PREOP_CALLBACK_STATUS
FsPreCreateNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/* ============================================================================
 * 十三、PreWrite：Write 前置回调流水线（2026-10 提取）
 *    原实现位于薄层 Callbacks\FileSystemNotification.c（FspPreWrite 段），
 *    static 去除后迁入 FileSystem\PreWrite.c。薄层回调表 IRP_MJ_WRITE 经本分区
 *    声明直接引用；事件上送原语 FspSendFileEvent 保留于薄层（见二分区），
 *    备份豁免 FspIsBackupDirPath / 卷影判定 FspIsVolumeShadowCopyPath 复用
 *    十一分区声明（PreSetInformation.c 实现）。
 * ========================================================================== */

/*++
 * FsPreWriteNotifyCallback
 *   IRP_MJ_WRITE Pre 回调：自保护/UDC 只读卷/canary 蜜罐三级阻断 + 快速跳过
 *     （内核/分页/零长度）→ 修改标记（verdict 失效）→ 蜜罐/速率/敏感 flag
 *     → boot 跳过 → 勒索评分接线 → FBE CoW 备份（备份目录豁免）→ 扩展名
 *     命中上送文件事件（熵 Q16）。
 *   阻断统一 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE；全部 fail-open
 *   （WkdUdcIsWriteBlocked 未初始化/禁用返回 FALSE 放行）。
 *   实现在 FileSystem\PreWrite.c；薄层回调表直接引用（FLT 注册
 *   签名：PFLT_PREOP_CALLBACK_STATUS）。
 *--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
FLT_PREOP_CALLBACK_STATUS
FsPreWriteNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

#endif /* _WC_INCLUDE_FILESYSTEM_H_ */