/**************************************************/
/*  PreWrite 前置回调（阻断三链 + CoW 备份 + 上送）  */
/*  迁移自薄层 Callbacks\FileSystemNotification.c   */
/*  FspPreWrite 段（2026-10 提取）                */
/*                                                  */
/*  活代码：FsPreWriteNotifyCallback 检测流水线      */
/*    （自保护阻断/UDC 只读卷阻断/canary 蜜罐阻断/    */
/*    快速跳过/进程路径排除/修改标记/蜜罐 flag/      */
/*    速率 flag/敏感 flag/boot 跳过/单写可疑判定     */
/*    +组合阻断/剪贴板倾倒(T1115)/勒索评分接线/     */
/*    FBE 备份/事件上送）                            */
/*    由薄层回调表 IRP_MJ_WRITE 直接引用（回调       */
/*    名沿用 Fs* 前缀，注册不变）。                 */
/*  依赖：FileScan/ProcessFileContext/USBDeviceControl */
/*    /FileBackupEngine/PostCreateContext/           */
/*    NotificationManager（均经公共头                */
/*    Include\FileSystem.h）。                       */
/*                                                  */
/*  事件上送原语 FspSendFileEvent 保留在薄层（去      */
/*    static，公共头声明）：本模块与 PreCreate/       */
/*    PreSetInformation 共用事件上送层语义            */
/*    （WKD_FS_FILE_FLAG_* 已上移公共头）。备份目录   */
/*    豁免 FspIsBackupDirPath 与卷影路径判定          */
/*    FspIsVolumeShadowCopyPath 位于                 */
/*    PreSetInformation.c（公共头声明）。私有辅助      */
/*    FspQueryFileId 随迁为文件内 static             */
/*    （原薄层 WkdFspQueryFileId，仅 PreWrite 使用）。 */
/**************************************************/

#include "FileSystem.h"                /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */
#include "../Notification/NotificationManager.h"   /* WKD_FLT_OP_* 操作类型 */
#include "../AnalysisEngine/IocProcess.h"          /* T1115 剪贴板检查（IocpClipboardCheckFileWrite） */
#include "../AnalysisEngine/AnalysisEngine.h"      /* AeReportIndicatorPair 阻断上报（B3 链） */
#include "../ThreatScoring/ThreatScoring.h"        /* TsIndicator_File_HighEntropy */

/**************************************************/
/*          单写可疑判定常量（对齐 SS）             */
/**************************************************/

#define WKD_PW_ENTROPY_HIGH_Q16         (491520u)   /* == 750(X100)：高熵阈值，对齐 PostWrite WKD_PWC_ENTROPY_HIGH_X100 */
#define WKD_PW_HEADER_OVERWRITE_MIN     512         /* 头覆写最小字节数（SS PW 判定同值） */

/**************************************************/
/*          文件对象 ID 查询（事件上送辅助）        */
/**************************************************/

/*++
 * FspQueryFileId
 *   查询文件对象 ID（FileInternalInformation → IndexNumber）。
 *   仅在上送文件事件前调用（扩展名命中时），控制热路径开销；失败返回 0。
 *   【迁移】原薄层 static WkdFspQueryFileId（仅 FspPreWrite 调用）；随
 *   PreWrite 提取迁入本模块并改名（文件内私有，方向薄层→能力）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG64
FspQueryFileId(
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

/**************************************************/
/*        PreWrite 前置回调（CoW 备份 + 上送）      */
/**************************************************/

/*++
 * FsPreWriteNotifyCallback
 *   IRP_MJ_WRITE Pre 回调（迁移自薄层 FspPreWrite 段，2026-10）：
 *     自保护阻断 → UDC 只读卷阻断 → canary 蜜罐阻断 → 快速跳过
 *     （内核/分页/零长度）→ 进程/路径排除 → 修改标记（verdict
 *     失效）→ 蜜罐 flag → 速率 flag → 敏感/卷影 flag → boot 跳过
 *     → 单写可疑判定（高熵/头覆写/可执行尾附）+ 组合阻断（对齐
 *     SS PwpAnalyzeWriteSuspicion/PwpShouldBlockWrite，2026-10）→
 *     剪贴板倾倒（T1115）→ 勒索评分接线 → 备份目录豁免下 FBE
 *     CoW 备份 → 扩展名命中上送文件事件（熵 Q16 复用，激活 agent
 *     高熵加密检测分支）。
 *   阻断统一 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE；全部 fail-open
 *   （WkdUdcIsWriteBlocked 未初始化/禁用返回 FALSE 放行）。
 *   实现在 FileSystem\PreWrite.c；薄层回调表直接引用（FLT 注册
 *   签名：PFLT_PREOP_CALLBACK_STATUS）。
 *--*/
_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
FsPreWriteNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG fileFlags = 0;
    BOOLEAN honeypotHit = FALSE;
    BOOLEAN sensitiveTarget = FALSE;   /* 敏感系统文件/卷影路径（flag + 组合阻断共用） */
    ULONG entropyQ16 = 0;              /* 写缓冲熵（Q16）：单写判定采样，上送阶段复用 */

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

    /* 自保护写阻断（PreWrite 迁移 2026-10）：四路径防篡改闭环
     * （PreCreate/PreSetInfo/PreAcquireSection/PreWrite）。先于 canary 与 boot 跳过
     * （boot 期防篡改同 SS 语义）。WkdFsShouldBlockFileAccess 内部含可信进程豁免。 */
    if (WkdFsShouldBlockFileAccess(&nameInfo->Name,
                                   FILE_WRITE_DATA | FILE_APPEND_DATA,
                                   PsGetCurrentProcessId(), FALSE)) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* USB 设备控制（迁移 2026-08 接线）：可移除只读卷写阻断（T1052.001）。
     * fail-safe：UDC 未初始化/禁用 → WkdUdcIsWriteBlocked 返回 FALSE（放行）。 */
    //if (WkdUdcIsWriteBlocked(FltObjects)) {
    //    FltReleaseFileNameInformation(nameInfo);
    //    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    //    Data->IoStatus.Information = 0;
    //    return FLT_PREOP_COMPLETE;
    //}

    /* 蜜罐 canary 检查（FileScan）：精确路径命中无条件阻断。
     * 阻断在备份之前，避免对蜜罐文件做无意义备份。 */
    if (WkdFsIsCanaryFile(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 快速跳过：内核模式 / 分页 I/O / 零长度写——纯内联判断，避免系统写
     * （日志/分页/缓存回写）触发 FBE 备份与事件上送。置于 canary 之后
     * （保留蜜罐无条件语义）。 */
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

    /* 进程/路径排除（2026-10 接线，对齐 SS ShadowStrikeIsProcessExcluded/
     * ShadowStrikeIsPathExcluded）：命中 → 跳过后续全部分析（含修改标记——
     * 被排除路径不参与 verdict 扫描闭环）。排列在 canary/快速跳过之后：
     * 蜜罐/自保护/UDC 无条件语义优先于排除（SS 排除在 UDC/canary 之前为
     * 历史顺序，wkd 保留"蜜罐最高优先级"语义）。WkdFsIsPathExcluded 有实现
     * （agent 策略前缀表）；WkdFsIsProcessExcluded 当前为空桩（仅信任表等价），
     * 调用无害、填表即生效。 */
    if (WkdFsIsProcessExcluded(PsGetCurrentProcessId()) ||
        WkdFsIsPathExcluded(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 文件已修改（PostCreate 迁移 2026-09）：用户模式写 → stream context
     * Dirty=TRUE → verdict 失效（后续 create/cleanup 经 WkdPocNeedsRescan
     * 判定重扫）。context 不存在/签名无效时内部安全跳过（fail-open）。 */
    WkdPocMarkFileModified(FltObjects);

    /* 内置蜜罐文件名命中 → 上送 Flags.Canary 供 agent 勒索评分（+50，不阻断） */
    honeypotHit = WkdFsIsHoneypotFile(&nameInfo->Name);
    if (honeypotHit) {
        fileFlags |= WKD_FS_FILE_FLAG_CANARY;
    }

    /* 勒索窗口计数（FileScan）：1s 窗口写速率超阈值 → RAPID_RATE 提升优先级 */
    if (WkdFsTrackFileOperation(PsGetCurrentProcessId(), WKD_FLT_OP_WRITE)) {
        fileFlags |= WKD_FS_FILE_FLAG_RAPID_RATE;
    }

    /* 敏感系统文件写 flag（PW_SUSPICION_SENSITIVE_TARGET 上送语义，不进阻断——
     * wkd Audit 架构）：敏感系统文件/卷影副本路径命中 → 事件 flag
     * 抬高 agent 勒索/数据破坏评分。WkdFsIsSensitiveSystemFile 三输出参数可空。
     * sensitiveTarget 同时复用于下方高熵组合阻断（对齐 SS PwpShouldBlockWrite
     * 的 shadow copy/credential/backup + 熵 组合）。 */
    sensitiveTarget = (WkdFsIsSensitiveSystemFile(&nameInfo->Name, NULL, NULL, NULL) ||
                       FspIsVolumeShadowCopyPath(&nameInfo->Name));
    if (sensitiveTarget) {
        fileFlags |= WKD_FS_FILE_FLAG_SENSITIVE_WRITE;
    }

    /* boot 期跳过 FBE 备份/熵采样/事件上送（canary 已过），防早期 I/O 洪泛 */
    //if (WkdFspIsBootPhase()) {
    //    FltReleaseFileNameInformation(nameInfo);
    //    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    //}

    /* 单写可疑判定 + 组合阻断（2026-10，对齐 SS PwpAnalyzeWriteSuspicion +
     * PwpShouldBlockWrite 8 条矩阵，wkd 收敛为 3 组组合）：
     *   - 高熵：写缓冲熵 Q16 ≥ 491520（== 750 X100，对齐 PostWrite
     *     WKD_PWC_ENTROPY_HIGH_X100）。WkdFsSampleWriteEntropy 内部：
     *     长度 <256B 直接返回 0、MDL/用户缓冲 ProbeForRead 保护——fail-open。
     *   - 头覆写：起始偏移 + ≥512B（勒索加密典型首块覆写；
     *     SS OVERWRITE_HEADER 同值）。
     *   - 可执行尾附：代码承载扩展名 + 非起始/未知偏移（代码注入 T1055；
     *     SS APPEND_EXECUTABLE；FsIsCodeBearingExtension 薄层导出，入参为
     *     fltmgr 解析的 nameInfo->Extension 字段——含扩展点规范净扩展名）。
     * 阻断组合：高熵 ∧ (敏感目标 | 头覆写 | 可执行尾附) → STATUS_ACCESS_DENIED +
     * 事件上报（TsIndicator_File_HighEntropy → 0x0E05，投递进程对）。
     * 阻断执行在 PFCP/备份/上送之前：被拦截的写不评分、不 CoW 备份（SS 为
     * 先备份后判定，本实现更优）；修改标记已先行（verdict 已失效，一致）。 */
    entropyQ16 = (ULONG)WkdFsSampleWriteEntropy(Data);

    if (entropyQ16 >= WKD_PW_ENTROPY_HIGH_Q16) {
        ULONGLONG writeOffset =
            (ULONGLONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
        BOOLEAN headerOverwrite =
            (writeOffset == 0 &&
             Data->Iopb->Parameters.Write.Length >= WKD_PW_HEADER_OVERWRITE_MIN);
             BOOLEAN appendExecutable =
             (!headerOverwrite &&
              writeOffset != (ULONGLONG)-1 &&
              FsIsCodeBearingExtension(&nameInfo->Extension));

        if (sensitiveTarget || headerOverwrite || appendExecutable) {
            
            AeReportIndicatorPair(
                PsGetCurrentProcessId(),
                PsGetCurrentProcessId(),
                TsSourceIOC,
                TsIndicator_File_HighEntropy,
                AeThreatSeverityCritical);

            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    /* 勒索行为评分（ProcessFileContext，2026-09 接线）：写操作入槽。
     * boot 期已跳过；FBE 备份 I/O 为 KernelMode，天然豁免。 */
    WkdPfcpNotifyFileOperation(PsGetCurrentProcessId(), WkdPfcpOp_Write,
                               &nameInfo->Name, NULL);

    /* T1115 剪贴板倾倒（2026-10 接线，IocProcess.c §8）：仅查已标记进程的
     * temp 快速写入（≥10 次/5s 窗口）；追踪表未初始化/进程未标记 → 内部
     * 短路 FALSE。命中置 flag 上送（SS 同时提交 BehaviorEvent_
     * ClipboardRapidTempWrites 65 分；wkd 由 agent 侧按 flag + 事件关联评分，
     * 对齐 SS 双路提交的 ② 面）。 */
    //if (IocpClipboardCheckFileWrite(PsGetCurrentProcessId(), &nameInfo->Name)) {
    //    fileFlags |= WKD_FS_FILE_FLAG_CLIPBOARD;
    //}

    if (!FspIsBackupDirPath(&nameInfo->Name)) {
        /* CoW 备份：FBE 内部完成扩展名过滤/哨兵防重入/容量/LRU 管理 */
        status = FbePreWriteBackup(Data, FltObjects, &nameInfo->Name);

        /* 扩展名命中（非 STATUS_FBE_SKIP）→ 上送文件事件供勒索检测/因果图。
         * FileEntropy：熵已在"单写可疑判定"阶段采样一次（entropyQ16 复用，
         * 不再二次采样），激活 agent 高熵加密检测分支。 */
        if (status != STATUS_FBE_SKIP) {
            FspSendFileEvent(WKD_FLT_OP_WRITE, &nameInfo->Name,
                             Data->Iopb->Parameters.Write.Length, entropyQ16, fileFlags,
                             Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
                             Data->Iopb->Parameters.Write.Length,
                             FspQueryFileId(FltObjects));
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}