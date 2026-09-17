/**************************************************/
/*  PreSetInformation 前置回调（强信号阻断 + 上送）  */
/*  迁移自薄层 Callbacks\FileSystemNotification.c   */
/*  FsPreSetInformationNotifyCallback 段（2026-10 提取）          */
/*                                                  */
/*  活代码：FsPreSetInformationNotifyCallback 检测流水线（分派/    */
/*    自保护/敏感文件/硬链接/卷影/速率/评分），由     */
/*    薄层回调表 IRP_MJ_SET_INFORMATION 直接引用      */
/*    （回调名保留，注册不变）。                     */
/*  依赖：FileScan/ProcessFileContext/USBDeviceControl */
/*    /FileBackupEngine/PostCreateContext/Exempts/    */
/*    ThreatScoring（均经公共头 Include\FileSystem.h）*/
/*                                                  */
/*  事件上送原语 FspSendFileEvent 保留在薄层（去      */
/*    static，公共头声明）：PreWrite/PreCreate 共用   */
/*    事件上送层语义（WKD_FS_FILE_FLAG_* 已上移公共   */
/*    头）。备份目录豁免 FspIsBackupDirPath 随本模块  */
/*    迁入（PreWrite 经公共头调用，方向薄层→能力）。  */
/**************************************************/

#include "FileSystem.h"                /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */
#include "../Notification/NotificationManager.h"   /* WKD_FLT_OP_* 操作类型 */
#include "../AnalysisEngine/AnalysisEngine.h"      /* AeReportIndicatorPair 评分上报（声明位于 AnalysisEngine.h） */
#include "../Common/Exempts/Exempts.h"             /* ExemptsIsProcessTrusted 可信进程豁免 */
#include "../ThreatScoring/ThreatScoring.h"        /* TsIndicator_* / TsSourceIOC 指示枚举 */

/**************************************************/
/*            FspIsBackupDirPath（FBE 递归豁免）    */
/**************************************************/

/*++
 * FspIsBackupDirPath
 *   检查路径是否位于 WkdBackup 备份目录内（大小写不敏感子串匹配）。
 *   用于防 FBE 备份 I/O 递归：备份文件自身写入（FbepCopyFileToBackup 写
 *   .bak）会重入 PreWrite/PreSetInfo，若无此豁免将无限递归。
 *   【迁移】原薄层 static 辅助；薄层 PreWrite 与本模块共用，
 *   声明已入公共头 Include\FileSystem.h（薄层→能力模块方向）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
FspIsBackupDirPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT len;
    USHORT patLen;
    USHORT i;
    USHORT j;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }
    len = FileName->Length / sizeof(WCHAR);
    patLen = (USHORT)(sizeof(FBE_BACKUP_DIR_NAME) / sizeof(WCHAR) - 1);

    if (len < patLen) {
        return FALSE;
    }

    for (i = 0; i <= len - patLen; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < patLen; j++) {
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

/**************************************************/
/*       SetInformation 前置回调（强信号阻断 + 上送）*/
/**************************************************/

/* 提取 Rename/Link 目标路径的最大缓冲（PSI_MAX_RENAME_BUFFER_SIZE） */
#define WKD_FS_MAX_RENAME_BUFFER_SIZE  65535

/*++
 * FsPreSetInformationNotifyCallback
 *   删除/重命名/硬链接/截断/属性 的 CoW 备份 + 强信号阻断 + 事件上送
 *   （勒索回滚能力 + T1003.003 凭据硬链接 + T1485 截断 + T1070.006 属性）。
 *   强信号（自保护/敏感文件/凭据硬链接）内核无条件阻断；勒索弱信号评分
 *   归 ProcessFileContext（2026-09 接线，Rename/Delete/Truncate 入槽）。
 *   【迁移】2026-10 自薄层 Callbacks\FileSystemNotification.c 提取，
 *   static 去除（声明入公共头），回调表 IRP_MJ_SET_INFORMATION 引用不变。
 *--*/
_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
FsPreSetInformationNotifyCallback(
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

    /* 内核模式操作信任放行（PreSetInfo.c KernelMode 跳过） */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 分页 I/O 跳过：SetInformation 的 EOF 更新等缓存管理器分页写路径必须放行，
     * 否则 boot 期内存压力下死锁（PreSetInfo.c L908-928）。 */
    if (Data->Iopb != NULL &&
        (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
         FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* USB 设备控制（迁移 2026-08 接线）：只读卷 rename/delete 阻断（T1052.001）。
     * fail-safe：UDC 未初始化/禁用 → WkdUdcIsSetInfoBlocked 返回 FALSE（放行）。 */
    //if (WkdUdcIsSetInfoBlocked(FltObjects)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender/FS] BLOCKED set-info on read-only volume (PID=%lu)\n",
    //        HandleToULong(PsGetCurrentProcessId()));
    //    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    //    Data->IoStatus.Information = 0;
    //    return FLT_PREOP_COMPLETE;
    //}

    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
    /* ---- 文件删除 ---- */
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        /* FSC-3：DeleteFile=FALSE 是清除删除标记（undelete），非真实删除——
         * 不计删除数/不备份/不阻断，防把 undelete 当删除导致勒索误报。 */
        if (!FspIsConfirmedDeletion(Data)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        opType = WKD_FLT_OP_DELETE;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
        opType = WKD_FLT_OP_RENAME;
        break;
    case FileLinkInformation:
    case FileLinkInformationEx:
        opType = WKD_FLT_OP_HARDLINK;
        break;
    /* ---- 设置文件的逻辑结尾（EOF），即改变文件的实际大小 ---- */
    case FileEndOfFileInformation:
    /* ---- 设置文件的分配大小（Allocation Size），即文件在磁盘上预占用的空间 ---- */
    case FileAllocationInformation:
    /* ---- 设置文件的有效数据长度（Valid Data Length, VDL）---- */
    case FileValidDataLengthInformation:
        /* 截断：仅监控不备份，上送 OperationType=3（T1485） */
        opType = WKD_FLT_OP_TRUNCATE;
        break;

    /* ---- 属性/时间戳变更（T1070.006）：监控上送，不阻断 ---- */
    case FileBasicInformation:
    /* ---- 短名操作（T1564.001）：归属性类监控上送 ---- */
    case FileShortNameInformation:
        opType = WKD_FLT_OP_ATTRIBUTE;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* boot 期跳过（ShadowFsIsBootPhase，PreWrite 同款判断） */
    //if (WkdFspIsBootPhase()) {
    //    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    //}

    reqPid = PsGetCurrentProcessId();

    /* 进程排除（FileScan）：用户配置排除进程跳过检测（当前空表，返回 FALSE） */
    if (WkdFsIsProcessExcluded(reqPid)) {
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

    /* 路径排除（FileScan）：用户配置排除路径跳过检测（当前空表，返回 FALSE） */
    if (WkdFsIsPathExcluded(&nameInfo->Name)) {
        goto CleanupOperation;
    }

    /* Rename/Link 提取目标路径（FileScan），供自保护目标检查/敏感 rename 目标
     * 检查/ProcessFileContext 扩展名变更评分复用。 */
    if (opType == WKD_FLT_OP_RENAME || opType == WKD_FLT_OP_HARDLINK) {
        status = WkdFsGetRenameDestination(
            Data,
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass,
            &newFileName);
        if (NT_SUCCESS(status) && newFileName.Buffer != NULL && newFileName.Length > 0) {
            newFileNameAllocated = TRUE;
        }
    }

    /* ========================================================================
     * 自保护（强信号，无条件阻断）：EDR 自身文件被删除/重命名/建硬链接
     * （T1562.001）。源 + rename 目标双查（防"无害文件改名到受保护路径"
     * 绕过）。豁免可信进程 + 备份目录（防 FBE 递归）。
     * ==================================================================== */
    if (opType == WKD_FLT_OP_DELETE || opType == WKD_FLT_OP_RENAME ||
        opType == WKD_FLT_OP_HARDLINK) {
        if (!FspIsBackupDirPath(&nameInfo->Name) &&
            WkdFsShouldBlockFileAccess(&nameInfo->Name, 0, reqPid, TRUE)) {
            goto BlockOperation;
        }
        if (newFileNameAllocated &&
            !FspIsBackupDirPath(&newFileName) &&
            WkdFsShouldBlockFileAccess(&newFileName, 0, reqPid, TRUE)) {
            goto BlockOperation;
        }
    }

    /* ========================================================================
     * 敏感系统文件保护（强信号，无条件阻断，FileScan）：SAM/注册表 hive/关键
     * exe/drivers/Boot/EFI/bootmgr/NTFS 元数据的删除/重命名。
     * 补漏：rename 目标路径二次检查（防"改名到受保护路径"）。
     * 豁免可信进程防系统正常维护（磁盘清理/更新）误阻断。
     * ==================================================================== */
    if (WkdFsIsSensitiveSystemFile(&nameInfo->Name,
                                   &blockDelete, &blockRename, &blockHardLink)) {
        BOOLEAN shouldBlock = FALSE;

        switch (opType) {
        case WKD_FLT_OP_DELETE:
            shouldBlock = blockDelete;
            break;
        case WKD_FLT_OP_RENAME:
            shouldBlock = blockRename;
            break;
        default:
            break;
        }

        if (shouldBlock && !ExemptsIsProcessTrusted(reqPid)) {
            goto BlockOperation;
        }
    }
    if (opType == WKD_FLT_OP_RENAME && newFileNameAllocated) {
        BOOLEAN d2 = FALSE, r2 = FALSE, h2 = FALSE;

        if (WkdFsIsSensitiveSystemFile(&newFileName, &d2, &r2, &h2) &&
            r2 && !ExemptsIsProcessTrusted(reqPid)) {
            goto BlockOperation;
        }
    }

    /* ========================================================================
     * 凭据硬链接阻断（强信号，无条件阻断）：对 SAM/SECURITY/SYSTEM/SOFTWARE/
     * DEFAULT 建硬链接（T1003.003）。命中 → 计数 + 评分上报 + 阻断；豁免可信进程。
     * ==================================================================== */
    if (opType == WKD_FLT_OP_HARDLINK) {
        if (FspIsHardlinkSensitivePath(&nameInfo->Name) &&
            !ExemptsIsProcessTrusted(reqPid)) {
            WkdFsTrackFileOperation(reqPid, WKD_FLT_OP_HARDLINK);
            AeReportIndicatorPair(reqPid, reqPid, TsSourceIOC,
                                  TsIndicator_File_HardLink, AeThreatSeverityCritical);
            goto BlockOperation;
        }
    }

    /* ========================================================================
     * 卷影副本删除检测（T1490）：\System Volume Information\ 或 @GMT- 路径
     * 删除 → 上送 shadow 事件 + 评分上报，agent IoaRansomware_UpdateScore +40。
     * ==================================================================== */
    if (opType == WKD_FLT_OP_DELETE && FspIsVolumeShadowCopyPath(&nameInfo->Name)) {
        if (!FspIsBackupDirPath(&nameInfo->Name)) {
            FspSendFileEvent(WKD_FLT_OP_DELETE, &nameInfo->Name, 0, 0,
                             WKD_FS_FILE_FLAG_SHADOW_DELETE, -1, 0, 0);
            AeReportIndicatorPair(reqPid, reqPid, TsSourceIOC,
                                  TsIndicator_File_ShadowDelete, AeThreatSeverityCritical);
        }
        goto CleanupOperation;
    }

    /* ========================================================================
     * 勒索窗口计数（FileScan）：1s 窗口 Rename/Delete 速率超阈值 → RAPID_RATE
     * 提升上送优先级；Truncate/HardLink/Attribute 仅计数（不参与速率阻断）。
     * ==================================================================== */
    {
        BOOLEAN rateSuspicious = WkdFsTrackFileOperation(reqPid, opType);
        ULONG setInfoFlags = rateSuspicious ? WKD_FS_FILE_FLAG_RAPID_RATE : 0;

        if (!FspIsBackupDirPath(&nameInfo->Name)) {
            if (opType == WKD_FLT_OP_DELETE || opType == WKD_FLT_OP_RENAME) {
                /* Delete/Rename：FBE CoW 备份（勒索回滚）+ 事件上送 */
                status = FbePreSetInfoBackup(Data, FltObjects, &nameInfo->Name,
                                             (FBE_OPERATION_TYPE)opType);
                if (status != STATUS_FBE_SKIP) {
                    FspSendFileEvent(opType, &nameInfo->Name, 0, 0,
                                     setInfoFlags, -1, 0, 0);
                }
            } else {
                /* Truncate/HardLink/Attribute：仅监控上送不备份（语义） */
                FspSendFileEvent(opType, &nameInfo->Name, 0, 0,
                                 setInfoFlags, -1, 0, 0);
            }
        }
    }

    /* 勒索行为评分（ProcessFileContext，2026-09 接线）：Rename/Delete/Truncate
     * 入槽（boot 期已跳过；KernelMode 已在函数头放行；FBE 备份 I/O 为
     * KernelMode 天然豁免）。扩展名变更比较在 ProcessFileContext 内部完成。 */
    if (opType == WKD_FLT_OP_RENAME) {
        WkdPfcpNotifyFileOperation(reqPid, WkdPfcpOp_Rename, &nameInfo->Name,
                                   newFileNameAllocated ? &newFileName : NULL);
    } else if (opType == WKD_FLT_OP_DELETE) {
        WkdPfcpNotifyFileOperation(reqPid, WkdPfcpOp_Delete, &nameInfo->Name, NULL);
    } else if (opType == WKD_FLT_OP_TRUNCATE) {
        WkdPfcpNotifyFileOperation(reqPid, WkdPfcpOp_Truncate, &nameInfo->Name, NULL);
    }

    /* verdict 失效（PostCreate 迁移 2026-09）：内容变更操作（Delete/Rename/
     * Truncate）→ 失效缓存（HardLink/Attribute 不改内容，verdict 仍有效）。
     * 置于评分之后、CleanupOperation 之前——BlockOperation 已 goto 跳过。
     * PreSetInfo.c 中 PocInvalidateFileVerdict 调用点。 */
    if (opType == WKD_FLT_OP_DELETE ||
        opType == WKD_FLT_OP_RENAME ||
        opType == WKD_FLT_OP_TRUNCATE) {
        WkdPocInvalidateFileVerdict(FltObjects);
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
 * 路径判定辅助（迁移自 FileScan.c，2026-10）
 *   FspIsVolumeShadowCopyPath / FspIsHardlinkSensitivePath 原实现位于
 *   FileSystem\FileScan.c，随 PreSetInformation 流水线提取一并迁入本模块
 *   （WkdFsIsSensitiveSystemFile 迁往 FileSystem.c，本模块经公共头调用）。
 *   依赖的通用包含匹配（原 WkdFsContainsStrInsensitive）因 FileScan.c 仍
 *   使用而保留原位；此处以私有静态实现避免跨模块耦合。
 * ========================================================================== */

/* 通用大小写不敏感包含匹配（ASCII 折叠，DISPATCH_LEVEL 安全）。
 * 私有副本：原 FileScan.c WkdFsContainsStrInsensitive。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
FspContainsStrInsensitive(
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

/* 卷影副本路径判定（T1490，迁移 SS PreSetInfo/PostWrite 敏感表 SHADOW_COPY 类）
 *   包含 \System Volume Information\ 或 @GMT-（VSS 快照视图/DFS 历史）命中。
 *   命中且为删除操作 → 上送 shadow 事件（WkdMessage_FileShadowCopyDelete），
 *   agent IoaRansomware_UpdateScore WKD_EVT_SHADOW_COPY_DELETE 分支 +40。 */
_Use_decl_annotations_
BOOLEAN
FspIsVolumeShadowCopyPath(
    PCUNICODE_STRING FileName
    )
{
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    return FspContainsStrInsensitive(FileName, L"\\System Volume Information\\") ||
           FspContainsStrInsensitive(FileName, L"@GMT-");
}

/* 硬链接目标是否为敏感路径（T1003.003）：SAM/SECURITY/SYSTEM/SOFTWARE/DEFAULT
 * 建硬链接 → 阻断。依赖 WkdFsIsSensitiveSystemFile 的 BlockHardLink 输出位
 * （敏感表已随迁 FileSystem.c，本声明经公共头）。 */
_Use_decl_annotations_
BOOLEAN
FspIsHardlinkSensitivePath(
    PCUNICODE_STRING FileName
    )
{
    BOOLEAN blockDelete = FALSE;
    BOOLEAN blockRename = FALSE;
    BOOLEAN blockHardLink = FALSE;

    if (WkdFsIsSensitiveSystemFile(FileName, &blockDelete, &blockRename, &blockHardLink)) {
        return blockHardLink;
    }
    return FALSE;
}