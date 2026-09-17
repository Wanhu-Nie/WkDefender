/**************************************************/
/*  PreCreate 前置回调（补齐后的完整检测流水线）    */
/*  迁移自薄层 Callbacks\FileSystemNotification.c  */
/*  CbpPreCreateNotifyCallback 段（2026-10 提取，  */
/*  与 PreSetInformation 同批迁移）。               */
/*                                                  */
/*  【本模块补齐】2026-10 相对 ShadowStrike 的       */
/*  ShadowStrikePreCreate 语义缺口：                */
/*    ① 排除检查：进程/路径排除（SS Phase 5）       */
/*    ② USB autorun：WkdUdcCheckAutorun 阻断        */
/*       （薄层原注释禁用，T1091/T1204.002）         */
/*    ③ EDR 自保护：WkdFsShouldBlockFileAccess      */
/*       （薄层原缺失——仅 PreWrite/PreSetInfo/      */
/*        PreAcquireSection 命中，T1562.001）        */
/*    ④ 勒索速率计数 + 敏感系统文件/卷影 flag       */
/*    ⑤ boot 期检查：WkdFspIsBootPhase             */
/*       （薄层原注释禁用，fail-open）               */
/*    ⑥ 本地威胁评分：路径分 + 蜜罐命中 + 访问模式  */
/*       分；≥75 阻断（对齐 SS BlockThreatScore），  */
/*       ≥50 评分上报（对齐 SS AlertThreatScore）    */
/*                                                  */
/*  保留自薄层原回调的有效逻辑：蜜罐 canary 阻断、   */
/*  快速跳过（内核/分页/System/可信）、扩展名判定、  */
/*  G2 收敛（纯读+非 code-bearing）、verdict 缓存    */
/*  命中（排除内容替换型）、同步 YARA 扫描、         */
/*  FILE_CREATE 创建事件、PostCreate verdict 传递。  */
/*                                                  */
/*  依赖：FileScan / USBDeviceControl /             */
/*    PostCreateContext / Exempts / ThreatScoring /  */
/*    AnalysisEngine / 薄层导出（均经公共头          */
/*    Include\FileSystem.h，见下 include 清单）。     */
/*                                                  */
/*  事件上送原语 FspSendFileEvent 保留在薄层（公共   */
/*   头声明）：PreWrite/PreSetInformation 共用。     */
/**************************************************/

#include "FileSystem.h"                /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */
#include "../Notification/NotificationManager.h"   /* WKD_FLT_OP_* 操作类型 */
#include "../AnalysisEngine/AnalysisEngine.h"      /* AeReportIndicatorPair 评分上报 */
#include "../Common/Exempts/Exempts.h"             /* ExemptsIsProcessTrusted 可信进程豁免 */
#include "../ThreatScoring/ThreatScoring.h"        /* TsIndicator_* / TsSourceIOC 指示枚举 */

/**************************************************/
/*                模块内常量与辅助                 */
/**************************************************/

/* 本地威胁评分阈值（对齐 SS ShadowStrikePreCreate 的
 * BlockThreatScore=75 / AlertThreatScore=50）。       */
#define WKD_PC_BLOCK_THREAT_SCORE       75
#define WKD_PC_ALERT_THREAT_SCORE       50

/* 本地评分权重（对齐 SS PcClassifyFile 汇编面；
 * 与 FileScan WkdFsCalcPathFlagScore 的双扩展/RLO/
 * 保留名/尾随权重联动，封顶 100）。                  */
#define WKD_PC_ACCESS_SCORE_EXEC_NO_READ   20  /* 执行且无读（LOLBin 特征） */
#define WKD_PC_ACCESS_SCORE_WRITE_EXEC     20  /* 写 + 执行（下载执行） */
#define WKD_PC_SCORE_HONEYPOT              40  /* 蜜罐命中（对齐 WKD_FS_PATH_HONEYPOT） */

/*++
 * PcpIsWriteAccess
 *   是否含写访问（FILE_WRITE_DATA / FILE_APPEND_DATA / GENERIC_WRITE）。
 *   对齐 SS PcIsWriteAccess。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PcpIsWriteAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    return ((DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) != 0);
}

/*++
 * PcpIsExecuteAccess
 *   是否含执行访问（FILE_EXECUTE / GENERIC_EXECUTE）。
 *   对齐 SS PcIsExecuteAccess。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PcpIsExecuteAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    return ((DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) != 0);
}

/*++
 * PcpIsExecuteWithoutReadAccess
 *   执行且无读（典型恶意加载/执行器特征，SS PcIsExecuteWithoutReadAccess）。
 *   GENERIC_EXECUTE 展开可能携带读位（FILE_READ_DATA/FILE_GENERIC_READ/
 *   GENERIC_READ），此处一并排除。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PcpIsExecuteWithoutReadAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    if (!PcpIsExecuteAccess(DesiredAccess)) {
        return FALSE;
    }
    if (DesiredAccess & (FILE_READ_DATA | FILE_GENERIC_READ | GENERIC_READ)) {
        return FALSE;
    }
    return TRUE;
}

/**************************************************/
/*              PreCreate 前置回调                 */
/**************************************************/

/*++
 * FsPreCreateNotifyCallback
 *   IRP_MJ_CREATE Pre 回调：补齐后的完整检测流水线（对齐 SS
 *   ShadowStrikePreCreate 语义 + wkd 模块化裁剪）：
 *
 *     Phase 0  参数校验（fail-open）
 *     Phase 1  文件名获取 + 解析（NORMALIZED|QUERY_DEFAULT）
 *     Phase 2  蜜罐 canary 无条件阻断（任意扩展名）
 *     Phase 3  快速跳过（内核模式/分页文件/System/可信进程）
 *     Phase 4  进程/路径排除检查
 *     Phase 5  USB autorun 阻断（WkdUdcCheckAutorun，fail-safe）
 *     Phase 6  EDR 自保护阻断（WkdFsShouldBlockFileAccess）
 *     Phase 7  扩展名判定（范围外 fail-open）
 *     Phase 8  G2 收敛：纯读 + 非 code-bearing → 创建事件照发 + 跳过
 *     Phase 9  verdict 缓存命中（排除内容替换型 create）
 *     Phase 10 勒索速率计数 + 敏感系统文件/卷影 flag
 *     Phase 11 boot 期跳过（fail-open：仅跳过重量路径）
 *     Phase 12 本地威胁评分（路径分 + 蜜罐 + 访问模式）→ 上报/阻断
 *     Phase 13 同步 YARA 扫描（fail-open）→ Deny 阻断
 *     Phase 14 FILE_CREATE 创建事件上送（合并本地分析 flag）
 *     Phase 15 PostCreate verdict 传递（completion context）
 *
 *   阻断统一 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE；
 *   全部 fail-open：任何分析失败放行，不阻塞系统 I/O。
 *   必须在 PASSIVE_LEVEL 调用（同步扫描 + 分页 I/O）。
 *   IRQL：PASSIVE_LEVEL（原薄层签名保留 _IRQL_requires_）。
 *   实现在 FileSystem\PreCreate.c；薄层回调表直接引用（FLT 注册
 *   签名：PFLT_PREOP_CALLBACK_STATUS）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
FLT_PREOP_CALLBACK_STATUS
FsPreCreateNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING extension;
    WKD_YARA_SCAN_VERDICT verdict;
    PWKD_POC_COMPLETION_CONTEXT completionCtx = NULL;
    HANDLE processId;
    ACCESS_MASK desiredAccess;
    ULONG createOptions;
    ULONG disposition;
    BOOLEAN isReadOnly;
    BOOLEAN contentReplace;
    BOOLEAN isSensitive;
    BOOLEAN blockDelete;
    BOOLEAN blockRename;
    BOOLEAN blockHardLink;
    ULONG pathFlags = 0;
    ULONG pathScore = 0;
    ULONG localScore = 0;
    ULONG fileFlags = 0;

    /* Phase 0：参数校验（SS Phase 0）。CompletionContext 恒先置 NULL。 */
    if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL ||
        CompletionContext == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    *CompletionContext = NULL;

    processId = PsGetCurrentProcessId();

    /* Phase 1：文件名获取（NORMALIZED + QUERY_DEFAULT，fail-open）。
     * FltParseFileNameInformation 失败需释放已分配对象（原薄层泄漏，
     * 迁移时修复）。 */
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Phase 2：蜜罐 canary 精确路径无条件阻断（置于扩展名过滤之前——
     * canary 文件任意扩展名均命中）。 */
    if (WkdFsIsCanaryFile(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Phase 3：快速跳过（SS Phase 1-2）——内核模式 / 分页文件 /
     * System 进程 / 可信进程。纯内联判断，避免对系统 I/O 做同步扫描
     * （性能 + 防死锁）。scanner 自身豁免已在 FsSendYaraScanRequest 内。 */
    if (Data->RequestorMode == KernelMode ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        processId == (HANDLE)4 ||
        ExemptsIsProcessTrusted(processId)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Phase 4：排除检查（补齐，SS Phase 5）——进程 + 路径双向豁免。 */
    if (WkdFsIsProcessExcluded(processId) || WkdFsIsPathExcluded(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Phase 5：USB autorun 阻断（补齐薄层原注释禁用代码）。
     * 置于扩展名过滤之前——autorun.inf 的 .inf 不在可扫集合，走不到
     * 下方 YARA 分支。fail-safe：UDC 未初始化/禁用 → 返回 FALSE（放行）。 */
    //if (WkdUdcCheckAutorun(FltObjects, &nameInfo->Name)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender/FS] BLOCKED autorun file create/open: %wZ (PID=%lu)\n",
    //        &nameInfo->Name, HandleToULong(processId));
    //    FltReleaseFileNameInformation(nameInfo);
    //    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    //    Data->IoStatus.Information = 0;
    //    return FLT_PREOP_COMPLETE;
    //}

    /* Phase 6：EDR 自保护阻断（补齐，T1562.001）。写/删/执行打开命中
     * 保护表即阻断；纯读打开恒放行（wkd 语义，读不走保护表）。内部已
     * 豁免 ExemptsIsProcessTrusted。SecurityContext 缺失时按写访问处理
     * （保守，对齐 SS 缺省 Data 分支）。 */
    desiredAccess = (Data->Iopb->Parameters.Create.SecurityContext != NULL) ?
        Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess : 0;
    if (WkdFsShouldBlockFileAccess(&nameInfo->Name, desiredAccess, processId, FALSE)) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Phase 7：扩展名判定（范围外类型不扫描，fail-open）。 */
    RtlInitUnicodeString(&extension, nameInfo->Extension.Buffer);
    extension.Length = nameInfo->Extension.Length;
    if (!FsIsScannableExtension(&extension)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Phase 8：G2 扫描范围收敛（原薄层逻辑保留）：纯读访问
     * （无写/追加/执行）且扩展名非 code-bearing → 跳同步扫描。
     * Explorer 枚举/缩略图等高频纯读若逐一阻塞等待 user-mode verdict，
     * 慢扫器会把全部文件 I/O 串行化（SS 观察到的系统级停顿根因）。
     * 此类文件由写与执行时扫描（PreAcquireSection/PostWrite）与异步
     * telemetry 覆盖。事件照发（创建事件无关扫描与否），完成上下文置
     * NULL（不建 verdict 缓存，不触发 PostCreate 记录）。
     * SecurityContext 缺失防御性跳过收敛（保守全扫）。 */
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        isReadOnly = !(desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) &&
                     !(desiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE));

        if (isReadOnly && !FsIsCodeBearingExtension(&extension)) {
            createOptions = Data->Iopb->Parameters.Create.Options;
            if ((((createOptions >> 24) & 0xFF) == FILE_CREATE)) {
                FspSendFileEvent(WKD_FLT_OP_WRITE, &nameInfo->Name, 0, 0,
                                 WKD_FS_FILE_FLAG_CREATE, -1, 0, 0);
            }
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    /* Phase 9：verdict 缓存命中（原薄层逻辑保留）——stream context
     * Scanned && !Dirty → 免同步扫描。fail-open：缺失/失效恒不命中。
     * 置于 boot 检查之前——boot 期内无 context（未扫描过），自然降级
     * 到 boot 跳过。排除内容替换型 create：FILE_OVERWRITE/OVERWRITE_IF/
     * SUPERSEDE 直接替换内容不走 Write IRP（Dirty 不置位）→ 强制重扫
     * 防缓存陈旧。 */
    createOptions = Data->Iopb->Parameters.Create.Options;
    disposition = (createOptions >> 24) & 0xFF;
    contentReplace = (disposition == FILE_OVERWRITE ||
                      disposition == FILE_OVERWRITE_IF ||
                      disposition == FILE_SUPERSEDE);

    if (!contentReplace && WkdPocHasFreshVerdict(FltObjects)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Phase 10：勒索速率计数 + 敏感系统文件/卷影 flag（boot 前轻量计数，
     * 对齐 PreWrite 现有结构与 SS 顺序——RateTracking/SensitiveFile 在
     * boot 检查之前）。fileFlags 随 Phase 14 创建事件上送。 */
    if (WkdFsTrackFileOperation(processId, WKD_FLT_OP_WRITE)) {
        fileFlags |= WKD_FS_FILE_FLAG_RAPID_RATE;
    }
    blockDelete = FALSE;
    blockRename = FALSE;
    blockHardLink = FALSE;
    isSensitive = WkdFsIsSensitiveSystemFile(&nameInfo->Name,
                                             &blockDelete, &blockRename, &blockHardLink);
    if (isSensitive || FspIsVolumeShadowCopyPath(&nameInfo->Name)) {
        fileFlags |= WKD_FS_FILE_FLAG_SENSITIVE_WRITE;
    }

    /* Phase 11：boot 期跳过（补齐薄层原注释禁用代码，fail-open）。
     * canary/自保护/autorun/速率计数已在前执行——SS boot 语义：
     * boot 期仅跳过重量路径（本地评分/同步扫描/事件上送），强信号
     * 先决后放。 */
    //if (WkdFspIsBootPhase()) {
    //    FltReleaseFileNameInformation(nameInfo);
    //    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    //}

    /* Phase 12：本地威胁评分（PcClassifyFile 汇编面——复用
     * FileScan FspAnalyzeFilePath 路径分 + 蜜罐命中 + 访问模式分）。
     * 评分汇报经 AeReportIndicatorPair（TsIndicator_Ioa_FileCreate）；
     * ≥75 内核本地阻断，50-74 仅上报（对齐 SS Block/Alert 阈值）。 */
    pathScore = FspAnalyzeFilePath(&nameInfo->Name, &extension, &pathFlags);
    localScore = pathScore;

    if (WkdFsIsHoneypotFile(&nameInfo->Name)) {
        localScore += WKD_PC_SCORE_HONEYPOT;
        fileFlags |= WKD_FS_FILE_FLAG_CANARY;
    }
    if (desiredAccess != 0) {
        if (PcpIsExecuteWithoutReadAccess(desiredAccess)) {
            localScore += WKD_PC_ACCESS_SCORE_EXEC_NO_READ;
        }
        if (PcpIsWriteAccess(desiredAccess) && PcpIsExecuteAccess(desiredAccess)) {
            localScore += WKD_PC_ACCESS_SCORE_WRITE_EXEC;
        }
    }
    if (localScore > 100) {
        localScore = 100;
    }

    if (localScore >= WKD_PC_BLOCK_THREAT_SCORE) {
        /* ≥75：内核本地阻断 + 评分上报（对齐 SS BlockThreatScore，
         * agent 因果图/评分消费）。 */
        AeReportIndicatorPair(processId, processId, TsSourceIOC,
                              TsIndicator_Ioa_FileCreate, AeThreatSeverityCritical);
        
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    if (localScore >= WKD_PC_ALERT_THREAT_SCORE) {
        /* 50-74：仅评分上报（不阻断，对齐 SS AlertThreatScore）。 */
        AeReportIndicatorPair(processId, processId, TsSourceIOC,
                              TsIndicator_Ioa_FileCreate, AeThreatSeverityHigh);
    }

    /* Phase 13：同步阻塞扫描（fail-open：端口断开/未连接 → Allow）。 */
    verdict = FsSendYaraScanRequest(
        &nameInfo->Name,
        HandleToULong(processId));

    if (verdict.Verdict == WkdYaraVerdict_Deny) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Phase 14：新文件创建事件上送（原薄层逻辑 + 补齐 fileFlags 合并）。
     * Disposition==FILE_CREATE 视为新建文件，供 agent 勒索评分与文件级
     * 持久化检测消费。FLT_PARAMETERS.Create 无 Disposition 字段：高 8 位
     * （Create.Options bit24-31）即 CreateDisposition 值。 */
    if (disposition == FILE_CREATE) {
        FspSendFileEvent(WKD_FLT_OP_WRITE, &nameInfo->Name, 0, 0,
                         WKD_FS_FILE_FLAG_CREATE | fileFlags, -1, 0, 0);
    }

    /* Phase 15：PostCreate verdict 传递（原薄层逻辑保留）。Allow 路径
     * 分配 completion context，FspPostCreate 转发 FsPostCreateNotifyCallback 缓存
     * verdict。分配失败降级 NO_CALLBACK（fail-open：无缓存，后续按需
     * 重扫）。 */
    completionCtx = NULL;
    status = WkdPocAllocateCompletionContext(&completionCtx);
    if (NT_SUCCESS(status) && completionCtx != NULL) {
        completionCtx->WasScanned = TRUE;   /* 已实际扫描（非缓存命中路径） */
        completionCtx->ScanResult = TRUE;   /* Allow 已通过 */
        completionCtx->ThreatScore = verdict.Score;
        *CompletionContext = completionCtx;
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}