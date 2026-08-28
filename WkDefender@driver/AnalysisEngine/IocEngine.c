/**************************************************/
/*  WkDefender — IOC 引擎实现                      */
/*                                                   */
/*  威胁程度映射表 + 命令行/LOLBin/签名检测函数      */
/**************************************************/

#include "IocEngine.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR 完整定义 */
#include "../Process/ProcessMonitor.h"
#include "../ThreatScoring/ThreatScoring.h"
#include "../Common/Utils.h"

//
// 池标签
//
#define POOL_TAG_IOC_CONTEXT    'iocC'

/**************************************************/
/*           IocEngine 内部状态（B2 修复）          */
/*                                                  */
/*  对称 IoaEngine（WkdIoaEngine.RundownRef）/      */
/*  TS_ENGINE.Rundown：引擎级 Rundown 保护。        */
/*  IocAllocateProcessPairContext 获取引用，         */
/*  IocFreeProcessPairContext 释放引用，            */
/*  IocCleanup 等待全部释放后返回。                 */
/**************************************************/

static struct {
    BOOLEAN Initialized;
    EX_RUNDOWN_REF RundownRef;
} WkdIocEngine = { 0 };

/**************************************************/
/*       威胁程度映射表 — 指标 → 默认威胁程度        */
/*                                                   */
/*  归分析引擎所有（IOC 侧）。评分系统不查本表。      */
/*  分级参考旧 DefaultScore 量纲:                    */
/*    ≤0 → None(0) / 1-20 → Low(1) / 21-50 →        */
/*    Medium(2) / 51-79 → High(3) / ≥80 → Critical(4) */
/**************************************************/

static const struct {
    TS_INDICATOR_TYPE Indicator;
    UCHAR Severity;                     /* AE_THREAT_SEVERITY 0-4 */
} G_IocSeverityMap[] = {

    /* ── 进程创建与分析（0x01xx） ── */
    { TsIndicator_Process_Elevated,             AeThreatSeverityLow },
    { TsIndicator_Process_SeDebugPrivilege,     AeThreatSeverityLow },
    { TsIndicator_Process_SeImpersonatePrivilege, AeThreatSeverityLow },
    { TsIndicator_Process_SeTcbPrivilege,       AeThreatSeverityMedium },
    { TsIndicator_Process_CrossSession,         AeThreatSeverityMedium },
    { TsIndicator_Process_PpidSpoofing,         AeThreatSeverityMedium },
    { TsIndicator_Process_DeepPpidSpoofing,     AeThreatSeverityHigh },
    { TsIndicator_Process_SuspiciousAncestry,   AeThreatSeverityMedium },
    { TsIndicator_Process_MissingMitigations,   AeThreatSeverityLow },

    /* ── 命令行检测（0x02xx） ── */
    { TsIndicator_CmdLine_LOLBin,               AeThreatSeverityLow },
    { TsIndicator_CmdLine_EncodedCommand,       AeThreatSeverityMedium },
    { TsIndicator_CmdLine_SuspiciousPowerShell, AeThreatSeverityMedium },
    { TsIndicator_CmdLine_DownloadCradle,       AeThreatSeverityMedium },
    { TsIndicator_CmdLine_ReflectionLoad,       AeThreatSeverityMedium },
    { TsIndicator_CmdLine_ClipboardAbuse,       AeThreatSeverityMedium },
    { TsIndicator_CmdLine_Obfuscation,          AeThreatSeverityMedium },
    { TsIndicator_CmdLine_HiddenWindow,         AeThreatSeverityLow },
    { TsIndicator_CmdLine_RemoteExecution,      AeThreatSeverityMedium },
    { TsIndicator_CmdLine_SuspiciousPath,       AeThreatSeverityLow },
    { TsIndicator_CmdLine_ScriptExecution,      AeThreatSeverityMedium },

    /* ── 注入检测（0x03xx） ── */
    { TsIndicator_Injection_RemoteThread,       AeThreatSeverityHigh },
    { TsIndicator_Injection_CrossProcessThread, AeThreatSeverityCritical },
    { TsIndicator_Injection_ProcessHollowing,   AeThreatSeverityCritical },
    { TsIndicator_Injection_ThreadShellcode,    AeThreatSeverityCritical },
    { TsIndicator_Injection_ROPChain,           AeThreatSeverityHigh },
    { TsIndicator_Injection_HeapSpray,          AeThreatSeverityHigh },
    { TsIndicator_Injection_ReflectiveDll,      AeThreatSeverityCritical },

    /* ── 持久化（0x04xx） ── */
    { TsIndicator_Persistence_RegistryRunKey,   AeThreatSeverityHigh },
    { TsIndicator_Persistence_MultiTechnique,   AeThreatSeverityHigh },
    { TsIndicator_Persistence_RansomwarePrep,   AeThreatSeverityCritical },
    { TsIndicator_Persistence_ServiceInstall,   AeThreatSeverityHigh },

    /* ── 防御绕过（0x05xx） ── */
    { TsIndicator_Defense_DisableDefender,      AeThreatSeverityCritical },
    { TsIndicator_Defense_AppControlBlock,      AeThreatSeverityHigh },
    { TsIndicator_Defense_StackTampering,       AeThreatSeverityCritical },

    /* ── 网络（0x06xx） ── */
    { TsIndicator_Network_Beaconing,            AeThreatSeverityHigh },
    { TsIndicator_Network_DataExfiltration,     AeThreatSeverityHigh },
    { TsIndicator_Network_C2Communication,      AeThreatSeverityHigh },
    { TsIndicator_Network_PortScanning,         AeThreatSeverityHigh },
    { TsIndicator_Network_KnownC2IOC,           AeThreatSeverityCritical },
    { TsIndicator_Network_MaliciousJA3,         AeThreatSeverityCritical },
    { TsIndicator_Network_DGA,                  AeThreatSeverityMedium },
    { TsIndicator_Network_DnsTunnel,            AeThreatSeverityMedium },
    { TsIndicator_Network_SuspiciousHTTP,       AeThreatSeverityMedium },
    { TsIndicator_Network_NamedPipeC2,          AeThreatSeverityCritical },  // 命名管道 C2（NamedPipeMonitor 迁移 2026-08）
    { TsIndicator_Network_NamedPipeSpoof,       AeThreatSeverityCritical },  // 系统管道冒充 T1036
    { TsIndicator_Network_NamedPipeHighEntropy, AeThreatSeverityLow },       // 高熵随机管道名（仅上报）

    /* ── 信誉（0x07xx） ──（ValidSignature 为信任项，None 不落记录） */
    { TsIndicator_Reputation_ValidSignature,    AeThreatSeverityNone },
    { TsIndicator_Reputation_UnsignedBinary,    AeThreatSeverityLow },
    { TsIndicator_Reputation_UnsignedNoDEP,     AeThreatSeverityLow },
    { TsIndicator_Reputation_SoftwarePacking,   AeThreatSeverityMedium },

    /* ── 句柄/对象（0x08xx） ── */
    { TsIndicator_Handle_LsassAccess,           AeThreatSeverityCritical },
    { TsIndicator_Handle_ProcessTermination,    AeThreatSeverityHigh },
    { TsIndicator_Handle_ThreadHijack,          AeThreatSeverityHigh },

    /* ── 线程（0x09xx） ── */
    { TsIndicator_Thread_ShellcodeStart,        AeThreatSeverityCritical },
    { TsIndicator_Thread_SuspiciousStart,       AeThreatSeverityMedium },

    /* ── 映像加载（0x0Axx） ── */
    { TsIndicator_Image_SuspiciousLoad,         AeThreatSeverityHigh },
    { TsIndicator_Image_HollowingHeuristic,     AeThreatSeverityCritical },
    { TsIndicator_Image_SuspiciousPath,         AeThreatSeverityLow },
    { TsIndicator_Image_MasqueradingName,       AeThreatSeverityHigh },
    { TsIndicator_Image_TypoSquatting,          AeThreatSeverityMedium },
    { TsIndicator_Image_NetworkPath,            AeThreatSeverityMedium },
    { TsIndicator_Image_DoubleExtension,        AeThreatSeverityMedium },
    { TsIndicator_Image_PhantomDllUnbacked,     AeThreatSeverityCritical },
    { TsIndicator_Image_EntrypointOutsideCode,  AeThreatSeverityHigh },
    { TsIndicator_Image_NoExports,              AeThreatSeverityLow },

    /* ── 注册表（0x0Bxx） ── */
    { TsIndicator_Registry_SuspiciousMod,       AeThreatSeverityMedium },

    /* ── WSL/容器逃逸（0x0Cxx，迁移自 SS WSLMonitor） ── */
    { TsIndicator_Wsl_EscapeToHost,             AeThreatSeverityCritical },  // 对齐 SS 80 分
    { TsIndicator_Wsl_CredentialAccess,         AeThreatSeverityCritical },  // 对齐 SS 85 分
    { TsIndicator_Wsl_DriverAccess,             AeThreatSeverityHigh },      // 对齐 SS 60 分
    { TsIndicator_Wsl_System32Access,           AeThreatSeverityLow },       // SS 无分仅记录

    /* ── 文件行为（0x0Exx，FBE/PreSetInfo 迁移 2026-08）。
     *   修复 AeReportIndicatorPair severity=0 查表返回 0 静默丢弃缺陷；
     *   HardLink/ShadowDelete 已接线 FspPreSetInformation 强信号阻断上报。 ── */
    { TsIndicator_File_Write,                   AeThreatSeverityMedium },
    { TsIndicator_File_Rename,                  AeThreatSeverityLow },
    { TsIndicator_File_Delete,                  AeThreatSeverityMedium },
    { TsIndicator_File_Truncate,                AeThreatSeverityHigh },
    { TsIndicator_File_HighEntropy,             AeThreatSeverityMedium },
    { TsIndicator_File_RansomNote,              AeThreatSeverityHigh },
    { TsIndicator_File_MassModify,              AeThreatSeverityHigh },
    { TsIndicator_File_ShadowDelete,            AeThreatSeverityCritical },
    { TsIndicator_File_HardLink,                AeThreatSeverityCritical },
    { TsIndicator_File_AttributeChange,         AeThreatSeverityMedium },
    { TsIndicator_File_DataDestruction,         AeThreatSeverityCritical },

    /* ── 代码执行映射检测（0x0D26 起，PreAcquireSection 迁移 2026-08） ── */
    { TsIndicator_Ioa_SectionMapCrossProcess,   AeThreatSeverityCritical },
    { TsIndicator_Ioa_SectionMapExecutable,     AeThreatSeverityMedium },
    { TsIndicator_Ioa_SectionMapHollowing,      AeThreatSeverityCritical },
    { TsIndicator_Ioa_SectionMapReflective,     AeThreatSeverityCritical },
    { TsIndicator_Ioa_SectionMapRapid,          AeThreatSeverityMedium },
    { TsIndicator_Ioa_UnmapViewSection,         AeThreatSeverityHigh },

    /* ── Section 创建检测（0x0D2C 起，SectionTracker 迁移 2026-08） ── */
    { TsIndicator_Ioa_SectionExecuteAnonymous,  AeThreatSeverityCritical },  // SS 200
    { TsIndicator_Ioa_SectionLargeAnonymous,    AeThreatSeverityMedium },     // SS 80
    { TsIndicator_Ioa_SectionNoBackingFile,     AeThreatSeverityHigh },       // SS 180
    { TsIndicator_Ioa_SectionTransacted,        AeThreatSeverityCritical },   // SS 300（Doppelganging）
    { TsIndicator_Ioa_SectionDeleted,           AeThreatSeverityCritical },   // SS 250（Doppelganging 变体）
};

_Use_decl_annotations_
UCHAR
IocGetIndicatorSeverity(
    _In_ TS_INDICATOR_TYPE Indicator
    )
/*++
Routine Description:
    查指标默认威胁程度（线性扫描，51 项）。未命中返回 0。

Arguments:
    Indicator - 指标类型。

Return Value:
    AE_THREAT_SEVERITY (0-4)。
--*/
{
    for (ULONG i = 0; i < ARRAYSIZE(G_IocSeverityMap); i++) {
        if (G_IocSeverityMap[i].Indicator == Indicator) {
            return G_IocSeverityMap[i].Severity;
        }
    }
    return 0;
}


/**************************************************/
/*           初始化 / 清理                         */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocInitialize(
    VOID
    )
{
    ExInitializeRundownProtection(&WkdIocEngine.RundownRef);
    WkdIocEngine.Initialized = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocCleanup(
    VOID
    )
{
    if (!WkdIocEngine.Initialized) {
        return;
    }
    WkdIocEngine.Initialized = FALSE;

    /* 等待所有 IOC 上下文（IocAllocateProcessPairContext 获取的）释放 */
    ExWaitForRundownProtectionRelease(&WkdIocEngine.RundownRef);
}

/**************************************************/
/*        IOC 证据链 — 去重 + 销毁                   */
/**************************************************/

//
// IocIndicatorDedupLocked — 查重 + "新覆盖旧"。
// 持有 Pair->Lock 独占时调用（由 AeReportIndicatorEx 调用）。
// 命中：原地更新链内节点的 Severity/Timestamp，返回 TRUE
//       （调用方不得再上报评分系统）。
// 未命中：返回 FALSE。链满（ChainCount >= WKD_MAX_IOC_RECORDS）
//      时 FIFO 丢最旧再插入。
// 注意：FIFO 淘汰的指标从证据链消失，其后重复命中会按"新事实"
//      重新上报评分（IocScore 再累加一次）——上限 64 远超实际
//      指标数，正常不会触发。
//
_Use_decl_annotations_
BOOLEAN
IocIndicatorDedupLocked(
    _Inout_ PAE_IOC_CONTEXT IocContext,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ UCHAR Severity,
    _In_ LARGE_INTEGER Timestamp
    )
{
    PLIST_ENTRY entry;

    if (!IocContext || Indicator >= TsIndicator_MaxValue
        || !VALID_SEVERITY(Severity) || !Timestamp.QuadPart) {
        return FALSE;
    }

    /* 查重：同 Indicator 已存在 → 新覆盖旧 */
    for (entry = IocContext->IocChain.Flink;
         entry != &IocContext->IocChain;
         entry = entry->Flink) {

        PAE_IOC_RECORD record = CONTAINING_RECORD(entry, AE_IOC_RECORD, Link);
        if (record->Indicator == Indicator) {
            record->Severity = Severity;
            record->Timestamp = Timestamp;
            return TRUE;
        }
    }

    /* 链满 FIFO 丢最旧（ActiveRecords = 当前链长） */
    while (IocContext->ActiveRecords >= WKD_MAX_IOC_RECORDS &&
        !IsListEmpty(&IocContext->IocChain)) {
        PLIST_ENTRY oldest = RemoveHeadList(&IocContext->IocChain);
        ExFreePoolWithTag(
            CONTAINING_RECORD(oldest, AE_IOC_RECORD, Link),
            'iocN');        /* 与 AeReportIndicatorEx 分配 tag 一致 */
        IocContext->ActiveRecords--;
    }

    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
IocAllocateProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    分配进程对的 IocContext。由 AeFindOrCreateProcessPair 创建时调用。

Return Value:
    分配成功的 PAE_IOC_CONTEXT；失败返回 NULL。
--*/
{
    PAE_IOC_CONTEXT iocContext;

    if (!Pair) return STATUS_INVALID_PARAMETER;

    /* 获取 IOC 引擎 Rundown（对称 IoaAllocateProcessPairContext，B2 修复） */
    if (!ExAcquireRundownProtection(&WkdIocEngine.RundownRef)) {
        return STATUS_REQUEST_ABORTED;
    }

    iocContext = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(AE_IOC_CONTEXT), POOL_TAG_IOC_CONTEXT);
    if (!iocContext) {
        ExReleaseRundownProtection(&WkdIocEngine.RundownRef);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(iocContext, sizeof(AE_IOC_CONTEXT));

    InitializeListHead(&iocContext->IocChain);

    Pair->IocContext = iocContext;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
IocFreeProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    销毁进程对的 IocContext。由 PsDereferenceWkdProcessPair refcount==0
    分支调用。先原子置 Pair->IocContext = NULL 关闭新提交入口，
    再等待运行中的提交路径（AeReportIndicatorEx IOC 分支持 rundown）
    退出，最后无锁释放证据链全部节点与上下文。

    与 TsFreeProcessPairContext 同模式：提交路径必须先
    ExAcquireRundownProtection(&IocContext->Rundown) 再使用。

Arguments:
    Pair - 目标进程对（IocContext 为 NULL 时静默返回）。

Return Value:
    VOID。
--*/
{
    PAE_IOC_CONTEXT iocContext;

    if (!Pair || !Pair->IocContext) return;

    /* ---- 无持有者，可安全无锁释放 ---- */
    iocContext = Pair->IocContext;

    /* 释放 IOC 证据链（去重节点，全部释放） */
    while (!IsListEmpty(&iocContext->IocChain)) {
        PLIST_ENTRY entry = RemoveHeadList(&iocContext->IocChain);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, AE_IOC_RECORD, Link),
            'iocN');
    }

    ExFreePoolWithTag(iocContext, POOL_TAG_IOC_CONTEXT);
    Pair->IocContext = NULL;

    /* 对称：IocAllocateProcessPairContext 曾获取引擎 RundownRef（B2 修复） */
    ExReleaseRundownProtection(&WkdIocEngine.RundownRef);
}

/**************************************************/
/*        以下为 IOC 检测函数（保留，功能不变）       */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckPowershellEncoded(
    _In_ PUNICODE_STRING CommandLine
    )
{
    if (!CommandLine || !CommandLine->Buffer) {
        return FALSE;
    }

    UNICODE_STRING lowerCmdLine = *CommandLine;
    WkdStringToLower(&lowerCmdLine);

    for (ULONG i = 0; i < g_WkdPowershellPatternCount; i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_WkdPowershellPatterns[i]);
        if (WkdStringContains(&lowerCmdLine, &pattern)) {
            return TRUE;
        }
    }

    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckDownloader(
    _In_ PUNICODE_STRING CommandLine
    )
{
    if (!CommandLine || !CommandLine->Buffer) {
        return FALSE;
    }

    UNICODE_STRING lowerCmdLine = *CommandLine;
    WkdStringToLower(&lowerCmdLine);

    for (ULONG i = 0; i < g_WkdDownloaderPatternCount; i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_WkdDownloaderPatterns[i]);
        if (WkdStringContains(&lowerCmdLine, &pattern)) {
            return TRUE;
        }
    }

    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckReflectiveLoad(
    _In_ PUNICODE_STRING CommandLine
    )
{
    if (!CommandLine || !CommandLine->Buffer) {
        return FALSE;
    }

    UNICODE_STRING lowerCmdLine = *CommandLine;
    WkdStringToLower(&lowerCmdLine);

    for (ULONG i = 0; i < g_WkdReflectivePatternCount; i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_WkdReflectivePatterns[i]);
        if (WkdStringContains(&lowerCmdLine, &pattern)) {
            return TRUE;
        }
    }

    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckSuspiciousCmd(
    _In_ PUNICODE_STRING CommandLine
    )
{
    UNREFERENCED_PARAMETER(CommandLine);
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocAnalyzeCommandLine(
    _In_ PUNICODE_STRING CommandLine,
    _Out_ PULONG Flags
    )
{
    if (!CommandLine || !Flags) {
        return;
    }

    *Flags = 0;

    if (IocCheckPowershellEncoded(CommandLine)) {
        *Flags |= WKD_CMD_FLAG_POWERSHELL_ENCODED;
    }

    if (IocCheckDownloader(CommandLine)) {
        *Flags |= WKD_CMD_FLAG_DOWNLOADER;
    }

    if (IocCheckReflectiveLoad(CommandLine)) {
        *Flags |= WKD_CMD_FLAG_REFLECTIVE_LOAD;
    }

    if (IocCheckSuspiciousCmd(CommandLine)) {
        *Flags |= WKD_CMD_FLAG_SUSPICIOUS_CMD;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckLolbin(
    _In_ PUNICODE_STRING ImagePath
    )
{
    if (!ImagePath || !ImagePath->Buffer) {
        return FALSE;
    }

    UNICODE_STRING lowerPath = *ImagePath;
    WkdStringToLower(&lowerPath);

    for (ULONG i = 0; i < g_WkdLolbinCount; i++) {
        UNICODE_STRING lolbinName;
        RtlInitUnicodeString(&lolbinName, g_WkdLolbinList[i]);
        if (WkdStringEndsWith(&lowerPath, &lolbinName)) {
            return TRUE;
        }
    }

    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocValidateSignature(
    _In_ struct _WKD_PROCESS * Process
    )
{
    UNREFERENCED_PARAMETER(Process);
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocValidatePeHeader(
    _In_ struct _WKD_PROCESS * Process
    )
{
    UNREFERENCED_PARAMETER(Process);
    return TRUE;
}
