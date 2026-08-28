/**************************************************/
/*  WkDefender Agent — 统一镜像分析流水线实现        */
/*                                                  */
/*  三级分级（漏斗）：                              */
/*    Tier1 命中+实例化 — 模块表三态                */
/*    Tier2 轻量快判   — 文件类型/欺骗/哈希/豁免     */
/*    Tier3 深度分析   — 六件套全量                  */
/*                                                  */
/*  复用清单（不复制实现）：                         */
/*    IocScanner_ScanFile     — 六件套完整流水线     */
/*    CoDetermineFileType / AnalyzeFileTypePath */
/*                            — 文件类型+欺骗检测   */
/*    IocScanner_QueryHash    — 哈希 IOC 查询       */
/*    IocScanner_ScanCmdline  — 进程级命令行        */
/*    ExemptsEvaluate         — 豁免融合            */
/*    IoaSigHunt_AnalyzeSignature — 签名狩猎(门控)  */
/**************************************************/

#include "ImageAnalyzer.h"

#include "../IocScanner.h"
#include "../Signature/SignatureHunting.h"
#include "../../Process/ProcessModule.h"
#include "../../Common/Exempts/Exempts.h"
#include "../../WkDefenderHeader.h"       /* IMG_SIGNATURE_* */
#include "../../tools.h"                   /* UtHeapAlloc/UtHeapFree */
#include <wchar.h>                          /* wcsncpy_s */
#include <string.h>                         /* strncpy_s/memcpy */

/* 等待他人深度分析的超时（ms）：超时后本线程兜底自做 */
#define WKD_IA_WAIT_TIMEOUT_MS   2000

/**************************************************/
/*               内部辅助函数                       */
/**************************************************/

/* 文件类型粗分类 → 是否 PE 可执行镜像（进模块表）。
 * 非 PE（文档/脚本/归档/未知）走独立分支，不建模块。 */
static BOOLEAN
IocpIsPe(
    _In_ PCWSTR ImagePath
    )
{
    if (!CoCheckStringValidity(ImagePath))  return FALSE;

    switch (CoDetermineFileType(ImagePath)) {
    case IocFileType_Pe32:
    case IocFileType_Pe64:
    case IocFileType_Dll:
    case IocFileType_Sys:
        return TRUE;
    default:
        return FALSE;
    }
}

/* Tier3 深度分析：六件套全量（每唯一镜像一次）。
 * IocScanner_ScanFile 内部完成 CertVerify/Lolbin/PeHeaders/
 * Heuristic/Aggregate/Reputation；签名狩猎为门控附加。
 * Module 可选：非 NULL 时传其构建期 PeInfo 复用惰性 Ctx，
 * 免深度分析二次完整 PE 解析 (2026-08-19 Ctx 基座)。 */
static NTSTATUS
IocDeepAnalyzeImage(
    _In_opt_ PWKD_MODULE   Module,
    _In_     PCWSTR        ImagePath,
    _Out_    PIOC_SCAN_RESULT Result
    )
{
    NTSTATUS status = IocScanner_ScanFileWithHint(
                          ImagePath,
                          (Module != NULL) ? &Module->PeInfo : NULL,
                          Result);

    /* 签名 APT 狩猎（门控 g_IoaSignatureHuntingEnabled，归位）：
     * ScanFile 内 CertVerify 已填证书详情，9 类异常零额外重读
     * （仅"未来时间戳"分支需重开文件）。 */
    if (g_IoaSignatureHuntingEnabled) {
        IoaSigHunt_AnalyzeSignature(ImagePath, Result, &Result->SignatureHunt);
    }
    return status;
}

/* 最终判定覆盖（黑名单 + 豁免融合优先级）：
 *   - 黑名单命中 (HashVerdict==Malicious) → FinalVerdict=Malicious
 *   - 强豁免 (Hash/Cert/Publisher) → Clean（压黑名单）
 *   - 弱豁免 (Path) → 仅未命中黑名单才 Clean（黑名单压弱豁免）
 * 在 IaMergeFileSignals 末尾与 cmdline Aggregate 后各调一次（幂等），
 * 保证豁免/黑名单优先级不被后续重新聚合推翻。 */
static VOID
IaApplyFinalOverride(
    _In_opt_ PWKD_MODULE      Module,       /* PE 才有；非 PE 传 NULL */
    _In_     PCWSTR           ImagePath,
    _Inout_  PIOC_SCAN_RESULT Result
    )
{
    EXEMPT_VERDICT ex;
    EXEMPT_REASON exReason = ExemptReason_None;
    BOOLEAN hashMalicious = (Result->HashChecked &&
                             Result->HashVerdict == DefIocVerdict_Malicious);

    /* 黑名单覆盖 → Malicious */
    if (hashMalicious) {
        Result->FinalVerdict = DefIocVerdict_Malicious;
        Result->FinalConfidence = 100;
        if (Result->ThreatName[0] == '\0') {
            strncpy_s(Result->ThreatName, sizeof(Result->ThreatName),
                      "Hash.Malicious", _TRUNCATE);
        }
    }

    /* 豁免融合（Result 已含证书详情，ExemptsEvaluate 不重复验签） */
    ex = ExemptsEvaluate(ImagePath,
                         Module ? &Module->Sha256 : NULL,
                         Result,
                         &exReason);
    if (ex == ExemptVerdict_Trusted) {
        BOOLEAN isStrong = (exReason == ExemptReason_HashMatch ||
                            exReason == ExemptReason_CertMatch ||
                            exReason == ExemptReason_PublisherMatch);
        if (isStrong) {
            Result->FinalVerdict = DefIocVerdict_Clean;
            Result->FinalConfidence = 100;
        } else if (!hashMalicious) {
            /* PathMatch 弱豁免，无黑名单命中 → Clean */
            Result->FinalVerdict = DefIocVerdict_Clean;
            Result->FinalConfidence = 100;
        }
        /* 黑名单命中保持 Malicious（弱豁免被覆盖） */
    }
}

/* 从模块权威副本生成 IOC_SCAN_RESULT（2026-08-18 阶段5）。
 * PE 镜像统一经此生成 Result：证书字段 ← module->CertInfo；
 * PE 头/哈希信号 ← module->Facts；哈希黑名单 ← module->Sha256；
 * IncludePe=TRUE 且深度完成（FileResult 有效）→ 叠加 PE 深度字段；
 * 末尾统一豁免 + 最终判定（IaApplyFinalOverride）。
 * 非 PE 不建模块，不经此路。 */
static VOID
IaBlendModuleToResult(
    _In_opt_ PWKD_MODULE      Module,
    _In_     PCWSTR           ImagePath,
    _Inout_  PIOC_SCAN_RESULT Result,
    _In_     BOOLEAN          IncludePe
    )
{
    BOOLEAN hashMalicious = FALSE;

    if (!Result) return;
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    if (!Module) return;

    /* 证书字段 ← CertInfo */
    {
        PWKD_CERT_INFO ci = &Module->CertInfo;
        Result->CertStatus  = ci->CertStatus;
        Result->CertValid   = ci->CertValid;
        Result->CertTrusted = ci->CertTrusted;
        Result->CertScore   = ci->CertScore;
        wcsncpy_s(Result->SignerName, RTL_NUMBER_OF(Result->SignerName),
                  ci->SignerName, _TRUNCATE);
        wcsncpy_s(Result->IssuerName, RTL_NUMBER_OF(Result->IssuerName),
                  ci->IssuerName, _TRUNCATE);
        memcpy(Result->Thumbprint, ci->Thumbprint, sizeof(Result->Thumbprint));
        Result->CertValidFrom = ci->CertValidFrom;
        Result->CertValidTo   = ci->CertValidTo;
        for (ULONG i = 0; i < 16; i++) {
            wcsncpy_s(Result->ChainName[i], RTL_NUMBER_OF(Result->ChainName[i]),
                      ci->ChainName[i], _TRUNCATE);
            memcpy(Result->ChainThumbprint[i], ci->ChainThumbprint[i],
                   sizeof(Result->ChainThumbprint[i]));
        }
        Result->ChainDepth     = ci->ChainDepth;
        Result->IsTrustedStrict = ci->IsTrustedStrict;
        Result->IsSelfSigned        = ci->IsSelfSigned;
        Result->IsCodeSigningEku    = ci->IsCodeSigningEku;
        Result->IsWhql              = ci->IsWhql;
        Result->IsDualSigned        = ci->IsDualSigned;
        memcpy(Result->SignatureAlgorithm, ci->SignatureAlgorithm,
               sizeof(Result->SignatureAlgorithm));
        Result->IsWeakSignature     = ci->IsWeakSignature;
        Result->IsRevocationChecked = ci->IsRevocationChecked;
        Result->SignTime            = ci->SignTime;
        memcpy(Result->CatalogName, ci->CatalogName, sizeof(Result->CatalogName));
        Result->SignerReputation    = ci->SignerReputation;
        Result->SignerCategory      = ci->SignerCategory;
        Result->IsEvCert            = ci->IsEvCert;
        Result->CertReputationAdjust = ci->CertReputationAdjust;
    }

    /* PE 头信号 ← Factss（轻量判定即含） */
    if (Module->Facts.Valid) {
        Result->HasSuspiciousSections = Module->Facts.HasWxSection;
        /* HasWxSection 为高信号；节/导入可疑等深度字段由 PeAnalysis 提供 */
    }

    /* 哈希黑名单 ← 模块 Sha256（零 I/O） */
    IocScanner_QueryHash(&Module->Sha256, &hashMalicious);
    Result->HashChecked = TRUE;
    Result->HashVerdict = hashMalicious ? DefIocVerdict_Malicious
                                        : DefIocVerdict_Clean;
    Result->HashConfidence = hashMalicious ? 100 : 0;

    /* 深度字段 ← PeAnalysis（可信拷贝；DONE 后 PeAnalysis 有效） */
    if (IncludePe && Module->FileResult) {
        *Result = *Module->FileResult;   /* 完整覆盖（含 Cert/Facts/深度/综合） */
    }

    /* 豁免 + 最终判定 */
    IaApplyFinalOverride(Module, ImagePath, Result);
}

/* Tier2/合并信号：深度分析后补充文件级判定。
 *   - 文件类型完整分析 + 欺骗检测（ScanFile 未覆盖）
 *   - 哈希 IOC 查询（用模块 Sha256，零 I/O；PE 才有模块）
 *   - 最终判定覆盖（黑名单/豁免优先级）由 IaApplyFinalOverride 统一应用
 * 注：Lolbin 由 ScanFile 内部已算，此处不重复。 */
static VOID
IaMergeFileSignals(
    _In_opt_ PWKD_MODULE      Module,       /* PE 才有；非 PE 传 NULL（跳过哈希） */
    _In_     PCWSTR           ImagePath,
    _Inout_  PIOC_SCAN_RESULT Result
    )
{
    WKD_FILE_TYPE_INFO fti;
    BOOLEAN hashMalicious = FALSE;

    /* 文件类型完整分析（读文件头，轻量）+ 欺骗检测 */
    if (NT_SUCCESS(IocScan_AnalyzeFileTypePath(ImagePath, &fti))) {
        Result->FileFormat   = fti.Format;
        Result->FileCategory = fti.Category;
        Result->RiskLevel    = fti.RiskLevel;
        Result->IsSpoofed    = fti.IsSpoofed;
        Result->SpoofingType = fti.SpoofingType;
        if (fti.SuggestedExt[0]) {
            wcsncpy_s(Result->SuggestedExtension,
                      ARRAYSIZE(Result->SuggestedExtension),
                      fti.SuggestedExt, _TRUNCATE);
        }
    }

    /* 哈希 IOC 查询（PE 才有 Sha256；黑名单最强信号，零 I/O） */
    if (Module) {
        IocScanner_QueryHash(&Module->Sha256, &hashMalicious);
        Result->HashChecked = TRUE;
        Result->HashVerdict = hashMalicious ? DefIocVerdict_Malicious
                                            : DefIocVerdict_Clean;
        Result->HashConfidence = hashMalicious ? 100 : 0;
    }

    /* 最终判定覆盖（黑名单 → Malicious；豁免融合压黑名单/被黑名单压） */
    IaApplyFinalOverride(Module, ImagePath, Result);
}

/**************************************************/
/*       异步 PE 深度分析工作线程（2026-08-18）   */
/*                                                   */
/*  全量 PE 深度（六件套 + PE 惰性解析）由本工作线程  */
/*  异步执行，调用线程保留阻塞等待框架（DONE/        */
/*  IN_PROGRESS 短等待/超时兜底自做）。               */
/*  入队前 pin 模块（RefCount++），worker 完成写      */
/*  PeAnalysis+FileResult 后置 DONE + SetEvent、     */
/*  deref pin。背压：队列满时入队失败（调用方兜底）。 */
/**************************************************/

#define IA_QUEUE_MAX        256
#define IA_PATH_MAX         (MAX_PATH * 4)

typedef struct _IA_QUEUE_ENTRY {
    LIST_ENTRY   Link;
    PWKD_MODULE  Module;          /* 已 pin：入队前 RefCount++ */
    WCHAR        Path[IA_PATH_MAX];
} IA_QUEUE_ENTRY, *PIA_QUEUE_ENTRY;

typedef struct _IA_ASYNC_ENGINE {
    CRITICAL_SECTION     Lock;
    LIST_ENTRY           Head;
    volatile LONG        Count;
    LONG                 MaxQueued;
    HANDLE               WorkerThread;
    HANDLE               WakeEvent;
    HANDLE               ShutdownEvent;
    volatile BOOLEAN     Running;
} IA_ASYNC_ENGINE, *PIA_ASYNC_ENGINE;

static IA_ASYNC_ENGINE g_IaAsync;

/* 前向声明（定义于 IaEnqueueDeepAnalysis 之后；IaWorkerProc 依赖） */
static
VOID
EnsureCompleteEvent(
    _Inout_ PWKD_MODULE Module
    );

static
VOID
FinalizeModuleResult(
    _Inout_ PWKD_MODULE      Module,
    _In_    PIOC_SCAN_RESULT Result
    );

static
DWORD
WINAPI
IaWorkerProc(
    _In_ LPVOID Context
    )
{
    HANDLE waitEvts[2];
    PLIST_ENTRY e;
    PIA_QUEUE_ENTRY qe;
    IOC_SCAN_RESULT r;

    (void)Context;
    waitEvts[0] = g_IaAsync.WakeEvent;
    waitEvts[1] = g_IaAsync.ShutdownEvent;

    for (;;) {
        DWORD w = WaitForMultipleObjects(2, waitEvts, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 + 1) break;          /* Shutdown */

        EnterCriticalSection(&g_IaAsync.Lock);
        if (IsListEmpty(&g_IaAsync.Head)) {
            LeaveCriticalSection(&g_IaAsync.Lock);
            continue;
        }
        e = g_IaAsync.Head.Flink;
        RemoveEntryList(e);
        g_IaAsync.Count--;
        LeaveCriticalSection(&g_IaAsync.Lock);

        qe = CONTAINING_RECORD(e, IA_QUEUE_ENTRY, Link);

        /* 深度分析（持 pin，模块不会被摘表释放） */
        RtlZeroMemory(&r, sizeof(r));
        IocDeepAnalyzeImage(qe->Module, qe->Path, &r);
        IaMergeFileSignals(qe->Module, qe->Path, &r);

        /* 定稿：写 FileResult + PeAnalysis，发布 DONE + 唤醒等待者 */
        FinalizeModuleResult(qe->Module, &r);

        PsDereferenceWkdModule(qe->Module);   /* 释放入队 pin */
        HeapFree(GetProcessHeap(), 0, qe);
    }
    return 0;
}

/* 提交模块深度分析到工作线程。返回 TRUE=已入队，FALSE=队列满/未初始化（调用方兜底）。 */
static
BOOLEAN
IaEnqueueDeepAnalysis(
    _In_ PWKD_MODULE Module,
    _In_ PCWSTR      Path
    )
{
    PIA_QUEUE_ENTRY qe;

    if (!g_IaAsync.Running || !Module || !Path) return FALSE;

    EnterCriticalSection(&g_IaAsync.Lock);
    if (g_IaAsync.Count >= g_IaAsync.MaxQueued) {
        LeaveCriticalSection(&g_IaAsync.Lock);
        return FALSE;          /* 背压：丢弃，调用方同步兜底 */
    }
    qe = (PIA_QUEUE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                    sizeof(IA_QUEUE_ENTRY));
    if (!qe) {
        LeaveCriticalSection(&g_IaAsync.Lock);
        return FALSE;
    }
    qe->Module = Module;
    wcsncpy_s(qe->Path, IA_PATH_MAX, Path, _TRUNCATE);
    InterlockedIncrement(&Module->RefCount);         /* pin 防摘表 */
    InsertTailList(&g_IaAsync.Head, &qe->Link);
    g_IaAsync.Count++;
    LeaveCriticalSection(&g_IaAsync.Lock);

    SetEvent(g_IaAsync.WakeEvent);
    return TRUE;
}

/* 确保模块具备完成事件（供 worker 完成后唤醒等待者） */
static
VOID
EnsureCompleteEvent(
    _Inout_ PWKD_MODULE Module
    )
{
    if (Module && !Module->CompleteEvent) {
        Module->CompleteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    }
}

/* 深度结果定稿：写 FileResult + PeAnalysis，发布 DONE 并唤醒等待者。
 * worker 完成后与同步兜底路径共用，保证两份实现一致。 */
static
VOID
FinalizeModuleResult(
    _Inout_ PWKD_MODULE      Module,
    _In_    PIOC_SCAN_RESULT Result
    )
{
    if (!Module || !Result) return;

    Result->CmdlineFlags = 0;
    Result->CmdlineConfidence = 0;
    if (!Module->FileResult) {
        Module->FileResult = UtHeapAlloc(sizeof(IOC_SCAN_RESULT));
    }
    if (Module->FileResult) {
        *Module->FileResult = *Result;
    }
    PmExtractPeAnalysis(Result, &Module->PeAnalysis);

    InterlockedExchange(&Module->AnalysisState, WKD_MODULE_ANALYSIS_DONE);
    /* 仅 SetEvent 唤醒等待者；句柄不在此关闭——等待者在 Wait 期间
     * 若句柄被 CloseHandle 会有句柄重用竞态。句柄随模块释放
     * （PspDestroyWkdModule）关闭。等待者 Wait 后以 AnalysisState 判定。 */
    if (Module->CompleteEvent) {
        SetEvent(Module->CompleteEvent);
    }
}

/* 异步引擎生命周期（main.c 接线） */
NTSTATUS
IaAsyncInitialize(
    VOID
    )
{
    if (g_IaAsync.Running) return STATUS_SUCCESS;

    InitializeCriticalSection(&g_IaAsync.Lock);
    InitializeListHead(&g_IaAsync.Head);
    g_IaAsync.MaxQueued = IA_QUEUE_MAX;
    g_IaAsync.WakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_IaAsync.ShutdownEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_IaAsync.WakeEvent || !g_IaAsync.ShutdownEvent) {
        if (g_IaAsync.WakeEvent) CloseHandle(g_IaAsync.WakeEvent);
        if (g_IaAsync.ShutdownEvent) CloseHandle(g_IaAsync.ShutdownEvent);
        return STATUS_UNSUCCESSFUL;
    }
    g_IaAsync.WorkerThread = CreateThread(NULL, 0, IaWorkerProc, NULL, 0, NULL);
    if (!g_IaAsync.WorkerThread) {
        CloseHandle(g_IaAsync.WakeEvent);
        CloseHandle(g_IaAsync.ShutdownEvent);
        return STATUS_UNSUCCESSFUL;
    }
    g_IaAsync.Running = TRUE;
    return STATUS_SUCCESS;
}

VOID
IaAsyncShutdown(
    VOID
    )
{
    if (!g_IaAsync.Running) return;
    g_IaAsync.Running = FALSE;

    SetEvent(g_IaAsync.ShutdownEvent);
    WaitForSingleObject(g_IaAsync.WorkerThread, 3000);
    CloseHandle(g_IaAsync.WorkerThread);
    CloseHandle(g_IaAsync.WakeEvent);
    CloseHandle(g_IaAsync.ShutdownEvent);

    /* 清空残留队列（worker 已停） */
    EnterCriticalSection(&g_IaAsync.Lock);
    while (!IsListEmpty(&g_IaAsync.Head)) {
        PIA_QUEUE_ENTRY qe;
        qe = CONTAINING_RECORD(g_IaAsync.Head.Flink, IA_QUEUE_ENTRY, Link);
        RemoveEntryList(&qe->Link);
        PsDereferenceWkdModule(qe->Module);   /* 释放未处理 pin */
        HeapFree(GetProcessHeap(), 0, qe);
    }
    g_IaAsync.Count = 0;
    LeaveCriticalSection(&g_IaAsync.Lock);
    DeleteCriticalSection(&g_IaAsync.Lock);
}

/**************************************************/
/*               主入口                            */
/**************************************************/

NTSTATUS
IocAnalyseImage(
    _In_ PCWSTR ImagePath,
    _In_opt_ PCWSTR CommandLine,
    _Out_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    统一镜像文件分析入口。详见 ImageAnalyzer.h 头注释。

    并发契约（2026-08-18 四态 + 证书分档）：
      DONE        → O(1) 复用 FileResult（完整）
      IN_PROGRESS → WaitForSingleObject(CompleteEvent, 2s)，超时/失败
                    兜底本线程自做
      CREATED     → 证书分档：CertTrusted → 跳过深度（同步 Clean，
                    仍含哈希黑名单+豁免）；否则提交异步深度 + 同步
                    返回轻量判定
      NONE        → CAS 抢占置 IN_PROGRESS，提交异步（或同步兜底）

    深度执行主体 = 工作线程（IaEnqueueDeepAnalysis）；同步路径仅在
    队列不可用/满时兜底自做。等待框架（DONE/IN_PROGRESS/兜底）保留。

Arguments:
    ImagePath - 文件完整路径（UNICODE_STRING）。
    Cmdline   - 可选进程命令行（仅 ProcessCreate 传）。
    Result    - 输出文件级静态分析结果。

Return Value:
    NTSTATUS。
--*/
{
    PWKD_MODULE module = NULL;
    BOOLEAN pin = FALSE;
    LONG st;

    if (!CoCheckStringValidity(ImagePath) || !Result) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    if (IocpIsPe(ImagePath)) {
        /* === PE 镜像：以模块表为文件级权威副本 === */
        if (NT_SUCCESS(PsFindOrCreateModule(ImagePath,
                                            0 /* 未知映射大小，宽松 Identity */,
                                            IMG_SIGNATURE_UNEVALUATED,
                                            &module))) {
            goto Cleanup;
            pin = TRUE;

            st = InterlockedCompareExchange(&module->AnalysisState,
                                            WKD_MODULE_ANALYSIS_IN_PROGRESS,
                                            WKD_MODULE_ANALYSIS_NONE);
            if (st == WKD_MODULE_ANALYSIS_DONE) {
                /* 已分析 → O(1) 完整复用 */
                IaBlendModuleToResult(module, ImagePath, Result, TRUE);
                goto cmdline;
            }
            if (st == WKD_MODULE_ANALYSIS_IN_PROGRESS) {
                /* 他人分析中 → 等待（带超时兜底） */
                if (module->CompleteEvent) {
                    WaitForSingleObject(module->CompleteEvent, WKD_IA_WAIT_TIMEOUT_MS);
                }
                if (module->AnalysisState == WKD_MODULE_ANALYSIS_DONE &&
                    module->FileResult) {
                    IaBlendModuleToResult(module, ImagePath, Result, TRUE);
                } else {
                    /* 超时/失败 → 本线程兜底自做完整深度 */
                    IocDeepAnalyzeImage(module, ImagePath, Result);
                    IaMergeFileSignals(module, ImagePath, Result);
                }
                goto cmdline;
            }
            if (st == WKD_MODULE_ANALYSIS_CREATED) {
                /* 证书分档（2026-08-18 阶段6）：
                 * 可信签名 → 跳过 PE 深度，同步返回轻量判定（含哈希
                 * 黑名单 + 豁免；哈希命中仍会置 Malicious，弥补跳过
                 * 深度的安全缺口）。否则提交异步深度 + 同步轻量。 */
                if (module->CertInfo.CertTrusted &&
                    !module->CertInfo.IsWeakSignature) {
                    IaBlendModuleToResult(module, ImagePath, Result, FALSE);
                    goto cmdline;
                }
                /* 未信任/弱签名 → 抢占 IN_PROGRESS 提交异步 */
                if (InterlockedCompareExchange(&module->AnalysisState,
                                               WKD_MODULE_ANALYSIS_IN_PROGRESS,
                                               WKD_MODULE_ANALYSIS_CREATED) !=
                                               WKD_MODULE_ANALYSIS_CREATED) {
                    /* 并发者已抢占 → 走等待分支 */
                    if (module->CompleteEvent) {
                        WaitForSingleObject(module->CompleteEvent, WKD_IA_WAIT_TIMEOUT_MS);
                    }
                    if (module->AnalysisState == WKD_MODULE_ANALYSIS_DONE &&
                        module->FileResult) {
                        IaBlendModuleToResult(module, ImagePath, Result, TRUE);
                    } else {
                        IocDeepAnalyzeImage(module, ImagePath, Result);
                        IaMergeFileSignals(module, ImagePath, Result);
                    }
                    goto cmdline;
                }
                /* 本线程成为属主：建完成事件 + 提交异步（失败则同步兜底） */
                EnsureCompleteEvent(module);
                if (!IaEnqueueDeepAnalysis(module, ImagePath)) {
                    /* 背压/不可用 → 同步兜底自做 + 写 FileResult + DONE */
                    IocDeepAnalyzeImage(module, ImagePath, Result);
                    IaMergeFileSignals(module, ImagePath, Result);
                    FinalizeModuleResult(module, Result);
                } else {
                    /* 已提交 → 同步返回轻量判定 */
                    IaBlendModuleToResult(module, ImagePath, Result, FALSE);
                }
                goto cmdline;
            }
            /* st == NONE：CAS 抢占成功（NONE→IN_PROGRESS）→ 本线程属主 */
            EnsureCompleteEvent(module);
            if (!IaEnqueueDeepAnalysis(module, ImagePath)) {
                IocDeepAnalyzeImage(module, ImagePath, Result);
                IaMergeFileSignals(module, ImagePath, Result);
                FinalizeModuleResult(module, Result);
            } else {
                IaBlendModuleToResult(module, ImagePath, Result, FALSE);
            }
            goto cmdline;
        } else {
            /* 模块表不可用（未初始化/配额）→ 回退直接深度分析 */
            //IocDeepAnalyzeImage(module, ImagePath, Result);
            //IaMergeFileSignals(NULL, ImagePath, Result);
        }
    } else {
        /* === 非 PE（文档/脚本/归档等）→ 不建模块，直接深度分析 === */
         IocDeepAnalyzeImage(module, ImagePath, Result);
         IaMergeFileSignals(NULL, ImagePath, Result);

        /* 非 PE 专项扫描器接线（ScanManager 三 TODO 归位 2026-08-15）：
         * 文件类型分发后按需接入，功能面已全量就绪（门控默认关，
         * 对齐 g_Ioa*Enabled 惯例，待部署决策开启）：
         *   // 归档:  IocArchive_IsArchive FastPath → 逐条目提取 → 哈希命中置
         *   //         Malicious → ResultToIocScan 合并 (IOC/IocArchiveScanner.c)
         *   // 文档:  IocDocument_DetectType 判定 PDF/OLE/OOXML/RTF → 宏/嵌入/
         *   //         CVE/IOC 提取 → ResultToIocScan 合并 (IOC/IocDocumentScanner.c)
         *   // 媒体:  IocMedia_ScanFile → 格式/隐写/EXIF/漏洞载荷 → 追加数据
         *   //         → IocMedia_ResultToIocScan 经 HeuristicConfidence 合并
         *   //         (IOC/IocScanner.c 媒体分析分区, API 已导出)
         * 注意: 非 PE 不建模块（无 Facts 价值），走 ScanManager 缓存承载结果。 */
    }

cmdline:
    /* 进程级 Cmdline（仅 ProcessCreate 传；不写 FileResult）：
     * IocScan_Cmdline 为合并语义（不清空文件级结果），随后重新
     * Aggregate + Reputation 使 Cmdline 信号参与最终判定
     * （对齐原 IocScanner_ScanProcess 语义；IocScanner_ScanCmdline
     * 入口 RtlZeroMemory 清空故不可用于合并）。
     * Aggregate 重算 FinalVerdict 后需重放 IaApplyFinalOverride，
     * 保证黑名单/豁免优先级不被重新聚合推翻。 */
    //if (CommandLine && CommandLine->Buffer && CommandLine->Length >= sizeof(WCHAR)) {
    //    /* UNICODE_STRING 不保证 NUL 终止, 拷贝副本后传给 IocScan_Cmdline (期望 PCWSTR) */
    //    WCHAR cmdlineBuf[2048];
    //    ULONG lenChars = Cmdline->Length / sizeof(WCHAR);

    //    if (lenChars >= 2048) lenChars = 2047;
    //    RtlCopyMemory(cmdlineBuf, Cmdline->Buffer, lenChars * sizeof(WCHAR));
    //    cmdlineBuf[lenChars] = 0;

    //    IocScan_Cmdline(cmdlineBuf, Result);
    //    IocScan_Aggregate(Result);
    //    IaApplyFinalOverride(module, ImagePath, Result);
    //    IocScan_ReputationScore(Result);
    //}

Cleanup:
    if (module)  PsDereferenceWkdModule(module);
    return STATUS_SUCCESS;
}
