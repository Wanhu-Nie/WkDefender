/**************************************************/
/*  WkDefender — 镜像加载通知 L0 采集器              */
/*  参考 PhantomSensor ImageNotify.c                 */
/*                                                   */
/*  职责（L0/L1 边界重构 2026-08-08 + 收敛 2026-08-09 +   */
/*       全局镜像对象 2026-08-11）：                    */
/*    - 无锁速率限制                                   */
/*    - ImageInfo 原始标志采集（IMG_IMGFLAG_* 位）*/
/*    - 镜像类型细分                                  */
/*    - per-process 模块视图持久化（MtLookupOrCreate   */
/*      全局对象 + PsModuleAttachProcessLocked，仅首见解析 PE）*/
/*    - 调度 L1（AeOrchestratorDispatch (X,X) 自对，   */
/*      恒执行，检测/评分/处置在 L1 IocImage.c）        */
/*    - 决策过滤（2026-08-09）：路径白名单命中 或       */
/*      CI 签名有效（SeGetCachedSigningLevel）→ 不推    */
/*      agent；无签名或非白名单 → ALPC 上送 agent 全量  */
/*      校验（CbpNotifyImageLoad）。hash/熵归 agent。  */
/*      PeInfo 在消息构建点从全局 WKD_MODULE 派生。     */
/*                                                   */
/*  检测判定已迁往 AnalysisEngine/IocImage.c（L1）。   */
/*  死代码区（末尾）：BYOVD/IOC匹配/哈希缓存/哈希计算/  */
/*    镂空检测/Section/回调注册表/Init状态机/服务连接/  */
/*    签名统计/配置 — 功能面全量覆盖，标注不接入原因     */
/**************************************************/

#include "ImageNotify.h"
#include "../Notification/NotificationManager.h"
#include "../Notification/AlpcService.h"
#include "../Process/ProcessMonitor.h"
#include "../Process/ProcessModuleTracker.h"
#include "../AnalysisEngine/IocEngine.h"
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../AnalysisEngine/IocAppControl.h"
#include "../Common/PeParser.h"
#include "../Common/Utils.h"
#include "../Common/ExportParser.h"
#include <ntimage.h>
#include <ntstrsafe.h>

//
// PsGetProcessInheritedFromUniqueProcessId / PsGetProcessSessionId /
// SeGetCachedSigningLevel 的原型与函数指针统一由 Common/ExportParser.h
// 提供（pfnPsGetProcessInheritedFromUniqueProcessId / pfnPsGetProcessSessionId /
// pfnSeGetCachedSigningLevel）。
//

// ============================================================================
// 引导阶段关键镜像基名表 g_CriticalBootImages + ImgpIsCriticalBootImage
// 已迁往死代码区（L0 引导抑制，注释态，2026-08-08 L0/L1 边界重构）
// ============================================================================

// ============================================================================
// 可疑路径模式表 g_SuspiciousPathPatterns 已迁往 AnalysisEngine/IocImage.c
// （L1 检测层，2026-08-08 L0/L1 边界重构）
// ============================================================================

// ============================================================================
// 系统 DLL 名表 g_SystemDllNames 已迁往 AnalysisEngine/IocImage.c
// （L1 检测层，2026-08-08 L0/L1 边界重构）
// ============================================================================

// ============================================================================
// 速率限制状态（对齐 PS IMG_RATE_LIMIT_STATE，无锁）
// ============================================================================

#define IMG_RATE_LIMIT_WINDOW_MS        1000
#define IMG_DEFAULT_MAX_EVENTS_PER_SEC  10000

typedef struct _IMG_RATE_LIMIT_STATE {
    volatile LONG EventsThisWindow;
    volatile LONG WindowStartTime;
    volatile LONG ResetInProgress;
} IMG_RATE_LIMIT_STATE;

static IMG_RATE_LIMIT_STATE g_ImgRateLimit = { 0 };

// ============================================================================
// 内部辅助函数
// ============================================================================

//
// 2026-08-11 全局镜像对象重构：PE 解析（含节明细采集）已归全局 WKD_MODULE，
// 在 ProcessModuleTracker.c 的 PspParseModule（MmpOnNtHeader/MmpOnSection）内完成，
// 仅首见路径解析一次。原 IMG_PE_PARSE_CTX / ImgpPeBasicOnNtHeader /
// ImgpPeBasicOnComplete / ImgpCollectSectionDetails / ImgpParsePeFacts 已删除。
//

//
// 镜像路径白名单（2026-08-09 镜像职责收敛）：内置目录前缀表。
// 覆盖 system32/wow64 等系统目录，组件边界 + 大小写不敏感前缀匹配。
// 白名单表存"盘符后组件序列"（盘符可变），匹配前经 CoNormalizeDosPath 归一化。
// 未来可由 agent 推送扩展（本次仅内置，反哺通道标注未来）。
//
static const PCWSTR g_WkdImgWhitelistPrefixes[] = {
    L"windows\\system32",
    L"windows\\syswow64",
    L"windows\\system",
    L"windows\\winsxs",
    L"windows\\sysnative",
};

static
BOOLEAN
ImgpMatchComponentPrefix(
    _In_ PCWSTR Path,
    _In_ ULONG PathLen,
    _In_ PCWSTR Prefix
    )
/*++
    组件边界 + 大小写不敏感前缀匹配（按长度限界，Path 无需 NUL 终止——
    CoNormalizeDosPath 输出缓冲可能不含终止符）：
    Path 以 Prefix 开头（逐字符 CI），且下一字符为 '\\' 或恰好到路径末尾
    （组件边界，防 C:\windows\system32_evil\ 之类目录名混淆命中）。
--*/
{
    ULONG i = 0;

    while (Prefix[i] != L'\0') {
        WCHAR pc, cc;
        if (i >= PathLen) return FALSE;
        pc = Path[i];
        cc = Prefix[i];
        if (pc >= L'A' && pc <= L'Z') pc += (L'a' - L'A');
        if (cc >= L'A' && cc <= L'Z') cc += (L'a' - L'A');
        if (pc != cc) return FALSE;
        i++;
    }
    return (i == PathLen || Path[i] == L'\\');
}

static
BOOLEAN
ImgpIsWhitelistedPath(
    _In_ PCUNICODE_STRING FullImageName
    )
/*++
    镜像路径白名单判定：CoNormalizeDosPath 归一化 → 跳盘符 X:\ → 组件边界
    前缀匹配内置目录表。归一化失败（原文未转为 DOS）→ 不命中（保守推 agent 全量）。
--*/
{
    NTSTATUS status;
    PUNICODE_STRING norm = NULL;
    PCWSTR p;
    ULONG len;
    BOOLEAN hit = FALSE;

    if (FullImageName == NULL || FullImageName->Buffer == NULL ||
        FullImageName->Length == 0) {
        return FALSE;
    }

    status = CoNormalizeDosPath((PUNICODE_STRING)FullImageName, &norm);
    if (!NT_SUCCESS(status) || norm == NULL || norm->Buffer == NULL || norm->Length == 0) {
        goto Done;
    }

    p = norm->Buffer;
    len = norm->Length / sizeof(WCHAR);

    /* 跳盘符 X:\（3 WCHAR，盘符可变）或单一前导分隔符（原文未归一化兜底） */
    if (len >= 3 &&
        (p[0] == L'\\' || p[0] == L'/') &&
        p[1] == L':' &&
        (p[2] == L'\\' || p[2] == L'/')) {
        p += 3;
        len -= 3;
    } else if (len >= 1 && (p[0] == L'\\' || p[0] == L'/')) {
        p += 1;
        len -= 1;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_WkdImgWhitelistPrefixes); i++) {
        if (ImgpMatchComponentPrefix(p, len, g_WkdImgWhitelistPrefixes[i])) {
            hit = TRUE;
            break;
        }
    }

Done:
    if (norm != NULL) {
        if (norm->Buffer != NULL) {
            ExFreePoolWithTag(norm->Buffer, 'upbp');
        }
        ExFreePoolWithTag(norm, 'upsp');
    }
    return hit;
}

//
// CI 缓存签名等级读取（2026-08-09 镜像职责收敛）。
// ExtendedInfoPresent → CONTAINING_RECORD 取 IMAGE_INFO_EX.FileObject；
// FileObject 可用 → SeGetCachedSigningLevel（读 CI 加载时缓存的签名等级，
// 零密码学零文件读取）。FileObject 不可用 → Evaluated=FALSE（跳过签名判定，
// 不视为未签名——反射加载/无背衬场景走 Unbacked 信号单独处理）。
//
static
VOID
ImgpGetCachedSigningLevel(
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PUCHAR SigningLevel,
    _Out_ PBOOLEAN Evaluated
    )
{
    if (ImageInfo == NULL || SigningLevel == NULL || Evaluated == NULL) {
        return;
    }
    *SigningLevel = IMG_SIGNATURE_UNEVALUATED;
    *Evaluated = FALSE;

    if (!ImageInfo->ExtendedInfoPresent) {
        return;
    }
    {
        PIMAGE_INFO_EX imageInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

        if (imageInfoEx->FileObject == NULL) {
            return;
        }

        NTSTATUS status;
        ULONG ciFlags = 0;
        SE_SIGNING_LEVEL level = SE_SIGNING_LEVEL_UNCHECKED;

        if (pfnSeGetCachedSigningLevel == NULL) {
            /* 函数不可用，跳过签名判定 */
            return;
        }

        status = pfnSeGetCachedSigningLevel(
            imageInfoEx->FileObject, &ciFlags, &level, NULL, NULL, NULL);

        if (NT_SUCCESS(status)) {
            *Evaluated = TRUE;
            *SigningLevel = (level > SE_SIGNING_LEVEL_UNSIGNED)
                ? IMG_SIGNATURE_VALID : IMG_SIGNATURE_UNSIGNED;
        } else if (status == STATUS_NOT_FOUND || status == STATUS_INVALID_INFO_CLASS) {
            /* 无 CI 缓存 → 视为未签名（降级，不视为错误） */
            *Evaluated = TRUE;
            *SigningLevel = IMG_SIGNATURE_UNSIGNED;
        }
        /* 其他错误（ACCESS_DENIED 等）：保持 Evaluated=FALSE，跳过签名判定 */
    }
}

//
// 网络路径 / 双扩展名检测（ImgpDetectSuspiciousIndicators）已迁往
// AnalysisEngine/IocImage.c（L1 检测层，2026-08-08 L0/L1 边界重构）
//

static
BOOLEAN
ImgpCheckRateLimit(
    VOID
    )
/*++
    无锁速率限制（对齐 PS ImgpCheckRateLimit:3469-3510）。
    防止镜像回调洪泛导致的资源耗尽。
--*/
{
    LARGE_INTEGER currentTime;
    LONG64 elapsed;
    LONG64 windowStart;

    KeQuerySystemTime(&currentTime);

    windowStart = InterlockedCompareExchange64(
        &g_ImgRateLimit.WindowStartTime, 0, 0);

    elapsed = (currentTime.QuadPart - windowStart) / 10000;  // ms

    if (elapsed >= IMG_RATE_LIMIT_WINDOW_MS) {
        /* 原子重置窗口 */
        if (InterlockedCompareExchange64(
            &g_ImgRateLimit.ResetInProgress, 1, 0) == 0) {

            InterlockedExchange64(&g_ImgRateLimit.EventsThisWindow, 0);
            InterlockedExchange64(&g_ImgRateLimit.WindowStartTime, currentTime.QuadPart);
            InterlockedExchange64(&g_ImgRateLimit.ResetInProgress, 0);
        }
    }

    return (InterlockedIncrement(&g_ImgRateLimit.EventsThisWindow)
            <= IMG_DEFAULT_MAX_EVENTS_PER_SEC);
}

//
// 综合威胁评分（ImgpCalculateThreatScore）已废弃 —— 评分统一走
// L1 IocImage 逐条指标提交 + ThreatScoring 权重结算（Phase 3），
// 不再在回调内手动聚合（2026-08-08 L0/L1 边界重构）
//

// ============================================================================
// ALPC 消息构建 + 发送（独立包装，对齐 PmpBuildProcessCreateBody /
// PmpNotifyProcessCreation 的"构建+发送分离"模式，2026-08-08）
// ============================================================================

static
NTSTATUS
CbpNotifyImageLoad(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ const PWKD_MODULE Module,
    _In_ PIMAGE_INFO ImageInfo
    )
/*++
    镜像加载事件 ALPC 上送（构建+发送包装，对齐 PmpNotifyProcessCreation）。
    异步发送，不阻塞加载路径；发送失败仅记录。
    Module 为全局镜像对象（消息构建点派生 PeInfo；NULL 时 PeInfo 全零）。
--*/
{
    NTSTATUS status;
    SIZE_T bodySize, msgSize;
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_IMAGE_LOAD body;

    if (!SourceProcessId || !TargetProcessId ||
        !ImageInfo || !Module) {
        return STATUS_INVALID_PARAMETER;
    }

    bodySize = sizeof(WKD_MESSAGE_BODY_IMAGE_LOAD);
    if (CoCheckUnicodeStringValidity(Module->ImagePath)) {
        bodySize += Module->ImagePath->Length + sizeof(WCHAR);
    }
    msgSize = sizeof(WKD_MESSAGE_HEADER) + bodySize;

    msg = (PWKD_MESSAGE)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgSize, WKD_IMG_POOL_TAG);
    if (msg == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(msg, msgSize);

    msg->Header.Magic = WKD_NOTIFICATION_MAGIC;
    msg->Header.Version = WKD_NOTIFICATION_VERSION;
    msg->Header.Type = WkdMessage_ImageLoaded;
    msg->Header.Source = WkdMessage_SourceImageCallback;
    msg->Header.Priority = WkdMessage_PriorityNormal;
    KeQuerySystemTime(&msg->Header.Timestamp);
    msg->Header.SourceProcessId = SourceProcessId;
    msg->Header.TargetProcessId = TargetProcessId;
    msg->Header.ThreadId = PsGetCurrentThreadId();
    msg->Header.BodySize = bodySize;
    msg->Header.Flags.IsAsync = 1;

    /* 填充WKD_MESSAGE_BODY_IMAGE_LOAD */
    {
        PUCHAR cursor;

        body = (PWKD_MESSAGE_BODY_IMAGE_LOAD)msg->Body;
        body->ImageBase = ImageInfo->ImageBase;
        body->ImageSize = Module->ImageSize;
        body->ImageType = Module->ImageType;

        /* === 消息构建点：从全局模块对象派生线格式 PeInfo（驱动内部其余位置禁用
         *      WKD_IMG_PE_BASIC，2026-08-11 决策 #2） === */
         //if (Module != NULL) {
         //    body->PeInfo.Valid = Module->Facts.Valid;
         //    body->PeInfo.IsDll = Module->Facts.IsDll;
         //    body->PeInfo.NumberOfSections = Module->Facts.NumberOfSections;
         //    body->PeInfo.SectionAlignment = Module->SectionAlignment;
         //    body->PeInfo.FileAlignment = Module->FileAlignment;
         //    body->PeInfo.ImageSize = Module->SizeOfImage;
         //    body->PeInfo.Indicators = 0;   /* 契约：事实位走 body->ImageIndicators */
         //} else {
         //    RtlZeroMemory(&body->PeInfo, sizeof(body->PeInfo));
         //}

         /* 内联路径 */
        cursor = (PUCHAR)(body + 1);
        if (CoCheckUnicodeStringValidity(Module->ImagePath)) {
            body->ImagePath.Length = Module->ImagePath->Length;
            body->ImagePath.MaximumLength = Module->ImagePath->Length + sizeof(WCHAR);
            body->ImagePath.Buffer = (PWSTR)cursor;
            RtlCopyMemory(cursor, Module->ImagePath->Buffer, Module->ImagePath->Length);
            body->ImagePath.Buffer = MAXULONG_PTR;
        }
        else {
            RtlInitUnicodeString(&body->ImagePath, NULL);
        }
    }

    /* 异步上送 agent */
    status = AlpcSendWkdMessage(msg);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] ImgNotify: send failed: 0x%X\n", status);
    }

    ExFreePoolWithTag(msg, WKD_IMG_POOL_TAG);
    return status;
}

// ============================================================================
// 核心回调
// ============================================================================

_Use_decl_annotations_
VOID
CbImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
/*++
    L0 镜像加载回调（纯采集 + 持久化 + 调度 L1 + 决策过滤）。
    L0/L1 边界重构（2026-08-08）+ 职责收敛（2026-08-09）：
      ① 速率限制
      ② 采集：ImageInfo 标志（PspAnalyzeImageProperties）+ 镜像类型（CbpDetermineImageType）
      ③ 持久化：PsFindOrCreateModule（全局唯一对象，仅首见解析 PE）+
         PsModuleAttachProcessLocked 挂接进程视图（每次加载，修复"仅首模块"bug）
      ④ 调度 L1：AeOrchestratorDispatch(wkdProcess, wkdProcess, ...) —— (X,X) 自对，
         Context=PIMAGE_INFO，检测/评分/处置在 L1（恒执行）
      ⑤ 决策过滤（2026-08-09）：白名单路径命中 或 CI 签名有效 → 不推 agent；
         无签名或非白名单 → ALPC 上送 agent 全量校验（CbpNotifyImageLoad）
--*/
{
    NTSTATUS status;
    UCHAR sigStatus = IMG_SIGNATURE_UNEVALUATED;
    BOOLEAN sigEval = FALSE;
    BOOLEAN whitelisted = FALSE;
    PWKD_MODULE module = NULL;
    PWKD_PROCESS targetWkdProcess;
    PCUNICODE_STRING normalizedImagePath;
    
    if (!ProcessId || !ImageInfo) {
        /* 镜像回调发生严重错误!!! */
        DbgBreakPoint();
        return;
    }

    /* === 引导阶段抑制（对齐 PS，注释态） === */
    /* 服务未连接时跳过非内核镜像，仅统计 */
    /* if (!ShadowStrikeIsServiceConnected()) return; */  /* TODO: 由外层框架提供 */

    /* 引导阶段关键系统 EXE 直接跳过（防灰屏） */
    //if (ImgpIsCriticalBootImage(FullImageName)) {
    //    return;
    //}

    /* === 速率限制（对齐 PS ImgpCheckRateLimit） === */
    if (!ImgpCheckRateLimit()) {
        return;
    }
    
    if (FullImageName) {
        /* 将镜像路径标准化为Dos路径 */
        status = CoNormalizeDosPath(FullImageName, &normalizedImagePath);
        if (!NT_SUCCESS(status)) { DbgBreakPoint(); return; } /* 发生严重错误 */
    } else {
        // 暂不支持
        DbgBreakPoint();
        return;
    }
    
    targetWkdProcess = PsLookupWkdProcessByProcessId(ProcessId);
    if (!targetWkdProcess) goto Cleanup;

    /* === 可信进程镜像免检（排除子系统） ===
     * 目标进程被排除子系统标记 Trusted（系统服务路径命中/TrustedPID/EDR 自身）
     * → 跳过模块追踪/L1 调度/ALPC 上送，降噪（系统启动有数千次 DLL 加载）。
     * 注入检测由 syscall 轨（IoaInjectionClassifier）覆盖，此处免检不影响注入判定。 */
    if (targetWkdProcess->SecurityFlags.Trusted) {
        goto Cleanup;
    }

    /* 查重或创建全局镜像对象（仅首见解析 PE；返回带调用者 pin） */
    {
        BOOLEAN existing;

        status = PsFindOrCreateModule(
            normalizedImagePath, ImageInfo, &module, &existing);
        if (!NT_SUCCESS(status))  goto Cleanup;

        /* 将Module附加到进程上，惰性创建进程的ModuleContext */
        /* 将Module添加到目标进程的ModuleContext */
        {
            PWKD_MODULE_INSTANCE instance;
            PWKD_MODULE_CONTEXT ctx;

            /* 2026-08-25 锁下沉: 惰性获取 ModuleContext (CAS 发布, 无进程锁) */
            ctx = targetWkdProcess->ModuleContext;
            if (!ctx) {
                PWKD_MODULE_CONTEXT newCtx = NULL;
                PVOID winner;

                status = PsAllocateModuleContext(targetWkdProcess);
                if (!NT_SUCCESS(status)) {
                    goto Cleanup;
                }

                winner = InterlockedCompareExchangePointer(
                    (PVOID volatile *)&targetWkdProcess->ModuleContext,
                    newCtx, NULL);
                if (winner) {
                    /* 并发输家: 赢家已发布, 释放本地副本 */
                    PsDestroyWkdModuleContext(newCtx);
                    ctx = (PWKD_MODULE_CONTEXT)winner;
                } else {
                    ctx = newCtx;
                }
            }

            /* 链头操作: 2026-08-25 锁下沉后持 ModuleContext::Lock 独占 */
            WkdAcquirePushLockExclusive(&ctx->Lock);

            /* 同目标进程的镜像文件路径与安全信息是否一致? */
#if (NTDDI_VERSION >= NTDDI_VISTA)
            if (ImageInfo->ExtendedInfoPresent) {
                PIMAGE_INFO_EX imageInfoEx =
                    CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
                if (imageInfoEx->FileObject != module->FileObject) {
                    // 不是镜像加载??? 暂不支持
                    DbgBreakPoint();
                }
            }
#endif
            instance = PsLookupModuleInstanceByImageBaseLocked(
                targetWkdProcess, ImageInfo->ImageBase);
            if (!instance) {
                PsModuleAttachProcessLocked(targetWkdProcess,
                    module, ImageInfo->ImageBase, &instance);
            }

            WkdReleasePushLockExclusive(&ctx->Lock);
        }
    }

    /* === AppControl 镜像判定（通知型，对齐 SS AcCheckImageLoad） ===
     * [死代码] 路径黑名单命中增强威胁分 + 指标上报
     * （TsIndicator_Defense_AppControlBlock，Block→High / Audit→Medium，SS 40/15）。
     * 不接入原因：IocAppControl 为存根态（IocAcEnabled 默认关），待接线。 */
    //if (ProcessId != NULL && IocAcEnabled()) {
    //    IOC_AC_VERDICT acVerdict = IocAppControlCheckImageLoad(FullImageName, ProcessId);
    //    if (acVerdict == AcVerdict_Block || acVerdict == AcVerdict_Audit) {
    //        AeReportIndicatorPair(
    //            ProcessId, ProcessId,
    //            TsSourceIOC,
    //            TsIndicator_Defense_AppControlBlock,
    //            (acVerdict == AcVerdict_Block) ? AeThreatSeverityHigh : AeThreatSeverityMedium);
    //    }
    //}

    {
        PWKD_PROCESS sourceWkdProcess = PsLookupWkdProcessByProcessId(PsGetCurrentProcessId());
        if (!sourceWkdProcess) goto Cleanup;

        /* === 调度 L1（(X,X) 自对；Context=PIMAGE_INFO） ===
         * dispatch 尾部 AeEvaluateVerdict 可能触发进程处置（浅层阻断），
         * 从镜像加载上下文调用有重入风险——速率限制已先行，回调激活前不触发。 */
        AeOrchestratorDispatch(sourceWkdProcess, targetWkdProcess,
            WkdMessage_SourceImageCallback,
            WkdMessage_ImageLoaded,
            ImageInfo);

        PsDereferenceWkdProcess(sourceWkdProcess);
    }

    /* === 决策分支（2026-08-09）：白名单 / 签名 → 不推 agent 全量 ===
     * 采集持久化（PsFindOrCreateModule + PsModuleAttachProcessLocked）+ L1 检测
     * （AeOrchestratorDispatch）已恒执行。
     * 白名单（内置目录前缀）或 CI 签名有效 → 不推 agent；
     * 无签名或非白名单 → 无条件推 agent 全量校验（L2 兜底）。
     * 事实位：module->ImageProperties 位域（文件级）+ viewFlags（每映射）+ Facts（内容固有）
     * → IMG_INDICATOR_* 线格式位。 */
    // whitelisted = ImgpIsWhitelistedPath(FullImageName);
    

    //if (!whitelisted && !(sigEval && sigStatus == IMG_SIGNATURE_VALID)) {
    //    factFlags = 0;
    //    if (module != NULL) {
    //        if (module->ImageProperties.SystemModule)  factFlags |= IMG_INDICATOR_SYSTEM_MODULE;
    //        if (module->ImageProperties.KernelMode)    factFlags |= IMG_INDICATOR_SYSTEM_MODULE;
    //        if (module->Facts.HasDotNet)               factFlags |= IMG_INDICATOR_DOTNET;
    //        if (module->Facts.HasSecurityDirectory)    factFlags |= IMG_INDICATOR_SECURITY_DIR;
    //        if (module->Facts.HasTlsCallbacks)         factFlags |= IMG_INDICATOR_TLS_CALLBACK;
    //    }
    //    if (viewFlags & WKD_MODULE_VIEW_UNBACKED)      factFlags |= IMG_INDICATOR_UNBACKED;

        CbpNotifyImageLoad(PsGetCurrentProcessId(), ProcessId, module, ImageInfo);
    // }

Cleanup:
    if (normalizedImagePath->Buffer) ExFreePool(normalizedImagePath->Buffer);
    if (normalizedImagePath) ExFreePool(normalizedImagePath);
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);
    if (module) PsDereferenceWkdModule(module);
}

// ============================================================================
// 公共 API
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CbInitializeImageNotify(
    VOID
    )
{
    // pfnSeGetCachedSigningLevel 已统一由 Common/ExportParser 在 DriverEntry
    // 早期解析，此处直接使用（可能为 NULL，调用点自行判空降级）。

    NTSTATUS status = PsSetLoadImageNotifyRoutine(CbImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbInitializeImageNotify failed: 0x%X\n", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Image load notify registered.\n");
    }
    return status;
}

_Use_decl_annotations_
VOID
ImgNotifyCleanup(
    VOID
    )
{
    PsRemoveLoadImageNotifyRoutine(CbImageNotifyCallback);
}

/* 2026-08-11：ImgNotifyProcessTerminated 死代码已删除——模块追踪清理统一由
 * PspDestroyProcess → PsDestroyWkdModuleContext（ProcessMonitor.c）覆盖（原函数无调用者）。 */

#pragma warning(push)
#pragma warning(disable:4505)   /* 死代码区：static 未引用告警 */

// ============================================================================
// 死代码区 — 功能面全量覆盖（对齐 SS ImageNotify.c 行号），不接入流水线
// ============================================================================
//
// 统一标注格式：// [死代码][SS ImageNotify.c:行号 对齐] 功能名 + 不接入原因。
// 死代码全部 static，保证可编译无链接错误。
//

// ============================================================================
// [死代码][SS ImageNotify.c:107-148 对齐] 引导阶段关键镜像跳过
// 不接入原因：L0 引导抑制（防灰屏）当前为注释态（回调内 if 未启用），
// 待"服务未连接跳过"通道（ShadowStrikeIsServiceConnected 等价物）接入后激活。
// ============================================================================

static const PCWSTR g_CriticalBootImages[] = {
    L"\\smss.exe",
    L"\\csrss.exe",
    L"\\wininit.exe",
    L"\\services.exe",
    L"\\lsass.exe",
    L"\\winlogon.exe",
    L"\\userinit.exe",
    L"\\explorer.exe",
    L"\\dwm.exe",
    L"\\sihost.exe",
    L"\\fontdrvhost.exe",
    L"\\LogonUI.exe",
};

static
BOOLEAN
ImgpIsCriticalBootImage(
    _In_opt_ PCUNICODE_STRING FullImageName
    )
/*++
    判断镜像是否为引导阶段关键系统 EXE（对齐 PS ShadowStrikeImgIsLoadingCriticalBootImage）。
--*/
{
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0) {
        return FALSE;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_CriticalBootImages); i++) {
        UNICODE_STRING needle;
        RtlInitUnicodeString(&needle, g_CriticalBootImages[i]);

        if (FullImageName->Length < needle.Length) continue;

        UNICODE_STRING tail;
        tail.Buffer = (PWCH)((PUCHAR)FullImageName->Buffer +
                             (FullImageName->Length - needle.Length));
        tail.Length = needle.Length;
        tail.MaximumLength = needle.Length;

        if (RtlEqualUnicodeString(&tail, &needle, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// [死代码][SS ImageNotify.c:291-367 对齐] 死代码全局状态
//
typedef struct _IMG_NOTIFY_DEAD_STATE {
    IMG_NOTIFY_CONFIG Config;
    IMG_NOTIFY_STATISTICS Stats;
    LIST_ENTRY VulnerableDriverHash[64];
    volatile LONG VulnerableDriverCount;
    LIST_ENTRY HashCacheBuckets[256];
    volatile LONG HashCacheCount;
} IMG_NOTIFY_DEAD_STATE, *PIMG_NOTIFY_DEAD_STATE;

static IMG_NOTIFY_DEAD_STATE g_ImgDead = { 0 };

// ============================================================================
// [死代码][SS ImageNotify.c:3615 对齐] 脆弱驱动哈希
// 不接入原因：依赖缺失（驱动无密码学能力，脆弱驱动哈希比对归 agent，架构决策 #30）
// ============================================================================

static
ULONG
ImgpHashVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash
    )
{
    ULONG hash;
    RtlCopyMemory(&hash, Sha256Hash, sizeof(ULONG));
    return hash % 64;
}

// ============================================================================
// [死代码][SS ImageNotify.c:1276-1413 对齐] BYOVD 脆弱驱动库
// 不接入原因：依赖缺失（驱动无密码学能力，脆弱驱动哈希比对归 agent，架构决策 #30）。
// Agent 侧可由镜像哈希查 SQLite ioc_hashes / 脆弱驱动表覆盖。
// ============================================================================

static
NTSTATUS
ImgNotifyAddVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash,
    _In_ PCWSTR DriverName,
    _In_opt_ PCSTR CveId
    )
{
    PIMG_VULNERABLE_DRIVER_ENTRY entry;
    ULONG bucket;

    if (Sha256Hash == NULL || DriverName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PIMG_VULNERABLE_DRIVER_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(IMG_VULNERABLE_DRIVER_ENTRY), WKD_IMG_POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(entry->Sha256Hash, Sha256Hash, 32);
    RtlStringCchCopyW(entry->DriverName, 64, DriverName);
    entry->CveId[0] = '\0';
    if (CveId != NULL) {
        RtlStringCchCopyA(entry->CveId, 32, CveId);
    }

    bucket = ImgpHashVulnerableDriver(Sha256Hash);
    InsertTailList(&g_ImgDead.VulnerableDriverHash[bucket], &entry->HashEntry);
    InterlockedIncrement(&g_ImgDead.VulnerableDriverCount);

    return STATUS_SUCCESS;
}

static
NTSTATUS
ImgNotifyRemoveVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash
    )
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PIMG_VULNERABLE_DRIVER_ENTRY driver;
    PIMG_VULNERABLE_DRIVER_ENTRY found = NULL;

    if (Sha256Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    bucket = ImgpHashVulnerableDriver(Sha256Hash);

    for (entry = g_ImgDead.VulnerableDriverHash[bucket].Flink;
         entry != &g_ImgDead.VulnerableDriverHash[bucket];
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, IMG_VULNERABLE_DRIVER_ENTRY, HashEntry);

        if (RtlCompareMemory(driver->Sha256Hash, Sha256Hash, 32) == 32) {
            RemoveEntryList(&driver->HashEntry);
            InterlockedDecrement(&g_ImgDead.VulnerableDriverCount);
            found = driver;
            break;
        }
    }

    if (found != NULL) {
        ExFreePoolWithTag(found, WKD_IMG_POOL_TAG);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

static
BOOLEAN
ImgNotifyIsVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash
    )
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PIMG_VULNERABLE_DRIVER_ENTRY driver;
    BOOLEAN found = FALSE;

    if (Sha256Hash == NULL) {
        return FALSE;
    }

    bucket = ImgpHashVulnerableDriver(Sha256Hash);

    for (entry = g_ImgDead.VulnerableDriverHash[bucket].Flink;
         entry != &g_ImgDead.VulnerableDriverHash[bucket];
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, IMG_VULNERABLE_DRIVER_ENTRY, HashEntry);

        if (RtlCompareMemory(driver->Sha256Hash, Sha256Hash, 32) == 32) {
            found = TRUE;
            break;
        }
    }
    return found;
}

// ============================================================================
// [死代码][SS ImageNotify.c:3630 对齐] 文件 ID 哈希
// 不接入原因：集中哈希缓存归 agent（架构决策 #30）。
// ============================================================================

static
ULONG
ImgpHashFileId(
    _In_ ULONG64 FileId
    )
{
    ULONG hash = (ULONG)(FileId ^ (FileId >> 32));
    return hash % 256;
}

// ============================================================================
// [死代码][SS ImageNotify.c:1737-1962 对齐] 集中哈希缓存（FileId→SHA256）
// 不接入原因：集中哈希缓存归 agent（架构决策 #30），驱动不建 FileId→hash 缓存。
// 参考 wkd agent ScanManager g_ScanCache 的固定数组缓存模式。
// ============================================================================

static
BOOLEAN
ImgNotifyLookupCachedHash(
    _In_ ULONG64 FileId,
    _In_ PLARGE_INTEGER LastWriteTime,
    _Out_writes_bytes_(32) PUCHAR Sha256Hash
    )
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PIMG_HASH_CACHE_ENTRY cacheEntry;
    LARGE_INTEGER currentTime;
    BOOLEAN found = FALSE;

    if (FileId == 0 || LastWriteTime == NULL || Sha256Hash == NULL) {
        return FALSE;
    }

    bucket = ImgpHashFileId(FileId);
    KeQuerySystemTime(&currentTime);

    for (entry = g_ImgDead.HashCacheBuckets[bucket].Flink;
         entry != &g_ImgDead.HashCacheBuckets[bucket];
         entry = entry->Flink) {

        cacheEntry = CONTAINING_RECORD(entry, IMG_HASH_CACHE_ENTRY, HashListEntry);

        if (cacheEntry->FileId == FileId &&
            cacheEntry->LastWriteTime.QuadPart == LastWriteTime->QuadPart &&
            cacheEntry->IsValid) {

            LONG64 ageSeconds = (currentTime.QuadPart - cacheEntry->CacheTime.QuadPart) / 10000000LL;
            if (ageSeconds < 300) {   /* IMG_CACHE_TTL_SECONDS */
                RtlCopyMemory(Sha256Hash, cacheEntry->Sha256Hash, 32);
                found = TRUE;
            }
            break;
        }
    }
    return found;
}

static
NTSTATUS
ImgNotifyAddCachedHash(
    _In_ ULONG64 FileId,
    _In_ PLARGE_INTEGER LastWriteTime,
    _In_reads_bytes_(32) PUCHAR Sha256Hash,
    _In_reads_bytes_opt_(20) PUCHAR Sha1Hash,
    _In_reads_bytes_opt_(16) PUCHAR Md5Hash
    )
{
    PIMG_HASH_CACHE_ENTRY cacheEntry;

    if (FileId == 0 || LastWriteTime == NULL || Sha256Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    cacheEntry = (PIMG_HASH_CACHE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(IMG_HASH_CACHE_ENTRY), WKD_IMG_EVENT_TAG);
    if (cacheEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cacheEntry, sizeof(IMG_HASH_CACHE_ENTRY));
    cacheEntry->FileId = FileId;
    cacheEntry->LastWriteTime = *LastWriteTime;
    KeQuerySystemTime(&cacheEntry->CacheTime);
    RtlCopyMemory(cacheEntry->Sha256Hash, Sha256Hash, 32);
    if (Sha1Hash != NULL) RtlCopyMemory(cacheEntry->Sha1Hash, Sha1Hash, 20);
    if (Md5Hash != NULL) RtlCopyMemory(cacheEntry->Md5Hash, Md5Hash, 16);
    cacheEntry->IsValid = TRUE;
    cacheEntry->RefCount = 1;

    InsertTailList(&g_ImgDead.HashCacheBuckets[ImgpHashFileId(FileId)],
                   &cacheEntry->HashListEntry);
    InterlockedIncrement(&g_ImgDead.HashCacheCount);

    return STATUS_SUCCESS;
}

// ============================================================================
// [死代码][SS ImageNotify.c:1907-1955 对齐] 哈希缓存 TTL 清理（PurgeHashCache）
// 不接入原因：集中哈希缓存归 agent（架构决策 #30）。
// ============================================================================

static
VOID
ImgNotifyPurgeHashCache(
    VOID
    )
{
    ULONG i;
    PLIST_ENTRY entry, next;
    PIMG_HASH_CACHE_ENTRY cacheEntry;
    LARGE_INTEGER currentTime;
    LIST_ENTRY purgeList;

    InitializeListHead(&purgeList);
    KeQuerySystemTime(&currentTime);

    for (i = 0; i < 256; i++) {   /* IMG_HASH_BUCKET_COUNT */
        for (entry = g_ImgDead.HashCacheBuckets[i].Flink;
             entry != &g_ImgDead.HashCacheBuckets[i];
             entry = next) {

            next = entry->Flink;
            cacheEntry = CONTAINING_RECORD(entry, IMG_HASH_CACHE_ENTRY, HashListEntry);

            LONG64 ageSeconds =
                (currentTime.QuadPart - cacheEntry->CacheTime.QuadPart) / 10000000LL;

            if (ageSeconds >= 300) {   /* IMG_CACHE_TTL_SECONDS */
                RemoveEntryList(&cacheEntry->HashListEntry);
                InsertTailList(&purgeList, &cacheEntry->HashListEntry);
                InterlockedDecrement(&g_ImgDead.HashCacheCount);
            }
        }
    }

    /* 锁外释放（对齐 PS 分离 purgeList 模式） */
    while (!IsListEmpty(&purgeList)) {
        entry = RemoveHeadList(&purgeList);
        cacheEntry = CONTAINING_RECORD(entry, IMG_HASH_CACHE_ENTRY, HashListEntry);
        ExFreePoolWithTag(cacheEntry, WKD_IMG_EVENT_TAG);
    }
}

// ============================================================================
// [死代码][SS ImageNotify.c:3718-3781 对齐] 镜像哈希计算
// 不接入原因：依赖缺失——驱动无 BCrypt(CNG) 封装（SS 底层用 FIPS CNG provider），
// 哈希归 agent（架构决策 #30）。IocAppControl 哈希黑名单亦因缺 SHA256 恒传 NULL。
// ============================================================================

static
NTSTATUS
ImgpComputeImageHash(
    _In_ PIMAGE_INFO ImageInfo,
    _Out_writes_bytes_(32) PUCHAR Sha256Hash
    )
{
    UNREFERENCED_PARAMETER(ImageInfo);
    UNREFERENCED_PARAMETER(Sha256Hash);
    return STATUS_NOT_IMPLEMENTED;   /* 待驱动 SHA256 能力 */
}

// ============================================================================
// [死代码][SS ImageNotify.c:2287-2316 对齐] IOC 哈希匹配段
// 不接入原因：wkd 驱动无 IOCMatcher 基础设施（架构决策 #30），哈希 IOC 匹配
// 归 agent IocMatcher_MatchHash + SQLite ioc_hashes。IOC 匹配证据链经
// AeReportIndicatorPair 完成。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:2398-2560 对齐] 进程镂空检测
// 不接入原因：无 HollowingDetector/MemoryMonitor 组件；EP 校验已由 L1
// IocImage.c（TsIndicator_Image_EntrypointOutsideCode，0x0A09）覆盖。
// 深度镂空检测归 agent 机制 B（MsHandleKernelImageLoad 无背衬判定 +
// IoaInjectionClassifier 镂空分类）。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:2574-2627 对齐] Section 追踪
// 不接入原因：无 SectionTracker 组件；架构冲突——wkd 可执行内存远程映射由
// Syscall 层第 2 层无条件同步阻塞覆盖（SmInitialize 激活后）。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:1100-1274 / 3513-3610 对齐] 回调注册表
// 不接入原因：无内部订阅者，注册 API 无调用方；wkd 事件分配直接 ExAllocatePool2，
// 事件分发走编排器 + ALPC 路由。SS 通用 PreLoad/PostLoad 回调机制废弃。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:549-583 / 1040-1092 对齐] 配置结构
// 不接入原因：wkd 配置走 agent 推送通道（同 IocAppControlSetPolicyMode 模式），
// 本文件无配置入口。IMG_NOTIFY_CONFIG 定义于 ImageNotify.h 死代码区。
// ============================================================================

static
VOID
ImgNotifyInitDefaultConfig(
    _Out_ PIMG_NOTIFY_CONFIG Config
    )
{
    if (Config == NULL) return;

    RtlZeroMemory(Config, sizeof(IMG_NOTIFY_CONFIG));
    Config->Size = sizeof(IMG_NOTIFY_CONFIG);
    Config->Version = (1 << 16) | 1;
    Config->EnablePeAnalysis = TRUE;
    Config->EnableHashComputation = TRUE;
    Config->EnableSuspiciousDetection = TRUE;
    Config->EnableDriverMonitoring = TRUE;
    Config->EnableVulnerableDriverCheck = TRUE;
    Config->EnableModuleTracking = TRUE;
    Config->MonitorSystemProcesses = TRUE;
    Config->MonitorKernelImages = TRUE;
    Config->MinThreatScoreToReport = 30;
    Config->HighEntropyThreshold = 700;
    Config->MaxEventsPerSecond = IMG_DEFAULT_MAX_EVENTS_PER_SEC;
    Config->MaxFileSizeForHash = 100 * 1024 * 1024;
    Config->HashTimeoutMs = 5000;
}

// ============================================================================
// [死代码][SS ImageNotify.c:1421-1488 对齐] 统计读取/重置
// 不接入原因：统计随配置走 agent 查询通道；IMG_NOTIFY_STATISTICS 定义于 .h 死代码区。
// ============================================================================

static
NTSTATUS
ImgNotifyGetStatistics(
    _Out_ PIMG_NOTIFY_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 原子读取防撕裂（对齐 PS 用 InterlockedCompareExchange64 读 volatile） */
    Stats->TotalImagesLoaded = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.TotalImagesLoaded, 0, 0);
    Stats->UserModeImages = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.UserModeImages, 0, 0);
    Stats->KernelModeImages = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.KernelModeImages, 0, 0);
    Stats->SignedImages = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.SignedImages, 0, 0);
    Stats->UnsignedImages = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.UnsignedImages, 0, 0);
    Stats->SuspiciousImages = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.SuspiciousImages, 0, 0);
    Stats->BlockedImages = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.BlockedImages, 0, 0);
    Stats->HashesComputed = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.HashesComputed, 0, 0);
    Stats->PeAnalyses = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.PeAnalyses, 0, 0);
    Stats->CacheHits = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.CacheHits, 0, 0);
    Stats->CacheMisses = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.CacheMisses, 0, 0);
    Stats->EventsDropped = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.EventsDropped, 0, 0);
    Stats->CallbackErrors = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.CallbackErrors, 0, 0);
    Stats->ModulesTracked = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ImgDead.Stats.ModulesTracked, 0, 0);
    Stats->StartTime = g_ImgDead.Stats.StartTime;

    return STATUS_SUCCESS;
}

static
VOID
ImgNotifyResetStatistics(
    VOID
    )
{
    InterlockedExchange64(&g_ImgDead.Stats.TotalImagesLoaded, 0);
    InterlockedExchange64(&g_ImgDead.Stats.UserModeImages, 0);
    InterlockedExchange64(&g_ImgDead.Stats.KernelModeImages, 0);
    InterlockedExchange64(&g_ImgDead.Stats.SignedImages, 0);
    InterlockedExchange64(&g_ImgDead.Stats.UnsignedImages, 0);
    InterlockedExchange64(&g_ImgDead.Stats.SuspiciousImages, 0);
    InterlockedExchange64(&g_ImgDead.Stats.BlockedImages, 0);
    InterlockedExchange64(&g_ImgDead.Stats.HashesComputed, 0);
    InterlockedExchange64(&g_ImgDead.Stats.PeAnalyses, 0);
    InterlockedExchange64(&g_ImgDead.Stats.CacheHits, 0);
    InterlockedExchange64(&g_ImgDead.Stats.CacheMisses, 0);
    InterlockedExchange64(&g_ImgDead.Stats.EventsDropped, 0);
    InterlockedExchange64(&g_ImgDead.Stats.CallbackErrors, 0);
    InterlockedExchange64(&g_ImgDead.Stats.ModulesTracked, 0);
    KeQuerySystemTime(&g_ImgDead.Stats.StartTime);
}

// ============================================================================
// [死代码][SS ImageNotify.c:1495-1677 对齐] 模块查询 API（QueryProcessModules/IsModuleLoaded）
// 不接入原因：SS 独立模块表（IMG_PROCESS_MODULES 双链表+哈希桶）由 wkd
// ProcessModuleTracker(Mt*) 覆盖——PsLookupModuleInstanceByImageBaseLocked/MtFindModuleByPath 单查已等价；
// 批量导出（QueryProcessModules 全量拷贝到调用者数组）与按名查询（IsModuleLoaded）
// 无调用方，不迁。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:2219 对齐] 校验和无效 → 异常区段（AbnormalSections）
// 不接入原因：wkd WKD_IMG_PE_BASIC 无线格式校验和字段（fold-add 计算+比对未接入），
// 且为线格式零变更约束不得增字段；校验和异常信号归 agent 侧 PE 深度验证
// （WpeValidate 校验和 fold-add 已覆盖）。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:591-1032 对齐] Init 状态机 + 生命周期
// 不接入原因：wkd 子系统生命周期由 WkdEntry 统一管理，SS 自持原子状态机 +
// EX_RUNDOWN_REF 与 wkd 初始化模型冲突。实际注册由 CbInitializeImageNotify 完成。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:87-90 / 2011-2019 对齐] 服务连接检查
// 不接入原因：wkd ALPC 无连接状态查询 API（异步发送不阻塞，无灰屏风险），
// 保留回调内 TODO 注释。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:2309-2331 对齐] 签名统计（Signed/Unsigned）
// 不接入原因：无 CI 签名验证（SeVerifyImageFileEx 未接入），Signed/Unsigned 标志
// 无来源；未签名 20 分档随之死代码。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:3655-3713 对齐] 区段熵算法（ImgpCalculateSectionEntropy）
// 不接入原因：2026-08-09 镜像职责收敛——熵计算彻底归 agent（IocScanner 启发式
// /PeAnalyzer 计算，线格式 WKD_IMG_PE_BASIC 已去熵字段），驱动 L0 采集不再请求熵
// （WKD_PE_FLAG_ENTROPY 已移除）。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:2820-2828 对齐] ImgpPopulateEvent 进程可执行路径上送
// 不接入原因：线格式 WKD_MESSAGE_BODY_IMAGE_LOAD 零变更约束，不得增 ProcessImagePath
// 字段；agent 侧进程表 IpeCollectUserContext 已能从 ProcessId 查进程路径，覆盖。
// ============================================================================

// ============================================================================
// [死代码][SS ImageNotify.c:2633-2676 对齐] BehaviorEngine 事件三分类
// （ReflectiveDLLLoad / ModuleStomping / DLLHijacking）
// 不接入原因：wkd dispatch 统一走 IocDetectImage（按 IMG_INDICATOR_* 映射
// TsIndicator_Image_*），不区分三注入方式；注入分类归 agent IoaInjectionClassifier
// （ReflectiveDLL/镂空/APC/SetContext 等 9 模式）。
// ============================================================================

#pragma warning(pop)
