/**************************************************/
/*  WkDefender Agent — 进程域模块挂载实现           */
/*                                                  */
/*  2026-08-15 新增。全局唯一镜像对象 + 进程私有视图。*/
/*  生命周期同构驱动 ProcessModuleTracker.c。         */
/**************************************************/

#include "ProcessModule.h"
#include "ProcessTree.h"
#include "../tools.h"
#include "../Common/Utils.h"

/* 全局模块表 */
WKD_MODULE_TABLE g_WkdModuleTable;

/**************************************************/
/*               内部辅助函数                       */
/**************************************************/

/**************************************************/
/*            模块上下文惰性申请                   */
/**************************************************/

static
PWKD_MODULE_CONTEXT
PspCreateModuleContextLazy(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    惰性分配并发布进程模块上下文（二次原子写）。
    指针为 NULL 时堆分配 + 初始化链表头 + 初始化 SRWLOCK，
    经 InterlockedCompareExchangePointer 发布；输家释放本地副本。
    Context 指针的发布自带 release 语义，读者 acquire 见非 NULL 即完整。

Arguments:
    Process — 进程节点。

Return Value:
    已发布的模块上下文指针（可能 NULL，仅当分配失败）。
--*/
{
    if (!WkdProcess) return NULL;
    if (!InterlockedCompareExchangePointer(&WkdProcess->ModuleContext, NULL, NULL)) {
        PWKD_MODULE_CONTEXT ctx = malloc(sizeof(WKD_MODULE_CONTEXT));
        if (!ctx) return NULL;
        RtlZeroMemory(ctx, sizeof(WKD_MODULE_CONTEXT));

        InitializeListHead(&ctx->ModuleList);
        ctx->ProcessId = WkdProcess->ProcessId;
        InitializeSRWLock(&ctx->Lock);
        if (InterlockedCompareExchangePointer(
                &WkdProcess->ModuleContext, ctx, NULL) != NULL) {
            free(ctx);   /* 输家释放本地副本 */
        }
    }
    return WkdProcess->ModuleContext;
}

static
WKD_IMAGE_TYPE
PspDetermineImageType(
    _In_ PCWSTR ImagePath
    )
{
    PCWSTR dot;
    
    if (!CoCheckStringValidity(ImagePath)) return WkdImageType_Unknown;

    dot = wcsrchr(ImagePath, L'.');
    if (dot) {
        /* 不区分大小写地比较两个宽字符串 */
        if (_wcsicmp(dot, L".exe") == 0) return WkdImageType_Exe;
        if (_wcsicmp(dot, L".dll") == 0) return WkdImageType_Dll;
        if (_wcsicmp(dot, L".sys") == 0) return WkdImageType_Sys;
        if (_wcsicmp(dot, L".ocx") == 0) return WkdImageType_Ocx;
        if (_wcsicmp(dot, L".cpl") == 0) return WkdImageType_Cpl;
        if (_wcsicmp(dot, L".scr") == 0) return WkdImageType_Scr;
        if (_wcsicmp(dot, L".drv") == 0) return WkdImageType_Drv;
    }
    return WkdImageType_Unknown;
}

static
VOID
PmExtractFacts(
    _In_ PPE_INFO Info,
    _Out_ PWKD_MODULE_PE_FACTS Facts
    )
{
    RtlZeroMemory(Facts, sizeof(WKD_MODULE_PE_FACTS));
    if (!Info || !Info->Valid) return;

    Facts->Valid                = TRUE;
    Facts->Amd64                = Info->Amd64;
    Facts->IsDll                = Info->IsDll;
    Facts->IsDriver             = Info->IsDriver;
    Facts->IsSystem             = FALSE;   /* agent 用户态不判定 */
    Facts->EntryPointInCode     = Info->EntryPointInExecutableSection;
    Facts->HasWxSection         = FALSE;   /* 下方遍历 Sections 填充 */
    Facts->HasNoExports         = (Info->DataDirectories[0].Rva == 0);  /* 导出目录 */
    Facts->HasDotNet            = Info->IsDotNet;
    Facts->HasSecurityDirectory = (Info->DataDirectories[4].Rva != 0);  /* 安全目录 */
    Facts->HasTlsCallbacks      = (Info->DataDirectories[9].Rva != 0);  /* TLS 目录 */
    Facts->NumberOfSections     = (USHORT)Info->NumberOfSections;
    Facts->AddressOfEntryPoint  = Info->AddressOfEntryPoint;
    Facts->ImageBase            = Info->ImageBase;
    Facts->TimeDateStamp        = Info->TimeDateStamp;
    Facts->CheckSum             = Info->Checksum;

    /* HasWxSection + SectionMask[3]（对齐驱动 Facts 语义）：
     * 遍历节表查 EXECUTE|WRITE（WX）区段，SectionMask bit i = 第 i 区段 WX。
     * WPE_SECTION.IsExecutable/IsWritable 已由解析器填充（节特征位）。 */
    if (Info->NumberOfSections > 0) {
        for (ULONG i = 0; i < Info->NumberOfSections && i < WKD_MT_PE_SECTION_MASK_BITS; i++) {
            if (Info->Sections[i].IsExecutable && Info->Sections[i].IsWritable) {
                Facts->HasWxSection = TRUE;
                Facts->SectionMask[i / 32] |= (1UL << (i % 32));
            }
        }
    }
}

static
VOID
PmExtractCertInfo(
    _In_  PIOC_SCAN_RESULT Result,
    _Out_ PWKD_CERT_INFO    CertInfo
    )
/*++
Routine Description:
    从 IOC_SCAN_RESULT 证书字段拷贝到 WKD_CERT_INFO（模块权威副本）。
    证书验证在模块构建期独立执行（不依赖 PE 解析成败）。

Arguments:
    Result   - 已验签的 IOC_SCAN_RESULT（IocVerifySignature 输出）。
    CertInfo - 输出模块内嵌证书信息。

Return Value:
    无。
--*/
{
    RtlZeroMemory(CertInfo, sizeof(WKD_CERT_INFO));
    if (!Result || !CertInfo) return;

    /* 状态组 */
    CertInfo->CertStatus  = Result->CertStatus;
    CertInfo->CertValid   = Result->CertValid;
    CertInfo->CertTrusted = Result->CertTrusted;
    CertInfo->CertScore   = Result->CertScore;

    /* 详情组 */
    wcsncpy_s(CertInfo->SignerName, RTL_NUMBER_OF(CertInfo->SignerName),
              Result->SignerName, _TRUNCATE);
    wcsncpy_s(CertInfo->IssuerName, RTL_NUMBER_OF(CertInfo->IssuerName),
              Result->IssuerName, _TRUNCATE);
    memcpy(CertInfo->Thumbprint, Result->Thumbprint, sizeof(CertInfo->Thumbprint));
    CertInfo->CertValidFrom = Result->CertValidFrom;
    CertInfo->CertValidTo   = Result->CertValidTo;
    for (ULONG i = 0; i < 16; i++) {
        wcsncpy_s(CertInfo->ChainName[i], RTL_NUMBER_OF(CertInfo->ChainName[i]),
                  Result->ChainName[i], _TRUNCATE);
        memcpy(CertInfo->ChainThumbprint[i], Result->ChainThumbprint[i],
               sizeof(CertInfo->ChainThumbprint[i]));
    }
    CertInfo->ChainDepth     = Result->ChainDepth;
    CertInfo->IsTrustedStrict = Result->IsTrustedStrict;

    /* 深度校验组 */
    CertInfo->IsSelfSigned        = Result->IsSelfSigned;
    CertInfo->IsCodeSigningEku    = Result->IsCodeSigningEku;
    CertInfo->IsWhql              = Result->IsWhql;
    CertInfo->IsDualSigned        = Result->IsDualSigned;
    memcpy(CertInfo->SignatureAlgorithm, Result->SignatureAlgorithm,
           sizeof(CertInfo->SignatureAlgorithm));
    CertInfo->IsWeakSignature     = Result->IsWeakSignature;
    CertInfo->IsRevocationChecked = Result->IsRevocationChecked;
    CertInfo->SignTime            = Result->SignTime;
    memcpy(CertInfo->CatalogName, Result->CatalogName, sizeof(CertInfo->CatalogName));

    /* 信誉组 */
    CertInfo->SignerReputation    = Result->SignerReputation;
    CertInfo->SignerCategory      = Result->SignerCategory;
    CertInfo->IsEvCert            = Result->IsEvCert;
    CertInfo->CertReputationAdjust = Result->CertReputationAdjust;
}

/* 从 IOC_SCAN_RESULT 抽离 PE 分析字段到 WKD_PE_ANALYSIS（模块权威副本，
 * 2026-08-18 阶段3）。深度分析完成后调用。进程级字段（Cmdline/Yara）不抽。 */
VOID
PmExtractPeAnalysis(
    _In_  PIOC_SCAN_RESULT  Result,
    _Out_ PWKD_PE_ANALYSIS  PeAnalysis
    )
{
    RtlZeroMemory(PeAnalysis, sizeof(WKD_PE_ANALYSIS));
    if (!Result || !PeAnalysis) return;

    /* LOLBin */
    PeAnalysis->IsLolbin = Result->IsLolbin;
    PeAnalysis->LolbinConfidence = Result->LolbinConfidence;

    /* PE 头异常 */
    PeAnalysis->HasSuspiciousSections = Result->HasSuspiciousSections;
    PeAnalysis->HasSuspiciousImports = Result->HasSuspiciousImports;

    /* 导入 */
    PeAnalysis->ImportSuspiciousCount = Result->ImportSuspiciousCount;
    PeAnalysis->HasDynamicLoading = Result->HasDynamicLoading;
    memcpy(PeAnalysis->ImpHash, Result->ImpHash, sizeof(PeAnalysis->ImpHash));
    memcpy(PeAnalysis->ImpHashStandard, Result->ImpHashStandard,
           sizeof(PeAnalysis->ImpHashStandard));

    /* 加壳 */
    PeAnalysis->IsPacked = Result->IsPacked;
    memcpy(PeAnalysis->PackerName, Result->PackerName, sizeof(PeAnalysis->PackerName));

    /* 字符串/启发式 */
    PeAnalysis->StringScore = Result->StringScore;
    PeAnalysis->HeuristicRan = Result->HeuristicRan;
    PeAnalysis->HeuristicConfidence = Result->HeuristicConfidence;
    memcpy(PeAnalysis->ThreatName, Result->ThreatName, sizeof(PeAnalysis->ThreatName));

    /* 静态解包闭环 */
    PeAnalysis->UnpackAttempted = Result->UnpackAttempted;
    PeAnalysis->Unpacked = Result->Unpacked;
    PeAnalysis->UnpackedSize = Result->UnpackedSize;
    memcpy(PeAnalysis->UnpackedHash, Result->UnpackedHash,
           sizeof(PeAnalysis->UnpackedHash));
    PeAnalysis->UnpackedEntropy = Result->UnpackedEntropy;
    PeAnalysis->UnpackedEntryPointRva = Result->UnpackedEntryPointRva;

    /* 文件类型/欺骗 */
    PeAnalysis->FileFormat = Result->FileFormat;
    PeAnalysis->FileCategory = Result->FileCategory;
    PeAnalysis->RiskLevel = Result->RiskLevel;
    PeAnalysis->IsSpoofed = Result->IsSpoofed;
    PeAnalysis->SpoofingType = Result->SpoofingType;
    wcsncpy_s(PeAnalysis->SuggestedExtension,
              RTL_NUMBER_OF(PeAnalysis->SuggestedExtension),
              Result->SuggestedExtension, _TRUNCATE);

    /* 签名狩猎 */
    PeAnalysis->SignatureHunt = Result->SignatureHunt;
    PeAnalysis->SigHuntRan = Result->SignatureHunt.Ran;

    /* 综合 */
    PeAnalysis->FinalVerdict = Result->FinalVerdict;
    PeAnalysis->FinalConfidence = Result->FinalConfidence;
    PeAnalysis->EvidenceCount = Result->EvidenceCount;
    PeAnalysis->HashChecked = Result->HashChecked;
    PeAnalysis->HashVerdict = Result->HashVerdict;
    PeAnalysis->HashConfidence = Result->HashConfidence;
    PeAnalysis->Reputation = Result->Reputation;
}

/* 判断模块是否仍对应磁盘当前文件版本（mtime 防替换，业务层，2026-08-20
 * 阶段5 起锁外调用——GetFileAttributesExW 为磁盘 syscall，禁止锁内）。
 * 模块 LastWriteTime==0（构建期取失败）→ 无法校验，保守返回 TRUE（复用）。
 * 当前文件 mtime 获取失败 → 同样保守返回 TRUE（不因 mtime 失败而误重建）。
 * 仅在两者均有效且不等时返回 FALSE（文件被替换，应重建模块）。 */
static
BOOLEAN
PmIsModuleCurrent(
    _In_ PCWSTR    ImagePath,
    _In_ PWKD_MODULE Module
    )
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    LARGE_INTEGER curMtime;

    if (!ImagePath || !Module) return FALSE;
    if (Module->LastWriteTime.QuadPart == 0) return TRUE;   /* 构建期取失败，保守复用 */

    if (!GetFileAttributesExW(ImagePath, GetFileExInfoStandard, &fad)) return TRUE;

    curMtime.LowPart  = fad.ftLastWriteTime.dwLowDateTime;
    curMtime.HighPart = (LONG)fad.ftLastWriteTime.dwHighDateTime;
    return (Module->LastWriteTime.QuadPart == curMtime.QuadPart);
}

static
NTSTATUS
PspCreateModule(
    _In_ PCWSTR ImagePath,
    _In_opt_ SIZE_T ImageSize,
    _In_ UCHAR SignatureStatus,
    _Out_ PWKD_MODULE* Module
    )
{
    NTSTATUS status;
    PWKD_MODULE module;
    PE_INFO info;
    UNICODE_STRING localImagePath;
    PUNICODE_STRING copyImagePath;

    /* 未知映射大小，宽松Identity，ImageSize无需校验 */
    if (!CoCheckStringValidity(ImagePath) || !Module) {
        return STATUS_INVALID_PARAMETER;
    }
    *Module = NULL;

    module = malloc(sizeof(WKD_MODULE));
    if (!module) return STATUS_NO_MEMORY;
    RtlZeroMemory(module, sizeof(WKD_MODULE));

    module->RefCount = 1; /* 返回给调用者 */
    module->ImageSize = ImageSize;
    module->SignatureStatus = SignatureStatus;
    module->AnalysisState = WKD_MODULE_ANALYSIS_CREATED;   /* 构建完成=轻量判定可得（2026-08-18） */
    module->CompleteEvent = NULL;
    module->FileResult = NULL;
    module->ImageType = PspDetermineImageType(ImagePath);   /* 这里没有深入检查文件的魔术签名??? */

    /* 原始路径副本（非表 key；表 key = 原始路径字节，与
     * PsDereferenceWkdModule 摘表 key 同源一致）。 */
    RtlInitUnicodeString(&localImagePath, ImagePath);
    status = CoCopyUnicodeString(&copyImagePath, &localImagePath);
    if (!NT_SUCCESS(status)) goto Cleanup;
    module->ImagePath = copyImagePath;

    ///* 证书验证（同步，模块构建期独立执行，不依赖 PE 解析成败）：
    // * 2026-08-18 修复原空参调用，统一入口 IocVerifySignature
    // * → WKD_CERT_INFO 模块内嵌权威副本。IocVerifyTrust 内部实现不动。 */
    //{
    //    IOC_SCAN_RESULT result;
    //    RtlZeroMemory(&result, sizeof(IOC_SCAN_RESULT));
    //    if (NT_SUCCESS(IocVerifySignature(ImagePath, &result))) {
    //        PmExtractCertInfo(&result, &module->CertInfo);
    //    } else {
    //        module->CertInfo.CertStatus = DefCertStatus_Unsigned;
    //        module->CertInfo.CertTrusted = FALSE;
    //        module->CertInfo.CertScore = 20;
    //    }
    //}

    //if (NT_SUCCESS(IocAnalyzePe(ImagePath, &info))) {
    //    /* 保留完整 PE 几何快照（含节表/数据目录），供 PmBuildLazyContext
    //     * 重建惰性解析 Ctx，深度分析复用同一次结构解析（2026-08-19）：
    //     * IocHeuristicPeAnalysis 不再对同一文件做第二次完整 PE 解析。 */
    //    module->PeInfo = info;
    //    PmExtractFacts(&info, &module->Facts);
    //    module->SectionAlignment = info.SectionAlignment;
    //    module->FileAlignment    = info.FileAlignment;
    //    module->SizeOfImage      = (ULONG)info.SizeOfImage;
    //    module->DllCharacteristics = info.DllCharacteristics;   /* 补存：PeHeaders 缓解检测免二次读头 */
    //}

    status = CoComputeFileSha256(ImagePath, &module->Sha256);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* 文件末写时间填充（防替换复用，2026-08-18 阶段2）：
     * 构建期取一次，PsFindOrCreateModule 命中兼容比对。
     * 取失败（文件被锁/暂不可读）时置零，命中断不比对（保守复用）。 */
    {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExW(ImagePath, GetFileExInfoStandard, &fad)) {
            module->LastWriteTime.LowPart  = fad.ftLastWriteTime.dwLowDateTime;
            module->LastWriteTime.HighPart = (LONG)fad.ftLastWriteTime.dwHighDateTime;
        } else {
            module->LastWriteTime.QuadPart = 0;
        }
    }
    
    *Module = module;
    return STATUS_SUCCESS;

Cleanup:
    CoFreeUnicodeString(copyImagePath);
    free(module);
    return status;
}

/**************************************************/
/*               生命周期 API                       */
/**************************************************/

NTSTATUS
PmInitialize(
    VOID
    )
{
    if (g_WkdModuleTable.Initialized) return STATUS_SUCCESS;

    /* Common/HashMap（2026-08-20 阶段5）：任意 key 抽象，哈希/比较
     * 表内统一；key=归一化小写路径字节。2026-08-25 强制对称契约:
     * UseRefCallbacks=TRUE, Reference=PmMapReference（Find pin）+
     * Dereference=PmMapDereference（摘表 -1，不释本体——真正释放
     * 由发起摘表的 PsDereferenceWkdModule 锁外 PspDestroyWkdModule 完成，
     * 避免锁内 free 与视图 UAF）。 */
    if (!NT_SUCCESS(CoInitializeHashMap(&g_WkdModuleTable.Map,
                                        WKD_MODULE_TABLE_BUCKETS,
                                        WKD_MODULE_TABLE_MAX_ENTRIES,
                                        FALSE, TRUE,
                                        PsReferenceWkdModule,
                                        NULL,   /* ShouldRemove */
                                        PsDereferenceWkdModule))) {
        return STATUS_UNSUCCESSFUL;
    }
    g_WkdModuleTable.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
PmCleanup(
    VOID
    )
{
    if (!g_WkdModuleTable.Initialized) return;

    /* 残留模块对象（卸载罕见路径）：与驱动 MtCleanup 对齐，跳过释放。
     * 摘除底层残留条目（Dereference=NULL，不触发对象释放）。 */
    CoHashMapClear(&g_WkdModuleTable.Map);
    g_WkdModuleTable.Initialized = FALSE;
}

/**************************************************/
/*           模块引用计数 / 本体释放                */
/*                                                  */
/*  2026-08-27 补全（重构遗漏）:                    */
/*    PsDereferenceWkdModule / PspDestroyWkdModule 声明     */
/*    与实现缺失致链接失败 (LNK2019) + C4013。       */
/*    语义对齐 HashMap 契约: 插入 +1 (表引用),       */
/*    摘除 -1 (Dereference 回调), 本体真正释放由     */
/*    PsDereferenceWkdModule 在锁外 PspDestroyWkdModule 完成。*/
/**************************************************/
static
VOID
PspDestroyWkdModule(
    _In_ PWKD_MODULE WkdModule
    )
{
    if (!WkdModule) return;

    /* CompleteEvent: ImageAnalyzer 定稿仅 SetEvent 不关闭
     * (防句柄重用竞态, 等待者 Wait 后以 AnalysisState 判定),
     * 句柄随模块释放在此关闭 — 见 ImageAnalyzer.c 定稿注释。 */
    if (WkdModule->CompleteEvent) {
        CloseHandle(WkdModule->CompleteEvent);
        WkdModule->CompleteEvent = NULL;
    }

    /* 文件级静态结果 (UtHeapAlloc 分配的 IOC_SCAN_RESULT 块) */
    if (WkdModule->FileResult) {
        UtHeapFree(WkdModule->FileResult);
        WkdModule->FileResult = NULL;
    }

    /* 原始路径副本 (CoCopyUnicodeString 产物, 与 PspCreateModule Cleanup 同构) */
    if (WkdModule->ImagePath) {
        CoFreeUnicodeString(WkdModule->ImagePath);
        WkdModule->ImagePath = NULL;
    }

    free(WkdModule);
}

_Use_decl_annotations_
LONG
PsReferenceWkdModule(
    _Inout_ PWKD_MODULE WkdModule
    )
{
    if (!WkdModule) return MAXLONG; 
    else return InterlockedIncrement(&WkdModule->RefCount);
}

_Use_decl_annotations_
LONG
PsDereferenceWkdModule(
    _In_ PWKD_MODULE WkdModule
    )
{
    LONG ref;

    if (!WkdModule) return MAXLONG;
    ref = InterlockedDecrement(&WkdModule->RefCount);
    if (ref == 1) {
        /* 仅剩表引用: 摘表 (表内 Dereference 同步 -1) → 归零则锁外释放。
         * 表 key 与插入同源 (原始路径字节), 见 PsFindOrCreateModule Phase1。
         * 摘表瞬间有并发 Find pin 时 RefCount>0, 不释放 (保留至 pin 归还)。 */
        CoRemoveHashMapEntry(&g_WkdModuleTable.Map,
            WkdModule->ImagePath->Buffer, WkdModule->ImagePath->Length, FALSE);
        ref = _InterlockedCompareExchange(&WkdModule->RefCount, 0, 0);
    } else if (ref == 0) {
        /* 无表引用 (替换/卸载路径已摘表), 最后一份引用归零 → 释放 */
        PspDestroyWkdModule(WkdModule);
    }
    return ref;
}

_Use_decl_annotations_
NTSTATUS
PsFindOrCreateModule(
    _In_ PCWSTR ImagePath,
    _In_opt_ SIZE_T ImageSize,
    _In_ UCHAR SignatureStatus,
    _Out_ PWKD_MODULE* Module
)
/*++
Routine Description:
    两阶段查重创建（对齐驱动 PsFindOrCreateModule）：
Phase1 表内等值查重（key=原始路径字节，哈希/比较表内
       统一完成）；命中后锁外 mtime 防替换校验（业务层）：
        - 仍对应磁盘当前版本 → 复用
        - 文件已被替换 → 摘旧建新（旧对象被其他视图 pin 时保留
          至视图关闭，与替换窗口语义等价）
      Phase2 锁外解析（IocAnalyzePeFromFilePath/SHA256）→ try-insert
      取并发赢家。

    2026-08-20 阶段5 变更：宽松 Identity（ImageSize 任一为 0 复用）
    退役——同路径恒等值命中；ImageSize 仅记录不参与查重。

Arguments:
    ImagePath       — 原始路径（内部小写归一化作表 key）。
    ImageSize       — 首见映射大小（仅记录，不参与查重）。
    SignatureStatus — 驱动上送 IMG_SIGNATURE_*。
    Module          — 输出模块（调用方负责 PsDereferenceWkdModule 释放 pin）。

Return Value:
    NTSTATUS。
--*/
{
    SIZE_T keySize;
    PWKD_MODULE module;
    PWKD_MODULE existing;
    NTSTATUS status;
    ULONG attempts = 3;

    /* 未知映射大小，宽松Identity，无需校验ImageSize */
    if (!CoCheckStringValidity(ImagePath) ||
        !Module || !g_WkdModuleTable.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }
    *Module = NULL;

    /* 表 key：原始路径字节（HashMap 字节语义，无小写归一化）。
     * 与 PsDereferenceWkdModule 摘表 key 同源一致（2026-08-20 修复：
     * 曾引用已删除的 PspNormalizePathKey 归一化，两端口径不一）。 */
    keySize = wcsnlen_s(ImagePath, MAX_PATH) * sizeof(WCHAR);

    /* Phase 1: 等值查重（表内统一比较，无谓词注入）。
     * CoLookupHashMapEntry 锁内命中时经 PmMapReference pin（RefCount++）。 */
    existing = CoLookupHashMapEntry(&g_WkdModuleTable.Map,
        ImagePath, keySize);
    if (existing) {
        /* 锁外 mtime 防替换（业务层） */
        if (PmIsModuleCurrent(existing->ImagePath->Buffer, existing)) {
            *Module = existing;
            return STATUS_SUCCESS;
        }

        /* 文件已被替换：摘除旧条目（Dereference 同步 -1 表引用），
         * 显式复位 InTable, 再归还查找 pin——仅剩表引用场景由
         * PsDereferenceWkdModule 内部归零释放; 仍有视图引用则保留至
         * 视图关闭。随后落新建（与 Phase2 同一路径）。 */
        CoRemoveHashMapEntry(&g_WkdModuleTable.Map, ImagePath, keySize, FALSE);
        PsDereferenceWkdModule(existing);
    }

    /* Phase 2: 锁外解析 + 回表 try-insert */
Retry:
    if (0 == attempts--) return STATUS_UNSUCCESSFUL;

    status = PspCreateModule(ImagePath, ImageSize, SignatureStatus, &module);
    if (!NT_SUCCESS(status)) return status;

    status = CoInsertHashMapEntry(&g_WkdModuleTable.Map, (PVOID)ImagePath,
        keySize, module);
    if (NT_SUCCESS(status)) {
        *Module = module;
        return STATUS_SUCCESS;
    } else {
        /* 发生条件竞争（或内存不足等），败者销毁新创建的对象并尝试重新获取 */
        PspDestroyWkdModule(module);
        if (status == STATUS_OBJECT_NAME_COLLISION) {
            existing = CoLookupHashMapEntry(&g_WkdModuleTable.Map, ImagePath, keySize);
            if (!existing) {
                /* 极端情况: 创建后快速销毁 */
                goto Retry;
            }
            *Module = existing;
            return STATUS_SUCCESS;
        } else return status;
    }
}

/**************************************************/
/*               进程视图挂接                       */
/**************************************************/

NTSTATUS
PsModuleInstanceAttachProcess(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Inout_ PWKD_MODULE Module,
    _In_opt_ PVOID ImageBase,
    _Out_opt_ PWKD_MODULE_INSTANCE* Instance
    )
/*++
Routine Description:
    挂接映射实例视图到进程模块上下文（Module 已 pin）。
    去重/升级语义 (2026-08-25 扩展):
      - 同 ImageBase 已挂 → 幂等返回已有实例，不增视图引用
        (对齐驱动 PsLookupModuleInstanceByImageBaseLocked 去重)；
      - ImageBase=NULL 表征"磁盘视图" — 主映像在 ProcessCreate
        补挂时无映射基址；同 Module 已有任意视图即幂等；
      - 既有同 Module 磁盘视图 + 本次带真实基址 → 原位升级为
        映射视图 (迟到的主映像 ImageLoad 不产生双实例)。

Arguments:
    Process   — 进程节点。
    Module    — 全局唯一镜像对象。
    ImageBase — 映射基址；NULL = 磁盘视图。
    Instance  — 输出视图（可 NULL）。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_MODULE_CONTEXT ctx;
    PWKD_MODULE_INSTANCE instance;
    PLIST_ENTRY le;

    if (!WkdProcess || !Module) return STATUS_INVALID_PARAMETER;
    if (Instance) *Instance = NULL;

    ctx = PspCreateModuleContextLazy(WkdProcess);
    if (!ctx) return STATUS_NO_MEMORY;

    if (InterlockedCompareExchange(&ctx->ActiveModules, 0, 0) >=
        MAX_MODULES_PER_PROCESS) return STATUS_QUOTA_EXCEEDED;

    /* 去重 / 升级：同基址已挂 → 幂等; 磁盘视图补挂遇同模块
     * 既有视图亦幂等; 磁盘视图 + 真实基址 → 原位升级 */
    AcquireSRWLockExclusive(&ctx->Lock);
    le = ctx->ModuleList.Flink;
    while (le != &ctx->ModuleList) {
        instance = CONTAINING_RECORD(le, WKD_MODULE_INSTANCE, ListEntry);
        /* 除了进程创建时的磁盘视图外（此时instance不可能实例化），不存在 ImageBase 为空的情况! */
        if (instance->Module == Module) {
            if (instance->ImageBase == ImageBase) {
                goto Cleanup;
            } else if (!instance->ImageBase && ImageBase) {
                /* 迟到的映射事件: 磁盘视图原位升级, 视图引用不变 */
                instance->ImageBase = ImageBase;
                goto Cleanup;
            }
        }
        le = le->Flink;
    }

    instance = malloc(sizeof(WKD_MODULE_INSTANCE));
    if (!instance) { status = STATUS_NO_MEMORY; goto Cleanup_1; }
    RtlZeroMemory(instance, sizeof(WKD_MODULE_INSTANCE));

    instance->ImageBase = ImageBase;
    instance->Module = Module;
    InterlockedIncrement(&Module->RefCount);   /* 视图引用 */
    GetSystemTimeAsFileTime((PFILETIME)&instance->LoadTime);

    InsertTailList(&ctx->ModuleList, &instance->ListEntry);
    InterlockedIncrement(&ctx->ActiveModules);
    InterlockedIncrement(&ctx->TotalModules);

Cleanup:
    if (Instance) *Instance = instance;
Cleanup_1:
    ReleaseSRWLockExclusive(&ctx->Lock);
    return status;
}

_Use_decl_annotations_
VOID
PsDestroyModuleContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    摘除进程全部模块视图并释放（对齐驱动 PsDestroyWkdModuleContext）：
    先摘孤儿链表（不持锁）→ 锁外逐个 deref（可能触发全局表摘除 + 释放）。

Arguments:
    Process — 进程节点。

Return Value:
    VOID。
--*/
{
    LIST_ENTRY orphan;
    PLIST_ENTRY entry, next;
    PWKD_MODULE_CONTEXT context;
    PWKD_MODULE_INSTANCE instance;

    if (!WkdProcess || !WkdProcess->ModuleContext) return;

    context = WkdProcess->ModuleContext;

    entry = context->ModuleList.Flink;
    while (entry != &context->ModuleList) {
        next = entry->Flink;
        instance = CONTAINING_RECORD(entry, WKD_MODULE_INSTANCE, ListEntry);
        RemoveEntryList(entry);
        PsDereferenceWkdModule(instance->Module);
        free(instance);
        InterlockedDecrement(&context->ActiveModules);
        entry = next;
    }

    free(context);
    WkdProcess->ModuleContext = NULL;
}

/**************************************************/
/*               镜像加载事件接线                   */
/**************************************************/

NTSTATUS
PsHandleImageLoad(
    _In_ const PWKD_EVENT_HEADER Event
    )
/*++
Routine Description:
    ImageLoad 事件 → 进程域模块挂载：
      payload 取进程节点 → PmFindOrCreateModule → PsModuleInstanceAttachProcess。

Arguments:
    Event — 已解析的镜像加载事件（EVENT_PAYLOAD_IMAGE_LOAD）。

Return Value:
    VOID。
--*/
{
    NTSTATUS status;
    PEVENT_PAYLOAD_IMAGE_LOAD payload;
    PWKD_PROCESS process = NULL;
    PWKD_MODULE module = NULL;
    PWKD_MODULE_INSTANCE instance = NULL;

    if (!Event || Event->Type != WkdEvent_ImageLoad) {
        return STATUS_INVALID_PARAMETER;
    }

    payload = (PEVENT_PAYLOAD_IMAGE_LOAD)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
    if (!CoCheckUnicodeStringValidity(&payload->ImagePath)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupWkdProcessByProcessId(
        NULL, payload->TargetProcessId, &process);
    if (!NT_SUCCESS(status)) return STATUS_OBJECTID_NOT_FOUND;

    status = PsFindOrCreateModule(payload->ImagePath.Buffer,
                                  payload->ImageSize,
                                  payload->SignatureStatus,
                                  &module);
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = PsModuleInstanceAttachProcess(process, module, payload->ImageBase, &instance);
    if (NT_SUCCESS(status)) {
        /* 视图级观测：驱动 IMG_IND_* 中"每映射"信号映射进 ViewFlags
            * （位值对齐，见 ProcessTypes.h WKD_MODULE_VIEW_*）。
            * Unbacked/入口点越界/机器类型失配/伪装等只影响该进程视图，
            * 不入全局文件级结果（对齐驱动决策 #2 防跨进程反射加载误报）。
            * 文件级静态信号（熵/WX/无导出/.NET/安全目录/TLS 等）由 Tier3 精确分析，
            * 不在此映射。 */
        instance->ViewFlags |= payload->ImageIndicators & (
            WKD_MODULE_VIEW_UNBACKED |
            WKD_MODULE_VIEW_ENTRYPOINT_OUTSIDE |
            WKD_MODULE_VIEW_MACHINE_MISMATCH |
            WKD_MODULE_VIEW_MASQUERADING |
            WKD_MODULE_VIEW_NETWORK_PATH |
            WKD_MODULE_VIEW_DOUBLE_EXTENSION |
            WKD_MODULE_VIEW_TYPOSQUATTING |
            WKD_MODULE_VIEW_SUSPICIOUS_PATH);
    }

Cleanup:
    if (module) PsDereferenceWkdModule(module);   /* 释放查找 pin */
    PsDereferenceWkdProcess(process);   /* 归还进程节点查找 pin */
    return status;
}
