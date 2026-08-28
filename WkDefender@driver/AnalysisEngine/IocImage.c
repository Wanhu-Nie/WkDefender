/**************************************************/
/*  WkDefender — 镜像加载 IOC 检测流水线（L1）       */
/*                                                   */
/*  L0/L1 边界重构（2026-08-08）：                    */
/*  回调（L0）只采集 PE 测量事实 + ImageInfo 标志并   */
/*  持久化到源进程 ModuleContext；本文件基于这些事实   */
/*  做全部检测判定，逐条提交细分指标实现评分融合，     */
/*  经 dispatch Phase4.5 获得浅层阻断能力。           */
/*                                                   */
/*  参考 PhantomSensor ImageNotify.c 全功能面。       */
/**************************************************/

#include "IocImage.h"
#include "../ThreatScoring/ThreatScoring.h"
#include "../Process/ProcessModuleTracker.h"   /* PWKD_MODULE_INSTANCE / PsLookupModuleInstanceByImageBaseLocked（显式依赖） */

/**************************************************/
/*                 静态表（L1 检测）                */
/**************************************************/

// 可疑路径模式（对齐 SS g_SuspiciousPaths，8 条）
static const PCWSTR g_IocSuspiciousPaths[] = {
    L"\\Temp\\",
    L"\\tmp\\",
    L"\\AppData\\Local\\Temp\\",
    L"\\Downloads\\",
    L"\\ProgramData\\",
    L"\\Users\\Public\\",
    L"\\Windows\\Temp\\",
    L"\\Recycle",
};

// 系统 DLL 名（对齐 SS g_SystemDllNames，12 条）
static const PCWSTR g_IocSystemDllNames[] = {
    L"ntdll.dll",     L"kernel32.dll",   L"kernelbase.dll", L"user32.dll",
    L"advapi32.dll",  L"shell32.dll",    L"ole32.dll",      L"combase.dll",
    L"msvcrt.dll",    L"ws2_32.dll",     L"crypt32.dll",    L"secur32.dll",
};

// 伪装判定结果位（本地，不依赖线格式 IMG_INDICATOR_*）
#define IOC_IMG_MASQ_NONE    0
#define IOC_IMG_MASQ_EXACT   1
#define IOC_IMG_MASQ_TYPO    2

/**************************************************/
/*            辅助函数（大小写/子串/文件名）        */
/**************************************************/

static FORCEINLINE
WCHAR
IocImgpToLower(
    _In_ WCHAR C
    )
{
    return (C >= L'A' && C <= L'Z') ? (WCHAR)(C + (L'a' - L'A')) : C;
}

static
BOOLEAN
IocImgpEqualsCI(
    _In_ PCWSTR A,
    _In_ PCWSTR B
    )
/*++
    大小写不敏感宽字符串相等比较。
--*/
{
    while (*A != L'\0' && *B != L'\0') {
        if (IocImgpToLower(*A) != IocImgpToLower(*B)) return FALSE;
        A++;
        B++;
    }
    return (*A == L'\0' && *B == L'\0');
}

static
BOOLEAN
IocImgpFindSubstrCI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
/*++
    大小写不敏感子串查找（对齐 SS IocpFindInUnicodeString 语义）。
--*/
{
    SIZE_T hlen, nlen, i, j;

    if (Haystack == NULL || Needle == NULL) return FALSE;
    hlen = wcslen(Haystack);
    nlen = wcslen(Needle);
    if (nlen == 0 || nlen > hlen) return FALSE;

    for (i = 0; i <= hlen - nlen; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < nlen; j++) {
            if (IocImgpToLower(Haystack[i + j]) != IocImgpToLower(Needle[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*              检测函数（L1 判定）                */
/**************************************************/

static
BOOLEAN
IocImgpIsPathSuspicious(
    _In_ PCWSTR ImagePath
    )
/*++
    检测镜像路径是否包含可疑子串（对齐 SS ImgpIsPathSuspicious）。
--*/
{
    if (ImagePath == NULL) return FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_IocSuspiciousPaths); i++) {
        if (IocImgpFindSubstrCI(ImagePath, g_IocSuspiciousPaths[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
IocImgpIsMasqueradingName(
    _In_ PCWSTR FileName
    )
/*++
    精确伪装系统 DLL 名（对齐 SS ImgpIsMasqueradingName 精确分支）。
--*/
{
    if (FileName == NULL) return FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_IocSystemDllNames); i++) {
        if (IocImgpEqualsCI(FileName, g_IocSystemDllNames[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static
ULONG
IocImgpDetectMasquerade(
    _In_ PCWSTR FileName
    )
/*++
    系统 DLL 伪装检测（精确 + typosquatting，对齐 SS ImgpIsMasqueradingName 全逻辑）：
      - 精确匹配 → IOC_IMG_MASQ_EXACT
      - typosquatting（同长 1 字符差异 / ±1 字符 ≥minLen-2 匹配）→ IOC_IMG_MASQ_TYPO
--*/
{
    ULONG result = IOC_IMG_MASQ_NONE;
    SIZE_T fileLen;

    if (FileName == NULL) return IOC_IMG_MASQ_NONE;
    fileLen = wcslen(FileName);

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_IocSystemDllNames); i++) {
        SIZE_T sysLen = wcslen(g_IocSystemDllNames[i]);

        /* 精确匹配（大小写不敏感） */
        if (fileLen == sysLen) {
            if (IocImgpEqualsCI(FileName, g_IocSystemDllNames[i])) {
                return IOC_IMG_MASQ_EXACT;
            }

            /* 同长度 1 字符差异 → typosquatting（对齐 SS:3311-3356） */
            SIZE_T diffCount = 0;
            for (SIZE_T j = 0; j < fileLen; j++) {
                if (IocImgpToLower(FileName[j]) != IocImgpToLower(g_IocSystemDllNames[i][j])) {
                    diffCount++;
                }
            }
            if (diffCount == 1) result = IOC_IMG_MASQ_TYPO;
        }

        /* ±1 长度：minLen-2 匹配 → typosquatting（对齐 SS:3361-3383） */
        if (fileLen == sysLen + 1 || fileLen == sysLen - 1) {
            SIZE_T minLen = (fileLen < sysLen) ? fileLen : sysLen;
            SIZE_T matches = 0;
            for (SIZE_T j = 0; j < minLen; j++) {
                if (IocImgpToLower(FileName[j]) == IocImgpToLower(g_IocSystemDllNames[i][j])) {
                    matches++;
                }
            }
            if (minLen >= 2 && matches >= minLen - 2) result = IOC_IMG_MASQ_TYPO;
        }
    }

    return result;
}

static
BOOLEAN
IocImgpHasDoubleExtension(
    _In_ PCWSTR FileName
    )
/*++
    双扩展名（文件名点计数 ≥2，对齐 SS ImgpDetectSuspiciousIndicators:3218-3228）。
--*/
{
    ULONG dotCount = 0;

    if (FileName == NULL) return FALSE;
    for (ULONG i = 0; FileName[i] != L'\0'; i++) {
        if (FileName[i] == L'.') dotCount++;
    }
    return dotCount >= 2;
}

/**************************************************/
/*           L1 主入口 — 检测 + 指标上报           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IocDetectImage(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PIMAGE_INFO ImageInfo
    )
/*++
    Routine Description（描述）:
        镜像加载 IOC 检测流水线（L1）。
        从源进程 ModuleContext 视图 → Module（全局唯一镜像对象）读内容固有事实
        + ViewFlags（每映射标志），逐条检测判定并提交细分指标；评分由
        dispatch Phase 4 统一结算，
        Phase 4.5 AeEvaluateVerdict 处置（浅层阻断：加载恶意镜像的进程
        评分达 Blocked 后经 AepIsCriticalProcess 豁免校验被终止）。

    Arguments（参数）:
        Pair      - 进程对（(X,X) 自对，源=目标=加载进程）。
        ImageInfo - L0 回调透传的原始镜像信息（用于定位模块视图基址）。

    Return Value:
        NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_PROCESS process;
    PWKD_MODULE_INSTANCE instance;

    if (!Pair || !ImageInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    process = PsLookupWkdProcessByProcessId(Pair->TargetProcessId);
    if (process == NULL) {
        /* 进程被错误释放, 发生严重错误! 理论上不可能发生. */
        return STATUS_INTERNAL_ERROR;
    }

    /* 2026-08-25 锁下沉: 模块视图查询持 ModuleContext::Lock 共享 */
    if (process->ModuleContext == NULL) {
        /* 进程的模块追踪上下文尚未初始化——不视为致命，返回内部错误 */
        status = STATUS_INTERNAL_ERROR;
        PsDereferenceWkdProcess(process);
        return status;
    }
    WkdAcquirePushLockShared(&process->ModuleContext->Lock);

    instance = PsLookupModuleInstanceByImageBaseLocked(process, ImageInfo->ImageBase);
    if (instance == NULL || instance->Module == NULL) {
        /* 模块未附加至进程或模块被意外释放??? 严重错误! */
        status = STATUS_INTERNAL_ERROR;
        goto Cleanup;
    }

    /* 以下全部检测在 process 引用有效期内完成
     * （modEntry->Module 为全局对象，视图持有引用，进程存活期间不被移除）。
     * 2026-08-11 全局镜像对象重构：路径/内容事实读 Module（内容固有，全局一致），
     * 每映射标志读 ViewFlags（Unbacked/MachineMismatch，防跨进程反射加载误报）。 */
    {


        /* 1. 可疑路径 */
        //if (IocImgpIsPathSuspicious(imagePath)) {
        //    AeReportIndicatorEx(Pair, TsSourceIOC,
        //        TsIndicator_Image_SuspiciousPath, AeThreatSeverityLow);
        //}

        /* 2. 系统 DLL 伪装（精确） */
        //if (fileName[0] != L'\0' && IocImgpIsMasqueradingName(fileName)) {
        //    AeReportIndicatorEx(Pair, TsSourceIOC,
        //        TsIndicator_Image_MasqueradingName, AeThreatSeverityHigh);
        //}

        /* 3. typosquatting */
        //if (IocImgpDetectMasquerade(fileName) & IOC_IMG_MASQ_TYPO) {
        //    AeReportIndicatorEx(Pair, TsSourceIOC,
        //        TsIndicator_Image_TypoSquatting, AeThreatSeverityMedium);
        //}

        /* 4. 网络路径（UNC）[注释态] */

        /* 5. 双扩展名 */
        //if (IocImgpHasDoubleExtension(fileName)) {
        //    AeReportIndicatorEx(Pair, TsSourceIOC,
        //        TsIndicator_Image_DoubleExtension, AeThreatSeverityMedium);
        //}

        /* 6. 无背衬内存（反射加载信号，PhantomDLL）— 每映射视图标志 */
        //if (modEntry->ViewFlags & WKD_MODULE_VIEW_UNBACKED) {
        //    AeReportIndicatorEx(Pair, TsSourceIOC,
        //        TsIndicator_Image_PhantomDllUnbacked, AeThreatSeverityCritical);
        //}

        /* 7. EP 不在代码段（镂空信号）— 内容固有 */
        if (instance->Module->Facts.Valid &&
            instance->Module->Facts.AddressOfEntryPoint != 0 &&
            !instance->Module->Facts.EntryPointInCode) {
            AeReportIndicatorEx(Pair, TsSourceIOC,
                TsIndicator_Image_EntrypointOutsideCode, AeThreatSeverityHigh);
        }

        /* 8. DLL 无导出 — 内容固有 */
        if (instance->Module->Facts.HasNoExports) {
            AeReportIndicatorEx(Pair, TsSourceIOC,
                TsIndicator_Image_NoExports, AeThreatSeverityLow);
        }

        /* 9. W^X 代码区段（SelfModifying）— 内容固有 */
        if (instance->Module->Facts.HasWxSection) {
            AeReportIndicatorEx(Pair, TsSourceIOC,
                TsIndicator_Image_HollowingHeuristic, AeThreatSeverityCritical);
        }
    }

    /* 10. 信息位（SystemModule/MachineMismatch）— 纯记录不上分，无指标上报
     * （高熵检测已移除：熵计算归 agent，2026-08-09 镜像职责收敛；
     *   SoftwarePacking 加壳判定由 agent IocScanner 启发式覆盖） */

Cleanup:
    WkdReleasePushLockShared(&process->ModuleContext->Lock);
    PsDereferenceWkdProcess(process);
    return status;;
}

#pragma warning(push)
#pragma warning(disable:4505)   /* 死代码区：static 未引用告警 */

// ============================================================================
// 死代码区 — SS ImageNotify 全功能面覆盖（不接入流水线）
// ============================================================================

//
// [死代码][SS ImageNotify.c:3655-3713 对齐] Shannon 熵近似
// 不接入原因：wkd 活代码用简化熵（uniqueFactor+distFactor, 0-1000 尺度），
// 线格式 WKD_IMG_PE_BASIC 保持一致；本函数为 SS 原算法功能面覆盖（0-800 尺度）。
//
static
ULONG
IocImgpCalculateSectionEntropy(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
{
    ULONG byteCount[256] = { 0 };
    ULONG entropy = 0;
    ULONG i;

    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* __try { */
        /* 统计字节频次 */
        for (i = 0; i < Size; i++) {
            byteCount[Data[i]]++;
        }

        /* 简化 Shannon 熵近似 ×100 */
        for (i = 0; i < 256; i++) {
            if (byteCount[i] > 0) {
                ULONG probability = (byteCount[i] * 10000) / Size;

                if (probability > 0 && probability < 10000) {
                    ULONG logApprox = 0;
                    ULONG temp = probability;

                    while (temp > 0) {
                        logApprox++;
                        temp >>= 1;
                    }

                    entropy += (probability * logApprox) / 10000;
                }
            }
        }
    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    } */

    /* 归一化到 0-800（8 bit × 100） */
    if (entropy > 800) {
        entropy = 800;
    }
    return entropy;
}

//
// [死代码][SS ImageNotify.c:3718-3781 对齐] 镜像哈希计算（SHA256/SHA1/MD5）
// 不接入原因：wkd 驱动无 BCrypt(CNG) 封装，哈希归 agent（架构决策 #30）。
//   agent 侧：IocScanner_ComputeFileHashMulti（多算法）+ ScanManager 缓存。
//
// [死代码][SS ImageNotify.c:2287-2316 对齐] IOC 哈希匹配
// 不接入原因：wkd 驱动无 IOCMatcher 基础设施，哈希 IOC 匹配归 agent
//   （IocMatcher_MatchHash + SQLite ioc_hashes）。
//
// [死代码][SS ImageNotify.c:1276-1413 对齐] BYOVD 脆弱驱动库
// 不接入原因：依赖哈希比对，归 agent（SQLite 脆弱驱动表 + 信誉）。
//
// [死代码][SS ImageNotify.c:2077-2096 对齐] 排除子系统三查
// 不接入原因：wkd 排除判定经 ProcessMonitor 创建路径 CoEvaluateProcessExemption
//   统一完成（路径/进程名/PID/父继承/EDR 自保护），镜像加载路径不重复判定；
//   门面文件为 Common/Exempts/Exempts.c。
//
// [死代码][SS ImageNotify.c:2344-2379 对齐] AppControl 镜像判定
// 不接入原因：IocAppControl 存根态（IocAcEnabled 默认关），接线见
//   Callbacks/ImageNotify.c AppControl 注释块。
//
// [死代码][SS ImageNotify.c:2385-2396 对齐] AMSI Bypass 检测
// 不接入原因：wkd AmsiBypassDetector 独立自持已激活（T1562.001）。
//
// [死代码][SS ImageNotify.c:2405-2626 对齐] 镂空深度 / Doppelganging /
//   Ghosting / Section 追踪
// 不接入原因：归 agent IoaInjectionClassifier（镂空分类）+ 驱动
//   Syscall 层 NtCreateSection 检测（0x0D2C 系，SectionTracker 迁移）。
//
// [死代码][SS ImageNotify.c:2633-2676 对齐] BehaviorEngine 事件三分类
// 不接入原因：wkd dispatch 统一走本函数逐条指标上报，不区分三注入方式。
//

#pragma warning(pop)
