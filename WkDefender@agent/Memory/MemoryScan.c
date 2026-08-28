/**************************************************/
/*  WkDefender 内存扫描 — 机制 B 进程内存入口实现        */
/**************************************************/

#include "MemoryScan.h"
#include "../Common/FileUtils.h"
#include "../WkDefenderHeader.h"
#include "../Storage/StorageEngine.h"
#include "../IOA/Tier1/T1ShellcodeDetect.h"
#include "../IOC/PEAnalyzer/PeAnalyzer.h"
#include "../IOC/IocYaraScanner.h"
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

#define MS_SCAN_CHUNK   (1024 * 1024)   /* 单次读取 1MB，避免大区域一次分配 */

/* 全局 AC 索引（机制 B，由 IocEngine_Initialize 构建，与机制 A 同源 yara_rules 表） */
static MS_PATTERN_INDEX* g_MsIndex = NULL;

/* 扫描统计（对齐 SS MemoryScanner MsGetStatistics L2273-2321，死代码读取 API） */
static WKD_MEM_SCANNER_STATS g_MsStats;

/*++
 * MsScanMatchCallback
 *   命中回调：打印命中（ProcessId 由调用上下文携带，见线程参数）。
 *   告警落 cg_alerts 表留 TODO（与机制 A 异步命中一致，见 SignatureStore.md §0.3-B）。
 *--*/
static DWORD g_MsScanProcessId = 0;   /* 当前扫描线程的 ProcessId（轻量，单扫描线程串行） */

static VOID CALLBACK MsScanMatchCallback(
    _In_ UINT PatternId,
    _In_ SIZE_T HitOffset,
    _In_ PMS_PATTERN Pattern)
{
    UNREFERENCED_PARAMETER(PatternId);
    printf("[MsScan] HIT pid=%u rule=%s threat=%d offset=0x%zX\n",
           g_MsScanProcessId,
           Pattern->RuleName ? Pattern->RuleName : "?",
           Pattern->ThreatLevel, HitOffset);
    /* TODO: 落 cg_alerts 表（severity 由 threat_level 映射，步骤 6.1 联调时补全） */
}

/*++
 * MsScanInitialize
 *   构建机制 B 全局 AC 索引：从 Storage yara_rules 表（enabled=1）解析 hex/text
 *   模式并构建失败链。与机制 A（libyara）同源（D7 决策）。
 *   须在 Storage 初始化之后调用（main 顺序保证）。
 *--*/
BOOL MsScanInitialize(VOID)
{
    if (g_MsIndex) return TRUE;
    g_MsIndex = MsPatternIndexCreate();
    if (!g_MsIndex) return FALSE;

    UINT rules = MsImportFromYaraRules(WkdStorageEngine.WarmDb, g_MsIndex);
    if (rules == 0) {
        printf("[MsScan] No YARA rules for pattern index (mechanism B idle)\n");
    }
    MsPatternIndexBuild(g_MsIndex);
    return TRUE;
}

VOID MsScanCleanup(VOID)
{
    if (g_MsIndex) { MsPatternIndexDestroy(g_MsIndex); g_MsIndex = NULL; }
}

BOOL MsScanProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPCVOID Base,
    _In_ SIZE_T Size,
    _In_ PMS_PATTERN_INDEX Index,
    _In_ MS_MATCH_CALLBACK Callback)
{
    if (!hProcess || !Base || Size == 0 || !Index || !Callback) return FALSE;

    /* 分块读取（防止单次超大分配）+ 跨块边界 overlap（对齐 SS MspScanSingleRegion
     * MED-1 fix L3362-3365：读 chunk+overlap、推进 chunk，重叠部分下轮重扫，
     * 保证跨块边界的模式不漏检）。overlap = 模式长度上限 - 1。 */
    SIZE_T chunk = MS_SCAN_CHUNK;
    SIZE_T overlap = MS_MAX_PATTERN_BYTES - 1;
    SIZE_T bufCap = chunk + overlap;
    SIZE_T offset = 0;
    BYTE* local = (BYTE*)malloc(bufCap);
    if (!local) return FALSE;

    BOOL anyScanned = FALSE;
    while (offset < Size) {
        SIZE_T remaining = Size - offset;
        SIZE_T toRead = (remaining > bufCap) ? bufCap : remaining;
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)Base + offset),
                               local, toRead, &read) || read == 0) {
            /* 该区域不可读，跳过剩余 */
            break;
        }
        MsPatternIndexSearch(Index, local, read, Callback);
        anyScanned = TRUE;

        /* 推进 chunk（而非 read），重叠字节在下轮被重新扫描以命中跨边界模式 */
        offset += chunk;
        if (read < toRead) break;   /* 实际读到的少于请求，到区域末尾 */
    }

    free(local);
    return anyScanned;
}

BOOL MsScanWithYARA(
    _In_ DWORD ProcessId,
    _In_opt_ LPCVOID ImageBase,
    _In_opt_ SIZE_T ImageSize,
    _In_ PMS_PATTERN_INDEX Index,
    _In_ MS_MATCH_CALLBACK Callback)
{
    if (!Callback) return FALSE;
    if (Index == NULL) Index = g_MsIndex;   /* 未指定则用全局索引 */
    if (!Index) return FALSE;

    /* 记录当前扫描 ProcessId 供命中回调打印（初版单线程串行；
     * 若需并发扫描，应在 MS_MATCH_CALLBACK 增加 context 参数，TODO） */
    g_MsScanProcessId = ProcessId;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) {
        printf("[MsScan] OpenProcess(%u) failed: %u\n", ProcessId, GetLastError());
        return FALSE;
    }

    BOOL result = FALSE;
    if (ImageBase && ImageSize > 0) {
        /* 仅扫指定映像区域 */
        result = MsScanProcessMemory(hProcess, ImageBase, ImageSize, Index, Callback);
    } else {
        /* 枚举全部可读提交页（参考 MemoryScanner 的内存区域枚举） */
        MEMORY_BASIC_INFORMATION mbi;
        LPCVOID addr = NULL;
        result = TRUE;
        while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE)) &&
                !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                if (mbi.RegionSize > 0) {
                    MsScanProcessMemory(hProcess, mbi.BaseAddress, mbi.RegionSize,
                                        Index, Callback);
                }
            }
            /* 推进到下一区域（避免死循环） */
            ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (next <= (ULONG_PTR)addr) break;  /* 地址未前进，退出 */
            addr = (LPCVOID)next;
        }
    }

    CloseHandle(hProcess);
    return result;
}

/*++
 * MsScanMemoryProfile
 *   枚举目标进程内存区域，统计可执行/RWX/无文件支撑可执行区域画像。
 *   参考 PS ProcessAnalyzer::AnalyzeMemoryInternal（仅计数，不做内容匹配）。
 *   ※ 待接入评分: 输出 WKD_MEMORY_PROFILE.RwxRegionCount/UnbackedExecRegionCount
 *      → WpeCalculateOverallRisk (WKD_RISK_INPUT 权重 ×20/×35, PEAnalyzer);
 *      当前无存活调用者。
 *--*/

#define MS_MAX_PROFILE_REGIONS  16384   /* 对齐 PS MAX_MEMORY_REGIONS */

static BOOL
MsIsExecutableProtection(
    _In_ ULONG Protect
    )
{
    const ULONG kExec = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (Protect & kExec) != 0;
}

static BOOL
MsIsRwxProtection(
    _In_ ULONG Protect
    )
{
    return (Protect & PAGE_EXECUTE_READWRITE) != 0;
}

BOOL
MsScanMemoryProfile(
    _In_ DWORD ProcessId,
    _Out_ PWKD_MEMORY_PROFILE Profile)
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = NULL;

    if (!Profile) return FALSE;
    RtlZeroMemory(Profile, sizeof(*Profile));

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (!hProcess) return FALSE;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            Profile->TotalCommittedSize += mbi.RegionSize;
            Profile->RegionCount++;

            if (MsIsExecutableProtection(mbi.Protect)) {
                Profile->ExecutableRegionCount++;
                Profile->TotalExecutableSize += mbi.RegionSize;

                /* RWX 区域（极少合法） */
                if (MsIsRwxProtection(mbi.Protect)) {
                    Profile->RwxRegionCount++;
                }
                /* 无文件支撑可执行区域（MEM_PRIVATE 且可执行 → 潜在注入/壳码） */
                if (mbi.Type == MEM_PRIVATE) {
                    Profile->UnbackedExecRegionCount++;
                }
            }
        }

        Profile->TotalVirtualSize += mbi.RegionSize;

        /* 防回绕/零尺寸死循环 */
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;
        addr = (LPCVOID)next;

        if (Profile->RegionCount >= MS_MAX_PROFILE_REGIONS) break;
    }

    CloseHandle(hProcess);
    return TRUE;
}

/*++
 * MsScanMemoryRegions
 *   收集 RWX / 无文件支撑可执行区域明细（对齐 PS rwxRegions / unbackedExecutable）。
 *--*/
BOOL
MsScanMemoryRegions(
    _In_  DWORD             ProcessId,
    _Out_writes_to_(MaxRegions, *Count) PWKD_MEMORY_REGION Regions,
    _In_  ULONG             MaxRegions,
    _Out_ PULONG            Count)
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = NULL;
    ULONG collected = 0;

    if (!Regions || MaxRegions == 0 || !Count) return FALSE;
    *Count = 0;
    RtlZeroMemory(Regions, (SIZE_T)MaxRegions * sizeof(WKD_MEMORY_REGION));

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (!hProcess) return FALSE;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && MsIsExecutableProtection(mbi.Protect)) {
            BOOLEAN isRwx = MsIsRwxProtection(mbi.Protect);
            BOOLEAN isUnbacked = (mbi.Type == MEM_PRIVATE);
            if ((isRwx || isUnbacked) && collected < MaxRegions) {
                Regions[collected].BaseAddress = (ULONG_PTR)mbi.BaseAddress;
                Regions[collected].RegionSize = mbi.RegionSize;
                Regions[collected].Protection = mbi.Protect;
                Regions[collected].IsRwx = isRwx;
                Regions[collected].IsUnbackedExec = isUnbacked;
                collected++;
            }
        }

        /* 防回绕/零尺寸死循环 */
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;
        addr = (LPCVOID)next;

        if (collected >= MaxRegions) break;
    }

    CloseHandle(hProcess);
    *Count = collected;
    return TRUE;
}

/**************************************************/
/*  检测层 — ShadowStrike MemoryScanner 迁移       */
/*  (MemoryScanner.cpp 全量功能合并于此)           */
/**************************************************/

#define MS_REGION_READ_LIMIT     (64 * 1024 * 1024)       /* 单区域整块读上限 64MB */
#define MS_SCAN_TIMEOUT_100NS    (60000LL * 10000LL)      /* 扫描超时 60s */
#define MS_MAX_BYTES_PER_PROC    (2ULL * 1024 * 1024 * 1024) /* 单进程字节上限 2GB */
#define MS_ENTROPY_THRESHOLD     5500                      /* CoEntropyBinary bits*1000 (5.5 bits shellcode 预判) */
#define MS_MIN_NOP_SLED          16
#define MS_MIN_SHELLCODE_SIZE    16   /* 最小壳码分析长度 (对齐 MS_MIN_NOP_SLED, 原引用无定义) */
#define MS_MAX_EXTRACTED_STRINGS 500
#define MS_MIN_REGION_SIZE       64                       /* 对齐 SS MS_MIN_REGION_SIZE (高熵采样过滤) */
#define MS_ENTROPY_SAMPLE_SIZE   (64 * 1024)              /* 对齐 SS MS_SCAN_CHUNK_SIZE=64KB (高熵采样) */

/*++ ShadowStrike ShellcodeDetector 迁移 static 函数前向声明 (2026-08-07)。
 *   本文件"SS 独有检测/死代码迁移"分区位于 MsAnalyzeShellcode 之后, 但后者
 *   已调用分区函数 — 统一在此声明, 消除隐式声明 (C4013) 与 4505 告警边界。
 *--*/
static BOOLEAN MsScanEggHunter(_In_ const BYTE* Buffer, _In_ ULONG Size,
                               _Out_opt_ PULONG HunterOffset);
static BOOLEAN MsScanEncoderLoop(_In_ const BYTE* Buffer, _In_ ULONG Size,
                                 _Out_ CHAR* EncoderType, _In_ ULONG TypeSize,
                                 _Out_opt_ PULONG LoopOffset);
static BOOLEAN MsScanHeavensGate(_In_ const BYTE* Buffer, _In_ ULONG Size);
static BOOLEAN MsScanStackPivot(_In_ const BYTE* Buffer, _In_ ULONG Size,
                                _Out_opt_ PULONG GadgetOffset);
static BOOLEAN MsScanSuspiciousCalls(_In_ const BYTE* Buffer, _In_ ULONG Size);
static BOOLEAN MsScanNopSled(_In_ const BYTE* Buffer, _In_ ULONG Size,
                             _Out_ PULONG Offset, _Out_ PULONG Length, _Out_ PUCHAR NopByte);
static BOOLEAN MsScanDirectSyscalls(_In_ const BYTE* Buffer, _In_ ULONG Size,
                                    _Out_writes_to_(MaxStubs, *StubCount) PWKD_SYSCALL_STUB Stubs,
                                    _In_ ULONG MaxStubs, _Out_ PULONG StubCount);
static BOOLEAN MsScanPositionIndependentCode(_In_ const BYTE* Buffer, _In_ ULONG Size);
static ULONG   MsScoreShellcodeConfidence(_In_ const WKD_SHELLCODE_ANALYSIS* Analysis);
static ULONG   MsScoreShellcodeSeverity(_In_ WKD_MEM_THREAT_TYPE Type,
                                        _In_ const WKD_SHELLCODE_ANALYSIS* Analysis);
static WKD_MEM_THREAT_TYPE MsDetermineShellcodeThreatType(_In_ const WKD_SHELLCODE_ANALYSIS* Analysis);
static BOOLEAN MsScanShellcodePipeline(_In_ const BYTE* Buffer, _In_ ULONG Size,
                                       _In_ BOOLEAN IsPrivateExecutable, _Out_ PWKD_MEM_THREAT Threat);

/* 熵: CoEntropyBinary bits*1000 语义 (对齐 WPA_ENTROPY_THRESHOLD_ENCRYPTED) */

static BOOLEAN
MsIsWritableProtection(
    _In_ ULONG Protect
    )
{
    const ULONG kW = PAGE_READWRITE | PAGE_WRITECOPY |
                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (Protect & kW) != 0;
}

static WKD_MEM_REGION_TYPE
MsRegionTypeFromMbi(
    _In_ ULONG MbiType
    )
{
    if (MbiType == MEM_IMAGE)  return WkdMemType_Image;
    if (MbiType == MEM_MAPPED) return WkdMemType_Mapped;
    if (MbiType == MEM_PRIVATE) return WkdMemType_Private;
    return WkdMemType_Unknown;
}

/* 区域可疑特征标记 (对齐 PS CheckSuspiciousRegion, MemoryScanner.cpp L720) */
static VOID
MsCheckSuspiciousRegion(
    _Inout_ PWKD_MEMORY_REGION Region
    )
{
    if (Region->Protection & PAGE_GUARD) {
        Region->IsSuspicious = TRUE;
        strcpy_s(Region->SuspicionReason, sizeof(Region->SuspicionReason),
                 "Guard page (anti-scan evasion)");
        return;
    }
    if (Region->IsPrivate && Region->IsExecutable && Region->IsWritable) {
        Region->IsSuspicious = TRUE;
        strcpy_s(Region->SuspicionReason, sizeof(Region->SuspicionReason),
                 "RWX private memory");
        return;
    }
    if (Region->IsPrivate && Region->IsExecutable &&
        Region->RegionSize > (1 * 1024 * 1024)) {   /* 1MB, 对齐 PS LARGE_PRIVATE_EXEC */
        Region->IsSuspicious = TRUE;
        strcpy_s(Region->SuspicionReason, sizeof(Region->SuspicionReason),
                 "Large private executable region");
        return;
    }
    if (Region->IsExecutable && Region->Type == WkdMemType_Private) {
        Region->IsSuspicious = TRUE;
        strcpy_s(Region->SuspicionReason, sizeof(Region->SuspicionReason),
                 "Unbacked executable memory");
        return;
    }
}

/* 区域过滤 (对齐 PS ShouldScanRegion, MemoryScanner.cpp L959) */
static BOOLEAN
MsShouldScanRegion(
    _In_ PWKD_MEMORY_REGION Region,
    _In_ WKD_MEM_SCAN_MODE Mode
    )
{
    if (Region->State != WkdMemState_Committed) return FALSE;
    if (Region->IsSuspicious) return TRUE;

    switch (Mode) {
    case WkdMemScan_Quick:
        return Region->IsExecutable;
    case WkdMemScan_Normal:
        return Region->IsExecutable || Region->IsPrivate;
    case WkdMemScan_Deep:
    default:
        return TRUE;
    }
}

/* 威胁收集 (上限 WKD_MEM_MAX_THREATS) */
static VOID
MsAddThreat(
    _Inout_ PWKD_MEM_SCAN_RESULT Result,
    _In_ PWKD_MEM_THREAT Threat
    )
{
    if (Result->ThreatsFound >= WKD_MEM_MAX_THREATS) return;
    Result->Threats[Result->ThreatsFound++] = *Threat;
    InterlockedIncrement64(&g_MsStats.ThreatsFound);
}

/* 区域威胁添加 + 证据预览填充 (对齐 PS 威胁 EvidencePreview) */
static VOID
MsAddRegionThreat(
    _Inout_ PWKD_MEM_SCAN_RESULT Result,
    _Inout_ PWKD_MEM_THREAT Threat,
    _In_ const BYTE* Buffer,
    _In_ ULONG Size,
    _In_ ULONG_PTR RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG Protection,
    _In_ WKD_MEM_REGION_TYPE MemType
    )
{
    Threat->RegionBase = RegionBase;
    Threat->RegionSize = RegionSize;
    Threat->Protection = Protection;
    Threat->MemType = MemType;

    /* 证据预览: 缓冲前 WKD_MEM_EVIDENCE_SIZE 字节 */
    if (Buffer != NULL && Size > 0) {
        Threat->EvidenceSize = min(Size, (ULONG)WKD_MEM_EVIDENCE_SIZE);
        memcpy(Threat->EvidencePreview, Buffer, Threat->EvidenceSize);
    }

    MsAddThreat(Result, Threat);
}

/*++
 * MsThreatTypeToString
 *   威胁类型 → 字符串 (对齐 PS MemoryThreatTypeToString).
 *--*/
_Use_decl_annotations_
PCSTR
MsThreatTypeToString(
    WKD_MEM_THREAT_TYPE Type
    )
{
    switch (Type) {
    case WkdMemThreat_Malware:          return "Malware";
    case WkdMemThreat_Shellcode:        return "Shellcode";
    case WkdMemThreat_APIHashing:       return "API Hashing Shellcode";
    case WkdMemThreat_SyscallStub:      return "Direct Syscall Stub";
    case WkdMemThreat_ROPChain:         return "ROP Chain";
    case WkdMemThreat_PEInjection:      return "PE Injection";
    case WkdMemThreat_CobaltStrike:     return "Cobalt Strike Beacon";
    case WkdMemThreat_Meterpreter:      return "Meterpreter";
    case WkdMemThreat_EncryptedPayload: return "Encrypted Payload";
    case WkdMemThreat_SuspiciousCode:   return "Suspicious Code";
    case WkdMemThreat_None:
    default:                            return "None";
    }
}

/* 缓冲内任意偏移子串匹配 */
static BOOLEAN
MsContainsBytes(
    _In_ const BYTE* Data,
    _In_ ULONG Size,
    _In_ const BYTE* Pattern,
    _In_ ULONG PatternLen
    )
{
    ULONG i, j;

    if (Size < PatternLen) return FALSE;
    for (i = 0; i <= Size - PatternLen; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < PatternLen; j++) {
            if (Data[i + j] != Pattern[j]) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/*++
 * MsParsePE
 *   从内存缓冲解析 PE 头 (PE32/PE32+),输出关键字段。
 *   复用 IocPeAnalyzer 的 WpeAnalyzePEHeadersFromBuffer (已补 EP/ImageBase)。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsParsePE(
    const BYTE* Buffer,
    ULONG Size,
    PULONG_PTR ImageBase,
    PULONG ImageSize,
    PULONG EntryPoint,
    PUSHORT Machine,
    PUSHORT Characteristics
    )
{
    WPA_PE_INFO peInfo;
    HRESULT hr;

    if (Buffer == NULL || Size < 64) return FALSE;

    hr = WpeAnalyzePEHeadersFromBuffer((PVOID)Buffer, Size, &peInfo);
    if (FAILED(hr) || !peInfo.IsPE) return FALSE;

    if (ImageBase)       *ImageBase = peInfo.ImageBase;
    if (ImageSize)       *ImageSize = peInfo.ImageSize;
    if (EntryPoint)      *EntryPoint = peInfo.EntryPoint;
    if (Machine)         *Machine = peInfo.Machine;
    if (Characteristics) *Characteristics = peInfo.Characteristics;
    return TRUE;
}

/*++
 * MsBuildModuleSet
 *   构建进程已加载模块基址/大小集 (EnumProcessModules + GetModuleInformation)。
 *   对齐 SS GetPEBModulesImpl (ReflectiveDLLDetector.cpp L2293)。
 *--*/
_Use_decl_annotations_
BOOL
MsBuildModuleSet(
    DWORD ProcessId,
    PWKD_MEM_MODULE_SET Set
    )
{
    HANDLE hProcess;
    HMODULE mods[WKD_MEM_MODULE_MAX];
    DWORD cbNeeded = 0;
    DWORD count, i;

    if (Set == NULL) return FALSE;
    RtlZeroMemory(Set, sizeof(*Set));

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return FALSE;

    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &cbNeeded)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    count = cbNeeded / sizeof(HMODULE);
    if (count > WKD_MEM_MODULE_MAX) count = WKD_MEM_MODULE_MAX;

    for (i = 0; i < count; i++) {
        MODULEINFO mi;
        if (GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi))) {
            Set->Bases[Set->Count] = (ULONG_PTR)mi.lpBaseOfDll;
            Set->Sizes[Set->Count] = mi.SizeOfImage;
            Set->Count++;
        }
    }

    CloseHandle(hProcess);
    return Set->Count > 0;
}

/*++
 * MsIsAddrInModuleSet
 *   地址是否落在任一模块 [Base, Base+Size) 区间内。
 *   对齐 SS IsAddressInAnyModule (ReflectiveDLLDetector.cpp L142)。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsIsAddrInModuleSet(
    const WKD_MEM_MODULE_SET* Set,
    ULONG_PTR Address
    )
{
    ULONG i;

    if (Set == NULL) return FALSE;

    for (i = 0; i < Set->Count; i++) {
        if (Address >= Set->Bases[i] &&
            Address < Set->Bases[i] + Set->Sizes[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
 * MsDetectPE
 *   非映像内存 PE 判定 (对齐 PS ContainsPEInternal + CreatePEThreat).
 *--*/
_Use_decl_annotations_
BOOLEAN
MsDetectPE(
    const BYTE* Buffer,
    ULONG Size,
    PWKD_MEM_THREAT Threat
    )
{
    ULONG_PTR imageBase = 0;
    ULONG imageSize = 0, entryPoint = 0;
    USHORT machine = 0, characteristics = 0;

    if (Threat == NULL || Buffer == NULL || Size < 64) return FALSE;
    RtlZeroMemory(Threat, sizeof(*Threat));

    if (!MsParsePE(Buffer, Size, &imageBase, &imageSize, &entryPoint,
                   &machine, &characteristics)) {
        return FALSE;
    }

    Threat->Type = WkdMemThreat_PEInjection;
    Threat->MatchedRule[0] = '\0';
    strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
             "PE Header in Non-Image Memory");
    strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "Reflective Loading");
    Threat->Confidence = 95;
    Threat->RiskScore = 95;
    strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
    Threat->PeValid = TRUE;
    Threat->PeImageBase = imageBase;
    Threat->PeImageSize = imageSize;
    Threat->PeEntryPoint = entryPoint;
    Threat->PeMachine = machine;
    Threat->PeCharacteristics = characteristics;
    return TRUE;
}

/*++
 * MsDetectShellcode
 *   全文壳码检测 (对齐 PS DetectShellcode, MemoryScanner.cpp L1016).
 *   特征复用 IocDetectShellcode,合并命中为单一综合威胁。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsDetectShellcode(
    const BYTE* Buffer,
    ULONG Size,
    BOOLEAN IsPrivateExecutable,
    PWKD_MEM_THREAT Threat
    )
{
    ULONG flags;
    CHAR detail[160];

    if (Threat == NULL || Buffer == NULL || Size < MS_MIN_SHELLCODE_SIZE) return FALSE;
    RtlZeroMemory(Threat, sizeof(*Threat));

    flags = IocDetectShellcode(Buffer, Size, IsPrivateExecutable);
    if (flags == 0) return FALSE;

    detail[0] = '\0';

    if (flags & T1_SC_NOP_SLED)  strcat_s(detail, sizeof(detail), "NOP sled; ");
    if (flags & T1_SC_GETPC)     strcat_s(detail, sizeof(detail), "GetPC; ");
    if (flags & T1_SC_APIHASH)   strcat_s(detail, sizeof(detail), "API hashing; ");
    if (flags & T1_SC_SYSCALL)   strcat_s(detail, sizeof(detail), "direct syscall; ");
    if (flags & T1_SC_ROP_CHAIN) strcat_s(detail, sizeof(detail), "ROP chain; ");

    if (flags & T1_SC_ROP_CHAIN) {
        Threat->Type = WkdMemThreat_ROPChain;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "ROP Chain");
        Threat->Confidence = 72;
        Threat->RiskScore = 80;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1055");
    } else if (flags & T1_SC_SYSCALL) {
        Threat->Type = WkdMemThreat_SyscallStub;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "Direct Syscall");
        Threat->Confidence = 80;
        Threat->RiskScore = 85;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1106");
    } else if (flags & T1_SC_APIHASH) {
        Threat->Type = WkdMemThreat_APIHashing;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "API Hashing");
        Threat->Confidence = 70;
        Threat->RiskScore = 75;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
    } else {
        Threat->Type = WkdMemThreat_Shellcode;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "Shellcode Pattern");
        Threat->Confidence = 75;
        Threat->RiskScore = 85;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
    }

    strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "Shellcode");
    return TRUE;
}

/**************************************************/
/*  已知反射加载器签名 (对齐 SS ReflectiveDLLDetector) */
/*  g_cobaltStrikePatterns / g_meterpreterPatterns  */
/*  / g_apiHashPatterns                            */
/**************************************************/

/* CS Beacon config marker (常见 malleable C2 profile) */
static const BYTE kCsBeaconConfig[] = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00
};
/* CS Beacon sleep mask stub (x64) */
static const BYTE kCsSleepMaskX64[] = {
    0x49, 0x89, 0xC8, 0x48, 0x8B, 0x48, 0x10, 0x48,
    0x8B, 0x50, 0x08, 0x4D, 0x31, 0xC9, 0x48, 0xFF
};
/* Meterpreter reflective DLL stub */
static const BYTE kMeterpreterReflStub[] = {
    0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89,
    0xE5, 0x31, 0xC0, 0x64, 0x8B, 0x50, 0x30, 0x8B
};
/* Meterpreter stage marker ("METERPRETER\0...") */
static const BYTE kMeterpreterStageMarker[] = {
    0x4D, 0x45, 0x54, 0x45, 0x52, 0x50, 0x52, 0x45,
    0x54, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* API-hash 字节模式 (mask 0xFF=精确, 0x00=通配) */
typedef struct _MS_APIHASH_PATTERN {
    const char* Name;
    BYTE Bytes[8];
    BYTE Mask[8];
} MS_APIHASH_PATTERN;

static const MS_APIHASH_PATTERN g_ApiHashPatterns[] = {
    /* ror r32,0x0D ; add r32,r32 (ROR-13 additive loop, x64) */
    { "ROR13_hash_x64",
      {0xC1, 0xCF, 0x0D, 0x03, 0xCF, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00} },
    /* ror edi,0x0D (x86 variant) */
    { "ROR13_hash_x86",
      {0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00} },
    /* djb2-style: shl reg,5 ; add reg,reg */
    { "DJB2_hash_loop",
      {0xC1, 0xE0, 0x05, 0x03, 0xC1, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00} },
    /* sRDI: CRC32 intrinsic */
    { "CRC32_hash_intrinsic",
      {0xF2, 0x0F, 0x38, 0xF1, 0x00, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00} },
};

/* 扫描缓冲找 API-hash 模式, 返回模式名或 NULL (对齐 SS DetectAPIHashingPattern L196) */
static
const char*
MsDetectApiHashingPattern(
    const BYTE* Data,
    ULONG Size
    )
{
    ULONG p, i, j;

    if (Data == NULL || Size < 8) return NULL;

    for (p = 0; p < RTL_NUMBER_OF(g_ApiHashPatterns); p++) {
        const MS_APIHASH_PATTERN* pat = &g_ApiHashPatterns[p];
        for (i = 0; i <= Size - 8; i++) {
            BOOLEAN match = TRUE;
            for (j = 0; j < 8; j++) {
                if ((Data[i + j] & pat->Mask[j]) != (pat->Bytes[j] & pat->Mask[j])) {
                    match = FALSE;
                    break;
                }
            }
            if (match) return pat->Name;
        }
    }
    return NULL;
}

/**************************************************/
/*  API 哈希值解析 (ShadowStrike ShellcodeDetector 迁移 2026-08-07) */
/*  对齐 SS SdpDetectApiHashing L2592-2692 +      */
/*  SdpInitializeApiHashDatabase L2056-2105        */
/**************************************************/

/* ROR13 内置哈希库 38 条 (数值逐条抄录 SS, 可用 WkRor13Hash 反向校验;
 * 含非真实导出 GetProcAddressForCaller — SS 原样保留) */
static const WKD_API_HASH_ENTRY g_ApiHashTable[] = {
    /* 基础 6 条 (SS L2056-2065) */
    { 0x0726774C, "LoadLibraryA", "kernel32.dll" },
    { 0x7C0DFCAA, "GetProcAddress", "kernel32.dll" },
    { 0x91AFCA54, "VirtualAlloc", "kernel32.dll" },
    { 0x7946C61B, "VirtualProtect", "kernel32.dll" },
    { 0x160D6838, "CreateThread", "kernel32.dll" },
    { 0x534C0AB8, "NtFlushInstructionCache", "ntdll.dll" },
    /* kernel32 常用 10 条 (SS L2068-2077) */
    { 0xEC0E4E8E, "LoadLibraryW", "kernel32.dll" },
    { 0x7802F749, "GetProcAddressForCaller", "kernel32.dll" },
    { 0xE449F330, "VirtualAllocEx", "kernel32.dll" },
    { 0xE7BDD8C5, "VirtualProtectEx", "kernel32.dll" },
    { 0x799AACC6, "CreateRemoteThread", "kernel32.dll" },
    { 0xE035F044, "Sleep", "kernel32.dll" },
    { 0x876F8B31, "WinExec", "kernel32.dll" },
    { 0x56A2B5F0, "ExitProcess", "kernel32.dll" },
    { 0x5DE2C5AA, "GetLastError", "kernel32.dll" },
    { 0x4FDAF6DA, "CloseHandle", "kernel32.dll" },
    /* 网络 6 条 — 反向 shell 常用 (SS L2080-2085) */
    { 0x6174A599, "WSAStartup", "ws2_32.dll" },
    { 0xE0DF0FEA, "WSASocketA", "ws2_32.dll" },
    { 0x6737DBC2, "connect", "ws2_32.dll" },
    { 0x33604C84, "recv", "ws2_32.dll" },
    { 0x5FC8D902, "send", "ws2_32.dll" },
    { 0x614D6E75, "closesocket", "ws2_32.dll" },
    /* 进程线程 7 条 (SS L2088-2094) */
    { 0xAFC98D6F, "CreateProcessA", "kernel32.dll" },
    { 0x16B3FE72, "CreateProcessW", "kernel32.dll" },
    { 0x863FCC79, "OpenProcess", "kernel32.dll" },
    { 0x1E380A6E, "WriteProcessMemory", "kernel32.dll" },
    { 0xDBD95D5C, "ReadProcessMemory", "kernel32.dll" },
    { 0xCB72D9E8, "ResumeThread", "kernel32.dll" },
    { 0x1D1C1CAC, "SuspendThread", "kernel32.dll" },
    /* ntdll 9 条 — 直接 syscall 目标 (SS L2097-2105) */
    { 0x3CFA685D, "NtAllocateVirtualMemory", "ntdll.dll" },
    { 0x50E92888, "NtProtectVirtualMemory", "ntdll.dll" },
    { 0xE3BD6D35, "NtWriteVirtualMemory", "ntdll.dll" },
    { 0x4FFF8B29, "NtReadVirtualMemory", "ntdll.dll" },
    { 0x4B82F718, "NtCreateThreadEx", "ntdll.dll" },
    { 0xE9DAEE4C, "NtQueueApcThread", "ntdll.dll" },
    { 0x7299EAF9, "NtCreateSection", "ntdll.dll" },
    { 0x3B2E55EB, "NtMapViewOfSection", "ntdll.dll" },
    { 0x6AA412CD, "NtUnmapViewOfSection", "ntdll.dll" },
};

#pragma warning(push)
#pragma warning(disable:4505)   /* static 工具无调用者, 供哈希数值校验/未来扩展 */
/*++
 * WkRor13Hash
 *   ROR13 字符串哈希计算 (对齐 SS 壳码 API 哈希算法, SS 已删计算函数仅留
 *   硬编码常量 — 本函数为 wkd 新增工具, 用于校验 g_ApiHashTable 数值与
 *   未来"邻近 API 字符串反向确认"降误报)。
 *--*/
static ULONG
WkRor13Hash(
    _In_z_ const char* Name
    )
{
    ULONG hash = 0;

    if (Name == NULL) return 0;
    while (*Name != '\0') {
        hash = (hash >> 13) | (hash << 19);   /* 循环右移 13 位 */
        hash += (UCHAR)*Name++;
    }
    return hash;
}
#pragma warning(pop)

/*++
 * MsScanApiHashResolution
 *   哈希值解析: 单遍扫描缓冲, 提取 MOV EAX/ECX/EDX,imm32 (B8-BA) 与
 *   PUSH imm32 (68) 的 4 字节候选哈希, 线性查 g_ApiHashTable 解析 API 名。
 *   对齐 SS SdpDetectApiHashing L2636-2684 (wkd 仅字节模式识别升级为值解析)。
 *   返回 TRUE = 至少解析到一个已知 API。
 *--*/
static BOOLEAN
MsScanApiHashResolution(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_API_HASH_RESULT Resolved
    )
{
    ULONG i, k;

    if (Buffer == NULL || Resolved == NULL) return FALSE;
    RtlZeroMemory(Resolved, sizeof(*Resolved));
    if (Size < 5) return FALSE;

    for (i = 0; i <= Size - 5 && Resolved->ResolvedCount < 16; i++) {
        ULONG val;
        BOOLEAN isCandidate = FALSE;

        /* MOV EAX/ECX/EDX, imm32 — 哈希值装入寄存器 (B8/B9/BA) */
        if (Buffer[i] == 0xB8 || Buffer[i] == 0xB9 || Buffer[i] == 0xBA) {
            isCandidate = TRUE;
        }
        /* PUSH imm32 — 哈希值压栈 (68) */
        else if (Buffer[i] == 0x68) {
            isCandidate = TRUE;
        }

        if (!isCandidate) continue;

        memcpy(&val, &Buffer[i + 1], sizeof(val));

        /* 线性查 38 条静态库 (低频路径, 排序表+二分留作优化注释) */
        for (k = 0; k < RTL_NUMBER_OF(g_ApiHashTable); k++) {
            if (g_ApiHashTable[k].Hash == val) {
                ULONG idx = Resolved->ResolvedCount;
                Resolved->Resolved[idx].Hash = val;
                strcpy_s(Resolved->Resolved[idx].ApiName,
                         sizeof(Resolved->Resolved[idx].ApiName),
                         g_ApiHashTable[k].ApiName);
                strcpy_s(Resolved->Resolved[idx].DllName,
                         sizeof(Resolved->Resolved[idx].DllName),
                         g_ApiHashTable[k].DllName);
                if (Resolved->ResolutionOffset == 0) {
                    Resolved->ResolutionOffset = i;
                }
                Resolved->ResolvedCount++;
                break;
            }
        }
    }

    return (Resolved->ResolvedCount > 0);
}

/*++
 * MsDetectReflectiveLoader
 *   已知反射加载器签名检测 (对齐 SS DetectKnownLoader 启发式, ReflectiveDLLDetector.cpp L1514):
 *     - CS Beacon config marker / sleep mask stub (g_cobaltStrikePatterns L478-485)
 *     - Meterpreter reflective stub / stage marker (g_meterpreterPatterns L490-497)
 *     - API-hash 字节模式: ROR-13 x64/x86 / DJB2 / CRC32 (g_apiHashPatterns L176-193)
 *   供隐藏无背衬 PE 判定后加载器分类使用。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsDetectReflectiveLoader(
    const BYTE* Buffer,
    ULONG Size,
    PWKD_MEM_THREAT Threat
    )
{
    if (Threat == NULL || Buffer == NULL || Size < 8) return FALSE;
    RtlZeroMemory(Threat, sizeof(*Threat));

    if (Size >= sizeof(kCsBeaconConfig) &&
        MsContainsBytes(Buffer, Size, kCsBeaconConfig, sizeof(kCsBeaconConfig))) {
        Threat->Type = WkdMemThreat_CobaltStrike;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
                 "CobaltStrike Beacon Config");
        strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
        Threat->Confidence = 92;
        Threat->RiskScore = 95;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
        return TRUE;
    }

    if (Size >= sizeof(kCsSleepMaskX64) &&
        MsContainsBytes(Buffer, Size, kCsSleepMaskX64, sizeof(kCsSleepMaskX64))) {
        Threat->Type = WkdMemThreat_CobaltStrike;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
                 "CobaltStrike Sleep Mask (x64)");
        strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
        Threat->Confidence = 90;
        Threat->RiskScore = 93;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
        return TRUE;
    }

    if (Size >= sizeof(kMeterpreterReflStub) &&
        MsContainsBytes(Buffer, Size, kMeterpreterReflStub, sizeof(kMeterpreterReflStub))) {
        Threat->Type = WkdMemThreat_Meterpreter;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
                 "Meterpreter Reflective Stub");
        strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
        Threat->Confidence = 88;
        Threat->RiskScore = 90;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
        return TRUE;
    }

    if (Size >= sizeof(kMeterpreterStageMarker) &&
        MsContainsBytes(Buffer, Size, kMeterpreterStageMarker,
                        sizeof(kMeterpreterStageMarker))) {
        Threat->Type = WkdMemThreat_Meterpreter;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
                 "Meterpreter Stage Marker");
        strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
        Threat->Confidence = 90;
        Threat->RiskScore = 92;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
        return TRUE;
    }

    /* API-hash 字节模式 (对齐 SS DetectAPIHashingPattern L196) */
    {
        const char* hashName = MsDetectApiHashingPattern(Buffer, Size);
        if (hashName != NULL) {
            CHAR rule[64];
            snprintf(rule, sizeof(rule), "API-hash loader (%s)", hashName);
            Threat->Type = WkdMemThreat_APIHashing;
            strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), rule);
            strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "Reflective Loader");
            Threat->Confidence = 75;
            Threat->RiskScore = 80;
            strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
            return TRUE;
        }
    }

    /* API 哈希值解析 (SS SdpDetectApiHashing 迁移 2026-08-07):
     * 字节模式之外补强信号 — 提取 MOV/PUSH imm32 查 38 条 ROR13 库解析 API 名。
     * 随机匹配概率 ≈ 38/2^32 ≈ 8.9e-9/imm32 位置, 高置信低误报。 */
    {
        WKD_API_HASH_RESULT resolved;
        if (MsScanApiHashResolution(Buffer, Size, &resolved)) {
            CHAR rule[192];
            snprintf(rule, sizeof(rule), "API hash resolution (%s%s%s)",
                     resolved.Resolved[0].ApiName,
                     resolved.ResolvedCount > 1 ? "/" : "",
                     resolved.ResolvedCount > 1 ? resolved.Resolved[1].ApiName : "");
            if (resolved.ResolvedCount > 2) {
                strcat_s(rule, sizeof(rule), "/...");
            }
            Threat->Type = WkdMemThreat_APIHashing;
            strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), rule);
            strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "Reflective Loader");
            Threat->Confidence = (resolved.ResolvedCount >= 3) ? 90 :
                                 (resolved.ResolvedCount >= 2 ? 85 : 78);
            Threat->RiskScore    = (resolved.ResolvedCount >= 3) ? 92 : 85;
            strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
            return TRUE;
        }
    }

    return FALSE;
}

/*++
 * MsContainsPE
 *   进程级 PE 快速检查: 读给定地址前部字节判断 MZ 签名。
 *   对齐 SS ContainsPE (ReflectiveDLLDetector.cpp L1207-1217).
 *   ※ 死代码: 供实时内存监控 (T4) PE 预判用, 当前无调用者。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsContainsPE(
    DWORD ProcessId,
    ULONG_PTR Address,
    SIZE_T Size
    )
{
    HANDLE hProcess;
    BYTE header[64];
    SIZE_T bytesRead = 0;
    WORD magic = 0;

    if (Size == 0) return FALSE;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return FALSE;

    if (!ReadProcessMemory(hProcess, (LPCVOID)Address, header,
                           sizeof(header), &bytesRead) || bytesRead < 2) {
        CloseHandle(hProcess);
        return FALSE;
    }
    memcpy(&magic, header, sizeof(magic));
    CloseHandle(hProcess);
    return (magic == IMAGE_DOS_SIGNATURE);
}

/*++
 * MsHasReflectiveLoading
 *   快速布尔判定: 目标进程是否存在隐藏无背衬 PE (反射加载)。
 *   对齐 SS HasReflectiveLoading (ReflectiveDLLDetector.cpp L1114-1117).
 *   Quick 模式全扫 + 查 WkdMemThreat_PEInjection && !PeInPeb.
 *   ※ 死代码: 供 UI 快速体检/进程体检, 当前无调用者。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsHasReflectiveLoading(
    DWORD ProcessId
    )
{
    WKD_MEM_SCAN_RESULT result;
    ULONG i;
    BOOLEAN found = FALSE;

    if (ProcessId <= 4) return FALSE;
    if (!NT_SUCCESS(MsScanProcessMemoryFull(ProcessId, WkdMemScan_Quick, &result))) {
        return FALSE;
    }

    for (i = 0; i < result.ThreatsFound; i++) {
        if (result.Threats[i].Type == WkdMemThreat_PEInjection &&
            !result.Threats[i].PeInPeb) {
            found = TRUE;
            break;
        }
    }
    return found;
}

/*++
 * MsHandleKernelImageLoad
 *   镜像加载通知 → PEB 对照 → 无背衬判定 → 定向反射扫描。
 *   对齐 SS OnKernelImageLoad (ReflectiveDLLDetector.cpp L2567-2604):
 *     系统模块/低 PID 跳过 → 模块表对照 (正常加载已入 PEB 则跳过) →
 *     VirtualQueryEx 查 MEM_PRIVATE → MsScanRegionAt 定向扫描。
 *   ※ 死代码: 依赖 ImageLoad 事件接入 IOA (当前 process_manager.c:1720
 *     MsScanOnImageLoad 仅做 YARA 扫描, 未调用本函数)。
 *--*/
_Use_decl_annotations_
VOID
MsHandleKernelImageLoad(
    DWORD ProcessId,
    ULONG_PTR ImageBase,
    SIZE_T ImageSize,
    BOOLEAN IsSystemModule
    )
{
    WKD_MEM_MODULE_SET set;
    WKD_MEMORY_REGION region;
    PWKD_MEM_SCAN_RESULT scan;

    UNREFERENCED_PARAMETER(ImageSize);

    if (IsSystemModule) return;      /* 系统模块 (ntdll/kernel32 等) 低误报价值 */
    if (ProcessId <= 4) return;

    /* PEB 对照: 正常加载的镜像已入模块表 (对齐 SS L2573-2581) */
    if (!MsBuildModuleSet(ProcessId, &set)) return;
    if (MsIsAddrInModuleSet(&set, ImageBase)) return;

    /* 无背衬判定: 区域为 MEM_PRIVATE (对齐 SS L2587-2603) */
    if (!MsGetRegionInfo(ProcessId, ImageBase, &region)) return;
    if (region.Type != WkdMemType_Private) return;

    /* 定向反射扫描 (对齐 SS DispatchAsyncScan) */
    scan = (PWKD_MEM_SCAN_RESULT)malloc(sizeof(WKD_MEM_SCAN_RESULT));
    if (scan != NULL) {
        MsScanRegionAt(ProcessId, region.BaseAddress, region.RegionSize, scan);
        free(scan);
    }
}

/*++
 * MsDetectC2Beacon
 *   C2 Beacon 检测 (对齐 PS DetectC2Beacon, MemoryScanner.cpp L1208):
 *     - 直接字节模式: CS pipe hex (msagent_) + Meterpreter stage
 *     - 字符串路径: 提取 ASCII/UTF-16LE 串后匹配 pipe 名前缀
 *--*/
_Use_decl_annotations_
BOOLEAN
MsDetectC2Beacon(
    const BYTE* Buffer,
    ULONG Size,
    PWKD_MEM_THREAT Threat
    )
{
    static const BYTE kBeaconPipe[] = {
        0x5C, 0x5C, 0x2E, 0x5C, 0x70, 0x69, 0x70, 0x65,
        0x5C, 0x6D, 0x73, 0x61, 0x67, 0x65, 0x6E, 0x74, 0x5F  /* \\.\pipe\msagent_ */
    };
    static const BYTE kMeterpreter1[] = { 0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00 };
    static const BYTE kMeterpreter2[] = { 0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00 };
    static const BYTE kMeterpreter3[] = { 0xFC, 0xE8, 0x8F, 0x00, 0x00, 0x00 };
    static const char* kPipePatterns[] = {
        "\\\\.\\pipe\\msagent_",
        "\\\\.\\pipe\\MSSE-",
        "\\\\.\\pipe\\postex_",
        "\\\\.\\pipe\\status_",
    };
    CHAR strings[2048];
    ULONG i;

    if (Threat == NULL || Buffer == NULL || Size < 64) return FALSE;
    RtlZeroMemory(Threat, sizeof(*Threat));

    /* 直接字节模式 */
    if (MsContainsBytes(Buffer, Size, kBeaconPipe, sizeof(kBeaconPipe))) {
        Threat->Type = WkdMemThreat_CobaltStrike;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
                 "CobaltStrike Beacon Config");
        strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
        Threat->Confidence = 85;
        Threat->RiskScore = 92;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1071");
        return TRUE;
    }
    if (MsContainsBytes(Buffer, Size, kMeterpreter1, sizeof(kMeterpreter1)) ||
        MsContainsBytes(Buffer, Size, kMeterpreter2, sizeof(kMeterpreter2)) ||
        MsContainsBytes(Buffer, Size, kMeterpreter3, sizeof(kMeterpreter3))) {
        Threat->Type = WkdMemThreat_Meterpreter;
        strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "Meterpreter Stage");
        strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
        Threat->Confidence = 88;
        Threat->RiskScore = 90;
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1055");
        return TRUE;
    }

    /* 字符串路径: 提取后匹配 pipe 名前缀 (含 UTF-16LE) */
    if (MsExtractStrings(Buffer, Size, 4, strings, sizeof(strings)) > 0) {
        for (i = 0; i < RTL_NUMBER_OF(kPipePatterns); i++) {
            if (strstr(strings, kPipePatterns[i]) != NULL) {
                Threat->Type = WkdMemThreat_CobaltStrike;
                strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule),
                         "CobaltStrike Beacon Pipe");
                strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "C2 Framework");
                Threat->Confidence = 90;
                Threat->RiskScore = 95;
                strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1071");
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*++
 * MsCheckHighEntropy
 *   高熵判定 (对齐 PS 高熵检测层, 复用 CoEntropyBinary bits*1000).
 *--*/
_Use_decl_annotations_
BOOLEAN
MsCheckHighEntropy(
    const BYTE* Buffer,
    ULONG Size,
    PULONG Entropy,
    PWKD_MEM_THREAT Threat
    )
{
    ULONG entropy = 0;

    if (Threat == NULL || Buffer == NULL || Size == 0) return FALSE;
    RtlZeroMemory(Threat, sizeof(*Threat));

    entropy = (ULONG)(CoEntropyBinary((PVOID)Buffer, Size, 0) * 1000.0);
    if (Entropy) *Entropy = entropy;

    if (entropy < MS_ENTROPY_THRESHOLD) return FALSE;

    Threat->Type = WkdMemThreat_EncryptedPayload;
    strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "High Entropy Executable");
    strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "Packed");
    Threat->Confidence = 65;
    Threat->RiskScore = 55;
    strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1027");
    return TRUE;
}

/*++
 * MsFindHighEntropyRegions
 *   全进程高熵区域发现（对齐 SS MsFindHighEntropyRegions L2135-2265）：
 *   枚举 MEM_COMMIT 区域 → 读首块采样（64KB，对齐 SS MS_SCAN_CHUNK_SIZE）→
 *   熵 ≥ 阈值（0-1000 尺度）→ 记录。采样不足以 100% 代表整区，但供取证初筛。
 *   ※ 死代码: 供取证 / UI 主动扫描接线，当前无调用者。
 *--*/
_Use_decl_annotations_
NTSTATUS
MsFindHighEntropyRegions(
    DWORD ProcessId,
    ULONG EntropyThreshold,
    PWKD_ENTROPY_REGION Results,
    ULONG MaxResults,
    PULONG ResultCount
    )
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = NULL;
    ULONG count = 0;
    BYTE* sample;

    if (Results == NULL || MaxResults == 0 || ResultCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ResultCount = 0;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return STATUS_ACCESS_DENIED;

    sample = (BYTE*)malloc(MS_ENTROPY_SAMPLE_SIZE);
    if (sample == NULL) {
        CloseHandle(hProcess);
        return STATUS_NO_MEMORY;
    }

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        ULONG_PTR next;

        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= MS_MIN_REGION_SIZE &&
            count < MaxResults) {
            SIZE_T sampleSize = min(mbi.RegionSize, (SIZE_T)MS_ENTROPY_SAMPLE_SIZE);
            SIZE_T bytesRead = 0;
            ULONG entropy = 0;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample, sampleSize,
                                  &bytesRead) && bytesRead > 0 &&
                (entropy = (ULONG)(CoEntropyBinary(sample, (ULONG)bytesRead, 0) * 1000.0), TRUE) &&
                entropy >= EntropyThreshold) {
                Results[count].BaseAddress = (ULONG_PTR)mbi.BaseAddress;
                Results[count].RegionSize = mbi.RegionSize;
                Results[count].Entropy = entropy;
                count++;
            }
        }

        /* 防回绕/零尺寸死循环 */
        next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;
        addr = (LPCVOID)next;
    }

    free(sample);
    CloseHandle(hProcess);
    *ResultCount = count;
    return STATUS_SUCCESS;
}

/*++
 * MsExtractStrings
 *   字符串提取 (ASCII + UTF-16LE 双 pass, 对齐 PS ExtractStringsInternal).
 *   输出为逗号分隔拼接 (上限 MS_MAX_EXTRACTED_STRINGS).
 *--*/
_Use_decl_annotations_
ULONG
MsExtractStrings(
    const BYTE* Buffer,
    ULONG Size,
    ULONG MinLength,
    PCHAR Out,
    ULONG OutCapacity
    )
{
    const ULONG kMaxLen = 256;
    CHAR cur[256];
    ULONG curLen = 0;
    ULONG count = 0;
    ULONG i;
    SIZE_T outLen = 0;

    if (Out == NULL || OutCapacity == 0) return 0;
    Out[0] = '\0';

#define MS_STR_FLUSH()                                                     \
    do {                                                                   \
        if (curLen >= MinLength) {                                         \
            if (outLen + curLen + 2 < OutCapacity) {                       \
                if (outLen > 0) Out[outLen++] = ',';                       \
                memcpy_s(Out + outLen, OutCapacity - outLen, cur, curLen);  \
                outLen += curLen;                                           \
                Out[outLen] = '\0';                                        \
                count++;                                                   \
            }                                                              \
        }                                                                  \
        curLen = 0;                                                        \
    } while (0)

#define MS_STR_PUSH(ch)                                                    \
    do {                                                                   \
        if (curLen >= kMaxLen) { MS_STR_FLUSH(); if (count >= MS_MAX_EXTRACTED_STRINGS) goto done; } \
        cur[curLen++] = (ch);                                              \
    } while (0)

    /* ASCII pass */
    for (i = 0; i < Size; i++) {
        BYTE b = Buffer[i];
        if (b >= 0x20 && b <= 0x7E) {
            MS_STR_PUSH((char)b);
        } else {
            MS_STR_FLUSH();
            if (count >= MS_MAX_EXTRACTED_STRINGS) goto done;
        }
    }
    MS_STR_FLUSH();
    if (count >= MS_MAX_EXTRACTED_STRINGS) goto done;

    /* UTF-16LE pass: {printable, 0x00} 对取低字节 */
    if (Size >= 2) {
        for (i = 0; i + 1 < Size; i += 2) {
            BYTE lo = Buffer[i], hi = Buffer[i + 1];
            if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E) {
                MS_STR_PUSH((char)lo);
            } else {
                MS_STR_FLUSH();
                if (count >= MS_MAX_EXTRACTED_STRINGS) goto done;
            }
        }
        MS_STR_FLUSH();
    }

done:
    return count;

#undef MS_STR_FLUSH
#undef MS_STR_PUSH
}

/* AC 快筛命中计数 (双引擎分级, 串行扫描) */
static volatile LONG g_MsAcHitCount = 0;

static VOID CALLBACK
MsAcHitCallback(
    _In_ UINT PatternId,
    _In_ SIZE_T HitOffset,
    _In_ PMS_PATTERN Pattern
    )
{
    UNREFERENCED_PARAMETER(PatternId);
    UNREFERENCED_PARAMETER(HitOffset);
    UNREFERENCED_PARAMETER(Pattern);
    InterlockedIncrement(&g_MsAcHitCount);
}

/*++
 * MsScanRegionYara
 *   双引擎分级: AC 快筛候选 → libyara 精扫确认.
 *   仅在 AC 命中时调 libyara (规避全局扫描锁逐区域开销).
 *--*/
static VOID
MsScanRegionYara(
    _In_ const BYTE* Buffer,
    _In_ ULONG Size,
    _Inout_ PWKD_MEM_SCAN_RESULT Result
    )
{
    BOOLEAN detected = FALSE;
    ULONG score = 0;
    WCHAR ruleName[128] = { 0 };

    if (Size == 0) return;

    /* ① AC 快筛 */
    if (g_MsIndex) {
        g_MsAcHitCount = 0;
        MsPatternIndexSearch(g_MsIndex, Buffer, Size, MsAcHitCallback);
        if (g_MsAcHitCount == 0) return;
    }

    /* ② libyara 精扫 (仅候选区) */
    if (!NT_SUCCESS(IocYara_ScanBuffer(Buffer, Size, &detected, &score,
                                       ruleName, RTL_NUMBER_OF(ruleName))) ||
        !detected) {
        return;
    }

    {
        WKD_MEM_THREAT threat;
        RtlZeroMemory(&threat, sizeof(threat));
        threat.Type = WkdMemThreat_Malware;
        strcpy_s(threat.RuleCategory, sizeof(threat.RuleCategory), "YARA");
        threat.Confidence = 85;
        threat.RiskScore = 75;
        strcpy_s(threat.MitreTechnique, sizeof(threat.MitreTechnique), "T1055");
        if (ruleName[0]) {
            size_t cch;
            WideCharToMultiByte(CP_UTF8, 0, ruleName, -1,
                                threat.MatchedRule, sizeof(threat.MatchedRule),
                                NULL, NULL);
            cch = strnlen(threat.MatchedRule, sizeof(threat.MatchedRule));
            if (cch >= sizeof(threat.MatchedRule)) cch = sizeof(threat.MatchedRule) - 1;
            threat.MatchedRule[cch] = '\0';
        } else {
            strcpy_s(threat.MatchedRule, sizeof(threat.MatchedRule), "YARA Rule Match");
        }
        MsAddRegionThreat(Result, &threat, Buffer, Size, 0, 0, 0, WkdMemType_Unknown);
        InterlockedIncrement64(&g_MsStats.YaraMatches);
    }
}

/*++
 * MsScanRegionContent
 *   单区域检测编排 (对齐 PS ScanRegionInternal, MemoryScanner.cpp L771).
 *--*/
static VOID
MsScanRegionContent(
    _In_ DWORD ProcessId,
    _In_ HANDLE hProcess,
    _In_ PWKD_MEMORY_REGION Region,
    _In_opt_ const WKD_MEM_MODULE_SET* Modules,
    _Inout_ PWKD_MEM_SCAN_RESULT Result
    )
{
    MEMORY_BASIC_INFORMATION live;
    BYTE* buffer;
    SIZE_T bytesRead = 0;
    ULONG size;

    UNREFERENCED_PARAMETER(ProcessId);

    if (Region->RegionSize == 0 || Region->RegionSize > MS_REGION_READ_LIMIT) {
        return;
    }

    /* TOCTOU 重查: 区域可能已释放/变 guard/noaccess (对齐 PS) */
    if (VirtualQueryEx(hProcess, (LPCVOID)Region->BaseAddress, &live,
                       sizeof(live)) != sizeof(live)) {
        return;
    }
    if (live.State != MEM_COMMIT ||
        (live.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        return;
    }

    buffer = (BYTE*)malloc(Region->RegionSize);
    if (buffer == NULL) return;

    if (!ReadProcessMemory(hProcess, (LPCVOID)Region->BaseAddress, buffer,
                           Region->RegionSize, &bytesRead) || bytesRead == 0) {
        InterlockedIncrement64(&g_MsStats.ScanErrors);
        free(buffer);
        return;
    }
    size = (ULONG)bytesRead;
    InterlockedAdd64(&g_MsStats.BytesScanned, bytesRead);

    /* ① 非映像内存 PE 判定 + 模块表对照 (对齐 SS FindHiddenModules L1292) */
    if (Region->Type != WkdMemType_Image) {
        WKD_MEM_THREAT threat;
        if (MsDetectPE(buffer, size, &threat)) {
            InterlockedIncrement64(&g_MsStats.PeDetections);
            Region->ContainsPE = TRUE;

            /* 隐藏模块对照: PE 基址是否在已加载模块表内 */
            if (Modules != NULL) {
                threat.PeInPeb = MsIsAddrInModuleSet(Modules, (ULONG_PTR)Region->BaseAddress);
                threat.PeFileBacked = threat.PeInPeb;
                if (threat.PeInPeb) {
                    /* 已在模块表 (文件支撑映像残留/特殊映射) → 降置信, 防误报 */
                    threat.Confidence = 40;
                    threat.RiskScore = 30;
                    strcpy_s(threat.MatchedRule, sizeof(threat.MatchedRule),
                             "PE in module list (file-backed)");
                } else {
                    /* 隐藏无背衬 PE → 反射加载高置信 (对齐 SS isHiddenFromPEB → High) */
                    threat.Confidence = 95;
                    threat.RiskScore = 95;
                    strcpy_s(threat.MatchedRule, sizeof(threat.MatchedRule),
                             "Hidden PE (not in module list)");
                }
            }

            /* 已知反射加载器签名 (对齐 SS DetectKnownLoader 启发式, 仅隐藏无背衬 PE) */
            if (Modules != NULL && !threat.PeInPeb) {
                WKD_MEM_THREAT loader;
                if (MsDetectReflectiveLoader(buffer, size, &loader)) {
                    threat = loader;
                    threat.PeInPeb = FALSE;
                    threat.PeFileBacked = FALSE;
                }
            }

            MsAddRegionThreat(Result, &threat, buffer, size,
                              Region->BaseAddress, Region->RegionSize,
                              Region->Protection, Region->Type);
        }
    }

    /* ② 壳码检测 (私有可执行区域) */
    {
        WKD_MEM_THREAT threat;
        BOOLEAN isPrivExec = (Region->IsPrivate && Region->IsExecutable);
        if (MsDetectShellcode(buffer, size, isPrivExec, &threat)) {
            InterlockedIncrement64(&g_MsStats.ShellcodeDetections);
            MsAddRegionThreat(Result, &threat, buffer, size,
                              Region->BaseAddress, Region->RegionSize,
                              Region->Protection, Region->Type);
        }
    }

    /* ③ 高熵判定 (私有可执行) */
    {
        WKD_MEM_THREAT threat;
        ULONG entropy = 0;
        if (Region->IsExecutable && Region->Type == WkdMemType_Private &&
            MsCheckHighEntropy(buffer, size, &entropy, &threat)) {
            Region->Entropy = entropy;
            MsAddRegionThreat(Result, &threat, buffer, size,
                              Region->BaseAddress, Region->RegionSize,
                              Region->Protection, Region->Type);
        }
    }

    /* ④ C2 Beacon 检测 */
    {
        WKD_MEM_THREAT threat;
        if (MsDetectC2Beacon(buffer, size, &threat)) {
            MsAddRegionThreat(Result, &threat, buffer, size,
                              Region->BaseAddress, Region->RegionSize,
                              Region->Protection, Region->Type);
        }
    }

    /* ⑤ 双引擎 YARA */
    MsScanRegionYara(buffer, size, Result);

    InterlockedIncrement64(&g_MsStats.RegionsScanned);
    free(buffer);
}

/* 内存级风险汇总 0.7*max + 0.3*avg (对齐 PS CalculateOverallRisk) */
static ULONG
MsCalculateOverallRisk(
    _In_ PWKD_MEM_SCAN_RESULT Result
    )
{
    ULONG maxRisk = 0, i;
    ULONG64 avg = 0;

    if (Result->ThreatsFound == 0) return 0;

    for (i = 0; i < Result->ThreatsFound; i++) {
        if (Result->Threats[i].RiskScore > maxRisk) {
            maxRisk = Result->Threats[i].RiskScore;
        }
        avg += Result->Threats[i].RiskScore;
    }
    avg /= Result->ThreatsFound;
    Result->MaxSeverity = maxRisk;
    return (ULONG)((maxRisk * 7 + avg * 3) / 10);
}

/*++
 * MsScanProcessMemoryFull
 *   全流程内存扫描 (对齐 PS ScanProcessMemory, MemoryScanner.cpp L1541).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsScanProcessMemoryFull(
    DWORD ProcessId,
    WKD_MEM_SCAN_MODE Mode,
    PWKD_MEM_SCAN_RESULT Result
    )
/*++
Routine Description:
    枚举进程内存区域 → 过滤 → TOCTOU → 检测层 (PE/壳码/高熵/C2) →
    双引擎 YARA → 威胁聚合 + 风险汇总.

Arguments:
    ProcessId - 目标进程 PID.
    Mode      - 扫描模式 (Quick/Normal/Deep).
    Result    - 输出扫描结果.

Return Value:
    NTSTATUS.
--*/
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = NULL;
    LARGE_INTEGER start, now, end;
    ULONG64 bytesAccum = 0;

    if (Result == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    Result->ProcessId = ProcessId;
    Result->Mode = Mode;
    Result->Completed = FALSE;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_ACCESS_DENIED;
    }
    InterlockedIncrement64(&g_MsStats.TotalScans);

    /* 模块表对照集 (隐藏模块判定, 对齐 SS GetPEBModulesImpl) */
    {
        WKD_MEM_MODULE_SET moduleSet;
        RtlZeroMemory(&moduleSet, sizeof(moduleSet));
        MsBuildModuleSet(ProcessId, &moduleSet);

        GetSystemTimeAsFileTime((PFILETIME)&start);

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        ULONG_PTR next;

        if (mbi.State == MEM_COMMIT) {
            WKD_MEMORY_REGION region;

            RtlZeroMemory(&region, sizeof(region));
            region.BaseAddress = (ULONG_PTR)mbi.BaseAddress;
            region.RegionSize = mbi.RegionSize;
            region.Protection = mbi.Protect;
            region.AllocationProtect = mbi.AllocationProtect;
            region.Type = MsRegionTypeFromMbi(mbi.Type);
            region.State = WkdMemState_Committed;
            region.IsExecutable = MsIsExecutableProtection(mbi.Protect);
            region.IsWritable = MsIsWritableProtection(mbi.Protect);
            region.IsPrivate = (mbi.Type == MEM_PRIVATE);
            region.IsRwx = MsIsRwxProtection(mbi.Protect);
            region.IsUnbackedExec = (region.IsExecutable && region.IsPrivate);
            MsCheckSuspiciousRegion(&region);

            Result->TotalRegions++;

            if (MsShouldScanRegion(&region, Mode)) {
                /* 超时/字节上限 */
                GetSystemTimeAsFileTime((PFILETIME)&now);
                if (now.QuadPart - start.QuadPart > MS_SCAN_TIMEOUT_100NS) {
                    InterlockedIncrement64(&g_MsStats.Timeouts);
                    break;
                }
                if (bytesAccum >= MS_MAX_BYTES_PER_PROC) break;

                /* Guard 页: 不读, 直接记规避威胁 (对齐 PS L805) */
                if (region.Protection & PAGE_GUARD) {
                    WKD_MEM_THREAT threat;
                    RtlZeroMemory(&threat, sizeof(threat));
                    threat.Type = WkdMemThreat_SuspiciousCode;
                    threat.RegionBase = region.BaseAddress;
                    threat.RegionSize = region.RegionSize;
                    threat.Protection = region.Protection;
                    threat.MemType = region.Type;
                    strcpy_s(threat.MatchedRule, sizeof(threat.MatchedRule),
                             "Guard Page (anti-scan evasion)");
                    strcpy_s(threat.RuleCategory, sizeof(threat.RuleCategory), "Evasion");
                    threat.Confidence = 55;
                    threat.RiskScore = 60;
                    strcpy_s(threat.MitreTechnique, sizeof(threat.MitreTechnique), "T1497");
                    MsAddThreat(Result, &threat);
                    Result->RegionsScanned++;
                    continue;
                }

                MsScanRegionContent(ProcessId, hProcess, &region, &moduleSet, Result);
                Result->RegionsScanned++;
                bytesAccum += region.RegionSize;

                if (region.IsSuspicious &&
                    Result->SuspiciousRegionCount < WKD_MEM_MAX_SUSPICIOUS) {
                    Result->SuspiciousRegions[Result->SuspiciousRegionCount++] = region;
                }
            } else {
                Result->RegionsSkipped++;
            }
        }

        /* 推进地址 (防回绕/零尺寸死循环) */
        next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;
        addr = (LPCVOID)next;
    }
    }   /* 结束 moduleSet 作用域 (模块表对照) */

    GetSystemTimeAsFileTime((PFILETIME)&end);
    Result->DurationMs = (ULONG)((end.QuadPart - start.QuadPart) / 10000);
    InterlockedAdd64(&g_MsStats.CumulativeScanTimeMs, Result->DurationMs);

    CloseHandle(hProcess);
    Result->Completed = TRUE;
    Result->OverallRiskScore = MsCalculateOverallRisk(Result);
    return STATUS_SUCCESS;
}

/*++
 * MsScanBufferFull
 *   无进程上下文缓冲扫描 (对齐 PS ScanBuffer, MemoryScanner.cpp L2162).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsScanBufferFull(
    const BYTE* Buffer,
    ULONG BufferSize,
    PWKD_MEM_SCAN_RESULT Result
    )
{
    WKD_MEM_THREAT threat;
    LARGE_INTEGER start, end;

    if (Result == NULL || Buffer == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(*Result));
    Result->Mode = WkdMemScan_Normal;
    Result->Completed = TRUE;
    InterlockedIncrement64(&g_MsStats.TotalScans);
    InterlockedAdd64(&g_MsStats.BytesScanned, BufferSize);
    GetSystemTimeAsFileTime((PFILETIME)&start);

    /* 检测层 (模拟私有可执行区域, 对齐 PS ScanBuffer) */
    if (MsDetectPE(Buffer, BufferSize, &threat)) {
        MsAddRegionThreat(Result, &threat, Buffer, BufferSize,
                          0, 0, 0, WkdMemType_Private);
    }
    if (MsDetectShellcode(Buffer, BufferSize, TRUE, &threat)) {
        MsAddRegionThreat(Result, &threat, Buffer, BufferSize,
                          0, 0, 0, WkdMemType_Private);
    }
    if (MsCheckHighEntropy(Buffer, BufferSize, NULL, &threat)) {
        MsAddRegionThreat(Result, &threat, Buffer, BufferSize,
                          0, 0, 0, WkdMemType_Private);
    }
    if (MsDetectC2Beacon(Buffer, BufferSize, &threat)) {
        MsAddRegionThreat(Result, &threat, Buffer, BufferSize,
                          0, 0, 0, WkdMemType_Private);
    }

    /* 双引擎 YARA */
    MsScanRegionYara(Buffer, BufferSize, Result);

    GetSystemTimeAsFileTime((PFILETIME)&end);
    Result->DurationMs = (ULONG)((end.QuadPart - start.QuadPart) / 10000);
    InterlockedAdd64(&g_MsStats.CumulativeScanTimeMs, Result->DurationMs);
    Result->OverallRiskScore = MsCalculateOverallRisk(Result);
    return STATUS_SUCCESS;
}

/**************************************************/
/*  死代码迁移 — 暂不接线                          */
/*  (待 UI 主动扫描 / 取证阶段接入)                */
/**************************************************/

/*++
 * MsScanProcesses
 *   多进程扫描 (对齐 PS ScanProcesses, MemoryScanner.cpp L1992).
 *   当前串行实现; 死代码: 待线程池并行化后接线。
 *--*/
_Use_decl_annotations_
NTSTATUS
MsScanProcesses(
    const DWORD* Pids,
    ULONG PidCount,
    PWKD_MEM_SCAN_RESULT Results,
    ULONG MaxResults,
    PULONG ResultCount
    )
{
    ULONG i, count = 0;

    if (Pids == NULL || Results == NULL || ResultCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ResultCount = 0;

    for (i = 0; i < PidCount && count < MaxResults; i++) {
        if (NT_SUCCESS(MsScanProcessMemoryFull(Pids[i], WkdMemScan_Normal,
                                               &Results[count]))) {
            count++;
        }
    }
    *ResultCount = count;
    return STATUS_SUCCESS;
}

/*++
 * MsScanAllProcesses
 *   枚举全部进程逐个扫描 (对齐 PS ScanAllProcesses, MemoryScanner.cpp L2031).
 *   死代码: 待 UI 主动全盘扫描接线。
 *--*/
_Use_decl_annotations_
NTSTATUS
MsScanAllProcesses(
    PWKD_MEM_SCAN_RESULT Results,
    ULONG MaxResults,
    PULONG ResultCount
    )
{
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    DWORD pids[1024];
    ULONG pidCount = 0, i;

    if (Results == NULL || ResultCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ResultCount = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (pidCount >= RTL_NUMBER_OF(pids)) break;
            pids[pidCount++] = pe.th32ProcessID;
        } while (Process32NextW(snapshot, &pe) && pidCount < RTL_NUMBER_OF(pids));
    }
    CloseHandle(snapshot);

    for (i = 0; i < pidCount && i < MaxResults; i++) {
        if (NT_SUCCESS(MsScanProcessMemoryFull(pids[i], WkdMemScan_Normal,
                                               &Results[i]))) {
            (*ResultCount)++;
        }
    }
    return STATUS_SUCCESS;
}

/*++
 * MsScanRegionAt
 *   定向扫描指定内存区域 [Base, Base+Size).
 *   对齐 PS ScanRegion + ScanRegionInternal (MemoryScanner.cpp L2059).
 *   为内核内存事件定向深度分析预留; 死代码: wkd 事件流不同, 暂不接线。
 *--*/
_Use_decl_annotations_
NTSTATUS
MsScanRegionAt(
    DWORD ProcessId,
    ULONG_PTR BaseAddress,
    SIZE_T Size,
    PWKD_MEM_SCAN_RESULT Result
    )
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    WKD_MEMORY_REGION region;
    LARGE_INTEGER start, end;

    if (Result == NULL || BaseAddress == 0 || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(*Result));
    Result->ProcessId = ProcessId;
    Result->Mode = WkdMemScan_Normal;
    GetSystemTimeAsFileTime((PFILETIME)&start);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) return STATUS_ACCESS_DENIED;
    InterlockedIncrement64(&g_MsStats.TotalScans);

    if (VirtualQueryEx(hProcess, (LPCVOID)BaseAddress, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        CloseHandle(hProcess);
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(&region, sizeof(region));
    region.BaseAddress = BaseAddress;
    region.RegionSize = (Size > 0) ? Size : mbi.RegionSize;
    region.Protection = mbi.Protect;
    region.AllocationProtect = mbi.AllocationProtect;
    region.Type = MsRegionTypeFromMbi(mbi.Type);
    region.State = (mbi.State == MEM_COMMIT) ? WkdMemState_Committed : WkdMemState_Reserved;
    region.IsExecutable = MsIsExecutableProtection(mbi.Protect);
    region.IsWritable = MsIsWritableProtection(mbi.Protect);
    region.IsPrivate = (mbi.Type == MEM_PRIVATE);
    region.IsRwx = MsIsRwxProtection(mbi.Protect);
    region.IsUnbackedExec = (region.IsExecutable && region.IsPrivate);
    MsCheckSuspiciousRegion(&region);

    /* 模块表对照集 (隐藏模块判定) */
    {
        WKD_MEM_MODULE_SET moduleSet;
        RtlZeroMemory(&moduleSet, sizeof(moduleSet));
        MsBuildModuleSet(ProcessId, &moduleSet);
        MsScanRegionContent(ProcessId, hProcess, &region, &moduleSet, Result);
    }
    CloseHandle(hProcess);

    GetSystemTimeAsFileTime((PFILETIME)&end);
    Result->DurationMs = (ULONG)((end.QuadPart - start.QuadPart) / 10000);
    InterlockedAdd64(&g_MsStats.CumulativeScanTimeMs, Result->DurationMs);

    Result->TotalRegions = 1;
    Result->RegionsScanned = 1;
    Result->Completed = TRUE;
    Result->OverallRiskScore = MsCalculateOverallRisk(Result);
    return STATUS_SUCCESS;
}

/*++
 * MsDumpRegion
 *   单区域内存转储到文件 (对齐 PS DumpRegion, MemoryScanner.cpp L2380).
 *   死代码: 取证阶段接入。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsDumpRegion(
    DWORD ProcessId,
    ULONG_PTR Address,
    SIZE_T Size,
    PCWSTR OutputPath
    )
{
    HANDLE hProcess;
    BYTE* buffer;
    SIZE_T bytesRead = 0;
    HANDLE hFile;
    DWORD written;
    BOOLEAN ok = FALSE;

    if (OutputPath == NULL || Size == 0 || Size > MS_REGION_READ_LIMIT) return FALSE;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return FALSE;

    buffer = (BYTE*)malloc(Size);
    if (buffer == NULL) { CloseHandle(hProcess); return FALSE; }

    if (ReadProcessMemory(hProcess, (LPCVOID)Address, buffer, Size, &bytesRead) && bytesRead > 0) {
        hFile = CreateFileW(OutputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, buffer, (DWORD)bytesRead, &written, NULL);
            CloseHandle(hFile);
            ok = TRUE;
        }
    }

    free(buffer);
    CloseHandle(hProcess);
    return ok;
}

/*++
 * MsCreateMemoryDump
 *   全进程内存转储 (对齐 PS CreateMemoryDump, MemoryScanner.cpp L2413).
 *   死代码: 取证阶段接入。
 *--*/
_Use_decl_annotations_
BOOLEAN
MsCreateMemoryDump(
    DWORD ProcessId,
    PCWSTR OutputPath
    )
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = NULL;
    HANDLE hFile;
    BOOLEAN ok = FALSE;

    if (OutputPath == NULL) return FALSE;

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) return FALSE;

    hFile = CreateFileW(OutputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProcess); return FALSE; }

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        ULONG_PTR next;

        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0) {
            BYTE* buffer = (BYTE*)malloc((size_t)mbi.RegionSize);
            if (buffer) {
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer,
                                      mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                    DWORD written;
                    WriteFile(hFile, buffer, (DWORD)bytesRead, &written, NULL);
                    ok = TRUE;
                }
                free(buffer);
            }
        }

        next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;
        addr = (LPCVOID)next;
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);
    return ok;
}

/**************************************************/
/*  死代码补充 — ShadowStrike MemoryScanner 遗漏项  */
/*  (工具函数/完整分析, 暂不接线)                   */
/**************************************************/

/*++
 * MsReadMemory
 *   安全读进程内存, 上限 MS_REGION_READ_LIMIT (对齐 PS MAX_REGION_SIZE).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsReadMemory(
    DWORD ProcessId,
    ULONG_PTR Address,
    SIZE_T Size,
    PBYTE* OutBuffer,
    PULONG OutSize
    )
{
    HANDLE hProcess;
    BYTE* buffer;
    SIZE_T bytesRead = 0;

    if (OutBuffer == NULL || OutSize == NULL) return STATUS_INVALID_PARAMETER;
    *OutBuffer = NULL;
    *OutSize = 0;

    if (Size == 0) return STATUS_INVALID_PARAMETER;
    if (Size > MS_REGION_READ_LIMIT) Size = MS_REGION_READ_LIMIT;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return STATUS_ACCESS_DENIED;

    buffer = (BYTE*)malloc(Size);
    if (buffer == NULL) { CloseHandle(hProcess); return STATUS_NO_MEMORY; }

    if (!ReadProcessMemory(hProcess, (LPCVOID)Address, buffer, Size, &bytesRead) ||
        bytesRead == 0) {
        free(buffer);
        CloseHandle(hProcess);
        return STATUS_UNSUCCESSFUL;
    }

    CloseHandle(hProcess);
    *OutBuffer = buffer;
    *OutSize = (ULONG)bytesRead;
    return STATUS_SUCCESS;
}

/*++
 * MsExtractPayload
 *   提取反射加载 PE 内存映像 (对齐 SS ExtractPayload, ReflectiveDLLDetector.cpp L1587-1635).
 *   上限 100MB (对齐 SS kMaxExtraction=100MB).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsExtractPayload(
    DWORD ProcessId,
    ULONG_PTR BaseAddress,
    SIZE_T Size,
    PBYTE* OutBuffer,
    PULONG OutSize
    )
{
    const SIZE_T kMaxExtraction = 100 * 1024 * 1024;   /* 对齐 SS kMaxExtraction */

    if (Size == 0 || Size > kMaxExtraction) {
        /* 对齐 SS: 无效大小直接失败, 防 DoS */
        if (OutBuffer) *OutBuffer = NULL;
        if (OutSize) *OutSize = 0;
        return STATUS_INVALID_PARAMETER;
    }

    return MsReadMemory(ProcessId, BaseAddress, Size, OutBuffer, OutSize);
}

/*++
 * MsReconstructPE 已迁移至 IOC\PEAnalyzer (WpeReconstructPeFromMemory)。
 * 重建能力由 PEAnalyzer 统一承接, 此处不再保留重复实现。
 *--*/

/*++
 * MsDumpPE
 *   提取 PE 内存映像并写盘 (对齐 SS DumpPE, ReflectiveDLLDetector.cpp L1637-1655).
 *--*/
_Use_decl_annotations_
BOOLEAN
MsDumpPE(
    DWORD ProcessId,
    ULONG_PTR BaseAddress,
    SIZE_T Size,
    PCWSTR OutputPath
    )
{
    PBYTE buf = NULL;
    ULONG bufSize = 0;
    FILE* f = NULL;
    BOOLEAN ok = FALSE;

    if (OutputPath == NULL) return FALSE;
    if (!NT_SUCCESS(MsExtractPayload(ProcessId, BaseAddress, Size, &buf, &bufSize))) {
        return FALSE;
    }
    if (buf == NULL || bufSize == 0) return FALSE;

    if (_wfopen_s(&f, OutputPath, L"wb") == 0 && f != NULL) {
        ok = (fwrite(buf, 1, bufSize, f) == bufSize);
        fclose(f);
    }
    free(buf);
    return ok;
}

/*++
 * MsEnumerateRegions
 *   完整区域枚举 (对齐 PS EnumerateRegions, 返回全部提交区域含完整模型).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsEnumerateRegions(
    DWORD ProcessId,
    PWKD_MEMORY_REGION Regions,
    ULONG MaxRegions,
    PULONG Count
    )
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = NULL;
    ULONG collected = 0;

    if (Regions == NULL || MaxRegions == 0 || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    RtlZeroMemory(Regions, (SIZE_T)MaxRegions * sizeof(WKD_MEMORY_REGION));

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return STATUS_ACCESS_DENIED;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && collected < MaxRegions) {
            WKD_MEMORY_REGION* r = &Regions[collected];
            r->BaseAddress = (ULONG_PTR)mbi.BaseAddress;
            r->RegionSize = mbi.RegionSize;
            r->Protection = mbi.Protect;
            r->AllocationProtect = mbi.AllocationProtect;
            r->Type = MsRegionTypeFromMbi(mbi.Type);
            r->State = WkdMemState_Committed;
            r->IsExecutable = MsIsExecutableProtection(mbi.Protect);
            r->IsWritable = MsIsWritableProtection(mbi.Protect);
            r->IsPrivate = (mbi.Type == MEM_PRIVATE);
            r->IsRwx = MsIsRwxProtection(mbi.Protect);
            r->IsUnbackedExec = (r->IsExecutable && r->IsPrivate);
            MsCheckSuspiciousRegion(r);
            collected++;
        }

        {
            ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (next <= (ULONG_PTR)addr) break;
            addr = (LPCVOID)next;
        }
    }

    CloseHandle(hProcess);
    *Count = collected;
    return STATUS_SUCCESS;
}

/*++
 * MsEnumerateExecutableRegions
 *   可执行区域子集 (对齐 PS EnumerateExecutableRegions).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsEnumerateExecutableRegions(
    DWORD ProcessId,
    PWKD_MEMORY_REGION Regions,
    ULONG MaxRegions,
    PULONG Count
    )
{
    WKD_MEMORY_REGION all[512];
    ULONG allCount = 0, i, out = 0;

    if (Regions == NULL || MaxRegions == 0 || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;

    if (NT_SUCCESS(MsEnumerateRegions(ProcessId, all, RTL_NUMBER_OF(all), &allCount))) {
        for (i = 0; i < allCount && out < MaxRegions; i++) {
            if (all[i].IsExecutable && all[i].State == WkdMemState_Committed) {
                Regions[out++] = all[i];
            }
        }
    }
    *Count = out;
    return STATUS_SUCCESS;
}

/*++
 * MsEnumerateSuspiciousRegions
 *   可疑区域子集 (对齐 PS EnumerateSuspiciousRegions).
 *--*/
_Use_decl_annotations_
NTSTATUS
MsEnumerateSuspiciousRegions(
    DWORD ProcessId,
    PWKD_MEMORY_REGION Regions,
    ULONG MaxRegions,
    PULONG Count
    )
{
    WKD_MEMORY_REGION all[512];
    ULONG allCount = 0, i, out = 0;

    if (Regions == NULL || MaxRegions == 0 || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;

    if (NT_SUCCESS(MsEnumerateRegions(ProcessId, all, RTL_NUMBER_OF(all), &allCount))) {
        for (i = 0; i < allCount && out < MaxRegions; i++) {
            if (all[i].IsSuspicious) {
                Regions[out++] = all[i];
            }
        }
    }
    *Count = out;
    return STATUS_SUCCESS;
}

/*++
 * MsGetRegionInfo
 *   地址 → 区域信息 (对齐 PS GetRegionInfo).
 *--*/
_Use_decl_annotations_
BOOLEAN
MsGetRegionInfo(
    DWORD ProcessId,
    ULONG_PTR Address,
    PWKD_MEMORY_REGION Region
    )
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;

    if (Region == NULL || Address == 0) return FALSE;
    RtlZeroMemory(Region, sizeof(*Region));

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) return FALSE;

    if (VirtualQueryEx(hProcess, (LPCVOID)Address, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    Region->BaseAddress = (ULONG_PTR)mbi.BaseAddress;
    Region->RegionSize = mbi.RegionSize;
    Region->Protection = mbi.Protect;
    Region->AllocationProtect = mbi.AllocationProtect;
    Region->Type = MsRegionTypeFromMbi(mbi.Type);
    Region->State = (mbi.State == MEM_COMMIT) ? WkdMemState_Committed :
                    (mbi.State == MEM_RESERVE) ? WkdMemState_Reserved : WkdMemState_Free;
    Region->IsExecutable = MsIsExecutableProtection(mbi.Protect);
    Region->IsWritable = MsIsWritableProtection(mbi.Protect);
    Region->IsPrivate = (mbi.Type == MEM_PRIVATE);
    Region->IsRwx = MsIsRwxProtection(mbi.Protect);
    Region->IsUnbackedExec = (Region->IsExecutable && Region->IsPrivate);
    MsCheckSuspiciousRegion(Region);

    CloseHandle(hProcess);
    return TRUE;
}

/*++
 * MsAnalyzeShellcode
 *   完整壳码分析 (对齐 PS AnalyzeForShellcode, 置信度对齐 SS SdpCalculateConfidenceScore).
 *   2026-08-07: 接入 SS ShellcodeDetector PIC/哈希值解析/高熵字段, 评分替换
 *   为 SS 组合加分表 (MsScoreShellcodeConfidence).
 *--*/
_Use_decl_annotations_
VOID
MsAnalyzeShellcode(
    const BYTE* Buffer,
    ULONG Size,
    PWKD_SHELLCODE_ANALYSIS Analysis
    )
{
    ULONG flags;
    ULONG r;
    ULONG s;
    ULONG apiCount;
    ULONGLONG startMs;

    if (Analysis == NULL) return;
    RtlZeroMemory(Analysis, sizeof(*Analysis));
    strcpy_s(Analysis->Architecture, sizeof(Analysis->Architecture), "x86");

    if (Buffer == NULL || Size < MS_MIN_SHELLCODE_SIZE) return;

    startMs = GetTickCount64();   /* 分析耗时计时 (对齐 SS AnalysisDurationMs) */

    flags = IocDetectShellcode(Buffer, Size, TRUE);

    if (flags & T1_SC_NOP_SLED) {
        ULONG nopOffset = 0, nopLength = 0;
        UCHAR nopByte = 0;
        Analysis->HasNopSled = TRUE;
        /* 补明细 (对齐 SS SdpDetectNopSledInternal): 评分 NopSledLength>64 加成 + 取证 NopByte */
        if (MsScanNopSled(Buffer, Size, &nopOffset, &nopLength, &nopByte)) {
            Analysis->NopSledLength = nopLength;
            Analysis->NopSledOffset = nopOffset;
            Analysis->NopByte = nopByte;
        }
    }
    if (flags & T1_SC_GETPC) {
        Analysis->HasGetPc = TRUE;
    }
    if (flags & T1_SC_APIHASH) {
        Analysis->HasApiHashing = TRUE;
        strcpy_s(Analysis->ApiHashAlgorithm, sizeof(Analysis->ApiHashAlgorithm), "ROL/ROR");
    }
    if (flags & T1_SC_SYSCALL) {
        WKD_SYSCALL_STUB stubs[16];
        ULONG stubCount = 0;
        ULONG n;
        Analysis->HasSyscallStubs = TRUE;
        /* 补明细 (对齐 SS SdpDetectDirectSyscalls): 评分 SyscallCount>2 加成 */
        if (MsScanDirectSyscalls(Buffer, Size, stubs, 16, &stubCount)) {
            Analysis->SyscallCount = stubCount;
            n = min(stubCount, (ULONG)RTL_NUMBER_OF(Analysis->SyscallNumbers));
            for (s = 0; s < n; s++) {
                Analysis->SyscallNumbers[s] = stubs[s].SyscallNumber;
            }
        }
    }
    if (flags & T1_SC_X64) {
        strcpy_s(Analysis->Architecture, sizeof(Analysis->Architecture), "x64");
    }

    /* ShadowStrike ShellcodeDetector 迁移 2026-08：SS 独有检测（wkd T1 未覆盖），
     * 对齐 SS SdpDetectEggHunter/EncoderLoop/HeavensGate/StackPivot/SuspiciousCalls */
    if (MsScanEggHunter(Buffer, Size, &Analysis->EggHunterOffset)) {
        Analysis->HasEggHunter = TRUE;
    }
    if (MsScanEncoderLoop(Buffer, Size, Analysis->EncoderType, sizeof(Analysis->EncoderType),
                          &Analysis->EncoderLoopOffset)) {
        Analysis->HasEncoder = TRUE;
    }
    if (MsScanHeavensGate(Buffer, Size)) {
        Analysis->HasHeavensGate = TRUE;
    }
    if (MsScanStackPivot(Buffer, Size, &Analysis->StackPivotGadgetOffset)) {
        Analysis->HasStackPivot = TRUE;
    }
    if (MsScanSuspiciousCalls(Buffer, Size)) {
        Analysis->HasSuspiciousCall = TRUE;
    }

    /* SS ShellcodeDetector 迁移 2026-08-07：PIC 5 模式 (SdpDetectPositionIndependentCode) */
    if (MsScanPositionIndependentCode(Buffer, Size)) {
        Analysis->HasPic = TRUE;
    }

    /* SS ShellcodeDetector 迁移 2026-08-07：API 哈希值解析 (SdpDetectApiHashing) —
     * 提取 MOV/PUSH imm32 查 38 条 ROR13 库解析 API 名, 升级 ApiHashAlgorithm 为 "ROR13" */
    {
        WKD_API_HASH_RESULT resolved;
        if (MsScanApiHashResolution(Buffer, Size, &resolved)) {
            Analysis->HasApiHashing = TRUE;
            strcpy_s(Analysis->ApiHashAlgorithm, sizeof(Analysis->ApiHashAlgorithm), "ROR13");
            Analysis->ResolvedApiCount = resolved.ResolvedCount;
            apiCount = min(resolved.ResolvedCount, (ULONG)RTL_NUMBER_OF(Analysis->ResolvedApis));
            for (r = 0; r < apiCount; r++) {
                strcpy_s(Analysis->ResolvedApis[r], sizeof(Analysis->ResolvedApis[r]),
                         resolved.Resolved[r].ApiName);
            }
        }
    }

    /* 熵分析（对齐 SS SdpCalculateEntropy，0-1000 尺度阈值 700 ↔ SS 70%） */
    Analysis->HasHighEntropy = (MsCalculateEntropy(Buffer, Size) >= MS_ENTROPY_THRESHOLD);

    /* 置信度评分 (SS SdpCalculateConfidenceScore 12 单项 + 5 组合加分, cap 100) */
    Analysis->Confidence = MsScoreShellcodeConfidence(Analysis);
    Analysis->IsShellcode = (Analysis->Confidence >= 50);   /* SS MinConfidenceScore 默认 50 */

    /* 分析耗时 (对齐 SS SdAnalyzeBuffer AnalysisDurationMs) */
    Analysis->AnalysisDurationMs = (ULONG)(GetTickCount64() - startMs);
}

/*++
 * MsCalculateEntropy
 *   公共熵计算 (复用 CoEntropyBinary, 返回 bits*1000).
 *--*/
_Use_decl_annotations_
ULONG
MsCalculateEntropy(
    const BYTE* Buffer,
    ULONG Size
    )
{
    if (Buffer == NULL || Size == 0) return 0;
    return (ULONG)(CoEntropyBinary(Buffer, Size, 0) * 1000.0);
}

/*++
 * MsCheckAPIHashing
 *   公共 API 哈希检测 (对齐 PS CheckAPIHashing).
 *--*/
_Use_decl_annotations_
BOOLEAN
MsCheckAPIHashing(
    const BYTE* Buffer,
    ULONG Size
    )
{
    if (Buffer == NULL || Size == 0) return FALSE;
    return (IocDetectShellcode(Buffer, Size, TRUE) & T1_SC_APIHASH) != 0;
}

/**************************************************/
/*  ShadowStrike ShellcodeDetector 迁移 2026-08     */
/*  SS 独有检测（wkd IocDetectShellcode 未覆盖）  */
/**************************************************/

/* EggHunter 签名（对齐 SS ShellcodeDetector.c g_EggHunter* L107-128） */
static const BYTE kSsEggHunterSeh[] = {
    0x66,0x81,0xCA,0xFF,0x0F,0x42,0x52,0x6A,0x02
};
static const BYTE kSsEggHunterSyscall[] = {
    0x66,0x81,0xCA,0xFF,0x0F,0x42,0x52,0x31,0xC0,0xCD,0x2E
};
static const BYTE kSsEggHunterNtDisplay[] = {
    0x66,0x81,0xCA,0xFF,0x0F,0x42,0x6A,0x43,0x58,0xCD,0x2E
};
/* Heaven's Gate RETF 过渡（对齐 SS g_HeavensGateRetf L172-177） */
static const BYTE kSsHeavensGateRetf[] = {
    0x6A,0x33,0xE8,0x00,0x00,0x00,0x00,0x83,0x04,0x24,0x05,0xCB
};
/* 扫描窗口（对齐 SS SD_EGG_HUNTER_MAX_SIZE=128 / SD_ENCODER_LOOP_MAX_SIZE=256，×4 扫描开头） */
#define SD_EGG_HUNTER_SCAN       (128 * 4)
#define SD_ENCODER_LOOP_SCAN     (256 * 4)

/*++
 * MsScanEggHunter
 *   EggHunter 检测（对齐 SS SdpDetectEggHunter L2378）：SEH/syscall/
 *   NtDisplayString 3 签名 + 通用 OR DX,0x0FFF; INC EDX 模式。
 *   HunterOffset 输出命中相对偏移 (对齐 SS EggHunter.HunterAddress)。
 *--*/
static BOOLEAN
MsScanEggHunter(
    const BYTE* Buffer,
    ULONG Size,
    PULONG HunterOffset
    )
{
    ULONG scanSize = Size;
    ULONG i;

    if (Buffer == NULL || Size < 5) return FALSE;
    if (HunterOffset != NULL) *HunterOffset = 0;

    /* 仅扫描缓冲开头（egg hunter 通常 <128 字节，对齐 SS ×4） */
    if (scanSize > SD_EGG_HUNTER_SCAN) scanSize = SD_EGG_HUNTER_SCAN;

    for (i = 0; i < scanSize; i++) {
        /* SEH 签名 */
        if (i + sizeof(kSsEggHunterSeh) <= scanSize &&
            RtlCompareMemory(&Buffer[i], kSsEggHunterSeh, sizeof(kSsEggHunterSeh)) == sizeof(kSsEggHunterSeh)) {
            if (HunterOffset != NULL) *HunterOffset = i;
            return TRUE;
        }
        /* Syscall 签名 */
        if (i + sizeof(kSsEggHunterSyscall) <= scanSize &&
            RtlCompareMemory(&Buffer[i], kSsEggHunterSyscall, sizeof(kSsEggHunterSyscall)) == sizeof(kSsEggHunterSyscall)) {
            if (HunterOffset != NULL) *HunterOffset = i;
            return TRUE;
        }
        /* NtDisplayString 签名 */
        if (i + sizeof(kSsEggHunterNtDisplay) <= scanSize &&
            RtlCompareMemory(&Buffer[i], kSsEggHunterNtDisplay, sizeof(kSsEggHunterNtDisplay)) == sizeof(kSsEggHunterNtDisplay)) {
            if (HunterOffset != NULL) *HunterOffset = i;
            return TRUE;
        }
        /* 通用模式：OR DX,0x0FFF (66 81 CA FF 0F) */
        if (i + 5 <= scanSize &&
            Buffer[i] == 0x66 && Buffer[i + 1] == 0x81 && Buffer[i + 2] == 0xCA &&
            Buffer[i + 3] == 0xFF && Buffer[i + 4] == 0x0F) {
            if (HunterOffset != NULL) *HunterOffset = i;
            return TRUE;
        }
    }
    return FALSE;
}

/*++
 * MsScanEncoderLoop
 *   编码器循环检测（对齐 SS SdpDetectEncoderLoop L2458）：XOR/ADD/SUB/ROL/ROR
 *   操作码 + 邻近 LOOP/JMP/JNZ/JZ 循环指令。
 *--*/
static BOOLEAN
MsScanEncoderLoop(
    const BYTE* Buffer,
    ULONG Size,
    CHAR* EncoderType,
    ULONG TypeSize,
    PULONG LoopOffset
    )
{
    ULONG scanSize = Size;
    ULONG i;

    if (Buffer == NULL || Size < 5 || EncoderType == NULL) return FALSE;
    if (TypeSize > 0) EncoderType[0] = '\0';

    if (scanSize > SD_ENCODER_LOOP_SCAN) scanSize = SD_ENCODER_LOOP_SCAN;

    for (i = 0; i + 4 < scanSize; i++) {
        BOOLEAN candidate = FALSE;
        BOOLEAN loopJcc = FALSE;   /* TRUE=XOR 认 JNZ/JZ; FALSE=ADD/SUB/ROL/ROR 仅 LOOP/JMP (对齐 SS L2496-2583) */
        const char* typeName = NULL;

        /* XOR BYTE PTR [reg+offset], imm8 (80 34) / XOR [reg],reg (31/33, 需内存操作数
         * modrm&0xC0!=0xC0 排除 31 C0=XOR EAX,EAX 等寄存器清零惯用法, 对齐 SS L2517) */
        if (Buffer[i] == 0x80 && (Buffer[i + 1] & 0x38) == 0x30) { candidate = TRUE; loopJcc = TRUE; typeName = "XOR"; }
        else if ((Buffer[i] == 0x31 || Buffer[i] == 0x33) && (Buffer[i + 1] & 0xC0) != 0xC0) { candidate = TRUE; loopJcc = TRUE; typeName = "XOR"; }
        /* ADD BYTE PTR [reg+offset], imm8 (80 00) */
        else if (Buffer[i] == 0x80 && (Buffer[i + 1] & 0x38) == 0x00) { candidate = TRUE; typeName = "ADD"; }
        /* SUB BYTE PTR [reg+offset], imm8 (80 28) */
        else if (Buffer[i] == 0x80 && (Buffer[i + 1] & 0x38) == 0x28) { candidate = TRUE; typeName = "SUB"; }
        /* ROL/ROR (C0 00 / C0 08) */
        else if (Buffer[i] == 0xC0 &&
                 ((Buffer[i + 1] & 0x38) == 0x00 || (Buffer[i + 1] & 0x38) == 0x08)) {
            candidate = TRUE;
            typeName = ((Buffer[i + 1] & 0x38) == 0x00) ? "ROL" : "ROR";
        }

        if (candidate) {
            ULONG j;
            for (j = i + 3; j < min(i + 32, scanSize - 1); j++) {
                BOOLEAN isLoop = (Buffer[j] == 0xE2 || Buffer[j] == 0xEB);  /* LOOP / JMP short */
                if (loopJcc) {
                    isLoop = isLoop || Buffer[j] == 0x75 || Buffer[j] == 0x74;  /* JNZ / JZ (仅 XOR) */
                }
                if (isLoop) {
                    if (TypeSize > 0 && typeName != NULL) {
                        strcpy_s(EncoderType, TypeSize, typeName);
                    }
                    if (LoopOffset != NULL) {
                        *LoopOffset = i;   /* 解码循环起始偏移 (对齐 SS Encoder.LoopStart=&buffer[i]) */
                    }
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/*++
 * MsScanHeavensGate
 *   WoW64 32→64 过渡检测（对齐 SS SdpDetectHeavensGate L2792）：
 *   JMP FAR 0x33/0x23 段 / RETF 过渡 / PUSH 0x33;...;RETF。
 *--*/
static BOOLEAN
MsScanHeavensGate(
    const BYTE* Buffer,
    ULONG Size
    )
{
    ULONG i;

    if (Buffer == NULL || Size < 13) return FALSE;

    if (MsContainsBytes(Buffer, Size, kSsHeavensGateRetf, sizeof(kSsHeavensGateRetf))) return TRUE;

    for (i = 0; i + 7 <= Size; i++) {
        /* JMP FAR（EA offset4 seg2），段为 0x33/0x23（64 位代码段） */
        if (Buffer[i] == 0xEA) {
            USHORT segment;
            RtlCopyMemory(&segment, &Buffer[i + 5], sizeof(USHORT));
            if (segment == 0x33 || segment == 0x23) return TRUE;
        }
        /* PUSH 0x33; ...; RETF（6A 33 ... CB） */
        if (Buffer[i] == 0x6A && Buffer[i + 1] == 0x33 &&
            i + 7 <= Size && Buffer[i + 6] == 0xCB) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
 * MsScanStackPivot
 *   栈转移 gadget 检测（对齐 SS SdpDetectStackPivot L2851）：
 *   XCHG ESP / MOV ESP / LEAVE RET / POP ESP / ADD ESP large + RET 验证。
 *   GadgetOffset 输出命中相对偏移 (对齐 SS StackPivot.GadgetAddress)。
 *--*/
static BOOLEAN
MsScanStackPivot(
    const BYTE* Buffer,
    ULONG Size,
    PULONG GadgetOffset
    )
{
    ULONG i;

    if (Buffer == NULL || Size < 5) return FALSE;
    if (GadgetOffset != NULL) *GadgetOffset = 0;

    for (i = 0; i + 4 < Size; i++) {
        BOOLEAN isGadget = FALSE;
        ULONG gadgetSize = 0;

        /* XCHG EAX, ESP (94) */
        if (Buffer[i] == 0x94) { isGadget = TRUE; gadgetSize = 1; }
        /* XCHG reg, ESP (87 xx) */
        else if (Buffer[i] == 0x87) {
            BYTE modrm = Buffer[i + 1];
            if ((modrm & 0xC7) == 0xC4 || (modrm & 0xF8) == 0xE0) { isGadget = TRUE; gadgetSize = 2; }
        }
        /* MOV ESP, reg (89 xx) */
        else if (Buffer[i] == 0x89) {
            BYTE modrm = Buffer[i + 1];
            if ((modrm & 0xC7) == 0xC4) { isGadget = TRUE; gadgetSize = 2; }
        }
        /* LEAVE + RET (C9 C3)，非 NOP/INT 前缀 */
        else if (Buffer[i] == 0xC9 && i + 1 < Size && Buffer[i + 1] == 0xC3) {
            if (i > 0 && Buffer[i - 1] != 0x90 && Buffer[i - 1] != 0xCC) { isGadget = TRUE; gadgetSize = 2; }
        }
        /* POP ESP (5C) */
        else if (Buffer[i] == 0x5C) { isGadget = TRUE; gadgetSize = 1; }
        /* ADD ESP, large (81/83 xx C4) */
        else if ((Buffer[i] == 0x81 || Buffer[i] == 0x83) && i + 2 < Size) {
            BYTE modrm = Buffer[i + 1];
            if ((modrm & 0xC7) == 0xC4 && (modrm & 0x38) == 0x00) {
                if (Buffer[i] == 0x81 && i + 6 <= Size) {
                    LONG value;
                    RtlCopyMemory(&value, &Buffer[i + 2], sizeof(LONG));
                    if (value > 0x1000 || value < -0x1000) { isGadget = TRUE; gadgetSize = 6; }
                }
            }
        }

        if (isGadget) {
            /* gadget 后紧跟 RET 才可利用（对齐 SS） */
            if (i + gadgetSize < Size &&
                (Buffer[i + gadgetSize] == 0xC3 || Buffer[i + gadgetSize] == 0xC2)) {
                if (GadgetOffset != NULL) *GadgetOffset = i;
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*++
 * MsScanSuspiciousCalls
 *   间接 CALL/JMP 密集检测（对齐 SS SdpDetectSuspiciousCalls L3134）：
 *   动态 API 解析（哈希解析后经寄存器间接调用），密度 ≥3 判定。
 *--*/
static BOOLEAN
MsScanSuspiciousCalls(
    const BYTE* Buffer,
    ULONG Size
    )
{
    ULONG i;
    ULONG indirectCalls = 0;

    if (Buffer == NULL || Size < 3) return FALSE;

    for (i = 0; i + 2 < Size; i++) {
        /* CALL reg (FF D0-D7) */
        if (Buffer[i] == 0xFF && (Buffer[i + 1] >= 0xD0 && Buffer[i + 1] <= 0xD7)) indirectCalls++;
        /* CALL [reg]（FF /2 内存操作数，mod != 11） */
        else if (Buffer[i] == 0xFF && (Buffer[i + 1] & 0x38) == 0x10 && (Buffer[i + 1] & 0xC0) != 0xC0) indirectCalls++;
        /* JMP reg (FF E0-E7) */
        else if (Buffer[i] == 0xFF && (Buffer[i + 1] >= 0xE0 && Buffer[i + 1] <= 0xE7)) indirectCalls++;
        /* JMP [reg]（FF /4 内存操作数，mod != 11） */
        else if (Buffer[i] == 0xFF && (Buffer[i + 1] & 0x38) == 0x20 && (Buffer[i + 1] & 0xC0) != 0xC0) indirectCalls++;

        if (indirectCalls >= 5) break;
    }
    return (indirectCalls >= 3);
}

/**************************************************/
/*  ShadowStrike ShellcodeDetector 死代码迁移区      */
/*  (2026-08-07) — 全功能面覆盖, 暂不接线            */
/*  对齐 SS ShellcodeDetector.c 逐函数重实现         */
/**************************************************/

/*++
 * MsScanNopSled
 *   带明细的 NOP sled 检测（对齐 SS SdpDetectNopSledInternal L2288-2373）：
 *   0x90 / 66 90 / 0F 1F /0 多字节变体 + 最长连续段 + offset/length/nopByte。
 *   与活路径 T1scCountMaxNOPSled 同源算法, 此处保留明细供取证/加权。
 *--*/
static BOOLEAN
MsScanNopSled(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PULONG Offset,
    _Out_ PULONG Length,
    _Out_ PUCHAR NopByte
    )
{
    ULONG i = 0;
    ULONG consecutive = 0, maxConsecutive = 0, maxOffset = 0;
    UCHAR maxNopByte = 0x90;
    ULONG runOffset = 0;
    UCHAR runByte = 0x90;

    if (Buffer == NULL || Offset == NULL || Length == NULL || NopByte == NULL) return FALSE;
    *Offset = 0; *Length = 0; *NopByte = 0;

    while (i < Size) {
        BOOLEAN isNop = FALSE;

        if (Buffer[i] == 0x90) {
            isNop = TRUE;
            if (consecutive == 0) { runOffset = i; runByte = 0x90; }
            i++;
        } else if (i + 1 < Size && Buffer[i] == 0x66 && Buffer[i + 1] == 0x90) {
            isNop = TRUE;
            if (consecutive == 0) { runOffset = i; runByte = 0x66; }
            i += 2;
        } else if (i + 1 < Size && Buffer[i] == 0x0F && Buffer[i + 1] == 0x1F) {
            isNop = TRUE;
            if (consecutive == 0) { runOffset = i; runByte = 0x0F; }
            i += 2;
            if (i < Size) {
                UCHAR modrm = Buffer[i];
                ULONG extra = 1;   /* ModR/M */
                if ((modrm & 0xC0) != 0xC0) {
                    if ((modrm & 0x07) == 0x04) extra++;          /* SIB */
                    if ((modrm & 0xC0) == 0x40) extra++;          /* disp8 */
                    else if ((modrm & 0xC0) == 0x80) extra += 4;  /* disp32 */
                }
                i += extra;
            }
        } else {
            i++;
        }

        if (isNop) {
            consecutive++;
            if (consecutive > maxConsecutive) {
                maxConsecutive = consecutive;
                maxOffset = runOffset;
                maxNopByte = runByte;
            }
        } else {
            consecutive = 0;
        }
    }

    if (maxConsecutive >= MS_MIN_NOP_SLED) {
        *Offset = maxOffset;
        *Length = maxConsecutive;
        *NopByte = maxNopByte;
        return TRUE;
    }
    return FALSE;
}

/*++
 * MsScanDirectSyscalls
 *   直接 syscall stub 检测（对齐 SS SdpDetectDirectSyscalls L2719-2781）：
 *   x64 完整 stub (MOV R10,RCX; MOV EAX,imm32; 20B 内 SYSCALL, 提取调用号) +
 *   裸 SYSCALL/SYSENTER/INT 2E, 去重 + 上限 16。
 *--*/
static BOOLEAN
MsScanDirectSyscalls(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_writes_to_(MaxStubs, *StubCount) PWKD_SYSCALL_STUB Stubs,
    _In_  ULONG MaxStubs,
    _Out_ PULONG StubCount
    )
{
    ULONG i, j, k;
    ULONG count = 0;

    if (Buffer == NULL || Stubs == NULL || StubCount == NULL || MaxStubs == 0) return FALSE;
    *StubCount = 0;
    if (Size < 9) return FALSE;

    for (i = 0; i < Size - 8 && count < MaxStubs; i++) {
        /* x64 stub: 4C 8B D1 B8 <imm32> ... [20B 内 0F 05] */
        if (Buffer[i] == 0x4C && Buffer[i + 1] == 0x8B && Buffer[i + 2] == 0xD1 &&
            Buffer[i + 3] == 0xB8) {
            for (j = i + 4; j < min(i + 20, Size - 1); j++) {
                if (Buffer[j] == 0x0F && Buffer[j + 1] == 0x05) {
                    ULONG num;
                    memcpy(&num, &Buffer[i + 4], sizeof(num));
                    Stubs[count].SyscallNumber = num;
                    Stubs[count].StubOffset = i;
                    Stubs[count].StubSize = (ULONG)(j + 2 - i);
                    Stubs[count].IsDirect = TRUE;
                    count++;
                    break;
                }
            }
        }

        /* 裸 SYSCALL (0F 05) / SYSENTER (0F 34) / INT 2E (CD 2E) — 已在 stub 内则跳过 */
        if (count < MaxStubs && i + 1 < Size &&
            ((Buffer[i] == 0x0F && Buffer[i + 1] == 0x05) ||
             (Buffer[i] == 0x0F && Buffer[i + 1] == 0x34) ||
             (Buffer[i] == 0xCD && Buffer[i + 1] == 0x2E))) {
            BOOLEAN inExisting = FALSE;
            for (k = 0; k < count; k++) {
                if (i >= Stubs[k].StubOffset && i < Stubs[k].StubOffset + Stubs[k].StubSize) {
                    inExisting = TRUE;
                    break;
                }
            }
            if (!inExisting) {
                Stubs[count].SyscallNumber = 0;
                Stubs[count].StubOffset = i;
                Stubs[count].StubSize = 2;
                Stubs[count].IsDirect = (Buffer[i] != 0xCD);  /* INT 2E 为间接 (对齐 SS StubType_Indirect) */
                count++;
            }
        }
    }

    *StubCount = count;
    return (count > 0);
}

/*++
 * MsScanPositionIndependentCode
 *   PIC GetPC 5 模式检测（对齐 SS SdpDetectPositionIndependentCode L3057-3127）：
 *   CALL $+5;POP / FNSTENV / FSTENV+FWAIT / LEA RIP / CALL 负偏移, 命中 ≥1 即真。
 *   ※ 死代码: 用户决策 FNSTENV 不进活路径 T1 (纯 FPU 代码误报 + 影响复用方),
 *     本函数保留 SS 完整语义供死分析加权精度对齐。
 *--*/
static BOOLEAN
MsScanPositionIndependentCode(
    _In_ const BYTE* Buffer,
    _In_ ULONG Size
    )
{
    ULONG i;
    ULONG picPatterns = 0;

    if (Buffer == NULL || Size < 6) return FALSE;

    for (i = 0; i + 5 < Size; i++) {
        /* 1. CALL $+5; POP reg (E8 00 00 00 00 58-5F) — 经典 x86 GetPC */
        if (Buffer[i] == 0xE8 && Buffer[i + 1] == 0x00 && Buffer[i + 2] == 0x00 &&
            Buffer[i + 3] == 0x00 && Buffer[i + 4] == 0x00 &&
            (Buffer[i + 5] >= 0x58 && Buffer[i + 5] <= 0x5F)) {
            picPatterns++;
            i += 5;
            continue;
        }

        /* 2. FNSTENV [ESP-0xC] (D9 74 24 F4) — FPU 环境含 EIP */
        if (i + 3 < Size && Buffer[i] == 0xD9 && Buffer[i + 1] == 0x74 &&
            Buffer[i + 2] == 0x24 && Buffer[i + 3] == 0xF4) {
            picPatterns++;
            i += 3;
            continue;
        }

        /* 3. FSTENV + FWAIT (9B D9 74 24 F4) */
        if (i + 4 < Size && Buffer[i] == 0x9B && Buffer[i + 1] == 0xD9 &&
            Buffer[i + 2] == 0x74 && Buffer[i + 3] == 0x24 && Buffer[i + 4] == 0xF4) {
            picPatterns++;
            i += 4;
            continue;
        }

        /* 4. LEA reg, [RIP+disp32] (48 8D, mod=00 r/m=101) — x64 PC-relative */
        if (i + 6 < Size && Buffer[i] == 0x48 && Buffer[i + 1] == 0x8D &&
            (Buffer[i + 2] & 0xC7) == 0x05) {
            picPatterns++;
            i += 6;
            continue;
        }

        /* 5. CALL near + POP 负偏移 (-256 < rel < 0) — 变体 GetPC */
        if (Buffer[i] == 0xE8 && i + 5 < Size &&
            (Buffer[i + 5] >= 0x58 && Buffer[i + 5] <= 0x5F)) {
            LONG relOffset;
            memcpy(&relOffset, &Buffer[i + 1], sizeof(LONG));
            if (relOffset < 0 && relOffset > -256) {
                picPatterns++;
                i += 5;
                continue;
            }
        }

        if (picPatterns >= 2) break;
    }

    return (picPatterns > 0);
}

/*++
 * MsScoreShellcodeConfidence
 *   置信度评分（对齐 SS SdpCalculateConfidenceScore L3232-3312）：
 *   12 单项 + 5 组合加分, cap 100。
 *   注: SS 原版 Polymorphic flag (Encoder&&HighEntropy) 与组合 HighEntropy+Encoder
 *   重复双计 (+10+10), wkd 合并为组合加分一次 (+10)。
 *--*/
static ULONG
MsScoreShellcodeConfidence(
    _In_ const WKD_SHELLCODE_ANALYSIS* Analysis
    )
{
    ULONG score = 0;

    if (Analysis == NULL) return 0;

    if (Analysis->HasNopSled) {
        score += 15;
        if (Analysis->NopSledLength > 64) score += 10;
    }
    if (Analysis->HasEggHunter) score += 30;
    if (Analysis->HasEncoder) score += 20;
    if (Analysis->HasApiHashing) {
        score += 25;
        if (Analysis->ResolvedApiCount > 3) score += 15;
    }
    if (Analysis->HasSyscallStubs) {
        score += 20;
        if (Analysis->SyscallCount > 2) score += 10;
    }
    if (Analysis->HasHeavensGate) score += 35;
    if (Analysis->HasStackPivot) score += 20;
    if (Analysis->HasHighEntropy) score += 10;
    if (Analysis->HasKnownSignature) score += 40;
    if (Analysis->HasPic) score += 15;
    if (Analysis->HasSuspiciousCall) score += 15;

    /* 组合加成 (对齐 SS L3286-3304) */
    if (Analysis->HasNopSled && Analysis->HasEncoder) score += 15;
    if (Analysis->HasApiHashing && Analysis->HasSyscallStubs) score += 20;
    if (Analysis->HasHighEntropy && Analysis->HasEncoder) score += 10;
    if (Analysis->HasPic && Analysis->HasSuspiciousCall) score += 15;
    if (Analysis->HasPic && Analysis->HasApiHashing) score += 15;

    if (score > 100) score = 100;
    return score;
}

/*++
 * MsScoreShellcodeSeverity
 *   严重度评分（对齐 SS SdpCalculateSeverityScore L3332-3384）→ RiskScore 0-100。
 *   HeavensGate/EggHunter 由 Type=Shellcode 时标志提升, 对齐 SS 语义。
 *--*/
static ULONG
MsScoreShellcodeSeverity(
    _In_ WKD_MEM_THREAT_TYPE Type,
    _In_ const WKD_SHELLCODE_ANALYSIS* Analysis
    )
{
    ULONG severity = 0;

    switch (Type) {
    case WkdMemThreat_Meterpreter:
    case WkdMemThreat_CobaltStrike:
        severity = 90;
        break;
    case WkdMemThreat_SyscallStub:
        severity = 80;          /* DirectSyscall */
        break;
    case WkdMemThreat_ROPChain:
        severity = 75;          /* StackPivot */
        break;
    case WkdMemThreat_APIHashing:
        severity = 70;
        break;
    case WkdMemThreat_EncryptedPayload:
        severity = 60;          /* Encoder */
        break;
    default:
        severity = 40;          /* NopSled/PIC/Generic 由标志上调 */
        break;
    }

    if (Analysis != NULL) {
        if (Analysis->HasHeavensGate) severity = 80;        /* SS: HeavensGate=80 */
        else if (Analysis->HasEggHunter) severity = 75;     /* SS: EggHunter=75 */
        if (Analysis->HasKnownSignature) severity += 20;
        if (Analysis->HasEncoder && Analysis->HasHighEntropy) severity += 15;  /* Polymorphic */
        if (Analysis->Confidence > 80) severity += 10;
    }

    if (severity > 100) severity = 100;
    return severity;
}

/*++
 * MsDetermineShellcodeThreatType
 *   主威胁类型判定（对齐 SS SdpDeterminePrimaryType L3405-3462, 最特异→最一般）。
 *   HasKnownSignature 为预留字段 (无填充者), 未来填充后可优先 Signature 家族。
 *--*/
static WKD_MEM_THREAT_TYPE
MsDetermineShellcodeThreatType(
    _In_ const WKD_SHELLCODE_ANALYSIS* Analysis
    )
{
    if (Analysis == NULL) return WkdMemThreat_Shellcode;

    if (Analysis->HasHeavensGate)  return WkdMemThreat_Shellcode;        /* T1620, WKD 无细类型 */
    if (Analysis->HasSyscallStubs) return WkdMemThreat_SyscallStub;      /* T1106 */
    if (Analysis->HasEggHunter)    return WkdMemThreat_Shellcode;        /* T1620 */
    if (Analysis->HasStackPivot)   return WkdMemThreat_ROPChain;         /* T1055 */
    if (Analysis->HasApiHashing)   return WkdMemThreat_APIHashing;       /* T1620 */
    if (Analysis->HasEncoder)      return WkdMemThreat_EncryptedPayload; /* T1027 */
    if (Analysis->HasNopSled)      return WkdMemThreat_Shellcode;        /* T1620 */
    if (Analysis->HasPic)          return WkdMemThreat_Shellcode;        /* T1620 */
    return WkdMemThreat_Shellcode;                                       /* Generic */
}

/*++
 * MsScanShellcodePipeline
 *   SS SdAnalyzeBuffer 12 阶段完整编排 (对齐 L766-910) — SS 全功能面忠实备份。
 *   阶段: 熵/NOP/EggHunter/Encoder/哈希值解析/DirectSyscall/HeavensGate/
 *   StackPivot/签名(跳过, SS 纸面)/PIC/SuspiciousCalls/Polymorphic 派生。
 *   ※ 死代码: wkd 活主路径 MsScanRegionContent 五段式已覆盖检测面, 本管道
 *     供未来按阶段加权接线; 独立 static 无调用者, pragma 4505 抑制告警。
 *--*/
#pragma warning(push)
#pragma warning(disable:4505)
static BOOLEAN
MsScanShellcodePipeline(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _In_  BOOLEAN IsPrivateExecutable,
    _Out_ PWKD_MEM_THREAT Threat
    )
{
    WKD_SHELLCODE_ANALYSIS analysis;
    ULONG nopOffset = 0, nopLength = 0, stubCount = 0;
    UCHAR nopByte = 0;
    WKD_SYSCALL_STUB stubs[16];
    ULONG r, s;

    UNREFERENCED_PARAMETER(IsPrivateExecutable);

    if (Threat == NULL || Buffer == NULL || Size < MS_MIN_SHELLCODE_SIZE) return FALSE;
    RtlZeroMemory(Threat, sizeof(*Threat));
    RtlZeroMemory(&analysis, sizeof(analysis));

    /* 阶段 1: 熵分析 (SS L769-776) */
    analysis.HasHighEntropy = (MsCalculateEntropy(Buffer, Size) >= MS_ENTROPY_THRESHOLD);

    /* 阶段 2: NOP sled (SS L781-794) */
    if (MsScanNopSled(Buffer, Size, &nopOffset, &nopLength, &nopByte)) {
        analysis.HasNopSled = TRUE;
        analysis.NopSledLength = nopLength;
        analysis.NopSledOffset = nopOffset;
    }

    /* 阶段 3: EggHunter (SS L799-805) */
    if (MsScanEggHunter(Buffer, Size, &analysis.EggHunterOffset)) analysis.HasEggHunter = TRUE;

    /* 阶段 4: Encoder (SS L810-815) */
    {
        ULONG encOffset = 0;
        if (MsScanEncoderLoop(Buffer, Size, analysis.EncoderType, sizeof(analysis.EncoderType),
                              &encOffset)) {
            analysis.HasEncoder = TRUE;
            analysis.EncoderLoopOffset = encOffset;
        }
    }

    /* 阶段 5: API 哈希值解析 (SS L820-825) */
    {
        WKD_API_HASH_RESULT resolved;
        if (MsScanApiHashResolution(Buffer, Size, &resolved)) {
            ULONG n = min(resolved.ResolvedCount, (ULONG)RTL_NUMBER_OF(analysis.ResolvedApis));
            analysis.HasApiHashing = TRUE;
            analysis.ResolvedApiCount = resolved.ResolvedCount;
            for (r = 0; r < n; r++) {
                strcpy_s(analysis.ResolvedApis[r], sizeof(analysis.ResolvedApis[r]),
                         resolved.Resolved[r].ApiName);
            }
        }
    }

    /* 阶段 6: DirectSyscall (SS L830-835) */
    if (MsScanDirectSyscalls(Buffer, Size, stubs, 16, &stubCount)) {
        ULONG n = min(stubCount, (ULONG)RTL_NUMBER_OF(analysis.SyscallNumbers));
        analysis.HasSyscallStubs = TRUE;
        analysis.SyscallCount = stubCount;
        for (s = 0; s < n; s++) {
            analysis.SyscallNumbers[s] = stubs[s].SyscallNumber;
        }
    }

    /* 阶段 7: HeavensGate (SS L840-845) */
    if (MsScanHeavensGate(Buffer, Size)) analysis.HasHeavensGate = TRUE;

    /* 阶段 8: StackPivot (SS L849-853) */
    if (MsScanStackPivot(Buffer, Size, &analysis.StackPivotGadgetOffset)) analysis.HasStackPivot = TRUE;

    /* 阶段 9: 签名匹配 (SS L858-862) — SS 纸面功能跳过, wkd 已知签名面由
     * YARA/AC/g_ApiHashPatterns/kCs/kMeterpreter 模式覆盖 */

    /* 阶段 10: PIC (SS L867-871) */
    if (MsScanPositionIndependentCode(Buffer, Size)) analysis.HasPic = TRUE;

    /* 阶段 11: SuspiciousCalls (SS L876-880) */
    if (MsScanSuspiciousCalls(Buffer, Size)) analysis.HasSuspiciousCall = TRUE;

    /* 阶段 12: Polymorphic 复合 (SS L887-889) — Encoder&&HighEntropy, 置信度组合加分体现 */

    /* 评分与类型 (SS 三件套) */
    analysis.Confidence = MsScoreShellcodeConfidence(&analysis);
    analysis.IsShellcode = (analysis.Confidence >= 50);   /* SS MinConfidenceScore 默认 50 */
    if (!analysis.IsShellcode) return FALSE;

    Threat->Type = MsDetermineShellcodeThreatType(&analysis);
    Threat->Confidence = analysis.Confidence;
    Threat->RiskScore = MsScoreShellcodeSeverity(Threat->Type, &analysis);
    strcpy_s(Threat->RuleCategory, sizeof(Threat->RuleCategory), "Shellcode Pipeline");
    switch (Threat->Type) {
    case WkdMemThreat_SyscallStub:
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1106");
        break;
    case WkdMemThreat_ROPChain:
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1055");
        break;
    case WkdMemThreat_EncryptedPayload:
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1027");
        break;
    case WkdMemThreat_Meterpreter:
    case WkdMemThreat_CobaltStrike:
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1055");
        break;
    default:
        strcpy_s(Threat->MitreTechnique, sizeof(Threat->MitreTechnique), "T1620");
        break;
    }
    strcpy_s(Threat->MatchedRule, sizeof(Threat->MatchedRule), "Shellcode pipeline match");
    return TRUE;
}
#pragma warning(pop)

/**************************************************/
/*  扫描统计 — SS MemoryScanner 迁移（死代码）      */
/*  对齐 SS MsGetStatistics L2273-2321             */
/**************************************************/

/*++
 * MsGetStatistics
 *   读取全局扫描统计（g_MsStats 由 MsScanProcessMemoryFull/MsScanBufferFull/
 *   MsScanRegionAt 入口维护 TotalScans·CumulativeScanTimeMs + 超时 break 维护
 *   Timeouts，MsScanRegionContent 维护 RegionsScanned/BytesScanned/ScanErrors/
 *   PeDetections/ShellcodeDetections，MsAddThreat 维护 ThreatsFound，
 *   MsScanRegionYara 维护 YaraMatches；AverageScanTimeMs 读取时计算）。
 *   ※ 死代码: 查询 API 无调用者（对齐项目惯例 #30/#40），供 UI/诊断接线。
 *--*/
_Use_decl_annotations_
VOID
MsGetStatistics(
    PWKD_MEM_SCANNER_STATS Stats
    )
{
    if (Stats == NULL) return;
    *Stats = g_MsStats;
    /* 对齐 SS MsGetStatistics L2314-2316：平均耗时 = 累计耗时 / 总扫描数 */
    if (Stats->TotalScans > 0) {
        Stats->AverageScanTimeMs = Stats->CumulativeScanTimeMs / Stats->TotalScans;
    }
}
