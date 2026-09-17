/**************************************************/
/*  WkDefender Agent — 进程镂空检测器实现           */
/*                                                  */
/*  2026-09-15 迁出: 自 IOC\IocProcessEnrich.c      */
/*  (L1361-2592) 物理收敛, 逻辑零改动。            */
/*                                                  */
/*  功能面迁移 ShadowStrike                         */
/*  ProcessHollowingDetector.cpp (ScanProcess) +    */
/*  C 版 HollowingDetector 补遗:                   */
/*    ScanProcess (8 步)         → IpeDetectProcessHollowing */
/*    ScanAllProcesses          → IpeScanAllProcessesForHollowing */
/*    ScanProcesses             → IpeScanProcesses  */
/*    ScanByName                → IpeScanProcessesByName */
/*    ScanByPath                → IpeScanProcessesByPath */
/*    GetHollowedProcesses      → IpeGetHollowedProcesses */
/*    AnalyzeCreationPattern    → IpeIsSuspiciousSuspendedCreation (挂起时长维度) */
/*    ValidatePEHeader          → IpeValidatePeHeader */
/*    ValidateImageBase         → IpeValidateImageBase */
/*    ExtractPayload            → IpeExtractPayload */
/*    GetHollowingTypeName      → IpeHollowingTypeToString */
/*    GetDetectionMethodName    → IpeHollowingMethodToString */
/*                                                  */
/*  私有结构 (PH_PEB 系列):                        */
/*  Process\InjectionDetectorInternal.h            */
/*  公共 API: Include\Process\InjectionDetector.h  */
/*                                                  */
/*  依赖驱动事件源 (创建模式向量 Unmap+Map+Write+   */
/*  SetCtx / 挂起时长 / EarlyBird / ThreadHijack /  */
/*  Doppelganging TxF) 的判定标注死代码, 见各注释。 */
/**************************************************/

#include "../Include/Process/InjectionDetector.h"
#include "InjectionDetectorInternal.h"
#include "../IOC/IocScanner.h"
#include "../Common/FileUtils.h"            /* CoEntropyBinary */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"   /* WpeAnalyzePEHeadersFromBuffer / WpeParseSectionHeaders / WpeComparePEHeaders / WPA_* */
#include "../Memory/MemoryScan.h"           /* WKD_MEM_SCAN_MODE / MsReadMemory / MsScanMemoryRegions */
#include "../IOA/Tier1/T1ShellcodeDetect.h" /* T1DetectShellcodePatterns */
#include "../ProcessThreads.h"              /* WptAnalyzeThreads / WKD_THREAD_PROFILE */
#include <windows.h>
#include <winternl.h>                       /* NtQueryInformationProcess / PROCESS_BASIC_INFORMATION */
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// ============================================================================
// 进程镂空检测（对齐 PS ProcessHollowingDetector::ScanProcess）
// ============================================================================

//
// 内部辅助: 记录检测方法（去重）
//
static VOID
IpepAddHollowingMethod(
    _Inout_ PWKD_HOLLOWING_RESULT Result,
    _In_    WKD_HOLLOWING_METHOD  Method
    )
{
    ULONG i;
    if (Result->DetectionMethodCount >= WKD_HOLLOWING_MAX_METHODS) return;
    for (i = 0; i < Result->DetectionMethodCount; i++) {
        if (Result->DetectionMethods[i] == (ULONG)Method) return;
    }
    Result->DetectionMethods[Result->DetectionMethodCount++] = (ULONG)Method;
}

//
// 内部辅助: 读目标进程内存
//
static BOOLEAN
IpepReadRemoteMemory(
    _In_  ULONG      ProcessId,
    _In_  ULONG_PTR  Address,
    _Out_writes_(Size) PBYTE Buffer,
    _In_  ULONG      Size,
    _Out_ PULONG     BytesRead
    )
{
    HANDLE hProcess;
    SIZE_T read = 0;
    BOOLEAN ok = FALSE;

    if (BytesRead) *BytesRead = 0;
    if (!Buffer || Size == 0) return FALSE;

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return FALSE;

    if (ReadProcessMemory(hProcess, (LPCVOID)Address, Buffer, Size, &read) && read > 0) {
        if (BytesRead) *BytesRead = (ULONG)read;
        ok = TRUE;
    }

    CloseHandle(hProcess);
    return ok;
}

//
// 内部辅助: 读磁盘文件（从头读取，上限 MaxSize）
//
static BOOLEAN
IpepReadFileBuffer(
    _In_  PCWSTR FilePath,
    _Out_writes_(MaxSize) PBYTE Buffer,
    _In_  ULONG  MaxSize,
    _Out_ PULONG BytesRead
    )
{
    HANDLE hFile;
    DWORD read = 0;
    BOOLEAN ok = FALSE;

    if (BytesRead) *BytesRead = 0;
    if (!FilePath || !Buffer || MaxSize == 0) return FALSE;

    hFile = CreateFileW(FilePath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (ReadFile(hFile, Buffer, MaxSize, &read, NULL) && read > 0) {
        if (BytesRead) *BytesRead = read;
        ok = TRUE;
    }

    CloseHandle(hFile);
    return ok;
}

//
// 内部辅助: 从 PE 缓冲解析头字段 + 节表
//
static VOID
IpepParsePeBuffer(
    _In_  PBYTE Buffer,
    _In_  ULONG Size,
    _Out_ PWPA_PE_INFO PeInfo,
    _Out_writes_(MaxSections) PWKD_PE_SECTION Sections,
    _In_  ULONG MaxSections,
    _Out_ PULONG SectionCount
    )
{
    RtlZeroMemory(PeInfo, sizeof(*PeInfo));
    if (SectionCount) *SectionCount = 0;

    if (WpeAnalyzePEHeadersFromBuffer(Buffer, Size, PeInfo) != S_OK) {
        return;
    }
    if (!PeInfo->IsPE) return;

    if (Sections && SectionCount && MaxSections > 0) {
        WpeParseSectionHeaders(Buffer, Size, Sections, MaxSections, SectionCount);
    }
}

_Use_decl_annotations_
BOOL
IpeDetectProcessHollowing(
    ULONG                 ProcessId,
    WKD_MEM_SCAN_MODE     ScanMode,
    PWKD_HOLLOWING_RESULT Result
    )
/*++
Routine Description:
    进程镂空检测（对齐 PS ProcessHollowingDetector::ScanProcess + C 版
    HollowingDetector 补遗）:
    1. 主模块 PE 头 7 字段比对 (磁盘 vs 内存, 含 ASLR/Checksum 豁免)
    2. 入口点分析 (EP 节归属 / RWX / 壳码 / 实际内存保护)
    2.5 PEB 篡改检测 (ImageBase 比对 + ImagePathName 比对, 对齐 C 版 PhpAnalyzePEB)
    3. 代码节内容采样比对 (diffRatio > 10%)
    4. 无映像可执行内存 / RWX 区域 (复用 MsScanMemoryRegions)
    5. Module Stomping (非主模块内存 vs 磁盘比对)
    6. Ghosting / Herpaderping 文件状态
    7. 载荷提取 + SHA256 + IOC 关联
    8. 置信度 / 风险分 / 镂空类型判定 (含 Overwriting / Phantom, 对齐 C 版)

    创建模式向量 (Unmap+Map+Write+SetCtx / 挂起时长 / EarlyBird /
    ThreadHijack / Doppelganging) 依赖驱动补 syscall 事件源, 本次以
    死代码标注, 见 IoaInjectionClassifier::IoaClassifyFromEdges。
    Doppelganging (TxF) 激活: 驱动 WkdFspCheckTransactedAccess (Filter.c)
    + g_FsTxnList 接线 → agent 事件; 用户态近似 = 文件不存在 + 无物理
    文件判定 (FileDeletePending 已覆盖部分语义)。

    SS HollowingDetector (ShadowStrike Memory/HollowingDetector.c, 2026-08 对比)
    14 指示器 → wkd 方法映射（功能面已全覆盖，本函数为唯一落点）:
      ImagePathMismatch→PebImagePathMismatch / SectionMismatch→SectionMismatch /
      EntryPointModified→EntryPointAnomaly / HeaderModified→PEHeaderMismatch /
      UnmappedMainModule→UnbackedExecMemory(近似) / TransactedFile→WkdHt_ProcessDoppelganging
      (TxF 依赖驱动, 死代码) / DeletedFile→DeletePendingFile / SuspiciousThread→
      IpeIsSuspiciousSuspendedCreation(死代码, 依赖驱动挂起标志) / ModifiedPEB→
      PebImageBaseMismatch / HiddenMemory→UnbackedExecMemory / NoPhysicalFile→
      DeletePending+WkdHt_Phantom / HashMismatch→SectionMismatch(哈希) /
      TimestampAnomaly→FileModifiedAfterMap(Herpaderping) / MemoryProtection→
      EntropyAnomaly+SectionCharacteristics
    8 类型: Classic/SectionHollowing/ModuleStomping/Ghosting/Herpaderping/
      EarlyBird(死)/ThreadHijack(死)/Doppelganging(死,TxF)/Overwriting/Phantom
      全在 WKD_HOLLOWING_TYPE。

Arguments:
    ProcessId - 目标进程 PID。
    ScanMode  - Quick=仅头比对+EP; Normal=+节采样+ModuleStomping;
                Deep=+无映像内存。载荷提取在命中时执行 (不分档)。
    Result    - 检测结果。

Return Value:
    TRUE = 检测已执行; FALSE = 无法检测 (进程不存在/无权限/非 PE)。
--*/
{
    WPA_PE_INFO memInfo = { 0 };
    WPA_PE_INFO diskInfo = { 0 };
    WKD_PE_SECTION memSections[WKD_PE_MAX_SECTIONS];
    WKD_PE_SECTION diskSections[WKD_PE_MAX_SECTIONS];
    ULONG memSecCount = 0;
    ULONG diskSecCount = 0;
    WKD_PE_HEADER_COMPARE compare = { 0 };
    WCHAR processPath[MAX_PATH] = { 0 };
    ULONG_PTR moduleBase = 0;
    BYTE headerBuf[8192];
    ULONG headerRead = 0;
    PBYTE diskFileBuf = NULL;
    ULONG diskFileRead = 0;
    HANDLE hProcess = NULL;
    SIZE_T sizeRead = 0;
    ULONG i;

    if (Result == NULL) return FALSE;
    RtlZeroMemory(Result, sizeof(*Result));

    if (ProcessId == 0 || ProcessId == 4) return FALSE;
    if (ScanMode != WkdMemScan_Quick && ScanMode != WkdMemScan_Normal &&
        ScanMode != WkdMemScan_Deep) {
        ScanMode = WkdMemScan_Normal;
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (!hProcess) {
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Cannot open process", _TRUNCATE);
        return FALSE;
    }

    /* 获取映像路径 */
    {
        DWORD pathLen = RTL_NUMBER_OF(processPath);
        if (!QueryFullProcessImageNameW(hProcess, 0, processPath, &pathLen)) {
            CloseHandle(hProcess);
            wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                      L"Cannot query image path", _TRUNCATE);
            return FALSE;
        }
    }

    /* 获取主模块基址 (Toolhelp 第一个模块即主模块) */
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                moduleBase = (ULONG_PTR)me.modBaseAddr;
            }
            CloseHandle(hSnap);
        }
    }
    if (moduleBase == 0) {
        CloseHandle(hProcess);
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Cannot determine module base", _TRUNCATE);
        return FALSE;
    }

    /* 读内存 PE 头 (8192 字节, 覆盖节表) + 解析 */
    if (ReadProcessMemory(hProcess, (LPCVOID)moduleBase, headerBuf,
                          sizeof(headerBuf), &sizeRead) && sizeRead >= sizeof(IMAGE_DOS_HEADER)) {
        headerRead = (ULONG)sizeRead;
    }
    if (headerRead == 0) {
        CloseHandle(hProcess);
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Cannot read memory PE header", _TRUNCATE);
        return FALSE;
    }
    IpepParsePeBuffer(headerBuf, headerRead, &memInfo,
                      memSections, WKD_PE_MAX_SECTIONS, &memSecCount);
    if (!memInfo.IsPE) {
        CloseHandle(hProcess);
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Memory image is not PE", _TRUNCATE);
        return FALSE;
    }

    /* 读磁盘文件 (上限 1MB, 头解析与节采样共用) + 解析 */
    diskFileBuf = (PBYTE)malloc(1024 * 1024);
    if (diskFileBuf) {
        if (IpepReadFileBuffer(processPath, diskFileBuf, 1024 * 1024, &diskFileRead) &&
            diskFileRead > 0) {
            IpepParsePeBuffer(diskFileBuf, diskFileRead, &diskInfo,
                              diskSections, WKD_PE_MAX_SECTIONS, &diskSecCount);
        }
        /* 文件不可读时磁盘 PE 无效, 由步骤 6 统一做 Ghosting 文件状态判定 */
    }

    /* 1. 头 7 字段比对 */
    if (diskInfo.IsPE) {
        WpeComparePEHeaders(&diskInfo, &memInfo, &compare);
        Result->MismatchCount = compare.MismatchCount;
        Result->OverallSimilarity = compare.OverallSimilarity;
        if (!compare.HeadersMatch) {
            IpepAddHollowingMethod(Result, WkdHm_PEHeaderMismatch);
            Result->IsHollowed = TRUE;
        }
    }

    /* 2. 入口点分析 (EP 节归属 / RWX / 壳码) */
    {
        ULONG epRva = memInfo.EntryPoint;
        if (epRva != 0 && diskInfo.IsPE) {
            BOOLEAN epFound = FALSE;
            BOOLEAN epExec = FALSE;
            BOOLEAN epWx = FALSE;

            for (i = 0; i < diskSecCount; i++) {
                ULONG64 secStart = diskSections[i].VirtualAddress;
                ULONG64 secEnd = secStart +
                    max(diskSections[i].VirtualSize, diskSections[i].SizeOfRawData);
                if ((ULONG64)epRva >= secStart && (ULONG64)epRva < secEnd) {
                    epFound = TRUE;
                    epExec = diskSections[i].IsExecutable || diskSections[i].ContainsCode;
                    epWx = diskSections[i].IsWritable && diskSections[i].IsExecutable;
                    break;
                }
            }

            /* EP 落在节外 / RWX 节 / 非可执行节 → 异常 (对齐 PS, 均置 IsHollowed) */
            if (!epFound || epWx || !epExec) {
                IpepAddHollowingMethod(Result, WkdHm_EntryPointAnomaly);
                Result->IsHollowed = TRUE;
            }
        }

        /* EP 起始字节壳码判定 (对齐 PS AnalyzeEntryPoint) */
        if (epRva != 0) {
            BYTE epBytes[64];
            ULONG epRead = 0;
            if (IpepReadRemoteMemory(ProcessId, moduleBase + epRva,
                                     epBytes, sizeof(epBytes), &epRead) && epRead >= 2) {
                if (T1DetectShellcodePatterns(epBytes, epRead)) {
                    Result->HasShellcodeAtEntryPoint = TRUE;
                    IpepAddHollowingMethod(Result, WkdHm_EntryPointAnomaly);
                    Result->IsHollowed = TRUE;
                }
            }
        }

        /* EP 实际内存保护检查 (对齐 C 版 PhpAnalyzeEntryPoint 的 ZwQueryVirtualMemory 分支):
           节归属判断基于磁盘节特性, 攻击者把内存节改 RWX 而磁盘节正常时漏检;
           此处直接查 EP 地址运行时保护捕获盲区。 */
        if (epRva != 0) {
            MEMORY_BASIC_INFORMATION epMbi = { 0 };
            if (VirtualQueryEx(hProcess, (LPCVOID)(moduleBase + epRva),
                               &epMbi, sizeof(epMbi)) && epMbi.State == MEM_COMMIT) {
                BOOLEAN epMemExec = (epMbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                BOOLEAN epMemWx  = (epMbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
                if (!epMemExec || epMemWx) {
                    IpepAddHollowingMethod(Result, WkdHm_EntryPointAnomaly);
                    Result->IsHollowed = TRUE;
                }
            }
        }
    }

    /* 2.5 PEB 篡改检测 (对齐 C 版 HollowingDetector PhpAnalyzePEB):
       ① PEB.ImageBaseAddress vs 主模块基址 (Toolhelp) — 捕获 PEB 声称基址被改;
       ② PEB.ProcessParameters.ImagePathName vs 实际路径 — 捕获 PEB 声称路径被改。
       PEB 读取失败 (受限权限/进程退出) 静默跳过, 不影响其余步骤 (对齐 C 版非致命继续)。 */
    {
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG retLen = 0;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                      sizeof(pbi), &retLen) == 0 && pbi.PebBaseAddress != NULL) {
            PH_PEB64 peb = { 0 };
            ULONG pebRead = 0;
            if (IpepReadRemoteMemory(ProcessId, (ULONG_PTR)pbi.PebBaseAddress,
                                     (PBYTE)&peb, sizeof(peb), &pebRead) &&
                pebRead >= sizeof(peb)) {
                /* ① ImageBase 比对: PEB 声称基址 vs Toolhelp 主模块基址 */
                if (peb.ImageBaseAddress != NULL &&
                    (ULONG_PTR)peb.ImageBaseAddress != moduleBase) {
                    Result->PebImageBaseModified = TRUE;
                    IpepAddHollowingMethod(Result, WkdHm_PebImageBaseMismatch);
                    Result->IsHollowed = TRUE;
                }

                /* ② ImagePathName 比对: 读 PEB.ProcessParameters.ImagePathName vs processPath */
                if (peb.ProcessParameters != NULL) {
                    PH_PROCESS_PARAMETERS64 params = { 0 };
                    ULONG paramsRead = 0;
                    if (IpepReadRemoteMemory(ProcessId, (ULONG_PTR)peb.ProcessParameters,
                                             (PBYTE)&params, sizeof(params), &paramsRead) &&
                        paramsRead >= sizeof(params)) {
                        ULONG_PTR imgBuf = (ULONG_PTR)params.ImagePathName.Buffer;
                        USHORT     imgLen = params.ImagePathName.Length;
                        /* 地址合法性: 用户态 + 长度合理 (对齐 C 版 H-6 fix) */
                        if (imgBuf >= 0x10000 && imgBuf < 0x00007FFFFFFFFFFFULL &&
                            imgLen > 0 && imgLen < MAX_PATH * sizeof(WCHAR)) {
                            WCHAR pebPath[MAX_PATH] = { 0 };
                            ULONG pathRead = 0;
                            if (IpepReadRemoteMemory(ProcessId, imgBuf,
                                                     (PBYTE)pebPath, imgLen, &pathRead) &&
                                pathRead > 0) {
                                pebPath[pathRead / sizeof(WCHAR)] = L'\0';
                                if (_wcsicmp(pebPath, processPath) != 0) {
                                    Result->PebImagePathMismatch = TRUE;
                                    IpepAddHollowingMethod(Result, WkdHm_PebImagePathMismatch);
                                    Result->IsHollowed = TRUE;
                                }
                            }
                        }
                    }
                }
            }
            /* WoW64 (32 位) PEB: PH_PEB32.ImageBaseAddress @0x08 可比对基址;
               32 位 ImagePathName 需 x86 RTL_USER_PROCESS_PARAMETERS @0x38 (UNICODE_STRING32),
               PH_PROCESS_PARAMETERS32 未定义该字段 — 32 位镂空少见, 路径比对死代码标注。 */
        }
    }

    /* 线程起始地址检查 (对齐 PS AnalyzeEntryPoint 主线程无支撑 RWX 检查, L2103-2132) */
    if (ScanMode >= WkdMemScan_Normal) {
        WKD_THREAD_PROFILE tprof = { 0 };
        if (WptAnalyzeThreads(ProcessId, &tprof) == STATUS_SUCCESS &&
            tprof.UnbackedStartCount > 0) {
            for (i = 0; i < tprof.AnalyzedCount; i++) {
                MEMORY_BASIC_INFORMATION mbi = { 0 };
                if (tprof.Threads[i].IsStartAddressBacked ||
                    tprof.Threads[i].StartAddress == 0) {
                    continue;
                }
                /* 精确判定: 起始地址落在无支撑 RWX 私有内存 (对齐 PS 条件) */
                if (VirtualQueryEx(hProcess, (LPCVOID)tprof.Threads[i].StartAddress,
                                   &mbi, sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT &&
                    (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 &&
                    (mbi.Type == 0 || mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
                    IpepAddHollowingMethod(Result, WkdHm_ThreadContextAnomaly);
                    Result->IsHollowed = TRUE;
                }
            }
        }
    }

    /* 3. 代码节内容采样比对 (Normal+) */
    if (ScanMode >= WkdMemScan_Normal && diskInfo.IsPE && memInfo.IsPE) {
        ULONG minSec = min(diskSecCount, memSecCount);
        for (i = 0; i < minSec; i++) {
            const WKD_PE_SECTION* ds = &diskSections[i];
            const WKD_PE_SECTION* ms = &memSections[i];

            /* 节特性变化 */
            if (ds->Characteristics != ms->Characteristics) {
                IpepAddHollowingMethod(Result, WkdHm_SectionCharacteristics);
            }

            /* 仅代码/可执行节采样比对 */
            if ((ds->ContainsCode || ds->IsExecutable) && ds->PointerToRawData > 0) {
                ULONG sampleSize = min(4096UL, min(ds->VirtualSize, ms->VirtualSize));
                if (sampleSize > 0) {
                    BYTE memSample[4096];
                    BYTE diskSample[4096];
                    ULONG memRead = 0;

                    /* 内存节采样 */
                    if (IpepReadRemoteMemory(ProcessId, moduleBase + ms->VirtualAddress,
                                             memSample, sampleSize, &memRead) && memRead > 0) {
                        /* 节熵 (对齐 PS EntropyAnomaly) */
                        ULONG entropy = 0;
                        entropy = (ULONG)(CoEntropyBinary(memSample, memRead, 0) * 1000.0);
                        if (
                            entropy >= WPA_ENTROPY_THRESHOLD_PACKED) {
                            IpepAddHollowingMethod(Result, WkdHm_EntropyAnomaly);
                        }

                        /* 磁盘节采样 (从已读文件缓冲按 PointerToRawData 偏移取) */
                        if (diskFileBuf && diskFileRead > ds->PointerToRawData) {
                            ULONG diskLen = min(memRead, min(ds->SizeOfRawData,
                                              diskFileRead - ds->PointerToRawData));
                            ULONG diff = 0;
                            ULONG b;
                            if (diskLen > 0) {
                                memcpy(diskSample, diskFileBuf + ds->PointerToRawData, diskLen);
                                for (b = 0; b < min(memRead, diskLen); b++) {
                                    if (memSample[b] != diskSample[b]) diff++;
                                }
                                if (min(memRead, diskLen) > 0 &&
                                    ((double)diff / (double)min(memRead, diskLen)) > 0.1) {
                                    IpepAddHollowingMethod(Result, WkdHm_SectionMismatch);
                                    Result->IsHollowed = TRUE;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* 4. 无映像可执行内存 / RWX (Deep+, 复用 MsScanMemoryRegions) */
    if (ScanMode >= WkdMemScan_Deep) {
        WKD_MEMORY_REGION regions[64];
        ULONG regCount = 0;
        if (MsScanMemoryRegions(ProcessId, regions, RTL_NUMBER_OF(regions), &regCount)) {
            for (i = 0; i < regCount; i++) {
                if (regions[i].IsUnbackedExec) {
                    Result->HasUnbackedExec = TRUE;
                    IpepAddHollowingMethod(Result, WkdHm_UnbackedExecMemory);
                }
                if (regions[i].IsRwx) {
                    Result->HasRwx = TRUE;
                }
            }
        }
    }

    /* 5. Module Stomping (Normal+, 非主模块内存 vs 磁盘比对) */
    if (ScanMode >= WkdMemScan_Normal) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                do {
                    BYTE memBuf[4096];
                    BYTE diskBuf[4096];
                    ULONG memRead = 0;
                    ULONG diskRead = 0;
                    ULONG_PTR modBase = (ULONG_PTR)me.modBaseAddr;
                    PIMAGE_DOS_HEADER dm;
                    PIMAGE_DOS_HEADER dd;

                    if (modBase == moduleBase || modBase == 0) continue;

                    if (IpepReadRemoteMemory(ProcessId, modBase, memBuf, sizeof(memBuf), &memRead) &&
                        memRead >= sizeof(IMAGE_DOS_HEADER) &&
                        IpepReadFileBuffer(me.szExePath, diskBuf, sizeof(diskBuf), &diskRead) &&
                        diskRead >= sizeof(IMAGE_DOS_HEADER)) {

                        dm = (PIMAGE_DOS_HEADER)memBuf;
                        dd = (PIMAGE_DOS_HEADER)diskBuf;
                        if (dm->e_magic == IMAGE_DOS_SIGNATURE && dd->e_magic == IMAGE_DOS_SIGNATURE &&
                            dm->e_lfanew == dd->e_lfanew) {
                            SIZE_T off = (SIZE_T)dm->e_lfanew;
                            if (off + sizeof(IMAGE_NT_HEADERS64) <= memRead &&
                                off + sizeof(IMAGE_NT_HEADERS64) <= diskRead) {
                                PIMAGE_NT_HEADERS nm = (PIMAGE_NT_HEADERS)(memBuf + off);
                                PIMAGE_NT_HEADERS nd = (PIMAGE_NT_HEADERS)(diskBuf + off);
                                if (nm->Signature == IMAGE_NT_SIGNATURE && nd->Signature == IMAGE_NT_SIGNATURE) {
                                    /* 入口点或节数不一致 → 模块被替换 */
                                    if (nm->OptionalHeader.AddressOfEntryPoint !=
                                            nd->OptionalHeader.AddressOfEntryPoint ||
                                        nm->FileHeader.NumberOfSections !=
                                            nd->FileHeader.NumberOfSections) {
                                        Result->ModuleStompingDetected = TRUE;
                                        IpepAddHollowingMethod(Result, WkdHm_SectionMismatch);
                                        Result->IsHollowed = TRUE;
                                    }
                                }
                            }
                        }
                    }
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
        }
    }

    /* 6. 文件状态 (Ghosting / Herpaderping, 无条件检查对齐 PS) */
    if (GetFileAttributesW(processPath) == INVALID_FILE_ATTRIBUTES &&
        GetLastError() == ERROR_FILE_NOT_FOUND) {
        Result->FileDeletePending = TRUE;
        IpepAddHollowingMethod(Result, WkdHm_DeletePendingFile);
        Result->IsHollowed = TRUE;
    } else {
        HANDLE hf = CreateFileW(processPath, FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            FILE_STANDARD_INFO info = { 0 };
            if (GetFileInformationByHandleEx(hf, FileStandardInfo, &info, sizeof(info)) &&
                info.DeletePending) {
                Result->FileDeletePending = TRUE;
                IpepAddHollowingMethod(Result, WkdHm_DeletePendingFile);
                Result->IsHollowed = TRUE;
            }
            CloseHandle(hf);
        }
    }
    /* Herpaderping: 磁盘时间戳 != 内存时间戳 (磁盘在映射后被修改) */
    if (diskInfo.IsPE && memInfo.IsPE &&
        diskInfo.TimeDateStamp != memInfo.TimeDateStamp) {
        Result->FileModifiedAfterMap = TRUE;
    }

    /* 7. 载荷提取 + SHA256 + IOC 关联 (命中时, 复用 MsReadMemory) */
    if (Result->IsHollowed && memInfo.ImageSize > 0) {
        ULONG extractSize = min(memInfo.ImageSize, 1024 * 1024UL);
        PBYTE payload = NULL;
        ULONG payRead = 0;
        if (MsReadMemory(ProcessId, moduleBase, extractSize, &payload, &payRead) ==
                STATUS_SUCCESS && payRead > 0) {
            DEF_SHA256_HASH hash = { 0 };
            if (IocScanner_ComputeBufferSha256(payload, payRead, &hash)) {
                Result->PayloadHash = hash;
                Result->PayloadHashValid = TRUE;
                {
                    BOOLEAN found = FALSE;
                    if (IocScanner_QueryHash(&hash, &found) == STATUS_SUCCESS && found) {
                        Result->CorrelatedWithKnownThreat = TRUE;
                    }
                }
            }
            free(payload);
        }
    }

    /* 8. 置信度 (对齐 PS CalculateConfidence: 检测法去重加权) */
    {
        ULONG score = 0;
        for (i = 0; i < Result->DetectionMethodCount; i++) {
            switch (Result->DetectionMethods[i]) {
                case WkdHm_PEHeaderMismatch:      score += 3; break;
                case WkdHm_SectionMismatch:       score += 3; break;
                case WkdHm_DeletePendingFile:     score += 3; break;
                case WkdHm_EntryPointAnomaly:     score += 2; break;
                case WkdHm_ThreadContextAnomaly:  score += 2; break;
                case WkdHm_UnbackedExecMemory:    score += 2; break;
                case WkdHm_PebImageBaseMismatch:  score += 2; break;   /* 对齐 C 版 ModifiedPEB=30 */
                case WkdHm_PebImagePathMismatch:  score += 2; break;   /* 对齐 C 版 ImagePathMismatch=25 */
                case WkdHm_SectionCharacteristics: score += 1; break;
                case WkdHm_EntropyAnomaly:        score += 1; break;
                default: break;
            }
        }
        if (score >= 6) {
            Result->Confidence = 90;        /* Confirmed */
        } else if (score >= 4) {
            Result->Confidence = 70;        /* High */
        } else if (score >= 2) {
            Result->Confidence = 50;        /* Medium */
        } else if (score >= 1) {
            Result->Confidence = 30;        /* Low */
        }
    }

    /* 风险分 (对齐 PS CalculateRiskScore, 封顶 100) */
    {
        ULONG risk = 0;
        switch (Result->Confidence) {
            case 90: risk = 90; break;
            case 70: risk = 70; break;
            case 50: risk = 50; break;
            case 30: risk = 30; break;
            default: risk = 0; break;
        }
        if (Result->HasUnbackedExec) risk += 5;
        if (Result->HasRwx) risk += 5;
        if (Result->HasShellcodeAtEntryPoint) risk += 10;
        if (Result->ModuleStompingDetected) risk += 10;
        if (Result->CorrelatedWithKnownThreat) risk += 10;
        Result->RiskScore = min(risk, 100);
    }

    /* 镂空类型判定 (对齐 PS; EarlyBird/ThreadHijack/Doppelganging 依赖事件源) */
    if (Result->IsHollowed) {
        BOOLEAN hasHeaderMismatch = FALSE;
        BOOLEAN hasSectionMismatch = FALSE;
        BOOLEAN hasEpAnomaly = FALSE;

        for (i = 0; i < Result->DetectionMethodCount; i++) {
            if (Result->DetectionMethods[i] == WkdHm_PEHeaderMismatch) hasHeaderMismatch = TRUE;
            if (Result->DetectionMethods[i] == WkdHm_SectionMismatch) hasSectionMismatch = TRUE;
            if (Result->DetectionMethods[i] == WkdHm_EntryPointAnomaly) hasEpAnomaly = TRUE;
        }

        if (Result->FileDeletePending) {
            Result->Type = WkdHt_ProcessGhosting;
        } else if (Result->FileModifiedAfterMap) {
            Result->Type = WkdHt_ProcessHerpaderping;
        } else if (Result->ModuleStompingDetected) {
            Result->Type = WkdHt_ModuleStomping;
        } else if (hasHeaderMismatch && hasSectionMismatch && !hasEpAnomaly) {
            /* RunPE 覆写: 头+节整体替换但 EP 仍有效 (对齐 C 版 Overwriting) */
            Result->Type = WkdHt_Overwriting;
        } else if (!diskInfo.IsPE && Result->HasUnbackedExec) {
            /* 无物理文件 + 隐藏可执行内存 (对齐 C 版 Phantom) */
            Result->Type = WkdHt_Phantom;
        } else {
            Result->Type = WkdHt_ClassicHollowing;
        }
    }

    if (diskFileBuf) free(diskFileBuf);
    CloseHandle(hProcess);
    return TRUE;
}

//
// 挂起创建模式判定 (对齐 PS AnalyzeCreationPattern 挂起时长部分, L2203-2229)
// ★ 死代码: 依赖驱动补「进程以 CREATE_SUSPENDED 创建」线格式字段 +
//   NtResumeThread 事件源 (当前均无, 见 IoaInjectionClassifier.h 数据源依赖)。
//   事件驱动创建模式 (Unmap+Map+Write+SetCtx 序列) 已由
//   IoaClassifyFromEdges 死分支覆盖, 本函数补充「挂起时长」维度。
//
_Use_decl_annotations_
BOOLEAN
IpeIsSuspiciousSuspendedCreation(
    BOOLEAN CreatedSuspended,
    BOOLEAN HasResumed,
    LONGLONG CreatedTick,
    LONGLONG ResumedTick,
    LONGLONG CurrentTick
    )
/*++
Routine Description:
    依据进程挂起创建/恢复时间判定可疑模式:
      - 已恢复且挂起时长在 (100ms, 5000ms) → 自动化特征 (对齐 PS MIN/MAX_CREATION_TO_RESUME)
      - 未恢复且挂起超过 5000ms → 注入进行中
    ★ 死代码: 激活需驱动补源 (创建挂起标志 + NtResumeThread), 当前无调用者。

Arguments:
    CreatedSuspended - 进程是否以挂起方式创建。
    HasResumed       - 是否已恢复。
    CreatedTick      - 创建时刻 (100ns 单位, FILETIME)。
    ResumedTick      - 恢复时刻 (100ns 单位), 未恢复传 0。
    CurrentTick      - 当前时刻 (100ns 单位)。

Return Value:
    TRUE = 挂起时长可疑。
--*/
{
    const LONGLONG MinSuspendedMs = 100;
    const LONGLONG MaxSuspendedMs = 5000;
    LONGLONG elapsedMs;

    if (!CreatedSuspended) return FALSE;

    if (HasResumed && ResumedTick > CreatedTick) {
        elapsedMs = (ResumedTick - CreatedTick) / 10000;
        if (elapsedMs > MinSuspendedMs && elapsedMs < MaxSuspendedMs) {
            return TRUE;
        }
    } else {
        elapsedMs = (CurrentTick - CreatedTick) / 10000;
        if (elapsedMs > MaxSuspendedMs) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// 镂空类型 → 名称 (对齐 PS GetHollowingTypeName)
//
_Use_decl_annotations_
PCWSTR
IpeHollowingTypeToString(
    WKD_HOLLOWING_TYPE Type
    )
{
    switch (Type) {
        case WkdHt_ClassicHollowing:     return L"Classic Hollowing";
        case WkdHt_SectionHollowing:     return L"Section Hollowing";
        case WkdHt_ModuleStomping:       return L"Module Stomping";
        case WkdHt_ProcessGhosting:      return L"Process Ghosting";
        case WkdHt_ProcessHerpaderping:  return L"Process Herpaderping";
        case WkdHt_EarlyBird:            return L"Early Bird";
        case WkdHt_ThreadHijack:         return L"Thread Hijack";
        case WkdHt_ProcessDoppelganging: return L"Process Doppelganging";
        case WkdHt_Overwriting:          return L"Process Overwriting";
        case WkdHt_Phantom:              return L"Phantom DLL Hollowing";
        default: return L"Unknown";
    }
}

//
// 检测方法 → 名称 (对齐 PS GetDetectionMethodName)
//
_Use_decl_annotations_
PCWSTR
IpeHollowingMethodToString(
    WKD_HOLLOWING_METHOD Method
    )
{
    switch (Method) {
        case WkdHm_PEHeaderMismatch:        return L"PE Header Mismatch";
        case WkdHm_EntryPointAnomaly:       return L"Entry Point Anomaly";
        case WkdHm_SectionMismatch:         return L"Section Mismatch";
        case WkdHm_SectionCharacteristics:  return L"Section Characteristics";
        case WkdHm_ImageBaseAnomaly:        return L"ImageBase Anomaly";
        case WkdHm_ChecksumMismatch:        return L"Checksum Mismatch";
        case WkdHm_TimestampMismatch:       return L"Timestamp Mismatch";
        case WkdHm_SizeOfImageMismatch:     return L"SizeOfImage Mismatch";
        case WkdHm_UnbackedExecMemory:      return L"Unbacked Executable Memory";
        case WkdHm_ThreadContextAnomaly:    return L"Thread Context Anomaly";
        case WkdHm_CreationPatternAnomaly:  return L"Creation Pattern Anomaly";
        case WkdHm_PebImageBaseMismatch:    return L"PEB Image Base Mismatch";
        case WkdHm_PebImagePathMismatch:    return L"PEB Image Path Mismatch";
        case WkdHm_DeletePendingFile:       return L"Delete Pending File";
        case WkdHm_EntropyAnomaly:          return L"Entropy Anomaly";
        default: return L"Unknown";
    }
}

//
// 校验 PE 头有效性 (对齐 PS ValidatePEHeader)
//
_Use_decl_annotations_
BOOLEAN
IpeValidatePeHeader(
    PWPA_PE_INFO PeInfo
    )
{
    return PeInfo != NULL && PeInfo->IsPE &&
           PeInfo->NumberOfSections > 0 &&
           PeInfo->NumberOfSections <= WKD_PE_MAX_SECTIONS;
}

//
// 校验映像基址 (对齐 PS ValidateImageBase)
//
_Use_decl_annotations_
BOOLEAN
IpeValidateImageBase(
    ULONG      ProcessId,
    ULONG_PTR  ModuleBase,
    PCWSTR     ProcessPath
    )
/*++
Routine Description:
    校验进程映像加载基址:
      - 非 ASLR 二进制加载于非预期基址 → 异常
      - 内存 EP 与磁盘 EP 不一致 → 异常
    ASLR 二进制基址偏移属正常, 不判异常。

Arguments:
    ProcessId  - 目标进程 PID。
    ModuleBase - 映像加载基址。
    ProcessPath- 磁盘映像路径。

Return Value:
    TRUE = 基址正常或无法校验; FALSE = 基址/EP 异常。
--*/
{
    WPA_PE_INFO memInfo = { 0 };
    WPA_PE_INFO diskInfo = { 0 };
    BYTE headerBuf[8192];
    BYTE diskBuf[8192];
    ULONG headerRead = 0;
    ULONG diskRead = 0;

    if (ModuleBase == 0 || !ProcessPath || !ProcessPath[0]) return TRUE;

    /* 读内存 PE */
    if (!IpepReadRemoteMemory(ProcessId, ModuleBase, headerBuf, sizeof(headerBuf), &headerRead) ||
        headerRead < sizeof(IMAGE_DOS_HEADER)) {
        return TRUE;   /* 无法读取, 保守 */
    }
    if (WpeAnalyzePEHeadersFromBuffer(headerBuf, headerRead, &memInfo) != S_OK ||
        !memInfo.IsPE) {
        return FALSE;  /* 基址处不是 PE → 可疑 */
    }

    /* 读磁盘 PE */
    if (!IpepReadFileBuffer(ProcessPath, diskBuf, sizeof(diskBuf), &diskRead) ||
        diskRead < sizeof(IMAGE_DOS_HEADER)) {
        return TRUE;
    }
    if (WpeAnalyzePEHeadersFromBuffer(diskBuf, diskRead, &diskInfo) != S_OK ||
        !diskInfo.IsPE) {
        return TRUE;
    }

    /* 非 ASLR 且基址不匹配 → 异常 */
    if ((diskInfo.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0 &&
        diskInfo.ImageBase != ModuleBase) {
        return FALSE;
    }

    /* 入口点不一致 → 异常 */
    if (diskInfo.EntryPoint != memInfo.EntryPoint) {
        return FALSE;
    }

    return TRUE;
}

//
// 提取进程主模块载荷 (对齐 PS ExtractPayload, 上限 1MB)
//
_Use_decl_annotations_
BOOLEAN
IpeExtractPayload(
    ULONG    ProcessId,
    PBYTE*   OutBuffer,
    PULONG   OutSize
    )
/*++
Routine Description:
    提取进程主模块完整载荷 (ImageSize 字节, 上限 1MB), 供取证/哈希复用。
    对齐 PS ExtractPayload (ProcessHollowingDetector.cpp L2529)。

Arguments:
    ProcessId  - 目标进程 PID。
    OutBuffer  - 输出堆缓冲, 调用方 free()。
    OutSize    - 实际读取字节数。

Return Value:
    TRUE = 成功。
--*/
{
    ULONG_PTR moduleBase = 0;
    BYTE headerBuf[8192];
    ULONG headerRead = 0;
    WPA_PE_INFO memInfo = { 0 };
    PBYTE buf = NULL;
    ULONG got = 0;

    if (!OutBuffer || !OutSize) return FALSE;
    *OutBuffer = NULL;
    *OutSize = 0;

    /* 主模块基址 (Toolhelp 第一个模块) */
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                moduleBase = (ULONG_PTR)me.modBaseAddr;
            }
            CloseHandle(hSnap);
        }
    }
    if (moduleBase == 0) return FALSE;

    /* 读内存 PE 头拿 ImageSize */
    if (!IpepReadRemoteMemory(ProcessId, moduleBase, headerBuf, sizeof(headerBuf), &headerRead) ||
        headerRead < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }
    if (WpeAnalyzePEHeadersFromBuffer(headerBuf, headerRead, &memInfo) != S_OK ||
        !memInfo.IsPE || memInfo.ImageSize == 0) {
        return FALSE;
    }

    /* 提取 (复用 MsReadMemory) */
    {
        ULONG size = min(memInfo.ImageSize, 1024 * 1024UL);
        if (MsReadMemory(ProcessId, moduleBase, size, &buf, &got) != STATUS_SUCCESS || got == 0) {
            if (buf) free(buf);
            return FALSE;
        }
    }

    *OutBuffer = buf;
    *OutSize = got;
    return TRUE;
}

#pragma warning(push)
#pragma warning(disable:4505)  /* 死代码 static, 激活条件见下方注释 */
//
// 内部辅助: 整体内存镜像 vs 磁盘文件 64KB 比对 + 双 SHA256
// (对齐 C 版 HollowingDetector PhpCompareMemoryWithFile, L2395-2611)
// ★ 死代码: 成本高 (每进程 64KB 内存 + 64KB 磁盘读 + 双 SHA256), 与
//   IpeDetectProcessHollowing 现有节采样 (4096B/节) + 头比对重叠。
//   激活条件 = Deep 扫描门控或 ScanProcess 接线后按需调用。
//   语义对齐 C 版: 不一致 → *Match=FALSE (HashMismatch + SectionMismatch,
//   wkd 复用 WkdHm_SectionMismatch, 不新增方法枚举)。
//
_Use_decl_annotations_
static BOOLEAN
IpepCompareFullImageWithFile(
    _In_  ULONG      ProcessId,
    _In_  ULONG_PTR  ModuleBase,
    _In_  PCWSTR     FilePath,
    _Out_ PBOOLEAN   Match,
    _Out_opt_ PULONG MismatchOffset,
    _Out_opt_ PDEF_SHA256_HASH MemoryHash,
    _Out_opt_ PDEF_SHA256_HASH FileHash
    )
/*++
Routine Description:
    读目标进程主模块前 64KB (对齐 C 版 PH_MAX_SECTION_COMPARE) 与磁盘文件前
    64KB, 逐字节比对 (memcmp) 并计算双方 SHA256。与 C 版一致, 磁盘读不足
    64KB 时以实际读到的字节数为准 (对齐 C 版 CWE-393 防护, 防稀疏/截断
    文件伪造哈希不匹配)。读失败 (进程退出/权限) 返回 FALSE 不判定。

Arguments:
    ProcessId      - 目标进程 PID。
    ModuleBase     - 主模块内存基址。
    FilePath       - 磁盘文件路径。
    Match          - 输出: 内存与磁盘 64KB 是否一致。
    MismatchOffset - 可选: 首个不一致字节偏移。
    MemoryHash     - 可选: 内存前 64KB SHA256。
    FileHash       - 可选: 磁盘前 64KB SHA256。

Return Value:
    TRUE = 比对执行; FALSE = 无法读取内存或磁盘。
--*/
{
    const ULONG CompareSize = 64 * 1024;
    PBYTE memBuf = NULL;
    PBYTE fileBuf = NULL;
    ULONG memRead = 0;
    ULONG fileRead = 0;
    ULONG compareLen;
    ULONG i;
    BOOLEAN ok = FALSE;

    if (Match == NULL) return FALSE;
    *Match = FALSE;
    if (MismatchOffset) *MismatchOffset = 0;

    memBuf = (PBYTE)malloc(CompareSize);
    fileBuf = (PBYTE)malloc(CompareSize);
    if (memBuf == NULL || fileBuf == NULL) {
        goto Cleanup;
    }

    if (!IpepReadRemoteMemory(ProcessId, ModuleBase, memBuf, CompareSize, &memRead) ||
        memRead < CompareSize) {
        goto Cleanup;
    }
    if (!IpepReadFileBuffer(FilePath, fileBuf, CompareSize, &fileRead) ||
        fileRead < CompareSize) {
        goto Cleanup;
    }

    /* 对齐 C 版 CWE-393: 以实际读到字节数为准, 不比对越界零填充 */
    compareLen = min(memRead, fileRead);
    *Match = (memcmp(memBuf, fileBuf, compareLen) == 0);
    if (!*Match && MismatchOffset) {
        for (i = 0; i < compareLen; i++) {
            if (memBuf[i] != fileBuf[i]) {
                *MismatchOffset = i;
                break;
            }
        }
    }

    if (MemoryHash) {
        IocScanner_ComputeBufferSha256(memBuf, compareLen, MemoryHash);
    }
    if (FileHash) {
        IocScanner_ComputeBufferSha256(fileBuf, compareLen, FileHash);
    }

    ok = TRUE;

Cleanup:
    if (memBuf) free(memBuf);
    if (fileBuf) free(fileBuf);
    return ok;
}
#pragma warning(pop)  /* 4505 */

//
// 批量镂空扫描 (对齐 PS ScanAllProcesses, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 主动全盘扫描, 当前无调用者。
//
_Use_decl_annotations_
ULONG
IpeScanAllProcessesForHollowing(
    PWKD_HOLLOWING_RESULT Results,
    ULONG                  MaxResults,
    PULONG                 ResultCount,
    WKD_MEM_SCAN_MODE      ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (ResultCount) *ResultCount = 0;
    if (!Results || MaxResults == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (count >= MaxResults) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &Results[count]) &&
                Results[count].IsHollowed) {
                count++;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 按 PID 数组批量镂空扫描 (对齐 PS ScanProcesses, 仅返回 IsHollowed 命中)
//
_Use_decl_annotations_
ULONG
IpeScanProcesses(
    const ULONG* Pids,
    ULONG        PidCount,
    PWKD_HOLLOWING_RESULT Results,
    ULONG        MaxResults,
    PULONG       ResultCount,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    ULONG count = 0;
    ULONG i;

    if (ResultCount) *ResultCount = 0;
    if (!Pids || PidCount == 0 || !Results || MaxResults == 0) return 0;

    for (i = 0; i < PidCount && count < MaxResults; i++) {
        if (Pids[i] == 0 || Pids[i] == 4) continue;
        if (IpeDetectProcessHollowing(Pids[i], ScanMode, &Results[count]) &&
            Results[count].IsHollowed) {
            count++;
        }
    }

    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 按进程名批量镂空扫描 (对齐 PS ScanByName, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 定向扫描。
//
_Use_decl_annotations_
ULONG
IpeScanProcessesByName(
    PCWSTR ProcessName,
    PWKD_HOLLOWING_RESULT Results,
    ULONG  MaxResults,
    PULONG ResultCount,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (ResultCount) *ResultCount = 0;
    if (!ProcessName || !ProcessName[0] || !Results || MaxResults == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (count >= MaxResults) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (_wcsicmp(pe.szExeFile, ProcessName) != 0) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &Results[count]) &&
                Results[count].IsHollowed) {
                count++;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 按进程路径批量镂空扫描 (对齐 PS ScanByPath, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 定向扫描。
//
_Use_decl_annotations_
ULONG
IpeScanProcessesByPath(
    PCWSTR ProcessPath,
    PWKD_HOLLOWING_RESULT Results,
    ULONG  MaxResults,
    PULONG ResultCount,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (ResultCount) *ResultCount = 0;
    if (!ProcessPath || !ProcessPath[0] || !Results || MaxResults == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            WCHAR fullPath[MAX_PATH] = { 0 };
            DWORD pathLen = RTL_NUMBER_OF(fullPath);
            HANDLE hp;
            BOOLEAN match = FALSE;

            if (count >= MaxResults) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hp) {
                if (QueryFullProcessImageNameW(hp, 0, fullPath, &pathLen)) {
                    match = (_wcsicmp(fullPath, ProcessPath) == 0);
                }
                CloseHandle(hp);
            }
            if (!match) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &Results[count]) &&
                Results[count].IsHollowed) {
                count++;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 收集疑似镂空进程 PID 列表 (对齐 PS GetHollowedProcesses)
// ★ 死代码: 供 UI 主动全盘扫描。
//
_Use_decl_annotations_
ULONG
IpeGetHollowedProcesses(
    ULONG* Pids,
    ULONG  MaxPids,
    PULONG Count,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (Count) *Count = 0;
    if (!Pids || MaxPids == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            WKD_HOLLOWING_RESULT r = { 0 };
            if (count >= MaxPids) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &r) && r.IsHollowed) {
                Pids[count++] = pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (Count) *Count = count;
    return count;
}