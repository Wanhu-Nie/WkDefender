/**************************************************/
/*                                                    */
/*  WkDefender 内存完整性（Memory Integrity）         */
/*  检测子系统——实现                                */
/*                                                    */
/*  2026-09-13 自 Process\HollowingDetector 迁入：    */
/*    - PhCompareImageWithFile 公共专项比对（参数     */
/*      WKD_PROCESS 化：免打开进程/免镜像路径采集/    */
/*      免 PEB 基址探测，直取权威副本 + 模块链）      */
/*    - MiCompareMemoryWithFile 逐节比对（节表驱动，  */
/*      可写节规避，HollowingDetector 亦消费）        */
/*    - MiReadProcessMemory / MiLookupMainModule      */
/*      （内部辅助，跨模块共享）                      */
/*                                                    */
/*  跨进程内存读取统一经 Common\ExportParser 动态     */
/*  解析的 pfnMmCopyVirtualMemory，禁止对             */
/*  MmCopyVirtualMemory 的直接符号依赖。              */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#include "MemoryIntegrity.h"                        /* 内部私有头（结构 + 常量 + 私有声明） */
#include "../Include/Memory/MemoryIntegrity.h"      /* 对外公共头（PhCompareImageWithFile 声明） */
#include "../Common/ExportParser.h"                 /* pfnMmCopyVirtualMemory */
#include "../Common/BCryptUtils.h"                  /* CoComputeSha256 */
#include "../Common/Utils.h"                        /* WkdAcquirePushLockShared / WkdReleasePushLockShared */
#include "../Process/ProcessMonitor.h"              /* PWKD_PROCESS 完整定义（Core 访问） */

/* ============================================================================
 * 内部辅助 - 跨进程内存读取
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
MiReadProcessMemory(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
    )
{
    NTSTATUS status;
    SIZE_T bytesCopied = 0;

    if (BytesRead != NULL) {
        *BytesRead = 0;
    }

    //
    // pfnMmCopyVirtualMemory：由 Common\ExportParser 经 MmGetSystemRoutineAddress
    // 动态解析（1607+ 导出）。2026-09-13 起废除对 MmCopyVirtualMemory 的直接
    // NTKERNELAPI 前向声明依赖，统一收敛到 ExportParser 解析链；解析失败时
    // 指针为 NULL，返回 STATUS_NOT_SUPPORTED 由调用方降级处理。
    //
    if (pfnMmCopyVirtualMemory == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    //
    // MmCopyVirtualMemory：跨进程安全拷贝（免 attach / 免句柄）。
    // 拷贝目标取当前进程（分析线程自身），KernelMode 源访问由内核
    // 捕获页错误，缺页/无效页收敛为部分拷贝（bytesCopied < Size），
    // 与 ZwReadVirtualMemory 语义对齐，调用方按 bytesCopied 收敛处理。
    //
    status = pfnMmCopyVirtualMemory(
        Process,
        BaseAddress,
        PsGetCurrentProcess(),
        Buffer,
        Size,
        KernelMode,
        &bytesCopied
    );

    if (BytesRead != NULL) {
        *BytesRead = bytesCopied;
    }

    return status;
}

/* ============================================================================
 * 内部辅助 - 主模块定位
 * ============================================================================ */

_Use_decl_annotations_
PWKD_MODULE_INSTANCE
MiLookupMainModule(
    _In_ PWKD_PROCESS WkdProcess,
    _In_opt_ PUNICODE_STRING ImagePath
    )
/*++
    Routine Description:
        从 WKD_PROCESS 模块链定位主模块视图（2026-09-13 迁自
        HollowingDetector.PhpLookupMainModule）：
          1) 优先按权威副本镜像路径（大小写不敏感）匹配 WKD_MODULE.ImagePath；
          2) 未命中时 fallback 到首个 WkdImageType_Exe 实例（进程主映像
             通用特征）。

        线程安全：WkdProcess->ModuleContext 由 PsAllocateModuleContext 惰性
        创建（镜像回调首见时挂载）。本函数须持 ModuleContext.Lock 共享锁遍历
        ModuleList（EX_PUSH_LOCK，≤APC_LEVEL，与 PsLookupModule…Locked 等
        模块链读路径一致）。

        生命周期：调用方已持目标进程 EProcess 引用，进程存活期间
        ModuleContext 不会销毁，返回的视图实例与 WKD_MODULE 全局对象均有效；
        模块卸载不摘除视图（对齐 PsLookupWkdModuleContainingAddress 约定）。
        Instance 字段（ImageBase）可在锁外读取——进程引用保证视图存活。

    Arguments:
        WkdProcess - 目标进程 WKD_PROCESS（Core 已权威采集）；
        ImagePath - 权威副本镜像路径（可为 NULL：直接进入 Exe fallback）。

    Return Value:
        主模块视图；未找到返回 NULL。
--*/
{
    PWKD_MODULE_CONTEXT moduleContext;
    PWKD_MODULE_INSTANCE instance = NULL;
    PWKD_MODULE_INSTANCE exeFallback = NULL;
    PLIST_ENTRY entry;

    if (WkdProcess == NULL) {
        return NULL;
    }

    moduleContext = WkdProcess->ModuleContext;

    if (moduleContext == NULL) {
        return NULL;
    }

    WkdAcquirePushLockShared(&moduleContext->Lock);

    for (entry = moduleContext->ModuleList.Flink;
         entry != &moduleContext->ModuleList;
         entry = entry->Flink) {
        PWKD_MODULE_INSTANCE cur =
            CONTAINING_RECORD(entry, WKD_MODULE_INSTANCE, ListEntry);

        if (cur->Module == NULL) {
            continue;
        }

        if (ImagePath != NULL &&
            cur->Module->ImagePath != NULL &&
            RtlEqualUnicodeString(ImagePath, cur->Module->ImagePath, TRUE)) {
            instance = cur;
            break;
        }

        if (cur->Module->ImageType == WkdImageType_Exe &&
            exeFallback == NULL) {
            exeFallback = cur;
        }
    }

    WkdReleasePushLockShared(&moduleContext->Lock);

    if (instance == NULL) {
        instance = exeFallback;
    }

    return instance;
}

/* ============================================================================
 * 内部辅助 - 内存镜像与磁盘文件比对
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
MiCompareMemoryWithFile(
    _In_ PEPROCESS Process,
    _In_ PVOID MemoryBase,
    _In_ SIZE_T MemorySize,
    _In_opt_ PWKD_MODULE_SECTION Sections,
    _In_ ULONG SectionCount,
    _In_ BOOLEAN CompareWritableSections,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset,
    _Out_opt_ PULONG ComparedSectionCount,
    _Out_opt_ PULONG SkippedSectionCount,
    _Out_opt_ PUCHAR MemoryHash,
    _Out_opt_ PUCHAR FileHash
    )
/*++
    Routine Description:
        内存镜像与磁盘文件比对（2026-09-13 迁自
        HollowingDetector.PhpCompareMemoryWithFile）。

        两条路径（由调用方按是否有模块链节表选择）：
          - 节表驱动（Sections != NULL && SectionCount > 0）：
            逐节比对内存 [MemoryBase+VA, VA+min(VirtualSize,SizeOfRawData))
            与文件 [PointerToRawData, 同长)。只读节参与严格比对并决定
            Match；可写节（IMAGE_SCN_MEM_WRITE，如 .data）运行期合法写，
            默认跳过（防误报），CompareWritableSections=TRUE 时参与比对；
            .bss（VirtualSize > SizeOfRawData）只比 RawSize 内部分。
            每节读取/比对长度受 PH_MAX_SECTION_COMPARE_SIZE 上限（单节截断，
            资源有界——与原"整窗口 64KB"相比扩大了覆盖节数，但峰值
            内存不变）。
            哈希：参与比对区域内容拼接（上限 MI_HASH_CONCAT_LIMIT）后
            整体 SHA-256 —— 内存与文件两侧同法，一致时哈希必然相等，
            避免"全窗口哈希恒不等"的误导。
          - 兼容路径（无节表）：原全窗口整块比对（行为不变）。

    Arguments:
        Process - 目标进程 EPROCESS（读内存经 pfnMmCopyVirtualMemory）；
        MemoryBase - 内存镜像基址；
        MemorySize - 内存镜像大小；
        Sections / SectionCount - 模块链节表（WKD_MODULE.Sections）；
        CompareWritableSections - 可写节是否参与比对（严格模式）；
        FilePath - 磁盘文件路径；
        Match - 输出：是否一致；
        MismatchOffset - 输出（可选）：首个不一致偏移（相对镜像基址）；
        ComparedSectionCount / SkippedSectionCount - 输出（可选）：
            参与比对/跳过的节数（取证统计）；
        MemoryHash / FileHash - 输出（可选）：SHA-256（32 字节）。

    Return Value:
        STATUS_SUCCESS / NTSTATUS 错误码。
--*/
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    ULONGLONG fileSize = 0;
    PVOID memoryBuffer = NULL;
    PVOID fileBuffer = NULL;
    PVOID memHashBuffer = NULL;
    PVOID fileHashBuffer = NULL;
    SIZE_T bytesRead = 0;
    SIZE_T compareSize;
    ULONG i;
    UCHAR memHash[32] = { 0 };
    UCHAR fHash[32] = { 0 };
    ULONG comparedCount = 0;
    ULONG skippedCount = 0;

    if (Process == NULL || MemoryBase == NULL || FilePath == NULL ||
        FilePath->Buffer == NULL || Match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Match = FALSE;
    if (MismatchOffset != NULL) *MismatchOffset = 0;
    if (ComparedSectionCount != NULL) *ComparedSectionCount = 0;
    if (SkippedSectionCount != NULL) *SkippedSectionCount = 0;

    //
    // 打开文件
    //
    InitializeObjectAttributes(
        &objAttr,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // 获取文件大小
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    fileSize = (ULONGLONG)fileInfo.EndOfFile.QuadPart;

    if (Sections != NULL && SectionCount > 0) {
        //
        // ============ 节表驱动路径（2026-09-13，.data 可写节规避） ============
        //
        BOOLEAN match = TRUE;
        BOOLEAN foundMismatch = FALSE;
        ULONG globalMismatchOffset = 0;
        SIZE_T hashLen = 0;
        ULONG s;

        //
        // 单节缓存池：循环外一次性分配（峰值 = 单节上限，资源有界）。
        // 仅在 PASSIVE_LEVEL 运行，使用 PagedPool。
        //
        memoryBuffer = ExAllocatePool2(
            POOL_FLAG_PAGED,
            PH_MAX_SECTION_COMPARE_SIZE,
            PH_POOL_TAG_BUFFER
        );

        if (memoryBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        fileBuffer = ExAllocatePool2(
            POOL_FLAG_PAGED,
            PH_MAX_SECTION_COMPARE_SIZE,
            PH_POOL_TAG_BUFFER
        );

        if (fileBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        if (MemoryHash != NULL || FileHash != NULL) {
            memHashBuffer = ExAllocatePool2(
                POOL_FLAG_PAGED,
                MI_HASH_CONCAT_LIMIT,
                PH_POOL_TAG_BUFFER
            );

            if (memHashBuffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }

            fileHashBuffer = ExAllocatePool2(
                POOL_FLAG_PAGED,
                MI_HASH_CONCAT_LIMIT,
                PH_POOL_TAG_BUFFER
            );

            if (fileHashBuffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }
        }

        for (s = 0; s < SectionCount; s++) {
            const PWKD_MODULE_SECTION sec = &Sections[s];
            ULONG va = sec->VirtualAddress;
            ULONG cmpLen = sec->VirtualSize;
            LARGE_INTEGER fileOffset;
            BOOLEAN isWritable =
                (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            //
            // 比对长度：内存侧取 min(VirtualSize, SizeOfRawData)。
            // .bss（VirtualSize > SizeOfRawData）仅比 RawSize 内部分，
            // 防止"文件未初始化区"误报。单节受
            // PH_MAX_SECTION_COMPARE_SIZE 截断。
            //
            if (cmpLen > sec->SizeOfRawData) {
                cmpLen = sec->SizeOfRawData;
            }
            if (cmpLen > PH_MAX_SECTION_COMPARE_SIZE) {
                cmpLen = PH_MAX_SECTION_COMPARE_SIZE;
            }
            if (cmpLen == 0) {
                continue;
            }

            //
            // 越界防护：节的内存范围不得超出镜像边界；
            // 文件侧 PointerToRawData+cmpLen 不得超出文件大小（按文件收敛）。
            //
            if ((ULONGLONG)va + cmpLen > (ULONGLONG)MemorySize) {
                continue;
            }

            if ((ULONGLONG)sec->PointerToRawData + cmpLen > fileSize) {
                if (fileSize > (ULONGLONG)sec->PointerToRawData) {
                    cmpLen = (ULONG)(fileSize - (ULONGLONG)sec->PointerToRawData);
                } else {
                    continue;
                }
            }
            if (cmpLen == 0) {
                continue;
            }

            //
            // 可写节策略：运行期合法写（.data 等）默认跳过，防误报；
            // 严格模式（CompareWritableSections=TRUE）下参与比对。
            //
            if (isWritable && !CompareWritableSections) {
                skippedCount++;
                continue;
            }

            //
            // 从进程内存读取该节（pfnMmCopyVirtualMemory 免 attach/句柄）
            //
            status = MiReadProcessMemory(
                Process,
                (PUCHAR)MemoryBase + va,
                memoryBuffer,
                cmpLen,
                &bytesRead
            );

            if (!NT_SUCCESS(status) || bytesRead < cmpLen) {
                goto Cleanup;
            }

            //
            // 从文件按 PointerToRawData 偏移读取
            //
            fileOffset.QuadPart = (LONGLONG)sec->PointerToRawData;

            status = ZwReadFile(
                fileHandle,
                NULL,
                NULL,
                NULL,
                &ioStatus,
                fileBuffer,
                cmpLen,
                &fileOffset,
                NULL
            );

            if (!NT_SUCCESS(status)) {
                goto Cleanup;
            }

            //
            // CWE-393 防御：ZwReadFile 可能返回少于请求的数量
            // （比较窗口内文件被截断/缩小等）。保守视为该节不匹配，
            // 不伪造"哈希一致"。
            //
            if (ioStatus.Information < cmpLen) {
                match = FALSE;
                if (!foundMismatch) {
                    globalMismatchOffset = va;
                    foundMismatch = TRUE;
                }
                comparedCount++;
                continue;
            }

            //
            // 比对该节（逐字节）。不一致时记录首个不一致节内偏移：
            // MismatchOffset 语义 = 相对镜像基址的全局偏移。
            //
            if (RtlCompareMemory(memoryBuffer, fileBuffer, cmpLen) != cmpLen) {
                ULONG k;

                match = FALSE;

                for (k = 0; k < cmpLen; k++) {
                    if (((PUCHAR)memoryBuffer)[k] != ((PUCHAR)fileBuffer)[k]) {
                        ULONG off = va + k;

                        if (!foundMismatch || off < globalMismatchOffset) {
                            globalMismatchOffset = off;
                        }
                        foundMismatch = TRUE;
                        break;
                    }
                }
            }

            //
            // 拼接哈希：参与比对区域内容累计（上限 MI_HASH_CONCAT_LIMIT），
            // 内存/文件两侧同法，保证一致时哈希必然相等。
            //
            if ((MemoryHash != NULL || FileHash != NULL) &&
                hashLen < MI_HASH_CONCAT_LIMIT) {
                SIZE_T room = MI_HASH_CONCAT_LIMIT - hashLen;
                SIZE_T take = (room < (SIZE_T)cmpLen) ? room : (SIZE_T)cmpLen;

                if (take > 0) {
                    if (memHashBuffer != NULL) {
                        RtlCopyMemory((PUCHAR)memHashBuffer + hashLen,
                                      memoryBuffer, take);
                    }
                    if (fileHashBuffer != NULL) {
                        RtlCopyMemory((PUCHAR)fileHashBuffer + hashLen,
                                      fileBuffer, take);
                    }
                    hashLen += take;
                }
            }

            comparedCount++;
        }

        *Match = match;
        if (MismatchOffset != NULL) {
            *MismatchOffset = foundMismatch ? globalMismatchOffset : 0;
        }
        if (ComparedSectionCount != NULL) {
            *ComparedSectionCount = comparedCount;
        }
        if (SkippedSectionCount != NULL) {
            *SkippedSectionCount = skippedCount;
        }

        //
        // 拼接缓冲整体 SHA-256
        //
        if ((MemoryHash != NULL || FileHash != NULL) && hashLen > 0) {
            if (MemoryHash != NULL) {
                status = CoComputeSha256(memHashBuffer, (ULONG)hashLen, memHash);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(MemoryHash, memHash, 32);
                }
            }

            if (FileHash != NULL) {
                status = CoComputeSha256(fileHashBuffer, (ULONG)hashLen, fHash);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(FileHash, fHash, 32);
                }
            }
        }

        status = STATUS_SUCCESS;
    } else {
        //
        // ============ 兼容路径（无节表）：全窗口整块比对 ============
        //
        BOOLEAN match = FALSE;

        //
        // 确定比较大小（设置上限以防止过度占用内存）
        //
        compareSize = (SIZE_T)min(MemorySize, (SIZE_T)fileSize);
        compareSize = min(compareSize, PH_MAX_SECTION_COMPARE_SIZE);

        if (compareSize < MI_MIN_IMAGE_SIZE) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto Cleanup;
        }

        //
        // 使用 PagedPool — 本函数仅在 PASSIVE_LEVEL 运行。
        // 比较完整分配范围，而非仅前 4KB：原先截断到固定头长度（4096）
        // 的做法使检测极易被绕过（攻击者修改 4KB 之外的代码即可绕过）。
        //
        memoryBuffer = ExAllocatePool2(
            POOL_FLAG_PAGED,
            compareSize,
            PH_POOL_TAG_BUFFER
        );

        fileBuffer = ExAllocatePool2(
            POOL_FLAG_PAGED,
            compareSize,
            PH_POOL_TAG_BUFFER
        );

        if (memoryBuffer == NULL || fileBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        //
        // 从进程内存读取
        //
        status = MiReadProcessMemory(
            Process,
            MemoryBase,
            memoryBuffer,
            compareSize,
            &bytesRead
        );

        if (!NT_SUCCESS(status) || bytesRead < compareSize) {
            goto Cleanup;
        }

        //
        // 从文件读取
        //
        status = ZwReadFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            fileBuffer,
            (ULONG)compareSize,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        //
        // CWE-393 防御：ZwReadFile 可能返回少于请求的数量
        // （如稀疏文件、文件末尾、网络共享、备用数据流截断等场景）。
        // 若将完整请求长度与 fileBuffer 尾部清零字节或过期的 memoryBuffer
        // 内容进行比较，会伪造出"哈希不匹配"，从而触发进程镂空的
        // 误报检测。因此需将 compareSize 收敛到实际读取的长度，
        // 且拒绝小于最小映像大小的比较。
        //
        if (ioStatus.Information < compareSize) {
            compareSize = (SIZE_T)ioStatus.Information;
        }

        if (compareSize < MI_MIN_IMAGE_SIZE) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto Cleanup;
        }

        //
        // 比较完整分配范围，而非仅前 4KB。
        // 否则攻击者修改 4KB 之外的代码即可绕过检测。
        //
        match = (RtlCompareMemory(memoryBuffer, fileBuffer, compareSize) == compareSize);

        *Match = match;

        if (!match && MismatchOffset != NULL) {
            //
            // 查找首个不匹配位置
            //
            for (i = 0; i < compareSize; i++) {
                if (((PUCHAR)memoryBuffer)[i] != ((PUCHAR)fileBuffer)[i]) {
                    *MismatchOffset = i;
                    break;
                }
            }
        }

        //
        // 如请求则计算哈希
        //
        if (MemoryHash != NULL || FileHash != NULL) {
            if (MemoryHash != NULL) {
                status = CoComputeSha256(
                    memoryBuffer,
                    (ULONG)compareSize,
                    memHash
                );

                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(MemoryHash, memHash, 32);
                }
            }

            if (FileHash != NULL) {
                status = CoComputeSha256(
                    fileBuffer,
                    (ULONG)compareSize,
                    fHash
                );

                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(FileHash, fHash, 32);
                }
            }
        }

        status = STATUS_SUCCESS;
    }

Cleanup:
    if (memoryBuffer != NULL) {
        ExFreePoolWithTag(memoryBuffer, PH_POOL_TAG_BUFFER);
    }

    if (fileBuffer != NULL) {
        ExFreePoolWithTag(fileBuffer, PH_POOL_TAG_BUFFER);
    }

    if (memHashBuffer != NULL) {
        ExFreePoolWithTag(memHashBuffer, PH_POOL_TAG_BUFFER);
    }

    if (fileHashBuffer != NULL) {
        ExFreePoolWithTag(fileHashBuffer, PH_POOL_TAG_BUFFER);
    }

    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }

    return status;
}

/* ============================================================================
 * 公共 API - 专项比对
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
PhCompareImageWithFile(
    _In_ PPH_DETECTOR Detector,
    _In_ struct _WKD_PROCESS* WkdProcess,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset
    )
/*++
    Routine Description:
        内存镜像与磁盘文件逐节比对（2026-09-13 迁自
        HollowingDetector.PhCompareImageWithFile，参数 WKD_PROCESS 化）：

          1) 进程标识直接取自 WkdProcess->Core.EProcess（权威副本），
             经 ObReferenceObjectSafe 额外持引用防"分析中出现进程退出"
             竞态；
          2) 镜像路径复用 WkdProcess->Core.ImagePath，免去 SeLocate 采集；
          3) 映像基址 / 大小 / 节表取自模块链（MiLookupMainModule →
             WKD_MODULE_INSTANCE.ImageBase + WKD_MODULE.SizeOfImage +
             WKD_MODULE.Sections，L0 PeParser 已解析），免去 PEB 探测与
             重复 PE 解析；
          4) 可写节（.data 等运行期合法写）按
             Detector->Config.CompareWritableSections 策略跳过/参与。

        与旧实现的差异：不再打开进程句柄 / 不再采集镜像路径 / 不再读
        PEB 基址——全部冗余路径删除。Detector 仅消费公共 Config 字段，
        生命周期由宿主保障（对齐 DefensiveEvasion 公共 API 约定）。

    Arguments:
        Detector - 检测器实例（PhInitialize 输出，Config 消费）；
        WkdProcess - WKD_PROCESS 权威副本（调用方持有引用，分析期间不得释放）；
        Match - 输出：镜像是否与文件一致；
        MismatchOffset - 输出（可选）：首个不一致偏移（相对镜像基址）。

    Return Value:
        STATUS_SUCCESS / NTSTATUS 错误码（STATUS_NOT_FOUND = 无主模块或
        无可用磁盘路径）。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    PWKD_MODULE_INSTANCE mainModule = NULL;
    PWKD_MODULE module = NULL;
    PUNICODE_STRING imagePath = NULL;
    PWKD_MODULE_SECTION sections = NULL;
    ULONG sectionCount = 0;
    BOOLEAN match = FALSE;
    ULONG mismatchOffset = 0;

    if (Detector == NULL || WkdProcess == NULL || Match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Match = FALSE;
    if (MismatchOffset != NULL) {
        *MismatchOffset = 0;
    }

    //
    // 目标进程引用保护（M-5 模式）：ObReferenceObjectSafe 防
    // "分析中出现进程退出"竞态——进程退出瞬间引用释放后即失败。
    //
    process = ObReferenceObjectSafe(WkdProcess->Core.EProcess);
    if (process == NULL) {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    //
    // 主模块定位：优先权威副本镜像路径，fallback 首个 Exe 实例。
    //
    imagePath = WkdProcess->Core.ImagePath;
    mainModule = MiLookupMainModule(WkdProcess, imagePath);

    if (mainModule == NULL || mainModule->Module == NULL) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    module = mainModule->Module;

    //
    // 无磁盘路径可比较（权威副本未采集 / 无名镜像）：fail fast。
    // ZwOpenFile 不接受 NULL ObjectName。
    //
    if (imagePath == NULL || imagePath->Buffer == NULL) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    //
    // 模块链节表（L0 PeParser 已解析；Sections 为空时降级全窗口
    // 兼容路径）。
    //
    sections = (PWKD_MODULE_SECTION)DaGetElement(&module->Sections, 0);
    sectionCount = (ULONG)min(module->Sections.Count,
                              WKD_MT_PE_SECTION_MASK_BITS);

    //
    // 逐节比对（可写节策略取自公共 Config）。
    //
    status = MiCompareMemoryWithFile(
        process,
        mainModule->ImageBase,
        module->SizeOfImage,
        sections,
        sectionCount,
        Detector->Config.CompareWritableSections,
        imagePath,
        &match,
        &mismatchOffset,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (NT_SUCCESS(status)) {
        *Match = match;
        if (MismatchOffset != NULL) {
            *MismatchOffset = mismatchOffset;
        }
    }

Cleanup:
    if (process != NULL) {
        ObDereferenceObject(process);
    }

    return status;
}