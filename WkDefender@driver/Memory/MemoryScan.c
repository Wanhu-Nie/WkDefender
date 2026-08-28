#include "MemoryScan.h"
#include "../Common/Utils.h"
#include "../Common/PeParser.h"
#include "../Common/PeCallbacks.h"

#define WKD_MEMORY_MATCH_PATTERN_POOL 'mmpp'

//
// 模块说明：内存扫描功能实现
// 主要功能：
//   1. 解析PE结构定位指定节区
//   2. 基于特征码进行内存扫描匹配
// 
// 注意：内核模块基地址获取功能已迁移至 Common/Utils.c::UtGetKernelModuleBase
//       使用 DriverObject->DriverSection 遍历模块链表，无需依赖未导出的 PsLoadedModuleList
//

//
// 辅助函数：特征码匹配
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
MmpMatchPattern(
    _In_ PUCHAR Data,
    _In_ PWKD_MEMORY_SIGNATURE Pattern
    )
{
    if (!Data || !Pattern || Pattern->Length == 0) {
        return FALSE;
    }

    for (ULONG i = 0; i < Pattern->Length; i++) {
        // 如果掩码为0xFF，则必须精确匹配
        if (Pattern->Mask[i] == 0xFF) {
            if (Data[i] != Pattern->Pattern[i]) {
                return FALSE;
            }
        }
        // 如果掩码为0x00，则为通配符，跳过比较
        // 其他值保留用于未来扩展
    }

    return TRUE;
}

//
// 解析PE文件获取指定节区信息（统一解析核心薄包装，2026-08-08）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmParsePeSection(
    _In_ PVOID ImageBase,
    _In_ PCHAR SectionName,
    _Out_ PWKD_SECTION_INFO SectionInfo
    )
{
    WKD_PE_PARSE_CONTEXT ctx;
    WKD_PE_SECTION_MATCH match;
    NTSTATUS status;
    SIZE_T nameLen;

    if (!ImageBase || !SectionName || !SectionInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    // 初始化输出结构
    RtlZeroMemory(SectionInfo, sizeof(WKD_SECTION_INFO));

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.Size = sizeof(ctx);
    ctx.Data = ImageBase;
    ctx.DataSize = MAXULONG;    // 调用方无 ImageSize，SEH 兜底（对齐原无边界语义）
    ctx.Mode = WkdPeMode_Image;
    ctx.MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;
    WkdPeCbFindSectionByName(&ctx, SectionName, &match);

    status = CoParsePe(&ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception parsing PE sections: 0x%08X\n", status);
        return STATUS_ACCESS_VIOLATION;
    }

    if (!match.Found) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Section %.8s not found\n", SectionName);
        return STATUS_NOT_FOUND;
    }

    // 填充节区信息（对齐原语义：Name 复制匹配长度，Base=ImageBase+VA，Size=VirtualSize）
    nameLen = strlen(SectionName);
    if (nameLen > sizeof(SectionInfo->Name)) {
        nameLen = sizeof(SectionInfo->Name);
    }
    RtlCopyMemory(SectionInfo->Name, match.Section->Name, nameLen);
    SectionInfo->BaseAddress = (PVOID)((PUCHAR)ImageBase + match.Section->VirtualAddress);
    SectionInfo->Size = match.Section->Misc.VirtualSize;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Found section %.8s at 0x%p, size: 0x%X\n",
        SectionInfo->Name, SectionInfo->BaseAddress, SectionInfo->Size);

    return STATUS_SUCCESS;
}

//
// 注意：MmPrecompilePattern 和 MmFreePrecompiledPattern 已迁移至 MemorySignature.c
// 请使用 MsRegisterSignature / MsUnregisterSignature 进行签名的生命周期管理
//

//
// 优化的模式匹配函数
// 利用预编译的精确匹配信息进行快速筛选
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
MmpMatchPatternOptimized(
    _In_ PUCHAR Data,
    _In_ PWKD_MEMORY_SIGNATURE Pattern
    )
{
    if (!Data || !Pattern) {
        return FALSE;
    }

    // 如果未预编译或没有精确字节，回退到原始方法
    if (!Pattern->IsPrecompiled || Pattern->ExactCount == 0) {
        return MmpMatchPattern(Data, Pattern);
    }

    /* __try { */
        // 第一步：快速检查第一个精确匹配字节
        // 这是最常见的失败情况，可以尽早退出
        if (Pattern->HasFirstByte) {
            if (Data[0] != Pattern->FirstExactByte) {
                return FALSE;
            }
        }

        // 第二步：使用RtlCompareMemory批量比较连续的精确匹配段
        // 对于短pattern，直接逐字节比较可能更快
        if (Pattern->ExactCount <= 4) {
            // 少量精确字节，直接比较
            for (ULONG i = 1; i < Pattern->ExactCount; i++) {
                UCHAR pos = Pattern->ExactPositions[i];
                if (Data[pos] != Pattern->ExactPattern[i]) {
                    return FALSE;
                }
            }
        } else {
            // 大量精确字节，尝试批量比较
            // 注意：这里简化处理，实际可以进一步优化为分段批量比较
            for (ULONG i = 1; i < Pattern->ExactCount; i++) {
                UCHAR pos = Pattern->ExactPositions[i];
                if (Data[pos] != Pattern->ExactPattern[i]) {
                    return FALSE;
                }
            }
        }

        // 第三步：验证通配符位置的掩码（如果需要）
        // 由于我们已经验证了所有精确匹配字节，且通配符位置不需要检查
        // 所以这里可以直接返回TRUE
        
        return TRUE;
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception in optimized pattern match\n");
        return FALSE;
    } */
}

//
// 统一的内存扫描辅助函数
// 在指定地址范围内执行特征码扫描，使用三层优化策略
// 内部函数，供 MmScanSection 和 MmScanMemoryRange 调用
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
MmpScanMemoryRangeInternal(
    _In_ PUCHAR ScanStart,
    _In_ PUCHAR ScanEnd,
    _In_ PWKD_MEMORY_SIGNATURE Signature,
    _Out_ PWKD_SCAN_RESULT ScanResult
    )
{
    PUCHAR currentPos;

    // 参数验证
    if (!ScanStart || !ScanEnd || !Signature || !ScanResult) {
        return STATUS_INVALID_PARAMETER;
    }

    // 边界检查
    if (ScanStart >= ScanEnd) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Invalid scan range: start=0x%p, end=0x%p\n",
            ScanStart, ScanEnd);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 初始化扫描结果
    RtlZeroMemory(ScanResult, sizeof(WKD_SCAN_RESULT));

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Scanning memory from 0x%p to 0x%p (size: 0x%X)\n",
        ScanStart, ScanEnd, (ULONG)(ScanEnd - ScanStart));

    // 执行特征码扫描（使用三层优化：首字节过滤 + 快速失败 + 预编译）
    /* __try { */
        currentPos = ScanStart;

        // 第三层优化：首字节快速过滤
        if (Signature->HasFirstByte) {
            UCHAR targetByte = Signature->FirstExactByte;
            
            while (currentPos <= ScanEnd) {
                // 快速检查首字节
                if (*currentPos != targetByte) {
                    currentPos++;
                    continue;
                }
                
                // 第二层 + 第一层：完整匹配（预编译 + 快速失败）
                if (MmpMatchPatternOptimized(currentPos, Signature)) {
                    // 找到匹配
                    ScanResult->MatchAddress = (PVOID)currentPos;
                    ScanResult->MatchOffset = (ULONG)(currentPos - ScanStart);
                    ScanResult->Found = TRUE;

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[WkDefender] Pattern matched at offset 0x%X (address: 0x%p)\n",
                        ScanResult->MatchOffset, ScanResult->MatchAddress);

                    return STATUS_SUCCESS;
                }

                currentPos++;
            }
        } else {
            // 没有首字节信息，使用两层优化（预编译 + 快速失败）
            while (currentPos <= ScanEnd) {
                if (MmpMatchPatternOptimized(currentPos, Signature)) {
                    ScanResult->MatchAddress = (PVOID)currentPos;
                    ScanResult->MatchOffset = (ULONG)(currentPos - ScanStart);
                    ScanResult->Found = TRUE;

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[WkDefender] Pattern matched at offset 0x%X (address: 0x%p)\n",
                        ScanResult->MatchOffset, ScanResult->MatchAddress);

                    return STATUS_SUCCESS;
                }
                currentPos++;
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] No match found in scan range (0x%p - 0x%p)\n",
            ScanStart, ScanEnd);
        
        return STATUS_NOT_FOUND;
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception during memory scanning: 0x%08X\n",
            GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }*/
}

//
// 在指定节区内进行特征码扫描
// 逐字节滑动窗口匹配特征码
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmScanSection(
    _In_ PVOID ImageBase,
    _In_ PCHAR SectionName,
    _In_ PWKD_MEMORY_SIGNATURE Signature,
    _Out_ PWKD_SCAN_RESULT ScanResult
    )
{
    WKD_SECTION_INFO sectionInfo;
    NTSTATUS status;
    PUCHAR scanStart;
    PUCHAR scanEnd;
    PUCHAR currentPos;

    // 参数验证
    if (!ImageBase || !SectionName || !Signature || !ScanResult) {
        return STATUS_INVALID_PARAMETER;
    }

    // 初始化扫描结果
    RtlZeroMemory(ScanResult, sizeof(WKD_SCAN_RESULT));

    // 验证特征码参数
    if (Signature->Length == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Invalid signature pattern length\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 解析PE节区
    status = MmParsePeSection(ImageBase, SectionName, &sectionInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to parse section %.8s: 0x%08X\n",
            SectionName, status);
        return status;
    }

    // 计算扫描范围
    scanStart = (PUCHAR)sectionInfo.BaseAddress;
    scanEnd = scanStart + sectionInfo.Size - Signature->Length;

    // 边界检查
    if (scanStart >= scanEnd) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Section too small for pattern matching\n");
        return STATUS_BUFFER_TOO_SMALL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Scanning section %.8s from 0x%p to 0x%p (size: 0x%X)\n",
        SectionName, scanStart, scanEnd, (ULONG)(scanEnd - scanStart));

    // 调用统一的扫描辅助函数（三层优化：首字节过滤 + 快速失败 + 预编译）
    return MmpScanMemoryRangeInternal(scanStart, scanEnd, Signature, ScanResult);
}

//
// 在指定地址范围内进行特征码扫描（细粒度）
// 适用于已知函数地址或特定内存区域的扫描
// 默认扫描范围为 PAGE_SIZE（4096字节）地址对齐
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmScanMemoryRange(
    _In_ PVOID StartAddress,            // 扫描起始地址
    _In_opt_ SIZE_T RangeSize,          // 扫描范围大小
    _In_ PWKD_MEMORY_SIGNATURE Signature,
    _Out_ PWKD_SCAN_RESULT ScanResult
    )
{
    PUCHAR scanStart;
    PUCHAR scanEnd;
    PUCHAR currentPos;
    SIZE_T actualRangeSize;

    // 参数验证
    if (!StartAddress || !Signature || !ScanResult) {
        return STATUS_INVALID_PARAMETER;
    }

    // 验证特征码参数
    if (Signature->Length == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Invalid signature pattern length\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 如果未指定范围或范围为0，使用默认的PAGE_SIZE
    actualRangeSize = (RangeSize > 0) ? RangeSize : PAGE_SIZE;

    // 验证扫描范围合理性
    if (actualRangeSize < Signature->Length) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Range size (0x%X) smaller than pattern length (0x%X)\n",
            (ULONG)actualRangeSize, Signature->Length);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 限制最大扫描范围（防止意外的大范围扫描）
    if (actualRangeSize > 1024 * 1024) {  // 最大1MB
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Range size too large, limited to 1MB\n");
        actualRangeSize = 1024 * 1024;
    }

    // 初始化扫描结果
    RtlZeroMemory(ScanResult, sizeof(WKD_SCAN_RESULT));

    // 计算扫描范围
    scanStart = (PUCHAR)StartAddress;
    scanEnd = scanStart + actualRangeSize - Signature->Length;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Scanning memory range from 0x%p to 0x%p (size: 0x%X)\n",
        scanStart, scanEnd, (ULONG)actualRangeSize);

    // 调用统一的扫描辅助函数（三层优化：首字节过滤 + 快速失败 + 预编译）
    return MmpScanMemoryRangeInternal(scanStart, scanEnd, Signature, ScanResult);
}

