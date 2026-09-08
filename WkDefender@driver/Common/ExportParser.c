/*++
    Common/ExportParser.c - 未文档化导出函数解析子引擎实现

    以统一解析条目（WKD_EXPORT_ENTRY）驱动解析：一个条目同时表达
    "按名解析"（导出函数，MmGetSystemRoutineAddress）与"特征码定位"
    （未导出函数，在宿主导出函数体内按特征码匹配并从 call rel32 反推地址）。
    解析结果回填条目槽位（*Slot）。

    设计要点：
      - 无共享可变注册表、无锁。条目始终由调用方持有；引擎只按条目执行
        单条解析原语 CoExportFunctionAddress。初始化阶段由 CoInitialize
        的 for 循环对静态 g_ExportTable 逐条解析；外部动态解析请求同样走
        同一单条原语（调用方自带条目与槽位），线程间天然无竞态。
      - 特征码定位所需的宿主导出函数（如 FsRtlUninitializeBaseMcb）仅作为
        条目 HostName 属性，一次性随条目使用，不作为独立解析项、不写槽位。
      - 全局函数指针（pfnXxx）由静态 g_ExportTable 持有槽位，初始化后常驻。

    生命周期:
        CoInitializeExportParser（逐条解析）-> ...（只读使用）...
        -> ExportParserTeardown（复位）
    状态机用 Interlocked 防重复初始化/释放（无需 EX_RUNDOWN_REF，见 .h）。

    Copyright (c) WkDefender Team
--*/

#include "ExportParser.h"
#include "Utils.h"

/* ============================================================================
 * 内部前向声明
 * ============================================================================ */

static
NTSTATUS
CopExportByName(
    _Inout_ PWKD_EXPORT_ENTRY Entry
    );

_Must_inspect_result_
static
NTSTATUS
CopExportBySignature(
    _Inout_ PWKD_EXPORT_ENTRY Entry
    );

static
BOOLEAN
CopMatchSignatureAt(
    _In_ const PUCHAR Data,
    _In_ SIZE_T DataSize,
    _In_ const UCHAR* Pattern,
    _In_ const UCHAR* Mask,
    _In_ SIZE_T Length,
    _In_ ULONG Instance,
    _Out_ PVOID* Address
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CoInitializeExportParser)
#pragma alloc_text(PAGE, CopExportByName)
#pragma alloc_text(PAGE, CopExportBySignature)
#pragma alloc_text(PAGE, CopMatchSignatureAt)
#pragma alloc_text(PAGE, CoExportFunctionAddress)
#pragma alloc_text(PAGE, ExportParserResolveExports)
//#pragma alloc_text(PAGE, SpRegisterSelfProtectionCallback)
//#pragma alloc_text(PAGE, SppStartSelfProtectionEngine)
//#pragma alloc_text(PAGE, SpShutdownSelfProtectionEngine)
#endif

/* ============================================================================
 * 内部常量 / 状态
 * ============================================================================ */

#define EXPORT_PARSER_STATE_UNINITIALIZED   0
#define EXPORT_PARSER_STATE_RESOLVED        1
#define EXPORT_PARSER_STATE_TORNDOWN        2

#define COP_SIG_LOCATE_SCAN_RANGE       512 // 宿主函数体附近扫描范围

//
// 特征码: 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ??
//         (lea rcx,[rip+X]) (call rel32) (jmp short)
// 用于 FsRtlUninitializeBaseMcb 内两个 ExFreeTo* 调用点（Paged 在前，NonPaged 在后）。
//
#define COP_SIG_FREETO_LENGTH   14
static const UCHAR CopSigExFreeTo[COP_SIG_FREETO_LENGTH] = {
    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0xEB, 0x00
};
static const UCHAR CopSigExFreeToMask[COP_SIG_FREETO_LENGTH] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x00
};

//
// 特征码: 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??
//         (lea rcx,[rip+X]) (call rel32)
// 用于 FsRtlInitializeBaseMcbEx 内对 ExAllocateFromNPagedLookasideList 的调用点。
// 注意：Win10 中 Paged/NonPaged 分支均 call 同一 ExAllocateFromNPagedLookasideList，
//       仅 lea 目标（Lookaside 指针）不同；故只需取第一次命中。
//
#define COP_SIG_ALLOCATE_LENGTH  12
static const UCHAR CopSigExAllocate[COP_SIG_ALLOCATE_LENGTH] = {
    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x00
};
static const UCHAR CopSigExAllocateMask[COP_SIG_ALLOCATE_LENGTH] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0x00
};

/* ============================================================================
 * 类型化全局函数指针（唯一定义；.h 提供 extern 声明）
 * ============================================================================ */

PFN_ZwQueryInformationProcess                pfnZwQueryInformationProcess = NULL;
PFN_ZwQuerySystemInformation                 pfnZwQuerySystemInformation = NULL;
PFN_ZwOpenThread                             pfnZwOpenThread = NULL;
PFN_ZwQueryInformationThread                 pfnZwQueryInformationThread = NULL;
PFN_PsGetProcessSessionId                    pfnPsGetProcessSessionId = NULL;
PFN_PsGetProcessInheritedFromUniqueProcessId pfnPsGetProcessInheritedFromUniqueProcessId = NULL;
PFN_PsGetProcessProtection                   pfnPsGetProcessProtection = NULL;
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
PFN_PsGetProcessSignatureLevel               pfnPsGetProcessSignatureLevel = NULL;
#endif
PFN_SeGetCachedSigningLevel                  pfnSeGetCachedSigningLevel = NULL;

//
// ExLookaside* 未导出系列（特征码定位所得，见 g_ExportTable 特征码项 / CopExportBySignature）
//
PFN_ExAllocateFromNPagedLookasideList         pfnExAllocateFromNPagedLookasideList = NULL;
PFN_ExFreeToPagedLookasideList                pfnExFreeToPagedLookasideList = NULL;
PFN_ExFreeToNPagedLookasideList               pfnExFreeToNPagedLookasideList = NULL;

/* ============================================================================
 * 统一函数映射表（静态，驱动生命周期内不变）
 * 按名项：Method=ByName，Name 为目标导出函数名。
 * 特征码项：Method=BySignature，HostName 为宿主导出函数（辅助定位），
 *           Pattern/Mask/CallOffset/Instance 描述调用点。
 * ============================================================================ */

static WKD_EXPORT_ENTRY g_ExportTable[] = {
    /* ---- 按名项 ---- */
    { .Method = WkdResolveByName,
      .Name = L"ZwQueryInformationProcess",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnZwQueryInformationProcess,
      .Mandatory = FALSE },
    { .Method = WkdResolveByName,
      .Name = L"ZwQuerySystemInformation",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnZwQuerySystemInformation,
      .Mandatory = FALSE },
    { .Method = WkdResolveByName,
      .Name = L"ZwOpenThread",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnZwOpenThread,
      .Mandatory = FALSE },
    { .Method = WkdResolveByName,
      .Name = L"ZwQueryInformationThread",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnZwQueryInformationThread,
      .Mandatory = FALSE },
    { .Method = WkdResolveByName,
      .Name = L"PsGetProcessSessionId",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnPsGetProcessSessionId,
      .Mandatory = FALSE },
    { .Method = WkdResolveByName,
      .Name = L"PsGetProcessInheritedFromUniqueProcessId",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnPsGetProcessInheritedFromUniqueProcessId,
      .Mandatory = FALSE },
    { .Method = WkdResolveByName,
      .Name = L"PsGetProcessProtection",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnPsGetProcessProtection,
      .Mandatory = FALSE },
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
    { .Method = WkdResolveByName,
      .Name = L"PsGetProcessSignatureLevel",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnPsGetProcessSignatureLevel,
      .Mandatory = FALSE },
#endif
    { .Method = WkdResolveByName,
      .Name = L"SeGetCachedSigningLevel",
      .HostName = NULL, .Pattern = NULL, .Mask = NULL,
      .PatternLength = 0, .CallOffset = 0, .Instance = 0,
      .Address = (PVOID*)&pfnSeGetCachedSigningLevel,
      .Mandatory = FALSE },

    /* ---- 特征码项 ---- */
    /* ExAllocateFromNPagedLookasideList：宿主 FsRtlInitializeBaseMcbEx，第一次命中，E8 偏移 7 */
    { .Method = WkdResolveBySignature,
      .Name = L"ExAllocateFromNPagedLookasideList", .HostName = L"FsRtlInitializeBaseMcbEx",
      .Pattern = CopSigExAllocate, .Mask = CopSigExAllocateMask,
      .PatternLength = COP_SIG_ALLOCATE_LENGTH, .CallOffset = 8, .Instance = 0,
      .Address = (PVOID*)&pfnExAllocateFromNPagedLookasideList,
      .Mandatory = FALSE },
    /* ExFreeToPagedLookasideList：宿主 FsRtlUninitializeBaseMcb，第一次命中（Paged 在前），E8 偏移 7 */
    { .Method = WkdResolveBySignature,
      .Name = L"ExFreeToPagedLookasideList", .HostName = L"FsRtlUninitializeBaseMcb",
      .Pattern = CopSigExFreeTo, .Mask = CopSigExFreeToMask,
      .PatternLength = COP_SIG_FREETO_LENGTH, .CallOffset = 8, .Instance = 0,
      .Address = (PVOID*)&pfnExFreeToPagedLookasideList,
      .Mandatory = FALSE },
    /* ExFreeToNPagedLookasideList：宿主 FsRtlUninitializeBaseMcb，第二次命中（NonPaged 在后），E8 偏移 7 */
    { .Method = WkdResolveBySignature,
      .Name = L"", .HostName = L"FsRtlUninitializeBaseMcb",
      .Pattern = CopSigExFreeTo, .Mask = CopSigExFreeToMask,
      .PatternLength = COP_SIG_FREETO_LENGTH, .CallOffset = 8, .Instance = 1,
      .Address = (PVOID*)&pfnExFreeToNPagedLookasideList,
      .Mandatory = FALSE },
};

// 全局子引擎对象描述（状态机 + 统计 + 映射表视图）
WKD_EXPORT_PARSER g_ExportParser = { 0 };

/* ============================================================================
 * 内部解析子过程
 * ============================================================================ */

_Use_decl_annotations_
static
NTSTATUS
CopExportByName(
    _Inout_ PWKD_EXPORT_ENTRY Entry
    )
{
    UNICODE_STRING string;

    PAGED_CODE();
    
    if (!Entry || !Entry->Address || !CoCheckStringValidity(Entry->Name)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&string, Entry->Name);
    *(Entry->Address) = MmGetSystemRoutineAddress(&string);
    if (*(Entry->Address)) return STATUS_SUCCESS;
    else return STATUS_NOT_FOUND;
}

/*++
    CopExportBySignature - 特征码定位解析单个条目

    定位宿主导出函数（Entry->HostName，按名字面量），在函数体内做滑动窗口
    扫描，命中第 Instance 次匹配，从 call rel32 指令解析目标地址回填空位。
        call rel32 目标：target = callAddr + 5 + *(INT32*)(callAddr + 1)

    返回: STATUS_SUCCESS 解析成功；STATUS_NOT_FOUND 宿主缺失/特征码未命中。

    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
static
NTSTATUS
CopExportBySignature(
    _Inout_ PWKD_EXPORT_ENTRY Entry
    )
{
    PVOID pfnHost;
    PVOID matchedStart;
    UNICODE_STRING usHost;

    PAGED_CODE();

    if (!Entry || !Entry->Address ||
        !CoCheckStringValidity(Entry->HostName) ||
        !Entry->Pattern || !Entry->Mask ||
        Entry->PatternLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *(Entry->Address) = NULL;

    RtlInitUnicodeString(&usHost, Entry->HostName);
    pfnHost = MmGetSystemRoutineAddress(&usHost);
    if (!pfnHost) return STATUS_NOT_FOUND;

    // 单次调用：匹配器内部用 memchr 锚点扫描整个扫描区，
    // 直接返回第 Instance 个完整匹配的起始地址（无需外层 for 逐字节滑动）。
    if (!CopMatchSignatureAt((PUCHAR)pfnHost, COP_SIG_LOCATE_SCAN_RANGE,
                             Entry->Pattern, Entry->Mask, Entry->PatternLength,
                             Entry->Instance, &matchedStart)) {
        return STATUS_NOT_FOUND;
    }

    // 从命中起点按 CallOffset 定位 call rel32，解析目标地址
    {
        PUCHAR callAddr = (PUCHAR)matchedStart + Entry->CallOffset;
        PVOID target = (PVOID)(callAddr + 4 + *(PINT32)callAddr);

        *(Entry->Address) = target;
        return STATUS_SUCCESS;
    }
}

_Use_decl_annotations_
static
BOOLEAN
CopMatchSignatureAt(
    _In_ const PUCHAR Data,
    _In_ SIZE_T DataSize,
    _In_ const UCHAR* Pattern,
    _In_ const UCHAR* Mask,
    _In_ SIZE_T Length,
    _In_ ULONG Instance,
    _Out_ PVOID* Address
    )
{
    SIZE_T anchorIndex = 0;     // 锚索引（第一个非通配符字节）
    UCHAR anchorByte;
    PUCHAR cursor, scanEnd;
    UCHAR hitCount = 0;

    PAGED_CODE();

    if (!Data || DataSize == 0 || !Pattern || !Mask ||
        Length == 0 || Length > DataSize || !Address) {
        return FALSE;
    }
    *Address = NULL;

    // 查找第一个非通配符字节的位置作为锚点
    while (anchorIndex < Length && Mask[anchorIndex] == 0x00) anchorIndex++;

    // 特殊情况：特征码全部为通配符（仅返回首个）
    if (anchorIndex == Length) {
        *Address = (PVOID)Data;
        return (Instance == 0);
    }

    anchorByte = Pattern[anchorIndex];
    scanEnd = Data + DataSize - Length + 1;
    cursor = Data;

    // 使用 memchr 快速定位锚点字节；命中后按 Instance 计数，返回第 Instance 个匹配
    while (cursor < scanEnd) {
        PUCHAR found = memchr(cursor, anchorByte, scanEnd - cursor);
        if (!found) break; // 未找到更多锚点字节，搜索结束

        // 计算候选起始地址（锚点字节在特征码中的位置是 anchorIndex）
        PUCHAR candidate = found - anchorIndex;
        if (candidate < Data) {
            cursor = found + 1;   // 锚点太靠前导致候选越界，跳过
            continue;
        }
        if (candidate >= scanEnd) break; // 候选超出有效起始范围

        // 验证完整特征码（按连续非通配符块做 memcmp）
        BOOLEAN matched = TRUE;
        SIZE_T i = 0;
        while (i < Length && matched) {
            // 跳过通配符
            while (i < Length && Mask[i] == 0x00) i++;
            if (i >= Length) break;

            // 连续非通配符块
            SIZE_T blockStart = i;
            while (i < Length && Mask[i] != 0x00) i++;
            SIZE_T blockLen = i - blockStart;

            if (memcmp(candidate + blockStart, Pattern + blockStart, blockLen) != 0) {
                matched = FALSE;
                break;
            }
        }

        if (matched) {
            // 命中一次完整匹配，判断是否为目标 Instance
            if (hitCount == Instance) {
                *Address = (PVOID)candidate;
                return TRUE;
            }
            hitCount++;
        }

        cursor = found + 1;
    }

    return FALSE;
}

/* ============================================================================
 * 单条解析原语
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
CoExportFunctionAddress(
    _Inout_ PWKD_EXPORT_ENTRY Entry
    )
{
    PAGED_CODE();

    if (!Entry)                 return STATUS_INVALID_PARAMETER;
    switch (Entry->Method) {
    case WkdResolveByName:      return CopExportByName(Entry);
    case WkdResolveBySignature: return CopExportBySignature(Entry);
    default:                    return STATUS_NOT_SUPPORTED;
    }
}

/* ============================================================================
 * 生命周期 API 实现
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
CoInitializeExportParser(
    VOID
    )
{
    NTSTATUS status;
    ULONG resolved = 0;
    ULONG failed = 0;

    PAGED_CODE();

    // 防重复初始化
    if (InterlockedCompareExchange(
            &g_ExportParser.State,
            EXPORT_PARSER_STATE_RESOLVED,
            EXPORT_PARSER_STATE_UNINITIALIZED) !=
        EXPORT_PARSER_STATE_UNINITIALIZED) {
        return STATUS_SUCCESS;   // 已初始化
    }

    //
    // 统一 for 循环：逐条解析静态映射表（按名 + 特征码）。
    // 辅助定位函数（宿主）仅为特征码条目属性，无独立导出指针，随条目标记。
    //
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_ExportTable); i++) {
        status = CoExportFunctionAddress(&g_ExportTable[i]);
        if (NT_SUCCESS(status)) resolved++;
        else failed++;
    }

    g_ExportParser.State = EXPORT_PARSER_STATE_RESOLVED;
    g_ExportParser.Table = g_ExportTable;
    g_ExportParser.TableSize = RTL_NUMBER_OF(g_ExportTable);
    g_ExportParser.ResolvedCount = resolved;
    g_ExportParser.FailedCount = failed;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ExportParserTeardown(
    VOID
    )
{
    ULONG i;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_ExportParser.State,
                                   EXPORT_PARSER_STATE_TORNDOWN,
                                   EXPORT_PARSER_STATE_RESOLVED) !=
        EXPORT_PARSER_STATE_RESOLVED) {
        return;   // 未初始化或已拆除
    }

    // 复位所有槽位，避免悬挂引用
    for (i = 0; i < g_ExportParser.TableSize; i++) {
        PWKD_EXPORT_ENTRY entry = &g_ExportParser.Table[i];
        if (entry != NULL && entry->Address != NULL) {
            *entry->Address = NULL;
        }
    }

    g_ExportParser.Table = NULL;
    g_ExportParser.TableSize = 0;
    g_ExportParser.ResolvedCount = 0;
    g_ExportParser.FailedCount = 0;

    // 复位状态，允许再次 Initialize（如驱动重载）
    InterlockedExchange(&g_ExportParser.State, EXPORT_PARSER_STATE_UNINITIALIZED);
}

_Use_decl_annotations_
BOOLEAN
ExportParserIsResolved(
    _In_ PCWSTR Name
    )
{
    ULONG i;
    UNICODE_STRING usQuery;
    UNICODE_STRING usEntry;

    if (g_ExportParser.State != EXPORT_PARSER_STATE_RESOLVED) {
        return FALSE;
    }

    RtlInitUnicodeString(&usQuery, Name);

    for (i = 0; i < g_ExportParser.TableSize; i++) {
        PWKD_EXPORT_ENTRY entry = &g_ExportParser.Table[i];
        if (entry == NULL || entry->Address == NULL || *entry->Address == NULL) {
            continue;
        }
        // 仅按名项有意义；特征码项无名可查（Name 为空）。
        if (entry->Method != WkdResolveByName || entry->Name == NULL) {
            continue;
        }
        RtlInitUnicodeString(&usEntry, entry->Name);
        if (RtlEqualUnicodeString(&usQuery, &usEntry, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

/*++
    ExportParserResolveExports - 对外统一解析一组按名导出项

    供"自带类型体系、指针归模块私有"的子引擎（如 ALPC）复用本引擎的
    统一按名解析：把本模块的 {名称, 槽位, 必需} 数组交给本函数集中解析，
    从而消除各子引擎各自手写 RtlInitUnicodeString + MmGetSystemRoutineAddress
    的重样板。类型与指针槽仍由调用方私有持有，不进入 ExportParser 的
    Common 层，避免 Common 反向依赖子模块实现类型（无循环依赖）。

    Entry:
        Entries - 调用方持有的导出项数组。
        Count   - 数组项数。
        Resolved - [out, opt] 成功解析数。
        Failed  - [out, opt] 失败解析数。
    返回: STATUS_SUCCESS；若存在必需项缺失返回 STATUS_NOT_FOUND。

    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
NTSTATUS
ExportParserResolveExports(
    _In_reads_(Count) PWKD_EXPORT_ENTRY2 Entries,
    _In_ ULONG Count,
    _Out_opt_ PULONG Resolved,
    _Out_opt_ PULONG Failed
    )
{
    ULONG i;
    ULONG resolvedCount = 0;
    ULONG failedCount = 0;
    NTSTATUS overallStatus = STATUS_SUCCESS;

    PAGED_CODE();

    if (Entries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < Count; i++) {
        PWKD_EXPORT_ENTRY2 entry = &Entries[i];
        UNICODE_STRING string;

        if (entry == NULL || entry->Name == NULL || entry->Address == NULL) {
            failedCount++;
            continue;
        }

        RtlInitUnicodeString(&string, entry->Name);
        *entry->Address = MmGetSystemRoutineAddress(&string);

        if (*entry->Address != NULL) {
            resolvedCount++;
        } else {
            failedCount++;
            if (entry->Mandatory && NT_SUCCESS(overallStatus)) {
                overallStatus = STATUS_NOT_FOUND;
            }
        }
    }

    if (Resolved != NULL) {
        *Resolved = resolvedCount;
    }
    if (Failed != NULL) {
        *Failed = failedCount;
    }

    return overallStatus;
}
