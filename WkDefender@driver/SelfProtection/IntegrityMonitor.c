/*++
    SelfProtection/IntegrityMonitor.c - 驱动自我完整性监控（IntegrityMonitor, IM）子组件实现

    Baseline-and-verify：启动阶段为驱动自身内存映像（代码节/只读数据节/PE 头）
    建立 SHA-256 基线，周期任务重新哈希比对，发现偏离即判定为篡改并上报。

    架构对齐（自防护引擎铁律）:
        - 不持有 rundown / 生命周期标志，生命周期由引擎编排。
        - PE 解析复用 Common/PeParser.h 公共模板 CoParsePe（不重写解析器），
          经 OnSection 回调采集逐节信息，一次性构建基线。
        - 周期校验用 Common/PeriodicTimer.h Thread 模式（PASSIVE_LEVEL 回调）。
        - SHA-256 / 安全读取 / 上报复用 SelfProtectionCompat：
            CoComputeSha256 / CoReadKernelRegionSafe / WkdReportSelfProtectionEvent
        - 事件内部节点挂 EventList（EX_PUSH_LOCK 保护），对外返回值类型快照。

    基线与校验语义（对齐 SS IntegrityMonitor）:
        - 基线基于【内存映像】（WkdDriverObject->DriverStart/ImageSize），
          非磁盘文件。
        - 跳过可写节与 DISCARDABLE（INIT）节——OS 在 DriverEntry 返回后
          释放 INIT 节物理页（MmFreeDriverInitialization），哈希已释放内存
          会造成蓝屏或持续误报。
        - 篡改类型依节特征与导入/导出目录区间细分（IAT/导出钩子/代码补丁/
          数据损坏/头篡改）。

    Copyright (c) WkDefender Team
--*/

#include "IntegrityMonitor.h"
#include "SelfProtectionCompat.h"
#include "../Common/PeParser.h"
#include "../Common/Utils.h"   /* CoReadKernelRegionSafe */
#include "../Common/PeriodicTimer.h"
#include <ntstrsafe.h>

// Utils.c 定义、UtSetDriverObject 赋值；用于取驱动自身内存映像基址/大小。
extern PDRIVER_OBJECT WkdDriverObject;


#ifdef ALLOC_PRAGMA
#pragma alloc_text(SpInitializeIntegrityProtection)
#pragma alloc_text(PAGE, SpStartPeriodicIntegrityProtection)
#endif


/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================ */

#define IM_MAX_SECTION_SIZE     (64 * 1024 * 1024)  /* 单节校验上限（64MB，对齐 SS） */

/* 节特征（复用 PeParser 依赖的 ntimage.h 常量） */
#ifndef IMAGE_SCN_MEM_DISCARDABLE
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#endif

/* ============================================================================
 * INTERNAL TYPES
 * ============================================================================ */

//
// 节基线（启动阶段由 CoParsePe OnSection 采集 + SHA-256 建立）
//
typedef struct _IM_SECTION_BASELINE {
    CHAR        Name[8];            /* 节名（8 字节 ASCII） */
    ULONG       VirtualAddress;     /* RVA */
    SIZE_T      VirtualSize;        /* 内存大小 */
    ULONG       Characteristics;    /* 原始特征 */
    BOOLEAN     IsExecutable;       /* EXECUTE || CNT_CODE */
    BOOLEAN     IsWritable;         /* MEM_WRITE —— 不参与基线比对 */
    BOOLEAN     IsDiscardable;      /* MEM_DISCARDABLE（INIT）—— 不参与比对 */
    UCHAR       BaselineHash[BCRYPT_SHA256_SIZE];   /* 基线哈希 */
    BOOLEAN     Monitored;          /* 是否纳入周期比对（非可写/非可丢弃/非零长） */
} IM_SECTION_BASELINE, *PIM_SECTION_BASELINE;

//
// 内部事件节点——挂在 EventList 上，对外返回值类型快照
//
typedef struct _IM_EVENT {
    LIST_ENTRY      ListEntry;
    IM_MODIFICATION Modification;
    ULONG           SectionIndex;
    CHAR            SectionName[8];
    CHAR            Details[IM_MAX_DETAIL_LENGTH];
    LARGE_INTEGER   Timestamp;
} IM_EVENT, *PIM_EVENT;

//
// 保护器上下文（不透明句柄定义，tag 与 IntegrityMonitor.h 前向声明一致）
//
typedef struct _WKD_INTEGRITY_PROTECTION {
    //
    // 周期校验（Thread 模式，PASSIVE_LEVEL 回调）
    //
    WKD_PERIODIC_TIMER      CheckTimer;

    //
    // 驱动自身内存映像
    //
    PVOID                   ImageBase;
    SIZE_T                  ImageSize;

    //
    // 节基线（固定数组，上限 IM_MAX_SECTIONS，实际数量 SectionCount）
    //
    IM_SECTION_BASELINE     Sections[IM_MAX_SECTIONS];
    ULONG                   SectionCount;
    ULONG                   MonitoredCodeSections;
    ULONG                   MonitoredDataSections;

    //
    // PE 头基线
    //
    SIZE_T                  HeaderSize;
    UCHAR                   HeaderBaselineHash[BCRYPT_SHA256_SIZE];
    BOOLEAN                 HeaderMonitored;

    //
    // 导入/导出目录区间（用于代码节篡改类型细分）
    //
    ULONG                   ImportDirRva;
    ULONG                   ImportDirSize;
    ULONG                   ExportDirRva;
    ULONG                   ExportDirSize;

    //
    // 事件链表（EventLock 保护）
    //
    LIST_ENTRY              EventList;
    EX_PUSH_LOCK            EventLock;
    volatile LONG           EventCount;

    //
    // 生命周期辅助（防重复 Start/Shutdown）
    //
    volatile LONG           Started;

    //
    // 统计
    //
    IM_STATISTICS           Stats;
} WKD_INTEGRITY_PROTECTION, *PWKD_INTEGRITY_PROTECTION;

/* ============================================================================
 * FORWARD DECLARATIONS
 * ============================================================================ */

static NTSTATUS
SppSectionParserCallback(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ const PIMAGE_SECTION_HEADER Section,
    _In_ ULONG Index,
    _Inout_opt_ PVOID UserContext
    );

static VOID SppPeriodicIntegrityCheck(_Inout_opt_ PVOID Context);

static NTSTATUS SppComputeIntegrityBaselines(
    _Inout_ PWKD_INTEGRITY_PROTECTION Protection
    );

static NTSTATUS SppHashKernelRegion(
    _In_ const PWKD_INTEGRITY_PROTECTION Protection,
    _In_ const PVOID Address,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(BCRYPT_SHA256_SIZE) PUCHAR Hash
    );

static NTSTATUS SppVerifySectionIntegrity(
    _In_ const PWKD_INTEGRITY_PROTECTION Protection,
    _In_ ULONG SectionIndex,
    _Out_ PBOOLEAN IsIntact,
    _Out_ PIM_MODIFICATION ModificationType
    );

static BOOLEAN SppVerifyHeaderIntegrity(
    _In_ const PWKD_INTEGRITY_PROTECTION Protection
    );

static VOID ImpRecordEvent(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ IM_MODIFICATION Modification,
    _In_ ULONG SectionIndex,
    _In_opt_ PCCH Details
    );

static VOID ImpReport(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ ULONG SubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    );

static VOID ImpSnapshotEvent(
    _In_ PIM_EVENT Source,
    _Out_ PIM_EVENT_INFO Dest
    );

static VOID ImpFreeEventList(_Inout_ PLIST_ENTRY ListHead);

static VOID ImpEvictOldestEventsLocked(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ LONG TargetCount,
    _Inout_ PLIST_ENTRY FreeList
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SpInitializeIntegrityProtection)
#pragma alloc_text(PAGE, SppComputeIntegrityBaselines)
#endif


/* ============================================================================
 * SpInitializeIntegrityProtection
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
SpInitializeIntegrityProtection(
    _Out_ PWKD_INTEGRITY_PROTECTION* Protection
    )
{
    NTSTATUS status;
    PWKD_INTEGRITY_PROTECTION protection = NULL;
    WKD_PE_PARSE_CONTEXT parseCtx = { 0 };

    PAGED_CODE();

    if (!Protection) return STATUS_INVALID_PARAMETER;
    *Protection = NULL;

    /* 取驱动自身内存映像（DriverEntry 早期 UtSetDriverObject 已赋值） */
    if (!WkdDriverObject ||
        !WkdDriverObject->DriverStart ||
        WkdDriverObject->DriverSize == 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    protection = (PWKD_INTEGRITY_PROTECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_INTEGRITY_PROTECTION),
        IM_POOL_TAG_CTX
        );
    if (!protection) return STATUS_NO_MEMORY;

    ExInitializePushLock(&protection->EventLock);
    InitializeListHead(&protection->EventList);
    protection->ImageBase = WkdDriverObject->DriverStart;
    protection->ImageSize = (SIZE_T)WkdDriverObject->DriverSize;

    /* 复用公共 PE 解析模板，经 OnSection 回调采集逐节信息 */
    parseCtx.Data = protection->ImageBase;
    parseCtx.DataSize = protection->ImageSize;
    parseCtx.Mode = WkdPeMode_Image;
    parseCtx.Callbacks.OnSection = SppSectionParserCallback;
    parseCtx.CallbackContext = protection;

    status = CoParsePe(&parseCtx);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* PE 头大小（SizeOfHeaders），供头基线哈希使用 */
    if (parseCtx.NtHeaders) {
        protection->HeaderSize = WKD_PE_OPT_OFFSET(&parseCtx, SizeOfHeaders);
    }

    /* 取导入/导出目录区间（供代码节篡改类型细分），需目录项足够 */
    if (parseCtx.DirectoryEntries > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        IMAGE_DATA_DIRECTORY import = WKD_PE_OPT_DIR(&parseCtx, IMAGE_DIRECTORY_ENTRY_IMPORT);
        protection->ImportDirRva = import.VirtualAddress;
        protection->ImportDirSize = import.Size;
    }
    if (parseCtx.DirectoryEntries > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        IMAGE_DATA_DIRECTORY export = WKD_PE_OPT_DIR(&parseCtx, IMAGE_DIRECTORY_ENTRY_EXPORT);
        protection->ExportDirRva = export.VirtualAddress;
        protection->ExportDirSize = export.Size;
    }

    /* 建代码节/数据节/PE 头基线 */
    status = SppComputeIntegrityBaselines(protection);
    if (!NT_SUCCESS(status)) goto Cleanup;

    KeQuerySystemTimePrecise(&protection->Stats.StartTime);
    protection->Stats.CodeSectionCount = protection->MonitoredCodeSections;
    protection->Stats.DataSectionCount = protection->MonitoredDataSections;
  
    *Protection = protection;
    return STATUS_SUCCESS;

Cleanup:
    if (protection) ExFreePoolWithTag(protection, IM_POOL_TAG_CTX);
    return status;
}

/* ============================================================================
 * SpStartPeriodicIntegrityProtection
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
SpStartPeriodicIntegrityProtection(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ const PEX_RUNDOWN_REF RundownRef,
    _In_ ULONG IntervalMs
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!Protection || !RundownRef ||
        IntervalMs < WKD_TIMER_MIN_INTERVAL_MS || IntervalMs > WKD_TIMER_MAX_INTERVAL_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedExchange(&Protection->Started, 1) != 0) {
        /* 已启动 */
        return STATUS_SUCCESS;
    }

    status = CoCreatePeriodicTimer(
        &Protection->CheckTimer,
        IM_CHECK_INTERVAL_MS,
        SppPeriodicIntegrityCheck,
        Protection,
        TRUE,                                     /* Thread 模式，回调运行于 PASSIVE_LEVEL */
        RundownRef
        );
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&Protection->Started, 0);
        return status;
    }

    CoStartPeriodicTimer(&Protection->CheckTimer);
    return STATUS_SUCCESS;
}

/* ============================================================================
 * ImShutdown
 * ============================================================================ */

_Use_decl_annotations_
VOID
ImShutdown(
    PWKD_INTEGRITY_PROTECTION Protection
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;
    LIST_ENTRY freeList;

    PAGED_CODE();

    if (protection == NULL) {
        return;
    }

    if (InterlockedExchange(&protection->Started, 0) != 0) {
        /* 停止并销毁周期定时器（等待当前回调排空） */
        WkdTimerDestroy(&protection->CheckTimer);
    }

    /* 摘离并释放全部事件节点 */
    InitializeListHead(&freeList);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&protection->EventLock);
    {
        PLIST_ENTRY entry = protection->EventList.Flink;
        while (entry != &protection->EventList) {
            PLIST_ENTRY next = entry->Flink;
            PIM_EVENT evt = CONTAINING_RECORD(entry, IM_EVENT, ListEntry);
            InsertTailList(&freeList, &evt->ListEntry);
            entry = next;
        }
        InitializeListHead(&protection->EventList);
        protection->EventCount = 0;
    }
    ExReleasePushLockExclusive(&protection->EventLock);
    KeLeaveCriticalRegion();

    ImpFreeEventList(&freeList);

    /* 安全清基线段落与头哈希后释放上下文 */
    RtlSecureZeroMemory(protection->Sections, sizeof(protection->Sections));
    RtlSecureZeroMemory(protection->HeaderBaselineHash, sizeof(protection->HeaderBaselineHash));

    ExFreePoolWithTag(protection, IM_POOL_TAG_CTX);
}

/* ============================================================================
 * 周期校验回调（Thread 模式，PASSIVE_LEVEL）
 * ============================================================================ */

static VOID
SppPeriodicIntegrityCheck(
    _Inout_opt_ PVOID Context
    )
{
    PWKD_INTEGRITY_PROTECTION protection = (PWKD_INTEGRITY_PROTECTION)Context;

    if (!protection) return;

    /* 校验受监控代码/数据节 */
    for (ULONG i = 0; i < protection->SectionCount; i++) {
        PIM_SECTION_BASELINE section = &protection->Sections[i];
        BOOLEAN intact = TRUE;      // 完整
        IM_MODIFICATION mod = ImMod_None;

        /* 当前节未被监控，直接跳过 */
        if (!section->Monitored) continue;

        SppVerifySectionIntegrity(protection, i, &intact, &mod);
        if (!intact) {
            // CHAR details[IM_MAX_DETAIL_LENGTH];
            /*RtlStringCbPrintfA(details, sizeof(details),
                "Section %.8s tampered (type %u)", section->Name, (ULONG)mod);*/
            // ImpRecordEvent(protection, mod, i, details);

            InterlockedIncrement64(&protection->Stats.TotalViolations);
            //ImpReport(protection, IM_EVENT_SUBTYPE_CODE_SECTION, 7, L"IntegrityMonitor: "
            //    L"driver code section modified");
        }
    }

    /* 校验 PE 头 */
    if (protection->HeaderMonitored) {
        if (!SppVerifyHeaderIntegrity(protection)) {
            // ImpRecordEvent(protection, ImMod_HeaderTamper, 0xFFFFFFFF, "PE header tampered");

            InterlockedIncrement64(&protection->Stats.TotalViolations);
            /*ImpReport(protection, IM_EVENT_SUBTYPE_HEADER_TAMPER, 9, L"IntegrityMonitor: "
                L"driver PE header modified");*/
        }
    }

    InterlockedIncrement64(&protection->Stats.TotalChecks);
    KeQuerySystemTimePrecise(&protection->Stats.LastCheckTime);
}

/* ============================================================================
 * CoParsePe OnSection 回调：采集单节信息（UserContext = protection）
 * ============================================================================ */

_Use_decl_annotations_
static NTSTATUS
SppSectionParserCallback(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ const PIMAGE_SECTION_HEADER Section,
    _In_ ULONG Index,
    _Inout_opt_ PVOID UserContext
    )
{
    PWKD_INTEGRITY_PROTECTION protection = (PWKD_INTEGRITY_PROTECTION)UserContext;
    PIM_SECTION_BASELINE section;

    UNREFERENCED_PARAMETER(Context);

    if (!protection || !Section || Index > IM_MAX_SECTIONS) {
        return STATUS_INVALID_PARAMETER;
    }

    section = &protection->Sections[protection->SectionCount];
    RtlZeroMemory(section, sizeof(IM_SECTION_BASELINE));

    RtlCopyMemory(section->Name, Section->Name, 8);
    section->VirtualAddress = Section->VirtualAddress;
    section->VirtualSize = Section->Misc.VirtualSize;
    section->Characteristics = Section->Characteristics;
    section->IsExecutable = (BOOLEAN)(
        (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
        (Section->Characteristics & IMAGE_SCN_CNT_CODE) != 0
        );
    section->IsWritable = (Section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    section->IsDiscardable = (Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;

    protection->SectionCount++;

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 建基线：代码节 / 只读数据节 / PE 头
 * ============================================================================ */

static NTSTATUS
SppComputeIntegrityBaselines(
    _Inout_ PWKD_INTEGRITY_PROTECTION Protection
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!Protection) return STATUS_INVALID_PARAMETER;

    /* PE 头基线（哈希驱动映像头部 SizeOfHeaders 区段） */
    if (Protection->HeaderSize > 0 && Protection->HeaderSize <= Protection->ImageSize) {
        status = SppHashKernelRegion(Protection, 
                                     Protection->ImageBase,
                                     Protection->HeaderSize, 
                                     Protection->HeaderBaselineHash);
        if (NT_SUCCESS(status)) Protection->HeaderMonitored = TRUE;
    }

    /* 逐节基线（非可写 / 非可丢弃 / 非零长 才纳入监控） */
    for (ULONG i = 0; i < Protection->SectionCount; i++) {
        PIM_SECTION_BASELINE section = &Protection->Sections[i];

        if (section->IsWritable || section->IsDiscardable || section->VirtualSize == 0) {
            continue;   /* 跳过可变/已释放（INIT）/空节 */
        }
        if (section->VirtualSize > IM_MAX_SECTION_SIZE) {
            continue;   /* 超上限跳过 */
        }
        /* 越界防御：RVA 超出驱动映像则跳过 */
        if ((SIZE_T)section->VirtualAddress + section->VirtualSize > Protection->ImageSize) {
            continue;
        }

        status = SppHashKernelRegion(
            Protection,
            (PUCHAR)Protection->ImageBase + section->VirtualAddress,
            section->VirtualSize,
            section->BaselineHash
            );
        if (!NT_SUCCESS(status)) continue;

        section->Monitored = TRUE;
        if (section->IsExecutable) {
            Protection->MonitoredCodeSections++;
        } else {
            Protection->MonitoredDataSections++;
        }
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 安全读取内核节内存并计算 SHA-256（CoReadKernelRegionSafe + CoComputeSha256）
 * ============================================================================ */

_Use_decl_annotations_
static
NTSTATUS
SppHashKernelRegion(
    _In_ const PWKD_INTEGRITY_PROTECTION Protection,
    _In_ const PVOID Address,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(BCRYPT_SHA256_SIZE) PUCHAR Hash
    )
{
    // PUCHAR buffer;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Protection);

    if (!Protection || !Address || !Hash ||
        Size == 0 || Size > IM_MAX_SECTION_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //buffer = (PUCHAR)ExAllocatePoolZero(
    //    NonPagedPoolNx,
    //    Size,
    //    IM_POOL_TAG_SECT
    //    );
    //if (!buffer) return STATUS_NO_MEMORY;

    //status = CoReadKernelRegionSafe(buffer, Address, Size);
    //if (NT_SUCCESS(status)) {
    //    status = CoComputeSha256(buffer, Size, Hash);
    //}

    // ExFreePoolWithTag(buffer, IM_POOL_TAG_SECT);
    // return status;

    return CoComputeSha256(Address, Size, Hash);
}

/* ============================================================================
 * 校验单节完整性（重哈希比对基线）
 * ============================================================================ */

_Use_decl_annotations_
static
NTSTATUS
SppVerifySectionIntegrity(
    _In_ const PWKD_INTEGRITY_PROTECTION Protection,
    _In_ ULONG SectionIndex,
    _Out_ PBOOLEAN IsIntact,
    _Out_ PIM_MODIFICATION ModificationType
    )
{
    NTSTATUS status;
    PIM_SECTION_BASELINE baseline;
    UCHAR hash[BCRYPT_SHA256_SIZE];

    if (!Protection || !IsIntact || !ModificationType ||
        SectionIndex >= Protection->SectionCount) {
        return STATUS_INVALID_PARAMETER;
    }
    *IsIntact = TRUE;
    *ModificationType = ImMod_None;

    baseline = &Protection->Sections[SectionIndex];
    if (!baseline->Monitored) return STATUS_SUCCESS;

    status = SppHashKernelRegion(
        Protection,
        (PUCHAR)Protection->ImageBase + baseline->VirtualAddress,
        baseline->VirtualSize,
        hash
        );
    if (!NT_SUCCESS(status)) return status;

    if (RtlCompareMemory(hash, baseline->BaselineHash, BCRYPT_SHA256_SIZE) != BCRYPT_SHA256_SIZE) {
        /* 节内存被篡改!!! */
        *IsIntact = FALSE;
        if (baseline->IsExecutable) {
            /* 依导入/导出目录区间细分 */
            if (Protection->ImportDirRva >= baseline->VirtualAddress &&
                Protection->ImportDirRva < (baseline->VirtualAddress + baseline->VirtualSize)) {
                *ModificationType = ImMod_ImportHook;
            } else if (Protection->ExportDirRva >= baseline->VirtualAddress &&
                       Protection->ExportDirRva < (baseline->VirtualAddress + baseline->VirtualSize)) {
                *ModificationType = ImMod_ExportHook;
            } else {
                *ModificationType = ImMod_CodePatch;
            }
        } else {
            *ModificationType = ImMod_DataCorruption;
        }
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 校验 PE 头完整性
 * ============================================================================ */

_Use_decl_annotations_
static
BOOLEAN
SppVerifyHeaderIntegrity(
    _In_ const PWKD_INTEGRITY_PROTECTION Protection
    )
{
    NTSTATUS status;
    UCHAR hash[BCRYPT_SHA256_SIZE];

    if (!Protection || !Protection->HeaderMonitored) return FALSE;

    status = SppHashKernelRegion(Protection, Protection->ImageBase, Protection->HeaderSize, hash);
    if (!NT_SUCCESS(status)) return FALSE;

    if (RtlCompareMemory(hash,
        Protection->HeaderBaselineHash,
        BCRYPT_SHA256_SIZE) == BCRYPT_SHA256_SIZE)
        return TRUE;
    else return FALSE;
}

/* ============================================================================
 * 记录事件（加锁插入 + 淘汰 + 统计）
 * ============================================================================ */

static VOID
ImpRecordEvent(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ IM_MODIFICATION Modification,
    _In_ ULONG SectionIndex,
    _In_opt_ PCCH Details
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;
    PIM_EVENT evt;
    LIST_ENTRY freeList;

    evt = (PIM_EVENT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(IM_EVENT),
        IM_POOL_TAG_EVENT
        );
    if (evt == NULL) {
        return;
    }

    evt->Modification = Modification;
    evt->SectionIndex = SectionIndex;
    KeQuerySystemTimePrecise(&evt->Timestamp);

    if (SectionIndex < protection->SectionCount) {
        RtlCopyMemory(evt->SectionName, protection->Sections[SectionIndex].Name, 8);
    }
    if (Details != NULL) {
        RtlStringCchCopyA(evt->Details, IM_MAX_DETAIL_LENGTH, Details);
    }

    InitializeListHead(&freeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&protection->EventLock);
    {
        if (protection->EventCount >= IM_MAX_EVENTS) {
            ImpEvictOldestEventsLocked(protection, IM_MAX_EVENTS - 1, &freeList);
        }
        InsertTailList(&protection->EventList, &evt->ListEntry);
        protection->EventCount++;
    }
    ExReleasePushLockExclusive(&protection->EventLock);
    KeLeaveCriticalRegion();

    ImpFreeEventList(&freeList);
}

/* ============================================================================
 * 上报（IRQL 门控 + WkdReportSelfProtectionEvent）
 * ============================================================================ */

static VOID
ImpReport(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ ULONG SubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;

    /* WkdReportSelfProtectionEvent（经 ALPC）要求 PASSIVE_LEVEL */
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    (VOID)WkdReportSelfProtectionEvent(SubType, Severity, Description);
    InterlockedIncrement64(&protection->Stats.ReportInvocations);
}

/* ============================================================================
 * 事件快照（值类型深拷贝）
 * ============================================================================ */

static VOID
ImpSnapshotEvent(
    _In_ PIM_EVENT Source,
    _Out_ PIM_EVENT_INFO Dest
    )
{
    if (Source == NULL || Dest == NULL) {
        return;
    }

    RtlZeroMemory(Dest, sizeof(IM_EVENT_INFO));
    Dest->Modification = Source->Modification;
    Dest->SectionIndex = Source->SectionIndex;
    RtlCopyMemory(Dest->SectionName, Source->SectionName, 8);
    RtlStringCbCopyA(Dest->Details, sizeof(Dest->Details), Source->Details);
    Dest->Timestamp = Source->Timestamp;
}

/* ============================================================================
 * 释放事件链表节点
 * ============================================================================ */

static VOID
ImpFreeEventList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    while (!IsListEmpty(ListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(ListHead);
        PIM_EVENT evt = CONTAINING_RECORD(entry, IM_EVENT, ListEntry);
        ExFreePoolWithTag(evt, IM_POOL_TAG_EVENT);
    }
}

/* ============================================================================
 * 锁内淘汰最旧事件至 freeList（调用方须已持 EventLock 独占）
 * ============================================================================ */

static VOID
ImpEvictOldestEventsLocked(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ LONG TargetCount,
    _Inout_ PLIST_ENTRY FreeList
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;

    while (protection->EventCount > TargetCount && !IsListEmpty(&protection->EventList)) {
        PLIST_ENTRY head = protection->EventList.Flink;
        PLIST_ENTRY oldest = head;
        PLIST_ENTRY entry = head->Flink;

        /* 找时间戳最小的（最旧）节点 */
        for (; entry != &protection->EventList; entry = entry->Flink) {
            PIM_EVENT evt = CONTAINING_RECORD(entry, IM_EVENT, ListEntry);
            PIM_EVENT oldEvt = CONTAINING_RECORD(oldest, IM_EVENT, ListEntry);
            if (evt->Timestamp.QuadPart < oldEvt->Timestamp.QuadPart) {
                oldest = entry;
            }
        }

        RemoveEntryList(oldest);
        InsertTailList(FreeList, oldest);
        protection->EventCount--;
    }
}

/* ============================================================================
 * 公共 API：按需校验 / 事件 / 统计
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
ImCheckIntegrity(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ ULONG Stage,
    _Out_ PBOOLEAN IsIntact,
    _Out_ PIM_MODIFICATION ModificationType
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    if (protection == NULL || IsIntact == NULL || ModificationType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Stage >= IM_STAGE_MAX) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsIntact = TRUE;
    *ModificationType = ImMod_None;

    switch (Stage) {
    case IM_STAGE_HEADER:
        *IsIntact = SppVerifyHeaderIntegrity(protection);
        break;

    case IM_STAGE_CODE_SECTIONS:
    case IM_STAGE_DATA_SECTIONS:
    default:
        for (i = 0; i < protection->SectionCount; i++) {
            PIM_SECTION_BASELINE sect = &protection->Sections[i];
            BOOLEAN intact = TRUE;
            IM_MODIFICATION mod = ImMod_None;

            if (!sect->Monitored) {
                continue;
            }
            /* 按阶段过滤：代码段接口只查可执行节 */
            if (Stage == IM_STAGE_CODE_SECTIONS && !sect->IsExecutable) {
                continue;
            }
            if (Stage == IM_STAGE_DATA_SECTIONS && sect->IsExecutable) {
                continue;
            }

            status = SppVerifySectionIntegrity(protection, i, &intact, &mod);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!intact) {
                *IsIntact = FALSE;
                *ModificationType = mod;
                break;
            }
        }
        break;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ImCheckAll(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _Out_ PBOOLEAN AllIntact
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;
    NTSTATUS status;
    BOOLEAN intact = TRUE;
    IM_MODIFICATION mod = ImMod_None;

    PAGED_CODE();

    if (protection == NULL || AllIntact == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *AllIntact = TRUE;

    status = ImCheckIntegrity(protection, IM_STAGE_CODE_SECTIONS, &intact, &mod);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!intact) {
        *AllIntact = FALSE;
    }

    status = ImCheckIntegrity(protection, IM_STAGE_DATA_SECTIONS, &intact, &mod);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!intact) {
        *AllIntact = FALSE;
    }

    status = ImCheckIntegrity(protection, IM_STAGE_HEADER, &intact, &mod);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!intact) {
        *AllIntact = FALSE;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ImGetEvents(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PIM_EVENT_INFO EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;
    ULONG count = 0;
    PLIST_ENTRY entry;

    PAGED_CODE();

    if (protection == NULL || EventArray == NULL || ReturnedCount == NULL || MaxEvents == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnedCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&protection->EventLock);
    {
        for (entry = protection->EventList.Flink;
             entry != &protection->EventList && count < MaxEvents;
             entry = entry->Flink)
        {
            PIM_EVENT evt = CONTAINING_RECORD(entry, IM_EVENT, ListEntry);
            ImpSnapshotEvent(evt, &EventArray[count]);
            count++;
        }
    }
    ExReleasePushLockShared(&protection->EventLock);
    KeLeaveCriticalRegion();

    *ReturnedCount = count;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ImGetStatistics(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _Out_ PIM_STATISTICS Stats
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;

    PAGED_CODE();

    if (protection == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(IM_STATISTICS));
    Stats->TotalChecks = protection->Stats.TotalChecks;
    Stats->TotalViolations = protection->Stats.TotalViolations;
    Stats->ReportInvocations = protection->Stats.ReportInvocations;
    Stats->CurrentEventCount = protection->EventCount;
    Stats->CodeSectionCount = protection->MonitoredCodeSections;
    Stats->DataSectionCount = protection->MonitoredDataSections;
    Stats->LastCheckTime = protection->Stats.LastCheckTime;
    Stats->StartTime = protection->Stats.StartTime;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ImClearEvents(
    _In_ PWKD_INTEGRITY_PROTECTION Protection
    )
{
    PWKD_INTEGRITY_PROTECTION protection = Protection;
    LIST_ENTRY freeList;

    PAGED_CODE();

    if (protection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&freeList);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&protection->EventLock);
    {
        PLIST_ENTRY entry = protection->EventList.Flink;
        while (entry != &protection->EventList) {
            PLIST_ENTRY next = entry->Flink;
            PIM_EVENT evt = CONTAINING_RECORD(entry, IM_EVENT, ListEntry);
            InsertTailList(&freeList, &evt->ListEntry);
            entry = next;
        }
        InitializeListHead(&protection->EventList);
        protection->EventCount = 0;
    }
    ExReleasePushLockExclusive(&protection->EventLock);
    KeLeaveCriticalRegion();

    ImpFreeEventList(&freeList);
    return STATUS_SUCCESS;
}
