#include "MemoryRegion.h"
#include "../Common/Utils.h"
#include <ntddk.h>
#include <ntstrsafe.h>

//
// Pool tag
//
#define WKD_MEM_POOL_TAG 'gMeM'

//
// MEM_* 常量在内核模式未定义（MemoryMonitor.c 顶部的兼容处理）
//
#ifndef MEM_COMMIT
#define MEM_COMMIT      0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE     0x2000
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED      0x40000
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE       0x1000000
#endif

/**************************************************/
/*              内部辅助函数声明                    */
/**************************************************/

//
// MmpIsExecutableProtection / MmpIsWritableProtection / MmpIsRwxProtection
// 已转模块内公共（MemoryRegion.h 内部协作接口区，供 MemoryRegionVerify.c
// 复用保护判断）；MmpAnalyzeProtectionChange 保持内部（经
// WkdMemRegionGetProtectionChangeSuspicion 暴露）。
//
static ULONG MmpAnalyzeProtectionChange(_In_ ULONG OldProtection, _In_ ULONG NewProtection);

//
// MmpFindMemoryRegion / MmpRemoveMemoryRegionFromVirtualAddressSpace /
// MmpAddMemoryRegionToVirtualAddressSpace / WkdMemRegionUpdateProcessRisk
// 已转模块内公共（MemoryRegion.h 内部协作接口区，供 MemoryRegionVerify.c
// 复用区域表管理/风险聚合），此处不再 static 声明。
//
static VOID WkdMemRegionCleanupStaleRegions(_Inout_ PWKD_MEMORY_REGION_CONTEXT Context);

//
// 4 类事件处理器（MmMonitorHandleAllocation/ProtectionChange/
// CrossProcessWrite/SectionMap，去除 InjectionDetector/HeapSpray/VAD/
// MemoryScanner 委派——wkd 已由 agent IoaInjectionClassifier（#56）/
// IoaHeapSprayDetect（#55）覆盖，此处仅维护区域表 + 轻量预判标志）
//
static VOID MmAllcateMemoryRegion(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ HANDLE TargetProcessId, _In_ ULONG64 BaseAddress, _In_ ULONG64 Size, _In_ ULONG Protection, _In_ BOOLEAN IsCrossProcess);
static VOID WkdMemRegionHandleProtectionChange(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ ULONG64 BaseAddress, _In_ ULONG64 Size, _In_ ULONG OldProtection, _In_ ULONG NewProtection, _In_ BOOLEAN IsCrossProcess);
static VOID WkdMemRegionHandleCrossProcessWrite(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ ULONG64 TargetAddress, _In_ ULONG64 Size, _In_opt_ PVOID SourceBuffer);
static VOID MmpHandleSectionMapping(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ ULONG64 BaseAddress, _In_ ULONG64 ViewSize, _In_ ULONG Protection, _In_ BOOLEAN IsCrossProcess);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MmAllcateMemoryRegion)
#pragma alloc_text(MmTrackMemoryRegionProtectionChange)
#pragma alloc_text(MmpAnalyzeProtectionChange)
#pragma alloc_text(MmTrackSectionMapping)
#pragma alloc_text(MmpHandleSectionMapping)
#pragma alloc_text(MmTrackMemoryRegionAllocation)
#pragma alloc_text(MmBuildMemoryRegionBaseline)
#endif

/**************************************************/
/*              保护判断辅助（对齐 SS）             */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
MmpIsExecutableProtection(
    _In_ ULONG Protection
    )
{
    return ((Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

_Use_decl_annotations_
BOOLEAN
MmpIsWritableProtection(
    _In_ ULONG Protection
    )
{
    return ((Protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

_Use_decl_annotations_
BOOLEAN
MmpIsRwxProtection(
    _In_ ULONG Protection
    )
{
    return ((Protection & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

//
// 保护变化分析（MmpAnalyzeProtectionChange c:3622）
// 返回：0=不敏感 / 1=RW→RX（经典解包）/ 2=→RWX
//
_Use_decl_annotations_
static
ULONG
MmpAnalyzeProtectionChange(
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    )
{
    PAGED_CODE();

    // RW→RX（经典解包/shellcode 模式）
    if (MmpIsWritableProtection(OldProtection) &&
        !MmpIsExecutableProtection(OldProtection) &&
        MmpIsExecutableProtection(NewProtection)) {
        return 1;
    }

    // any→RWX
    if (!MmpIsRwxProtection(OldProtection) &&
        MmpIsRwxProtection(NewProtection)) {
        return 2;
    }

    return 0;
}

/**************************************************/
/*              区域表管理（对齐 SS）               */
/**************************************************/

//
// 查找地址所在区域（调用者必须持有 Context->RegionLock）
// 内部协作接口（MemoryRegion.h）：供 MemoryRegionVerify.c 定时一致性校验复用
//
_Use_decl_annotations_
PWKD_MEMORY_REGION
MmpFindMemoryRegion(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 Address
    )
{
    PLIST_ENTRY entry;
    PWKD_MEMORY_REGION region;

    entry = Context->RegionList.Flink;
    while (entry != &Context->RegionList) {
        region = CONTAINING_RECORD(entry, WKD_MEMORY_REGION, ListEntry);

        if (Address >= region->BaseAddress &&
            Address < region->BaseAddress + region->Size) {
            return region;
        }

        entry = entry->Flink;
    }

    return NULL;
}

_Use_decl_annotations_
VOID
MmpRemoveMemoryRegionFromVirtualAddressSpace(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context,
    _Inout_ PWKD_MEMORY_REGION Region
    )
{
    RemoveEntryList(&Region->ListEntry);
    Context->RegionCount--;
    ExFreePoolWithTag(Region, WKD_MEM_POOL_TAG);
}

//
// 清理过期区域（MmpCleanupStaleRegions c:3544）
// 非高风险且超龄（3600s）的区域移除
//
static
VOID
WkdMemRegionCleanupStaleRegions(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context
    )
{
    LARGE_INTEGER now;
    ULONG64 maxAge;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;

    KeQuerySystemTimePrecise(&now);
    maxAge = (ULONG64)WKD_MEMORY_REGION_MAX_AGE_SEC * 10000000ULL;

    WkdAcquirePushLockExclusive(&Context->RegionLock);

    entry = Context->RegionList.Flink;
    while (entry != &Context->RegionList) {
        PWKD_MEMORY_REGION region;

        nextEntry = entry->Flink;
        region = CONTAINING_RECORD(entry, WKD_MEMORY_REGION, ListEntry);

        if (!region->IsHighRisk &&
            (ULONG64)(now.QuadPart - region->AllocationTime.QuadPart) > maxAge) {
            MmpRemoveMemoryRegionFromVirtualAddressSpace(Context, region);
        }

        entry = nextEntry;
    }

    WkdReleasePushLockExclusive(&Context->RegionLock);
}

//
// 添加区域（MmpAddRegion c:3402）
// 4096 上限 + 过期清理 + 重复地址检测（FIX MM-L1）
//
_Use_decl_annotations_
NTSTATUS
MmpAddMemoryRegionToVirtualAddressSpace(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection,
    _In_ ULONG Type
    )
{
    PWKD_MEMORY_REGION region;

    // 预检（乐观快速路径）
    if (Context->RegionCount >= WKD_MEM_MAX_REGIONS_PER_PROCESS) {
        WkdMemRegionCleanupStaleRegions(Context);
        if (Context->RegionCount >= WKD_MEM_MAX_REGIONS_PER_PROCESS) {
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    region = (PWKD_MEMORY_REGION)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              sizeof(WKD_MEMORY_REGION),
                                              WKD_MEM_POOL_TAG);
    if (region == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(region, sizeof(WKD_MEMORY_REGION));

    region->BaseAddress = BaseAddress;
    region->Size = Size;
    region->ProcessId = Context->ProcessId;
    region->Protection = Protection;
    region->State = MEM_COMMIT;
    region->Type = Type;
    region->Flags = WKD_MEM_FLAG_MONITORED;
    KeQuerySystemTimePrecise(&region->AllocationTime);

    // 区域类型（MmpAddRegion c:3448）
    if (Type == MEM_IMAGE) {
        region->RegionType = WkdMemRegion_Image;
    } else if (Type == MEM_MAPPED) {
        region->RegionType = WkdMemRegion_Mapped;
    } else {
        region->RegionType = WkdMemRegion_Private;
    }

    // RWX 初始保护即高风险
    if (MmpIsRwxProtection(Protection)) {
        region->IsHighRisk = TRUE;
    }

    // 锁内二重检查：重复地址 + 数量上限（TOCTOU 防护，FIX MM-L1）
    WkdAcquirePushLockExclusive(&Context->RegionLock);

    if (MmpFindMemoryRegion(Context, BaseAddress) != NULL) {
        WkdReleasePushLockExclusive(&Context->RegionLock);
        ExFreePoolWithTag(region, WKD_MEM_POOL_TAG);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    if (Context->RegionCount >= WKD_MEM_MAX_REGIONS_PER_PROCESS) {
        WkdReleasePushLockExclusive(&Context->RegionLock);
        ExFreePoolWithTag(region, WKD_MEM_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&Context->RegionList, &region->ListEntry);
    Context->RegionCount++;

    WkdReleasePushLockExclusive(&Context->RegionLock);

    return STATUS_SUCCESS;
}

//
// 风险聚合（MmpUpdateProcessRisk c:3699）
// MemoryRiskScore = Shellcode×200 + Injection×300 + Suspicious×10，cap 1000
//
_Use_decl_annotations_
VOID
WkdMemRegionUpdateProcessRisk(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context
    )
{
    ULONG riskScore;

    riskScore  = (ULONG)Context->ShellcodeDetectionCount * 200;
    riskScore += (ULONG)Context->InjectionAttemptCount * 300;
    riskScore += (ULONG)(Context->SuspiciousOperations * 10);

    if (riskScore > 1000) {
        riskScore = 1000;
    }

    Context->MemoryRiskScore = riskScore;
}

/**************************************************/
/*              4 类事件处理器（对齐 SS）           */
/**************************************************/

//
// 内存分配（MmMonitorHandleAllocation c:1261）
// 记录区域 + RWX 初始分配预判 + 跨进程注入标记
//
static
VOID
MmAllcateMemoryRegion(
    _Inout_ PWKD_PROCESS Owner,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection,
    _In_ BOOLEAN IsCrossProcess
    )
{
    PWKD_MEMORY_REGION_CONTEXT context;
    NTSTATUS status;

    PAGED_CODE();

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    // 惰性挂载：上下文未构建时尝试分配（非致命，分配失败静默跳过）
    context = WkdMemRegionGetContext(Owner);
    if (context == NULL) {
        return;
    }

    // 小分配跳过（MinAllocationSizeToTrack=4096）
    if (Size < WKD_MEM_MIN_ALLOC_SIZE_TO_TRACK) {
        return;
    }

    status = MmpAddMemoryRegionToVirtualAddressSpace(context, BaseAddress, Size, Protection, MEM_PRIVATE);
    if (!NT_SUCCESS(status)) {
        return;
    }

    // RWX 初始分配 → 高风险 + 高熵（c:1349）
    if (MmpIsRwxProtection(Protection)) {
        PWKD_MEMORY_REGION region;

        WkdAcquirePushLockExclusive(&context->RegionLock);
        region = MmpFindMemoryRegion(context, BaseAddress);
        if (region != NULL) {
            region->IsHighRisk = TRUE;
            region->Flags |= WKD_MEM_FLAG_HIGH_ENTROPY;
        }
        WkdReleasePushLockExclusive(&context->RegionLock);
    }

    // 跨进程分配 → 可疑 + 注入目标标记（c:1321）
    if (IsCrossProcess) {
        PWKD_MEMORY_REGION region;

        InterlockedIncrement64(&context->SuspiciousOperations);
        InterlockedOr((volatile LONG*)&context->Flags, WKD_MEM_PROCESS_FLAG_INJECTION_TARGET);

        WkdAcquirePushLockExclusive(&context->RegionLock);
        region = MmpFindMemoryRegion(context, BaseAddress);
        if (region != NULL) {
            region->Flags |= WKD_MEM_FLAG_INJECTION_DST;
        }
        WkdReleasePushLockExclusive(&context->RegionLock);
    }

    WkdMemRegionUpdateProcessRisk(context);
}

//
// 保护变化（MmMonitorHandleProtectionChange c:1452）
// W→X 解包 / Image 区早期 RWX（镂空）/ 保护变化评分 / 跨进程注入标记
//
static
VOID
WkdMemRegionHandleProtectionChange(
    _Inout_ PWKD_PROCESS Owner,
    _In_ HANDLE SourceProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection,
    _In_ BOOLEAN IsCrossProcess
    )
{
    PWKD_MEMORY_REGION_CONTEXT context;
    PWKD_MEMORY_REGION region;
    NTSTATUS status;
    ULONG suspicionType;

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    // 惰性挂载：上下文未构建时尝试分配（非致命，分配失败静默跳过）
    context = WkdMemRegionGetContext(Owner);
    if (context == NULL) {
        return;
    }

    WkdAcquirePushLockExclusive(&context->RegionLock);

    region = MmpFindMemoryRegion(context, BaseAddress);

    if (region == NULL) {
        // 区域未追踪 → 释放锁、添加、重取
        WkdReleasePushLockExclusive(&context->RegionLock);

        status = MmpAddMemoryRegionToVirtualAddressSpace(context, BaseAddress, Size, NewProtection, MEM_PRIVATE);
        if (!NT_SUCCESS(status)) {
            return;
        }

        WkdAcquirePushLockExclusive(&context->RegionLock);
        region = MmpFindMemoryRegion(context, BaseAddress);
    }

    if (region != NULL) {
        region->Protection = NewProtection;
        region->ProtectionChangeCount++;
        KeQuerySystemTimePrecise(&region->LastProtectionChangeTime);

        // W→X 转换（经典解包/shellcode 模式，c:1527）
        if (region->WasWritten && MmpIsExecutableProtection(NewProtection)) {
            region->NowExecutable = TRUE;
            region->IsHighRisk = TRUE;
            region->Flags |= WKD_MEM_FLAG_SHELLCODE_SCAN;
        }

        // 镂空指示器：Image 区早期 RWX（c:1536，FIX-19）
        if (region->RegionType == WkdMemRegion_Image &&
            MmpIsRwxProtection(NewProtection) &&
            region->ProtectionChangeCount <= 2) {
            InterlockedOr((volatile LONG*)&context->Flags, WKD_MEM_PROCESS_FLAG_HOLLOWING_TARGET);
        }

        // 保护变化分析（RW→RX / →RWX）
        suspicionType = MmpAnalyzeProtectionChange(OldProtection, NewProtection);
        if (suspicionType != 0) {
            InterlockedIncrement64(&context->SuspiciousOperations);

            if (suspicionType == 1) {
                region->Flags |= WKD_MEM_FLAG_SHELLCODE_SCAN;
            }
            if (suspicionType == 2) {
                region->IsHighRisk = TRUE;
            }
        }

        // 跨进程保护变化 → 注入目标标记（c:1563）
        if (IsCrossProcess) {
            InterlockedIncrement64(&context->SuspiciousOperations);
            region->Flags |= WKD_MEM_FLAG_INJECTION_DST;
        }
    }

    WkdReleasePushLockExclusive(&context->RegionLock);

    UNREFERENCED_PARAMETER(SourceProcessId);

    WkdMemRegionUpdateProcessRisk(context);
}

//
// 跨进程写入（MmMonitorHandleCrossProcessWrite c:1654）
// 标记 WasWritten/INJECTION_DST + 高熵（锁外算熵 FIX-07）
//
static
VOID
WkdMemRegionHandleCrossProcessWrite(
    _Inout_ PWKD_PROCESS Owner,
    _In_ HANDLE SourceProcessId,
    _In_ ULONG64 TargetAddress,
    _In_ ULONG64 Size,
    _In_opt_ PVOID SourceBuffer
    )
{
    PWKD_MEMORY_REGION_CONTEXT context;
    PWKD_MEMORY_REGION region;
    NTSTATUS status;
    ULONG entropy = 0;
    ULONG readSize;

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    // 惰性挂载：上下文未构建时尝试分配（非致命，分配失败静默跳过）
    context = WkdMemRegionGetContext(Owner);
    if (context == NULL) {
        return;
    }

    // 锁外提前算熵（FIX-07：避免高 IRQL 下大栈分配）
    if (SourceBuffer != NULL && Size > 0) {
        readSize = (ULONG)min(Size, (ULONG64)WKD_MEM_MAX_REGION_ENTROPY_READ);
        /* __try { */
            ProbeForRead(SourceBuffer, readSize, 1);
            entropy = WkdCalculateEntropy(SourceBuffer, readSize);
        /* }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            entropy = 0;
        } */
    }

    WkdAcquirePushLockExclusive(&context->RegionLock);

    region = MmpFindMemoryRegion(context, TargetAddress);

    if (region == NULL) {
        WkdReleasePushLockExclusive(&context->RegionLock);

        status = MmpAddMemoryRegionToVirtualAddressSpace(context, TargetAddress, Size, 0, MEM_PRIVATE);
        if (!NT_SUCCESS(status)) {
            return;
        }

        WkdAcquirePushLockExclusive(&context->RegionLock);
        region = MmpFindMemoryRegion(context, TargetAddress);
    }

    if (region != NULL) {
        region->WasWritten = TRUE;
        region->Flags |= WKD_MEM_FLAG_INJECTION_DST;

        if (entropy > 0) {
            region->LastContentEntropy = entropy;
            if (entropy >= WKD_MEM_SHELLCODE_SCAN_THRESHOLD) {
                region->Flags |= WKD_MEM_FLAG_HIGH_ENTROPY;
                region->IsHighRisk = TRUE;
            }
        }
    }

    WkdReleasePushLockExclusive(&context->RegionLock);

    InterlockedIncrement64(&context->SuspiciousOperations);
    InterlockedIncrement(&context->InjectionAttemptCount);
    InterlockedOr((volatile LONG*)&context->Flags, WKD_MEM_PROCESS_FLAG_INJECTION_TARGET);
    WkdMemRegionUpdateProcessRisk(context);

    UNREFERENCED_PARAMETER(SourceProcessId);
}

//
// Section 映射（MmMonitorHandleSectionMap c:1774）
// 记录 MAPPED 区域 + 跨进程注入标记
//
static
VOID
MmpHandleSectionMapping(
    _Inout_ PWKD_PROCESS Owner,
    _In_ HANDLE SourceProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 ViewSize,
    _In_ ULONG Protection,
    _In_ BOOLEAN IsCrossProcess
    )
{
    PWKD_MEMORY_REGION_CONTEXT context;
    NTSTATUS status;

    PAGED_CODE();

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    // 惰性挂载：上下文未构建时尝试分配（非致命，分配失败静默跳过）
    context = WkdMemRegionGetContext(Owner);
    if (context == NULL) {
        return;
    }

    status = MmpAddMemoryRegionToVirtualAddressSpace(context, BaseAddress, ViewSize, Protection, MEM_MAPPED);
    if (!NT_SUCCESS(status)) {
        return;
    }

    // 跨进程映射 → 注入目标标记（c:1850）
    if (IsCrossProcess) {
        PWKD_MEMORY_REGION region;

        InterlockedIncrement64(&context->SuspiciousOperations);

        WkdAcquirePushLockExclusive(&context->RegionLock);
        region = MmpFindMemoryRegion(context, BaseAddress);
        if (region != NULL) {
            region->Flags |= WKD_MEM_FLAG_INJECTION_DST;
            if (MmpIsExecutableProtection(Protection)) {
                region->IsHighRisk = TRUE;
            }
        }
        WkdReleasePushLockExclusive(&context->RegionLock);

        WkdMemRegionUpdateProcessRisk(context);
    }

    UNREFERENCED_PARAMETER(SourceProcessId);
}

/**************************************************/
/*              便捷入口（SyscallHijack 调用）      */
/**************************************************/

//
// 跨进程注入源标记（MM_PROCESS_FLAG_INJECTION_SOURCE）
// 跨进程操作时对源进程（调用者）状态置注入源标志，供评分/查询消费
//
static
VOID
WkdMemRegionMarkInjectionSource(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    )
{
    PWKD_PROCESS sourceProc;
    PWKD_MEMORY_REGION_CONTEXT sourceContext;

    if (SourceProcessId == TargetProcessId) {
        return;
    }

    sourceProc = PsLookupWkdProcessByProcessId(SourceProcessId);
    if (sourceProc == NULL) {
        return;
    }

    sourceContext = WkdMemRegionGetContext(sourceProc);
    if (sourceContext != NULL) {
        InterlockedOr((volatile LONG*)&sourceContext->Flags,
                      WKD_MEM_PROCESS_FLAG_INJECTION_SOURCE);
    }
    PsDereferenceWkdProcess(sourceProc);
}

_Use_decl_annotations_
VOID
MmTrackMemoryRegionAllocation(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection
    )
{
    PWKD_PROCESS owner;
    HANDLE ownerPid;
    BOOLEAN isCross;

    PAGED_CODE();

    isCross = (SourceProcessId != TargetProcessId);
    ownerPid = isCross ? TargetProcessId : SourceProcessId;

    owner = PsLookupWkdProcessByProcessId(ownerPid);
    if (owner == NULL) {
        return;
    }

    MmAllcateMemoryRegion(owner, SourceProcessId, TargetProcessId,
                                 BaseAddress, Size, Protection, isCross);

    /* 跨进程注入源标记（MM_PROCESS_FLAG_INJECTION_SOURCE） */
    if (isCross) {
        WkdMemRegionMarkInjectionSource(SourceProcessId, TargetProcessId);
    }

    PsDereferenceWkdProcess(owner);
}

_Use_decl_annotations_
VOID
MmTrackMemoryRegionProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ HANDLE SourceProcessId
    )
{
    PWKD_PROCESS owner;

    PAGED_CODE();

    owner = PsLookupWkdProcessByProcessId(ProcessId);
    if (owner == NULL) {
        return;
    }

    WkdMemRegionHandleProtectionChange(owner, SourceProcessId, BaseAddress, Size,
                                       OldProtection, NewProtection, IsCrossProcess);

    /* 跨进程注入源标记（MM_PROCESS_FLAG_INJECTION_SOURCE） */
    if (IsCrossProcess) {
        WkdMemRegionMarkInjectionSource(SourceProcessId, ProcessId);
    }

    PsDereferenceWkdProcess(owner);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackCrossProcessWrite(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 TargetAddress,
    _In_ ULONG64 Size,
    _In_opt_ PVOID SourceBuffer
    )
{
    PWKD_PROCESS owner;

    owner = PsLookupWkdProcessByProcessId(TargetProcessId);
    if (owner == NULL) {
        return;
    }

    WkdMemRegionHandleCrossProcessWrite(owner, SourceProcessId, TargetAddress,
                                        Size, SourceBuffer);

    /* 跨进程注入源标记（跨进程写必然跨进程） */
    WkdMemRegionMarkInjectionSource(SourceProcessId, TargetProcessId);

    PsDereferenceWkdProcess(owner);
}

_Use_decl_annotations_
VOID
MmTrackSectionMapping(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 ViewSize,
    _In_ ULONG Protection,
    _In_ BOOLEAN IsCrossProcess
    )
{
    PWKD_PROCESS owner;
    HANDLE ownerPid;

    PAGED_CODE();

    ownerPid = IsCrossProcess ? TargetProcessId : SourceProcessId;

    owner = PsLookupWkdProcessByProcessId(ownerPid);
    if (owner == NULL) {
        return;
    }

    MmpHandleSectionMapping(owner, SourceProcessId, BaseAddress, ViewSize,
                                 Protection, IsCrossProcess);

    /* 跨进程注入源标记（MM_PROCESS_FLAG_INJECTION_SOURCE） */
    if (IsCrossProcess) {
        WkdMemRegionMarkInjectionSource(SourceProcessId, TargetProcessId);
    }

    PsDereferenceWkdProcess(owner);
}

/**************************************************/
/*              生命周期（方案 A 指针化）            */
/**************************************************/

//
// 主动构建内存区域追踪上下文（2026-09-09 方案 A；2026-09-10 二次重构
// 撤销 WKD_MEMORY_REGION_STATE，事件轨成员直接内嵌于上下文）
// 进程创建路径调用；CAS 赢家/输家收敛并发构建，幂等。
// 失败返回状态码，调用方（PspCreateProcessContextInternal）处理为非致命。
//
_Use_decl_annotations_
NTSTATUS
MmCreateMemoryRegionContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    PWKD_MEMORY_REGION_CONTEXT ctx;
    PVOID oldValue;

    if (WkdProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 已存在：幂等成功
    if (WkdProcess->MemoryRegionContext != NULL) {
        return STATUS_SUCCESS;
    }

    ctx = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                          sizeof(WKD_MEMORY_REGION_CONTEXT),
                          WKD_MEM_POOL_TAG);
    if (ctx == NULL) {
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(ctx, sizeof(WKD_MEMORY_REGION_CONTEXT));

    /* 事件轨初始化（原 WKD_MEMORY_REGION_STATE 成员已上提内嵌） */
    InitializeListHead(&ctx->RegionList);
    ExInitializePushLock(&ctx->RegionLock);
    ctx->ProcessId = WkdProcess->Core.ProcessId;

    /* CAS 发布：赢家保留 ctx，输家释放（对齐 ModuleContext 双路范式） */
    oldValue = InterlockedCompareExchangePointer(
        (PVOID volatile*)&WkdProcess->MemoryRegionContext,
        ctx,
        NULL);
    if (oldValue != NULL) {
        ExFreePoolWithTag(ctx, WKD_MEM_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

//
// 惰性挂载获取事件轨上下文指针（Track*/Handle* 热路径）
// 上下文未构建时尝试分配（CAS 收敛，单次分配）；失败返回 NULL，
// 调用方静默跳过该事件。幂等安全，可多次调用。
//
_Use_decl_annotations_
PWKD_MEMORY_REGION_CONTEXT
WkdMemRegionGetContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    if (WkdProcess == NULL) {
        return NULL;
    }

    // 惰性挂载：上下文未构建时尝试分配（非致命）
    if (WkdProcess->MemoryRegionContext == NULL) {
        MmCreateMemoryRegionContext(WkdProcess);
    }

    return WkdProcess->MemoryRegionContext;
}

//
// 统一销毁内存区域追踪上下文（进程退出路径）
// 取出指针并置空（防止热路径继续消费），遍历释放事件轨
// 区域节点，随后释放上下文载荷块。
//
_Use_decl_annotations_
VOID
WkdDestroyMemoryRegionContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    PWKD_MEMORY_REGION_CONTEXT ctx;

    if (WkdProcess == NULL) {
        return;
    }

    /* 原子取出并置空；进程销毁路径无并发消费者 */
    ctx = (PWKD_MEMORY_REGION_CONTEXT)InterlockedExchangePointer(
        (PVOID volatile*)&WkdProcess->MemoryRegionContext,
        NULL);
    if (ctx == NULL) {
        return;
    }

    /* 事件轨区域节点释放（区域链表含基线 + 事件增量节点） */
    WkdMemRegionCleanupProcess(ctx);

    ExFreePoolWithTag(ctx, WKD_MEM_POOL_TAG);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionCleanupProcess(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context
    )
{
    PLIST_ENTRY entry;

    if (!Context) return;

    WkdAcquirePushLockExclusive(&Context->RegionLock);

    while (!IsListEmpty(&Context->RegionList)) {
        PWKD_MEMORY_REGION region;

        entry = RemoveHeadList(&Context->RegionList);
        region = CONTAINING_RECORD(entry, WKD_MEMORY_REGION, ListEntry);
        Context->RegionCount--;
        ExFreePoolWithTag(region, WKD_MEM_POOL_TAG);
    }

    WkdReleasePushLockExclusive(&Context->RegionLock);

    Context->RegionCount = 0;
    Context->MemoryRiskScore = 0;
    Context->SuspiciousOperations = 0;
    Context->ShellcodeDetectionCount = 0;
    Context->InjectionAttemptCount = 0;
    Context->Flags = 0;
    Context->BaselineValid = FALSE;
}

//
// 拍摄并创建内存基线快照（2026-09-10 激活）
// 进程创建回调（PspCreateProcessContextInternal Phase 0.1）调用：
// 此刻地址空间尚未被用户代码污染（仅主 EXE/ntdll 等初始映像），
// 全量枚举 COMMIT 区域灌入 RegionList，形成事件增量/定时一致性校验
// 的参照基线。基线与事件轨共用 RegionList（无独立快照轨）：
// 基线节点标记 WKD_MEM_FLAG_BASELINE。
//
// 读取方式对齐 WkdMemRegionBuildVadMap / ThreadNotification.c
// （ObOpenObjectByPointer + ZwQueryVirtualMemory，无需 KeStackAttachProcess）。
// 幂等：BaselineValid 置位后直接返回。失败非致命：仅丢基线标记，
// 事件轨仍可增量工作（对齐 ModuleContext 双路范式）。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmBuildMemoryRegionBaseline(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    NTSTATUS status;
    PWKD_MEMORY_REGION_CONTEXT ctx;
    PEPROCESS process;
    HANDLE hProcess = NULL;
    PVOID currentAddress = NULL;
    ULONG regionCount = 0;
    ULONG maxRegions;
    SIZE_T returnLength = 0;

    PAGED_CODE();

    if (WkdProcess == NULL || WkdProcess->MemoryRegionContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ctx = WkdProcess->MemoryRegionContext;

    // 幂等：基线已拍（惰性挂载路径可能二次触发）
    if (ctx->BaselineValid) {
        return STATUS_SUCCESS;
    }

    process = WkdProcess->Core.EProcess;
    if (process == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    maxRegions = (ULONG)WKD_MEM_VAD_MAX_REGIONS;

    while (regionCount < maxRegions) {
        MEMORY_BASIC_INFORMATION mbi;
        PVOID nextAddress;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            hProcess, currentAddress, MemoryBasicInformation,
            &mbi, sizeof(mbi), &returnLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        // 基线仅收录 COMMIT 区域（对齐事件轨 State=MEM_COMMIT 语义）
        if (mbi.State == MEM_COMMIT) {
            PWKD_MEMORY_REGION region;

            status = MmpAddMemoryRegionToVirtualAddressSpace(
                ctx,
                (ULONG64)(ULONG_PTR)mbi.BaseAddress,
                mbi.RegionSize,
                mbi.Protect,
                mbi.Type);
            if (NT_SUCCESS(status)) {
                /* 标记基线节点（进程创建期无并发创建/退出，锁内取指安全） */
                WkdAcquirePushLockExclusive(&ctx->RegionLock);
                region = MmpFindMemoryRegion(
                    ctx, (ULONG64)(ULONG_PTR)mbi.BaseAddress);
                if (region != NULL) {
                    region->Flags |= WKD_MEM_FLAG_BASELINE;
                }
                WkdReleasePushLockExclusive(&ctx->RegionLock);
                regionCount++;
            }
            /* 冲突/超限：跳过该区域继续（失败非致命） */
        }

        // 回绕/非前进防护（对齐 WkdMemRegionBuildVadMap c:2702）
        if (mbi.RegionSize == 0) {
            break;
        }
        nextAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if (nextAddress < mbi.BaseAddress || nextAddress <= currentAddress) {
            break;
        }
        currentAddress = nextAddress;
    }

    if (hProcess != NULL) {
        ZwClose(hProcess);
    }

    /* 基线元数据：无论枚举是否中途截断（超上限/非前进），
     * 已灌入的节点即为基线事实——置位使幂等成立 */
    ctx->BaselineValid = TRUE;
    KeQuerySystemTimePrecise(&ctx->BaselineTime);

    return STATUS_SUCCESS;
}

/**************************************************/
/*              查询 API                           */
/**************************************************/

_IRQL_requires_max_(APC_LEVEL)
ULONG
WkdMemRegionGetRiskScore(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context
    )
{
    if (Context == NULL) {
        return 0;
    }
    return (ULONG)Context->MemoryRiskScore;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
MmIsVirtualAddressExecutable(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 Address
    )
{
    PWKD_MEMORY_REGION region;
    BOOLEAN isExecutable = FALSE;

    if (Context == NULL) {
        return FALSE;
    }

    WkdAcquirePushLockShared(&Context->RegionLock);
    region = MmpFindMemoryRegion(Context, Address);
    if (region != NULL) {
        isExecutable = MmpIsExecutableProtection(region->Protection);
    }
    WkdReleasePushLockShared(&Context->RegionLock);

    return isExecutable;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdMemRegionIsProcessHighRisk(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context
    )
{
    if (Context == NULL) {
        return FALSE;
    }
    return (Context->MemoryRiskScore >= 500);
}

/**************************************************/
/*        保护变化怀疑分 / 后备文件查询（补遗）      */
/**************************************************/

//
// 保护变化怀疑分（MmMonitorGetProtectionChangeSuspicion c:2895）
// 返回 0-100：RW→RX +60 / any→RWX +80 / Private +10 / Stack +20
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdMemRegionGetProtectionChangeSuspicion(
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection,
    _In_ WKD_MEMORY_REGION_TYPE RegionType
    )
{
    ULONG score = 0;

    // RW→RX（经典解包/shellcode 模式，c:2908）
    if (MmpIsWritableProtection(OldProtection) &&
        !MmpIsExecutableProtection(OldProtection) &&
        MmpIsExecutableProtection(NewProtection) &&
        !MmpIsWritableProtection(NewProtection)) {
        score += 60;
    }

    // any→RWX（c:2918）
    if (!MmpIsRwxProtection(OldProtection) &&
        MmpIsRwxProtection(NewProtection)) {
        score += 80;
    }

    // 区域类型修正（c:2925-2931）
    if (RegionType == WkdMemRegion_Private) {
        score += 10;
    }
    if (RegionType == WkdMemRegion_Stack) {
        score += 20;
    }

    if (score > 100) {
        score = 100;
    }
    return score;
}

//
// 区域后备文件名查询（MmMonitorGetBackingFile c:2838，FIX MM-C3）
// 死代码：BackingFile 填充依赖对象查询（syscall 轨无文件对象），当前恒 NOT_FOUND
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdMemRegionGetBackingFile(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 Address,
    _Out_writes_bytes_(FileNameSize) PWCHAR FileName,
    _In_ ULONG FileNameSize
    )
{
    PWKD_MEMORY_REGION region;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (FileName == NULL || FileNameSize < sizeof(WCHAR) || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    FileName[0] = L'\0';

    WkdAcquirePushLockShared(&Context->RegionLock);
    region = MmpFindMemoryRegion(Context, Address);
    if (region != NULL && region->BackingFileLength > 0) {
        ULONG copySize = min((ULONG)region->BackingFileLength, FileNameSize - sizeof(WCHAR));
        RtlCopyMemory(FileName, region->BackingFile, copySize);
        FileName[copySize / sizeof(WCHAR)] = L'\0';
        status = STATUS_SUCCESS;
    }
    WkdReleasePushLockShared(&Context->RegionLock);

    return status;
}

/**************************************************/
/*              VAD 枚举工具（对齐 SS）             */
/**************************************************/

//
// 构建进程 VAD 映射（MmMonitorBuildVadMap c:2577）
// 通过 ZwQueryVirtualMemory 全量枚举 COMMIT/RESERVE 区域（1024 上限），
// 统计 Image/Mapped/Private 分类、可执行/可写/RWX/未备份可执行。
// 预留：供后续定时一致性校验/按需查询复用（校验器枚举当前 VAD 与
// RegionList 交叉比对）；基线拍摄已自包含枚举（MmBuildMemoryRegionBaseline），
// 此处仅保留枚举+统计工具定位。
// 读取方式对齐 wkd ThreadNotification.c（ObOpenObjectByPointer +
// ZwQueryVirtualMemory，无需 KeStackAttachProcess）。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdMemRegionBuildVadMap(
    _In_ HANDLE ProcessId,
    _Out_writes_to_(WKD_MEM_VAD_MAX_REGIONS, *EntryCount) PWKD_MEM_VAD_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount,
    _Out_ PWKD_MEM_VAD_MAP Summary
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE hProcess = NULL;
    PVOID currentAddress = NULL;
    ULONG regionCount = 0;
    ULONG maxRegions;

    if (Entries == NULL || EntryCount == NULL || Summary == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntryCount = 0;
    RtlZeroMemory(Summary, sizeof(WKD_MEM_VAD_MAP));
    Summary->ProcessId = ProcessId;

    maxRegions = min(MaxEntries, (ULONG)WKD_MEM_VAD_MAX_REGIONS);

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    while (regionCount < maxRegions) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnLength = 0;
        PVOID nextAddress;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            hProcess, currentAddress, MemoryBasicInformation,
            &mbi, sizeof(mbi), &returnLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (mbi.State != MEM_FREE) {
            PWKD_MEM_VAD_ENTRY entry = &Entries[regionCount];

            entry->BaseAddress = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
            entry->Size = mbi.RegionSize;
            entry->Protection = mbi.Protect;
            entry->VadType = mbi.Type;

            // 区域类型（c:2650）
            if (mbi.Type == MEM_IMAGE) {
                entry->RegionType = WkdMemRegion_Image;
                Summary->TotalVirtualSize += mbi.RegionSize;
            } else if (mbi.Type == MEM_MAPPED) {
                entry->RegionType = WkdMemRegion_Mapped;
            } else {
                entry->RegionType = WkdMemRegion_Private;
            }

            if (mbi.State == MEM_COMMIT) {
                Summary->TotalCommittedSize += mbi.RegionSize;
            }

            if (MmpIsExecutableProtection(mbi.Protect)) {
                Summary->TotalExecutableSize += mbi.RegionSize;
                entry->Flags |= WKD_MEM_VAD_FLAG_EXECUTABLE;
            }
            if (MmpIsWritableProtection(mbi.Protect)) {
                Summary->TotalWritableSize += mbi.RegionSize;
                entry->Flags |= WKD_MEM_VAD_FLAG_WRITABLE;
            }
            if (MmpIsRwxProtection(mbi.Protect)) {
                Summary->TotalRWXSize += mbi.RegionSize;
                entry->Flags |= WKD_MEM_VAD_FLAG_RWX;
            }

            // 未备份可执行（可疑，c:2684）
            if ((mbi.Type == MEM_PRIVATE) && MmpIsExecutableProtection(mbi.Protect)) {
                Summary->UnbackedExecutableCount++;
                entry->Flags |= WKD_MEM_VAD_FLAG_UNBACKED | WKD_MEM_VAD_FLAG_SUSPICIOUS;
            }

            regionCount++;
        }

        // 回绕/非前进防护（c:2702）
        if (mbi.RegionSize == 0) {
            break;
        }
        nextAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if (nextAddress < mbi.BaseAddress || nextAddress <= currentAddress) {
            break;
        }
        currentAddress = nextAddress;
    }

    Summary->VadCount = regionCount;
    *EntryCount = regionCount;

    ZwClose(hProcess);
    return STATUS_SUCCESS;
}
