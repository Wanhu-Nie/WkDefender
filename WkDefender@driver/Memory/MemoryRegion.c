#include "MemoryRegion.h"
#include "../Common/Utils.h"
#include <ntddk.h>
#include <ntstrsafe.h>

//
// Pool tag
//
#define WKD_MEM_POOL_TAG 'gMeM'

//
// MEM_* 常量在内核模式未定义（对齐 SS MemoryMonitor.c 顶部的兼容处理）
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

static BOOLEAN WkdMemRegionIsExecutableProtection(_In_ ULONG Protection);
static BOOLEAN WkdMemRegionIsWritableProtection(_In_ ULONG Protection);
static BOOLEAN WkdMemRegionIsRWXProtection(_In_ ULONG Protection);
static ULONG WkdMemRegionAnalyzeProtectionChange(_In_ ULONG OldProtection, _In_ ULONG NewProtection);
static PWKD_MEM_REGION WkdMemRegionFindRegion(_In_ PWKD_MEM_REGION_STATE State, _In_ ULONG64 Address);
static VOID WkdMemRegionRemoveRegion(_Inout_ PWKD_MEM_REGION_STATE State, _Inout_ PWKD_MEM_REGION Region);
static VOID WkdMemRegionCleanupStaleRegions(_Inout_ PWKD_MEM_REGION_STATE State);
static NTSTATUS WkdMemRegionAddRegion(_Inout_ PWKD_MEM_REGION_STATE State, _In_ ULONG64 BaseAddress, _In_ ULONG64 Size, _In_ ULONG Protection, _In_ ULONG Type);
static VOID WkdMemRegionUpdateProcessRisk(_Inout_ PWKD_MEM_REGION_STATE State);

//
// 4 类事件处理器（对齐 SS MmMonitorHandleAllocation/ProtectionChange/
// CrossProcessWrite/SectionMap，去除 InjectionDetector/HeapSpray/VAD/
// MemoryScanner 委派——wkd 已由 agent IoaInjectionClassifier（#56）/
// IoaHeapSprayDetect（#55）覆盖，此处仅维护区域表 + 轻量预判标志）
//
static VOID WkdMemRegionHandleAllocation(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ HANDLE TargetProcessId, _In_ ULONG64 BaseAddress, _In_ ULONG64 Size, _In_ ULONG Protection, _In_ BOOLEAN IsCrossProcess);
static VOID WkdMemRegionHandleProtectionChange(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ ULONG64 BaseAddress, _In_ ULONG64 Size, _In_ ULONG OldProtection, _In_ ULONG NewProtection, _In_ BOOLEAN IsCrossProcess);
static VOID WkdMemRegionHandleCrossProcessWrite(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ ULONG64 TargetAddress, _In_ ULONG64 Size, _In_opt_ PVOID SourceBuffer);
static VOID WkdMemRegionHandleSectionMap(_Inout_ PWKD_PROCESS Owner, _In_ HANDLE SourceProcessId, _In_ ULONG64 BaseAddress, _In_ ULONG64 ViewSize, _In_ ULONG Protection, _In_ BOOLEAN IsCrossProcess);

/**************************************************/
/*              保护判断辅助（对齐 SS）             */
/**************************************************/

static
BOOLEAN
WkdMemRegionIsExecutableProtection(
    _In_ ULONG Protection
    )
{
    return ((Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

static
BOOLEAN
WkdMemRegionIsWritableProtection(
    _In_ ULONG Protection
    )
{
    return ((Protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

static
BOOLEAN
WkdMemRegionIsRWXProtection(
    _In_ ULONG Protection
    )
{
    return ((Protection & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

//
// 保护变化分析（对齐 SS MmpAnalyzeProtectionChange c:3622）
// 返回：0=不敏感 / 1=RW→RX（经典解包）/ 2=→RWX
//
static
ULONG
WkdMemRegionAnalyzeProtectionChange(
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    )
{
    // RW→RX（经典解包/shellcode 模式）
    if (WkdMemRegionIsWritableProtection(OldProtection) &&
        !WkdMemRegionIsExecutableProtection(OldProtection) &&
        WkdMemRegionIsExecutableProtection(NewProtection)) {
        return 1;
    }

    // any→RWX
    if (!WkdMemRegionIsRWXProtection(OldProtection) &&
        WkdMemRegionIsRWXProtection(NewProtection)) {
        return 2;
    }

    return 0;
}

/**************************************************/
/*              区域表管理（对齐 SS）               */
/**************************************************/

//
// 查找地址所在区域（调用者必须持有 State->RegionLock）
//
static
PWKD_MEM_REGION
WkdMemRegionFindRegion(
    _In_ PWKD_MEM_REGION_STATE State,
    _In_ ULONG64 Address
    )
{
    PLIST_ENTRY entry;
    PWKD_MEM_REGION region;

    entry = State->RegionList.Flink;
    while (entry != &State->RegionList) {
        region = CONTAINING_RECORD(entry, WKD_MEM_REGION, ListEntry);

        if (Address >= region->BaseAddress &&
            Address < region->BaseAddress + region->Size) {
            return region;
        }

        entry = entry->Flink;
    }

    return NULL;
}

static
VOID
WkdMemRegionRemoveRegion(
    _Inout_ PWKD_MEM_REGION_STATE State,
    _Inout_ PWKD_MEM_REGION Region
    )
{
    RemoveEntryList(&Region->ListEntry);
    State->RegionCount--;
    ExFreePoolWithTag(Region, WKD_MEM_POOL_TAG);
}

//
// 清理过期区域（对齐 SS MmpCleanupStaleRegions c:3544）
// 非高风险且超龄（3600s）的区域移除
//
static
VOID
WkdMemRegionCleanupStaleRegions(
    _Inout_ PWKD_MEM_REGION_STATE State
    )
{
    LARGE_INTEGER now;
    ULONG64 maxAge;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;

    KeQuerySystemTimePrecise(&now);
    maxAge = (ULONG64)WKD_MEM_REGION_MAX_AGE_SEC * 10000000ULL;

    WkdAcquirePushLockExclusive(&State->RegionLock);

    entry = State->RegionList.Flink;
    while (entry != &State->RegionList) {
        PWKD_MEM_REGION region;

        nextEntry = entry->Flink;
        region = CONTAINING_RECORD(entry, WKD_MEM_REGION, ListEntry);

        if (!region->IsHighRisk &&
            (ULONG64)(now.QuadPart - region->AllocationTime.QuadPart) > maxAge) {
            WkdMemRegionRemoveRegion(State, region);
        }

        entry = nextEntry;
    }

    WkdReleasePushLockExclusive(&State->RegionLock);
}

//
// 添加区域（对齐 SS MmpAddRegion c:3402）
// 4096 上限 + 过期清理 + 重复地址检测（FIX MM-L1）
//
static
NTSTATUS
WkdMemRegionAddRegion(
    _Inout_ PWKD_MEM_REGION_STATE State,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection,
    _In_ ULONG Type
    )
{
    PWKD_MEM_REGION region;

    // 预检（乐观快速路径）
    if (State->RegionCount >= WKD_MEM_MAX_REGIONS_PER_PROCESS) {
        WkdMemRegionCleanupStaleRegions(State);
        if (State->RegionCount >= WKD_MEM_MAX_REGIONS_PER_PROCESS) {
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    region = (PWKD_MEM_REGION)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              sizeof(WKD_MEM_REGION),
                                              WKD_MEM_POOL_TAG);
    if (region == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(region, sizeof(WKD_MEM_REGION));

    region->BaseAddress = BaseAddress;
    region->Size = Size;
    region->ProcessId = State->ProcessId;
    region->Protection = Protection;
    region->State = MEM_COMMIT;
    region->Type = Type;
    region->Flags = WKD_MEM_FLAG_MONITORED;
    KeQuerySystemTimePrecise(&region->AllocationTime);

    // 区域类型（对齐 SS MmpAddRegion c:3448）
    if (Type == MEM_IMAGE) {
        region->RegionType = WkdMemRegion_Image;
    } else if (Type == MEM_MAPPED) {
        region->RegionType = WkdMemRegion_Mapped;
    } else {
        region->RegionType = WkdMemRegion_Private;
    }

    // RWX 初始保护即高风险
    if (WkdMemRegionIsRWXProtection(Protection)) {
        region->IsHighRisk = TRUE;
    }

    // 锁内二重检查：重复地址 + 数量上限（TOCTOU 防护，FIX MM-L1）
    WkdAcquirePushLockExclusive(&State->RegionLock);

    if (WkdMemRegionFindRegion(State, BaseAddress) != NULL) {
        WkdReleasePushLockExclusive(&State->RegionLock);
        ExFreePoolWithTag(region, WKD_MEM_POOL_TAG);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    if (State->RegionCount >= WKD_MEM_MAX_REGIONS_PER_PROCESS) {
        WkdReleasePushLockExclusive(&State->RegionLock);
        ExFreePoolWithTag(region, WKD_MEM_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&State->RegionList, &region->ListEntry);
    State->RegionCount++;

    WkdReleasePushLockExclusive(&State->RegionLock);

    return STATUS_SUCCESS;
}

//
// 风险聚合（对齐 SS MmpUpdateProcessRisk c:3699）
// MemoryRiskScore = Shellcode×200 + Injection×300 + Suspicious×10，cap 1000
//
static
VOID
WkdMemRegionUpdateProcessRisk(
    _Inout_ PWKD_MEM_REGION_STATE State
    )
{
    ULONG riskScore;

    riskScore  = (ULONG)State->ShellcodeDetectionCount * 200;
    riskScore += (ULONG)State->InjectionAttemptCount * 300;
    riskScore += (ULONG)(State->SuspiciousOperations * 10);

    if (riskScore > 1000) {
        riskScore = 1000;
    }

    State->MemoryRiskScore = riskScore;
}

/**************************************************/
/*              4 类事件处理器（对齐 SS）           */
/**************************************************/

//
// 内存分配（对齐 SS MmMonitorHandleAllocation c:1261）
// 记录区域 + RWX 初始分配预判 + 跨进程注入标记
//
static
VOID
WkdMemRegionHandleAllocation(
    _Inout_ PWKD_PROCESS Owner,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection,
    _In_ BOOLEAN IsCrossProcess
    )
{
    PWKD_MEM_REGION_STATE state;
    NTSTATUS status;

    return;

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    state = &Owner->MemRegionState;

    // 小分配跳过（对齐 SS MinAllocationSizeToTrack=4096）
    if (Size < WKD_MEM_MIN_ALLOC_SIZE_TO_TRACK) {
        return;
    }

    status = WkdMemRegionAddRegion(state, BaseAddress, Size, Protection, MEM_PRIVATE);
    if (!NT_SUCCESS(status)) {
        return;
    }

    // RWX 初始分配 → 高风险 + 高熵（对齐 SS c:1349）
    if (WkdMemRegionIsRWXProtection(Protection)) {
        PWKD_MEM_REGION region;

        WkdAcquirePushLockExclusive(&state->RegionLock);
        region = WkdMemRegionFindRegion(state, BaseAddress);
        if (region != NULL) {
            region->IsHighRisk = TRUE;
            region->Flags |= WKD_MEM_FLAG_HIGH_ENTROPY;
        }
        WkdReleasePushLockExclusive(&state->RegionLock);
    }

    // 跨进程分配 → 可疑 + 注入目标标记（对齐 SS c:1321）
    if (IsCrossProcess) {
        PWKD_MEM_REGION region;

        InterlockedIncrement64(&state->SuspiciousOperations);
        InterlockedOr((volatile LONG*)&state->Flags, WKD_MEM_PROCESS_FLAG_INJECTION_TARGET);

        WkdAcquirePushLockExclusive(&state->RegionLock);
        region = WkdMemRegionFindRegion(state, BaseAddress);
        if (region != NULL) {
            region->Flags |= WKD_MEM_FLAG_INJECTION_DST;
        }
        WkdReleasePushLockExclusive(&state->RegionLock);
    }

    WkdMemRegionUpdateProcessRisk(state);
}

//
// 保护变化（对齐 SS MmMonitorHandleProtectionChange c:1452）
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
    PWKD_MEM_REGION_STATE state;
    PWKD_MEM_REGION region;
    NTSTATUS status;
    ULONG suspicionType;

    return;

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    state = &Owner->MemRegionState;

    WkdAcquirePushLockExclusive(&state->RegionLock);

    region = WkdMemRegionFindRegion(state, BaseAddress);

    if (region == NULL) {
        // 区域未追踪 → 释放锁、添加、重取
        WkdReleasePushLockExclusive(&state->RegionLock);

        status = WkdMemRegionAddRegion(state, BaseAddress, Size, NewProtection, MEM_PRIVATE);
        if (!NT_SUCCESS(status)) {
            return;
        }

        WkdAcquirePushLockExclusive(&state->RegionLock);
        region = WkdMemRegionFindRegion(state, BaseAddress);
    }

    if (region != NULL) {
        region->Protection = NewProtection;
        region->ProtectionChangeCount++;
        KeQuerySystemTimePrecise(&region->LastProtectionChangeTime);

        // W→X 转换（经典解包/shellcode 模式，对齐 SS c:1527）
        if (region->WasWritten && WkdMemRegionIsExecutableProtection(NewProtection)) {
            region->NowExecutable = TRUE;
            region->IsHighRisk = TRUE;
            region->Flags |= WKD_MEM_FLAG_SHELLCODE_SCAN;
        }

        // 镂空指示器：Image 区早期 RWX（对齐 SS c:1536，FIX-19）
        if (region->RegionType == WkdMemRegion_Image &&
            WkdMemRegionIsRWXProtection(NewProtection) &&
            region->ProtectionChangeCount <= 2) {
            InterlockedOr((volatile LONG*)&state->Flags, WKD_MEM_PROCESS_FLAG_HOLLOWING_TARGET);
        }

        // 保护变化分析（RW→RX / →RWX）
        suspicionType = WkdMemRegionAnalyzeProtectionChange(OldProtection, NewProtection);
        if (suspicionType != 0) {
            InterlockedIncrement64(&state->SuspiciousOperations);

            if (suspicionType == 1) {
                region->Flags |= WKD_MEM_FLAG_SHELLCODE_SCAN;
            }
            if (suspicionType == 2) {
                region->IsHighRisk = TRUE;
            }
        }

        // 跨进程保护变化 → 注入目标标记（对齐 SS c:1563）
        if (IsCrossProcess) {
            InterlockedIncrement64(&state->SuspiciousOperations);
            region->Flags |= WKD_MEM_FLAG_INJECTION_DST;
        }
    }

    WkdReleasePushLockExclusive(&state->RegionLock);

    UNREFERENCED_PARAMETER(SourceProcessId);

    WkdMemRegionUpdateProcessRisk(state);
}

//
// 跨进程写入（对齐 SS MmMonitorHandleCrossProcessWrite c:1654）
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
    PWKD_MEM_REGION_STATE state;
    PWKD_MEM_REGION region;
    NTSTATUS status;
    ULONG entropy = 0;
    ULONG readSize;

    return;

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    state = &Owner->MemRegionState;

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

    WkdAcquirePushLockExclusive(&state->RegionLock);

    region = WkdMemRegionFindRegion(state, TargetAddress);

    if (region == NULL) {
        WkdReleasePushLockExclusive(&state->RegionLock);

        status = WkdMemRegionAddRegion(state, TargetAddress, Size, 0, MEM_PRIVATE);
        if (!NT_SUCCESS(status)) {
            return;
        }

        WkdAcquirePushLockExclusive(&state->RegionLock);
        region = WkdMemRegionFindRegion(state, TargetAddress);
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

    WkdReleasePushLockExclusive(&state->RegionLock);

    InterlockedIncrement64(&state->SuspiciousOperations);
    InterlockedIncrement(&state->InjectionAttemptCount);
    InterlockedOr((volatile LONG*)&state->Flags, WKD_MEM_PROCESS_FLAG_INJECTION_TARGET);
    WkdMemRegionUpdateProcessRisk(state);

    UNREFERENCED_PARAMETER(SourceProcessId);
}

//
// Section 映射（对齐 SS MmMonitorHandleSectionMap c:1774）
// 记录 MAPPED 区域 + 跨进程注入标记
//
static
VOID
WkdMemRegionHandleSectionMap(
    _Inout_ PWKD_PROCESS Owner,
    _In_ HANDLE SourceProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 ViewSize,
    _In_ ULONG Protection,
    _In_ BOOLEAN IsCrossProcess
    )
{
    PWKD_MEM_REGION_STATE state;
    NTSTATUS status;

    return;

    if (Owner == NULL || Owner->SecurityContext == NULL) {
        return;
    }

    state = &Owner->MemRegionState;

    status = WkdMemRegionAddRegion(state, BaseAddress, ViewSize, Protection, MEM_MAPPED);
    if (!NT_SUCCESS(status)) {
        return;
    }

    // 跨进程映射 → 注入目标标记（对齐 SS c:1850）
    if (IsCrossProcess) {
        PWKD_MEM_REGION region;

        InterlockedIncrement64(&state->SuspiciousOperations);

        WkdAcquirePushLockExclusive(&state->RegionLock);
        region = WkdMemRegionFindRegion(state, BaseAddress);
        if (region != NULL) {
            region->Flags |= WKD_MEM_FLAG_INJECTION_DST;
            if (WkdMemRegionIsExecutableProtection(Protection)) {
                region->IsHighRisk = TRUE;
            }
        }
        WkdReleasePushLockExclusive(&state->RegionLock);

        WkdMemRegionUpdateProcessRisk(state);
    }

    UNREFERENCED_PARAMETER(SourceProcessId);
}

/**************************************************/
/*              便捷入口（SyscallHijack 调用）      */
/**************************************************/

//
// 跨进程注入源标记（对齐 SS MM_PROCESS_FLAG_INJECTION_SOURCE）
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

    return;
    
    if (SourceProcessId == TargetProcessId) {
        return;
    }

    sourceProc = PsLookupWkdProcessByProcessId(SourceProcessId);
    if (sourceProc == NULL) {
        return;
    }

    InterlockedOr((volatile LONG*)&sourceProc->MemRegionState.Flags,
                  WKD_MEM_PROCESS_FLAG_INJECTION_SOURCE);
    PsDereferenceWkdProcess(sourceProc);
}

//
// 分配（对齐 SS：区域归属 = 内存所属进程）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackAllocation(
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

    isCross = (SourceProcessId != TargetProcessId);
    ownerPid = isCross ? TargetProcessId : SourceProcessId;

    owner = PsLookupWkdProcessByProcessId(ownerPid);
    if (owner == NULL) {
        return;
    }

    WkdMemRegionHandleAllocation(owner, SourceProcessId, TargetProcessId,
                                 BaseAddress, Size, Protection, isCross);

    /* 跨进程注入源标记（对齐 SS MM_PROCESS_FLAG_INJECTION_SOURCE） */
    if (isCross) {
        WkdMemRegionMarkInjectionSource(SourceProcessId, TargetProcessId);
    }

    PsDereferenceWkdProcess(owner);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackProtectionChange(
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

    owner = PsLookupWkdProcessByProcessId(ProcessId);
    if (owner == NULL) {
        return;
    }

    WkdMemRegionHandleProtectionChange(owner, SourceProcessId, BaseAddress, Size,
                                       OldProtection, NewProtection, IsCrossProcess);

    /* 跨进程注入源标记（对齐 SS MM_PROCESS_FLAG_INJECTION_SOURCE） */
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

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackSectionMap(
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

    ownerPid = IsCrossProcess ? TargetProcessId : SourceProcessId;

    owner = PsLookupWkdProcessByProcessId(ownerPid);
    if (owner == NULL) {
        return;
    }

    WkdMemRegionHandleSectionMap(owner, SourceProcessId, BaseAddress, ViewSize,
                                 Protection, IsCrossProcess);

    /* 跨进程注入源标记（对齐 SS MM_PROCESS_FLAG_INJECTION_SOURCE） */
    if (IsCrossProcess) {
        WkdMemRegionMarkInjectionSource(SourceProcessId, TargetProcessId);
    }

    PsDereferenceWkdProcess(owner);
}

/**************************************************/
/*              生命周期（PspDestroyProcess 调用）  */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionCleanupProcess(
    _Inout_ PWKD_MEM_REGION_STATE State
    )
{
    PLIST_ENTRY entry;

    if (!State) return;

    WkdAcquirePushLockExclusive(&State->RegionLock);

    while (!IsListEmpty(&State->RegionList)) {
        PWKD_MEM_REGION region;

        entry = RemoveHeadList(&State->RegionList);
        region = CONTAINING_RECORD(entry, WKD_MEM_REGION, ListEntry);
        State->RegionCount--;
        ExFreePoolWithTag(region, WKD_MEM_POOL_TAG);
    }

    WkdReleasePushLockExclusive(&State->RegionLock);

    State->RegionCount = 0;
    State->MemoryRiskScore = 0;
    State->SuspiciousOperations = 0;
    State->ShellcodeDetectionCount = 0;
    State->InjectionAttemptCount = 0;
    State->Flags = 0;
}

/**************************************************/
/*              查询 API                           */
/**************************************************/

_IRQL_requires_max_(APC_LEVEL)
ULONG
WkdMemRegionGetRiskScore(
    _In_ PWKD_MEM_REGION_STATE State
    )
{
    if (State == NULL) {
        return 0;
    }
    return (ULONG)State->MemoryRiskScore;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdMemRegionIsAddressExecutable(
    _In_ PWKD_MEM_REGION_STATE State,
    _In_ ULONG64 Address
    )
{
    PWKD_MEM_REGION region;
    BOOLEAN isExecutable = FALSE;

    if (State == NULL) {
        return FALSE;
    }

    WkdAcquirePushLockShared(&State->RegionLock);
    region = WkdMemRegionFindRegion(State, Address);
    if (region != NULL) {
        isExecutable = WkdMemRegionIsExecutableProtection(region->Protection);
    }
    WkdReleasePushLockShared(&State->RegionLock);

    return isExecutable;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdMemRegionIsProcessHighRisk(
    _In_ PWKD_MEM_REGION_STATE State
    )
{
    if (State == NULL) {
        return FALSE;
    }
    return (State->MemoryRiskScore >= 500);
}

/**************************************************/
/*        保护变化怀疑分 / 后备文件查询（补遗）      */
/**************************************************/

//
// 保护变化怀疑分（对齐 SS MmMonitorGetProtectionChangeSuspicion c:2895）
// 返回 0-100：RW→RX +60 / any→RWX +80 / Private +10 / Stack +20
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdMemRegionGetProtectionChangeSuspicion(
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection,
    _In_ WKD_MEM_REGION_TYPE RegionType
    )
{
    ULONG score = 0;

    // RW→RX（经典解包/shellcode 模式，对齐 SS c:2908）
    if (WkdMemRegionIsWritableProtection(OldProtection) &&
        !WkdMemRegionIsExecutableProtection(OldProtection) &&
        WkdMemRegionIsExecutableProtection(NewProtection) &&
        !WkdMemRegionIsWritableProtection(NewProtection)) {
        score += 60;
    }

    // any→RWX（对齐 SS c:2918）
    if (!WkdMemRegionIsRWXProtection(OldProtection) &&
        WkdMemRegionIsRWXProtection(NewProtection)) {
        score += 80;
    }

    // 区域类型修正（对齐 SS c:2925-2931）
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
// 区域后备文件名查询（对齐 SS MmMonitorGetBackingFile c:2838，FIX MM-C3）
// 死代码：BackingFile 填充依赖对象查询（syscall 轨无文件对象），当前恒 NOT_FOUND
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdMemRegionGetBackingFile(
    _In_ PWKD_MEM_REGION_STATE State,
    _In_ ULONG64 Address,
    _Out_writes_bytes_(FileNameSize) PWCHAR FileName,
    _In_ ULONG FileNameSize
    )
{
    PWKD_MEM_REGION region;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (FileName == NULL || FileNameSize < sizeof(WCHAR) || State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    FileName[0] = L'\0';

    WkdAcquirePushLockShared(&State->RegionLock);
    region = WkdMemRegionFindRegion(State, Address);
    if (region != NULL && region->BackingFileLength > 0) {
        ULONG copySize = min((ULONG)region->BackingFileLength, FileNameSize - sizeof(WCHAR));
        RtlCopyMemory(FileName, region->BackingFile, copySize);
        FileName[copySize / sizeof(WCHAR)] = L'\0';
        status = STATUS_SUCCESS;
    }
    WkdReleasePushLockShared(&State->RegionLock);

    return status;
}

/**************************************************/
/*              VAD 枚举工具（对齐 SS）             */
/**************************************************/

//
// 构建进程 VAD 映射（对齐 SS MmMonitorBuildVadMap c:2577）
// 通过 ZwQueryVirtualMemory 全量枚举 COMMIT/RESERVE 区域（1024 上限），
// 统计 Image/Mapped/Private 分类、可执行/可写/RWX/未备份可执行。
// 死代码：供按需查询/后续扫描线程，当前无调用者。
// 读取方式对齐 wkd ThreadNotify.c（ObOpenObjectByPointer +
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

            // 区域类型（对齐 SS c:2650）
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

            if (WkdMemRegionIsExecutableProtection(mbi.Protect)) {
                Summary->TotalExecutableSize += mbi.RegionSize;
                entry->Flags |= WKD_MEM_VAD_FLAG_EXECUTABLE;
            }
            if (WkdMemRegionIsWritableProtection(mbi.Protect)) {
                Summary->TotalWritableSize += mbi.RegionSize;
                entry->Flags |= WKD_MEM_VAD_FLAG_WRITABLE;
            }
            if (WkdMemRegionIsRWXProtection(mbi.Protect)) {
                Summary->TotalRWXSize += mbi.RegionSize;
                entry->Flags |= WKD_MEM_VAD_FLAG_RWX;
            }

            // 未备份可执行（可疑，对齐 SS c:2684）
            if ((mbi.Type == MEM_PRIVATE) && WkdMemRegionIsExecutableProtection(mbi.Protect)) {
                Summary->UnbackedExecutableCount++;
                entry->Flags |= WKD_MEM_VAD_FLAG_UNBACKED | WKD_MEM_VAD_FLAG_SUSPICIOUS;
            }

            regionCount++;
        }

        // 回绕/非前进防护（对齐 SS c:2702）
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
