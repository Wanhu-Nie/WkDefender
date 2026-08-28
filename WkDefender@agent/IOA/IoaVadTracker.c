/**************************************************/
/*  IoaVadTracker — VAD 快照对比检测（agent）       */
/*  ShadowStrike VadTracker 迁移 2026-08            */
/*  重功能实现非复制。功能面补遗说明见头文件 banner。*/
/**************************************************/

#include "IoaVadTracker.h"
#include "../Memory/MemoryScan.h"   /* MsEnumerateRegions / MsBuildModuleSet / MsDetectShellcode */
#include "../Common/Utils.h"        /* UtHeapAlloc (IoaVad_AllocAlert) */
#include <stdlib.h>                 /* qsort / free */
#include <wchar.h>                  /* swprintf_s / wcscpy_s (IoaVad_AllocAlert) */

//
// 保护判断辅助（对齐 SS SS_IS_EXECUTABLE/WRITABLE/RWX）
//
static BOOLEAN IoaVadIsExecutableProtection(ULONG Protection)
{
    return ((Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

static BOOLEAN IoaVadIsWritableProtection(ULONG Protection)
{
    return ((Protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

/* 快照条目按 BaseAddress 排序（快照对比前置） */
static int __cdecl IoaVadCompareRegionBase(const void* a, const void* b)
{
    const WKD_VAD_REGION_ENTRY* ra = (const WKD_VAD_REGION_ENTRY*)a;
    const WKD_VAD_REGION_ENTRY* rb = (const WKD_VAD_REGION_ENTRY*)b;

    if (ra->BaseAddress < rb->BaseAddress) return -1;
    if (ra->BaseAddress > rb->BaseAddress) return 1;
    return 0;
}

/* 内容采样长度（对齐堆喷门控采样 4KB） */
#define WKD_VAD_CONTENT_SAMPLE_SIZE   4096

/* 全局统计（对齐 SS VAD_TRACKER.Stats，快照构建/对比时累计） */
static WKD_VAD_STATS g_IoaVadStats;

/**************************************************/
/*               内部辅助                           */
/**************************************************/

static
LARGE_INTEGER
IoaVadGetNow(
    VOID
    )
/*++
Routine Description:
    当前系统时间 (FILETIME 100ns 单位, 对齐 SS KeQuerySystemTimePrecise,
    wkd IoaHsGetNow 同款)。
--*/
{
    FILETIME ft;
    LARGE_INTEGER li;

    GetSystemTimeAsFileTime(&ft);
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = (LONG)ft.dwHighDateTime;
    return li;
}

static
BOOLEAN
IoaVadOverlapsModule(
    _In_ const WKD_MEM_MODULE_SET* Set,
    _In_ ULONG_PTR Base,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    区域 [Base, Base+Size) 与已加载模块任一 [MBase, MBase+MSize) 区间重叠判定。
    MsIsAddrInModuleSet 只测单点, 此处做区间重叠（OverlapWithImage 判定基础）。
    模块集为 PEB 可见模块 (EnumProcessModules), 隐藏/反射模块不可见,
    符合"与可见已加载镜像重叠"的检测语义。
--*/
{
    ULONG i;
    ULONG_PTR end = Base + Size;

    for (i = 0; i < Set->Count; i++) {
        ULONG_PTR mEnd = Set->Bases[i] + Set->Sizes[i];

        if (Base < mEnd && end > Set->Bases[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*              单区域怀疑度分析                    */
/**************************************************/

_Use_decl_annotations_
BOOL
IoaVad_AnalyzeRegion(
    _In_  const WKD_VAD_REGION_ENTRY* Region,
    _Out_opt_ PULONG SuspicionFlags,
    _Out_opt_ PULONG SuspicionScore
    )
/*++
Routine Description:
    单区域静态怀疑度分析（对齐 SS VadpAnalyzeRegionSuspicion L2063 +
    VadpCalculateSuspicionScore L2135）。静态可实现 7 项：
      RWX(100) / UnbackedExecute(80) / LargePrivate(20) / GuardRegion(30) /
      RecentRWtoRX(70, 静态 AllocationProtect 判) / SuspiciousBase(25) /
      ProtectionMismatch(40)。
    OverlapWithImage(60) 由 SnapshotProcess 补判（需模块集上下文）；
    ShellcodePattern(90) 由 IoaVad_ScanRegionContent 门控内容扫描；
    HiddenRegion(100) 需内核 VAD/PTE 比对，死代码标注。
--*/
{
    ULONG flags = 0;
    ULONG score = 0;
    BOOLEAN isExec;
    BOOLEAN isWrite;
    BOOLEAN allocWrite;

    if (Region == NULL) return FALSE;

    isExec = IoaVadIsExecutableProtection(Region->Protection);
    isWrite = IoaVadIsWritableProtection(Region->Protection);
    allocWrite = IoaVadIsWritableProtection(Region->AllocationProtect);

    /* RWX（读存在即视为有读，PAGE_NOACCESS 除外） */
    if (isExec && isWrite && (Region->Protection != PAGE_NOACCESS)) {
        flags |= WKD_VAD_SUSPICION_RWX;
        score += 100;
    }

    /* 未备份可执行（Private + 执行 + 无后备） */
    if (Region->Type == WkdMemType_Private && isExec && !Region->IsBacked) {
        flags |= WKD_VAD_SUSPICION_UNBACKED_EXEC;
        score += 80;
    }

    /* 大私有区域（>16MB） */
    if (Region->Type == WkdMemType_Private &&
        Region->RegionSize > WKD_VAD_LARGE_REGION_THRESHOLD) {
        flags |= WKD_VAD_SUSPICION_LARGE_PRIVATE;
        score += 20;
    }

    /* 守卫页模式（栈转移指示） */
    if (Region->Protection & PAGE_GUARD) {
        flags |= WKD_VAD_SUSPICION_GUARD_REGION;
        score += 30;
    }

    /* RW→RX（解包/解密） */
    if (allocWrite && !IoaVadIsExecutableProtection(Region->AllocationProtect) &&
        isExec && !isWrite) {
        flags |= WKD_VAD_SUSPICION_RECENT_RW_TO_RX;
        score += 70;
    }

    /* 可疑基址（<0x10000） */
    if ((ULONG_PTR)Region->BaseAddress < WKD_VAD_SUSPICIOUS_BASE_LOW) {
        flags |= WKD_VAD_SUSPICION_SUSPICIOUS_BASE;
        score += 25;
    }

    /* 保护不匹配（VirtualProtect 已使用，对齐 SS VAD2-L1 fix） */
    if (Region->Protection != Region->AllocationProtect) {
        flags |= WKD_VAD_SUSPICION_PROTECTION_MISMATCH;
        score += 40;
    }

    if (SuspicionFlags) *SuspicionFlags = flags;
    if (SuspicionScore) *SuspicionScore = score;
    return TRUE;
}

/**************************************************/
/*              进程快照构建                        */
/**************************************************/

_Use_decl_annotations_
BOOL
IoaVad_SnapshotProcess(
    _In_  DWORD ProcessId,
    _Out_ PWKD_VAD_SNAPSHOT Snapshot
    )
/*++
Routine Description:
    构建进程 VAD 快照：复用 MsEnumerateRegions（VirtualQueryEx 枚举 COMMIT
    区域）→ 映射为 WKD_VAD_REGION_ENTRY + 每区域怀疑度评分（含 OverlapWithImage
    模块集重叠判定）+ 进程级统计累计 + 按 BaseAddress 排序（快照对比前置）。
    对齐 SS VadpScanProcessVad 的枚举+评分阶段 + VAD_PROCESS_CONTEXT 统计字段。
--*/
{
    WKD_MEMORY_REGION regions[WKD_VAD_SNAPSHOT_MAX_ENTRIES];
    WKD_MEM_MODULE_SET moduleSet;
    BOOLEAN moduleSetOk;
    ULONG count = 0;
    ULONG i;

    if (Snapshot == NULL) return FALSE;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Snapshot->ProcessId = ProcessId;

    if (MsEnumerateRegions(ProcessId, regions, WKD_VAD_SNAPSHOT_MAX_ENTRIES, &count)
        != STATUS_SUCCESS) {
        return FALSE;
    }

    /* 模块集一次构建（EnumProcessModules），供 OverlapWithImage 判定 */
    moduleSetOk = MsBuildModuleSet(ProcessId, &moduleSet);

    for (i = 0; i < count; i++) {
        WKD_VAD_REGION_ENTRY* e = &Snapshot->Regions[Snapshot->RegionCount];

        e->BaseAddress = regions[i].BaseAddress;
        e->RegionSize = regions[i].RegionSize;
        e->Protection = regions[i].Protection;
        e->AllocationProtect = regions[i].AllocationProtect;
        e->Type = (ULONG)regions[i].Type;
        e->State = MEM_COMMIT;
        e->IsBacked = (regions[i].Type == WkdMemType_Image ||
                       regions[i].Type == WkdMemType_Mapped);

        IoaVad_AnalyzeRegion(e, &e->SuspicionFlags, &e->SuspicionScore);

        /* OverlapWithImage(60)：非 Image 区域与已加载镜像重叠且可执行
           （镜像内注入/code cave 信号；正常 Image 区域 Type==Image 不命中）。
           SS 仅评分表预留分值未置位，wkd 用 MsBuildModuleSet 真实现。 */
        if (moduleSetOk &&
            e->Type != WkdMemType_Image &&
            IoaVadIsExecutableProtection(e->Protection) &&
            IoaVadOverlapsModule(&moduleSet, e->BaseAddress, e->RegionSize)) {
            e->SuspicionFlags |= WKD_VAD_SUSPICION_OVERLAP_WITH_IMAGE;
            e->SuspicionScore += 60;
        }

        /* 进程级统计（对齐 SS VAD_PROCESS_CONTEXT 统计字段 L1929-1948） */
        if (e->SuspicionFlags & WKD_VAD_SUSPICION_RWX) {
            Snapshot->RWXRegionCount++;
            InterlockedIncrement64((volatile LONG64*)&g_IoaVadStats.RWXDetections);
        }
        if (e->SuspicionFlags & WKD_VAD_SUSPICION_UNBACKED_EXEC) {
            Snapshot->UnbackedExecuteCount++;
        }
        switch (regions[i].Type) {
        case WkdMemType_Private: Snapshot->TotalPrivateSize += regions[i].RegionSize; break;
        case WkdMemType_Mapped:  Snapshot->TotalMappedSize  += regions[i].RegionSize; break;
        case WkdMemType_Image:   Snapshot->TotalImageSize   += regions[i].RegionSize; break;
        default: break;
        }
        if (IoaVadIsExecutableProtection(e->Protection)) {
            Snapshot->TotalExecutableSize += regions[i].RegionSize;
        }

        /* 对齐 SS VadpQueryMemoryRegions L1950: SuspiciousRegionCount 计所有
           score>0 区域 (SS 阈值常量 VAD_SUSPICIOUS_REGION_THRESHOLD=100 定义
           但计数实际用 >0, 未用阈值) */
        if (e->SuspicionScore > 0) {
            Snapshot->SuspiciousRegionCount++;
        }
        Snapshot->TotalSuspicionScore += e->SuspicionScore;
        Snapshot->RegionCount++;
    }

    Snapshot->SnapshotTime = IoaVadGetNow();

    /* 按 BaseAddress 排序（快照对比需要，对齐 SS 有序区域链表） */
    qsort(Snapshot->Regions, Snapshot->RegionCount, sizeof(WKD_VAD_REGION_ENTRY),
          IoaVadCompareRegionBase);

    /* 全局统计（对齐 SS Stats.TotalScans/SuspiciousRegions/TotalRegions） */
    InterlockedIncrement64((volatile LONG64*)&g_IoaVadStats.TotalScans);
    InterlockedAdd64((volatile LONG64*)&g_IoaVadStats.SuspiciousRegions,
                     Snapshot->SuspiciousRegionCount);
    InterlockedAdd64((volatile LONG64*)&g_IoaVadStats.TotalRegions,
                     Snapshot->RegionCount);

    return TRUE;
}

/**************************************************/
/*              快照对比                           */
/**************************************************/

_Use_decl_annotations_
ULONG
IoaVad_CompareSnapshots(
    _In_  const WKD_VAD_SNAPSHOT* Old,
    _In_  const WKD_VAD_SNAPSHOT* New,
    _Out_writes_to_(MaxChanges, *) PWKD_VAD_CHANGE Changes,
    _In_  ULONG MaxChanges
    )
/*++
Routine Description:
    快照对比（对齐 SS VadpCompareSnapshots L2364 merge-compare）：
    两个按 BaseAddress 排序的数组双指针合并比较，输出创建/删除/
    保护变化/大小变化事件。

    跨快照时序判定（对齐 SS VadpCompareSnapshots L2481-2545）：
      - ProtectionChanged: Old 可写+不可执行 → New 可执行 = 动态 RW→RX 解包
        (RecentRWtoRX +70); New 为 RWX = 新 RWX (+100)。
      - RegionCreated: New 区域 Private + 可执行 = UnbackedExec (标注 0x02,
        事件分 = 80 对齐 SS 赋值语义)。
      - SuspicionScore = 纯变更语义分 (ProtectionChanged 0+70+100 / Created
        UnbackedExec=80 / Grew·Shrunk·Deleted 恒 0), 不含区域静态分。
--*/
{
    ULONG ci = 0;
    ULONG oi = 0;
    ULONG changeCount = 0;

    if (Old == NULL || New == NULL || Changes == NULL || MaxChanges == 0) {
        return 0;
    }

    while (ci < New->RegionCount && oi < Old->RegionCount) {
        ULONG_PTR curBase = New->Regions[ci].BaseAddress;
        ULONG_PTR oldBase = Old->Regions[oi].BaseAddress;

        if (curBase == oldBase) {
            /* 同一区域：检查保护/大小变化 */
            if (New->Regions[ci].Protection != Old->Regions[oi].Protection &&
                changeCount < MaxChanges) {
                ULONG tFlags = 0;
                ULONG tScore = 0;   /* 对齐 SS: 事件分 = 纯变更语义分 (0+70+100), 不含区域静态分 */
                BOOLEAN oldW = IoaVadIsWritableProtection(Old->Regions[oi].Protection);
                BOOLEAN oldX = IoaVadIsExecutableProtection(Old->Regions[oi].Protection);
                BOOLEAN newX = IoaVadIsExecutableProtection(New->Regions[ci].Protection);

                /* 动态 RW→RX（真实解包时序，对齐 SS L2481-2486） */
                if (oldW && !oldX && newX) {
                    tFlags |= WKD_VAD_SUSPICION_RECENT_RW_TO_RX;
                    tScore += 70;
                }
                /* 新 RWX（对齐 SS L2491-2495） */
                if (newX &&
                    IoaVadIsWritableProtection(New->Regions[ci].Protection) &&
                    New->Regions[ci].Protection != PAGE_NOACCESS) {
                    tFlags |= WKD_VAD_SUSPICION_RWX;
                    tScore += 100;
                }

                Changes[changeCount].ChangeType      = WkdVadChange_ProtectionChanged;
                Changes[changeCount].BaseAddress     = curBase;
                Changes[changeCount].RegionSize      = New->Regions[ci].RegionSize;
                Changes[changeCount].OldProtection   = Old->Regions[oi].Protection;
                Changes[changeCount].NewProtection   = New->Regions[ci].Protection;
                Changes[changeCount].SuspicionFlags  = tFlags;
                Changes[changeCount].SuspicionScore  = tScore;
                Changes[changeCount].Timestamp       = IoaVadGetNow();
                changeCount++;

                InterlockedIncrement64((volatile LONG64*)&g_IoaVadStats.ProtectionChanges);
            }
            if (New->Regions[ci].RegionSize != Old->Regions[oi].RegionSize &&
                changeCount < MaxChanges) {
                Changes[changeCount].ChangeType =
                    (New->Regions[ci].RegionSize > Old->Regions[oi].RegionSize) ?
                    WkdVadChange_RegionGrew : WkdVadChange_RegionShrunk;
                Changes[changeCount].BaseAddress     = curBase;
                Changes[changeCount].RegionSize      = New->Regions[ci].RegionSize;
                Changes[changeCount].OldProtection   = Old->Regions[oi].Protection;
                Changes[changeCount].NewProtection   = New->Regions[ci].Protection;
                Changes[changeCount].SuspicionFlags  = 0;
                Changes[changeCount].SuspicionScore  = 0;   /* 对齐 SS: Grew/Shrunk 事件无变更分 */
                Changes[changeCount].Timestamp       = IoaVadGetNow();
                changeCount++;
            }
            ci++;
            oi++;
        } else if (curBase < oldBase) {
            /* 新区区域：Private + 可执行 = UnbackedExec 标注 + 事件分 80
               （对齐 SS L2541-2545 赋值语义, 事件分 = 纯变更语义分） */
            if (changeCount < MaxChanges) {
                ULONG tFlags = 0;
                ULONG tScore = 0;

                if (New->Regions[ci].Type == WkdMemType_Private &&
                    IoaVadIsExecutableProtection(New->Regions[ci].Protection)) {
                    tFlags |= WKD_VAD_SUSPICION_UNBACKED_EXEC;
                    tScore = 80;
                }

                Changes[changeCount].ChangeType      = WkdVadChange_RegionCreated;
                Changes[changeCount].BaseAddress     = curBase;
                Changes[changeCount].RegionSize      = New->Regions[ci].RegionSize;
                Changes[changeCount].OldProtection   = 0;
                Changes[changeCount].NewProtection   = New->Regions[ci].Protection;
                Changes[changeCount].SuspicionFlags  = tFlags;
                Changes[changeCount].SuspicionScore  = tScore;
                Changes[changeCount].Timestamp       = IoaVadGetNow();
                changeCount++;
            }
            ci++;
        } else {
            /* 旧区区域删除 */
            if (changeCount < MaxChanges) {
                Changes[changeCount].ChangeType      = WkdVadChange_RegionDeleted;
                Changes[changeCount].BaseAddress     = oldBase;
                Changes[changeCount].RegionSize      = Old->Regions[oi].RegionSize;
                Changes[changeCount].OldProtection   = Old->Regions[oi].Protection;
                Changes[changeCount].NewProtection   = 0;
                Changes[changeCount].SuspicionFlags  = 0;
                Changes[changeCount].SuspicionScore  = 0;   /* 对齐 SS: Deleted 事件无变更分 */
                Changes[changeCount].Timestamp       = IoaVadGetNow();
                changeCount++;
            }
            oi++;
        }
    }

    /* 剩余新区域（Created，含 UnbackedExec 标注, 事件分 = 80/0 对齐 SS） */
    while (ci < New->RegionCount && changeCount < MaxChanges) {
        ULONG tFlags = 0;
        ULONG tScore = 0;

        if (New->Regions[ci].Type == WkdMemType_Private &&
            IoaVadIsExecutableProtection(New->Regions[ci].Protection)) {
            tFlags |= WKD_VAD_SUSPICION_UNBACKED_EXEC;
            tScore = 80;
        }

        Changes[changeCount].ChangeType      = WkdVadChange_RegionCreated;
        Changes[changeCount].BaseAddress     = New->Regions[ci].BaseAddress;
        Changes[changeCount].RegionSize      = New->Regions[ci].RegionSize;
        Changes[changeCount].OldProtection   = 0;
        Changes[changeCount].NewProtection   = New->Regions[ci].Protection;
        Changes[changeCount].SuspicionFlags  = tFlags;
        Changes[changeCount].SuspicionScore  = tScore;
        Changes[changeCount].Timestamp       = IoaVadGetNow();
        changeCount++;
        ci++;
    }

    /* 剩余旧区域（Deleted） */
    while (oi < Old->RegionCount && changeCount < MaxChanges) {
        Changes[changeCount].ChangeType      = WkdVadChange_RegionDeleted;
        Changes[changeCount].BaseAddress     = Old->Regions[oi].BaseAddress;
        Changes[changeCount].RegionSize      = Old->Regions[oi].RegionSize;
        Changes[changeCount].OldProtection   = Old->Regions[oi].Protection;
        Changes[changeCount].NewProtection   = 0;
        Changes[changeCount].SuspicionFlags  = 0;
        Changes[changeCount].SuspicionScore  = 0;   /* 对齐 SS: Deleted 事件无变更分 */
        Changes[changeCount].Timestamp       = IoaVadGetNow();
        changeCount++;
        oi++;
    }

    return changeCount;
}

/**************************************************/
/*              可疑区域查询                        */
/**************************************************/

_Use_decl_annotations_
ULONG
IoaVad_GetSuspiciousRegions(
    _In_  const WKD_VAD_SNAPSHOT* Snapshot,
    _In_  ULONG MinScore,
    _Out_writes_to_(MaxEntries, *) PWKD_VAD_REGION_ENTRY Out,
    _In_  ULONG MaxEntries
    )
{
    ULONG i;
    ULONG count = 0;

    if (Snapshot == NULL || Out == NULL) return 0;

    for (i = 0; i < Snapshot->RegionCount && count < MaxEntries; i++) {
        if (Snapshot->Regions[i].SuspicionScore >= MinScore) {
            Out[count++] = Snapshot->Regions[i];
        }
    }
    return count;
}

/**************************************************/
/*              查询 API 面（功能补遗）             */
/**************************************************/

_Use_decl_annotations_
BOOL
IoaVad_FindRegion(
    _In_  const WKD_VAD_SNAPSHOT* Snapshot,
    _In_  ULONG_PTR Address,
    _Out_opt_ PWKD_VAD_REGION_ENTRY Region
    )
/*++
Routine Description:
    地址 → 区域查找（对齐 SS VadpFindRegion L1725/VadGetRegionInfo L1056）：
    快照已按 BaseAddress 排序，二分定位最后一个 BaseAddress <= Address
    的区域，校验是否落在区间内。VAD 区域天然不重叠，判定无歧义。
--*/
{
    ULONG lo;
    ULONG hi;

    if (Snapshot == NULL) {
        return FALSE;
    }

    lo = 0;
    hi = Snapshot->RegionCount;

    while (lo < hi) {
        ULONG mid = lo + (hi - lo) / 2;

        if (Snapshot->Regions[mid].BaseAddress <= Address) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    /* lo 为第一个 BaseAddress > Address 的下标；候选为 lo-1 */
    if (lo > 0) {
        const WKD_VAD_REGION_ENTRY* e = &Snapshot->Regions[lo - 1];

        if (Address >= e->BaseAddress && Address < e->BaseAddress + e->RegionSize) {
            if (Region != NULL) {
                *Region = *e;
            }
            return TRUE;
        }
    }

    return FALSE;
}

_Use_decl_annotations_
ULONG
IoaVad_EnumerateRegions(
    _In_  const WKD_VAD_SNAPSHOT* Snapshot,
    _In_  WKD_VAD_REGION_FILTER Filter,
    _In_opt_ PVOID Context,
    _Out_writes_to_(MaxRegions, *) PWKD_VAD_REGION_ENTRY Regions,
    _In_  ULONG MaxRegions
    )
/*++
Routine Description:
    过滤器枚举（对齐 SS VadEnumerateRegions L1373）：返回 value copies，
    Filter 命中即拷贝，计数上限截断。
--*/
{
    ULONG i;
    ULONG count = 0;

    if (Snapshot == NULL || Filter == NULL || Regions == NULL || MaxRegions == 0) {
        return 0;
    }

    for (i = 0; i < Snapshot->RegionCount && count < MaxRegions; i++) {
        if (Filter(&Snapshot->Regions[i], Context)) {
            Regions[count++] = Snapshot->Regions[i];
        }
    }

    return count;
}

/**************************************************/
/*          ShellcodePattern 门控内容扫描          */
/**************************************************/

_Use_decl_annotations_
BOOL
IoaVad_ScanRegionContent(
    _In_  DWORD ProcessId,
    _Inout_ PWKD_VAD_REGION_ENTRY Region
    )
/*++
Routine Description:
    ShellcodePattern(90) 门控内容扫描（对齐 SS 评分表预留分值 L2153，SS
    分析函数从未置位；wkd 用 MsReadMemory + MsDetectShellcode 真实现）：
    仅对已命中高怀疑标志（UnbackedExec/RWX/RecentRWtoRX/OverlapWithImage）
    的区域做 4KB 样本二次确认，命中置 ContainsShellcode + 置位加分。
    门控条件函数内自带，防误用全量扫描成本。
--*/
{
    PBYTE buffer = NULL;
    ULONG outSize = 0;
    SIZE_T sampleLen;
    NTSTATUS status;
    WKD_MEM_THREAT threat;

    if (Region == NULL) {
        return FALSE;
    }

    /* 门控：仅高怀疑标志区域；已确认则直接返回 */
    if ((Region->SuspicionFlags &
         (WKD_VAD_SUSPICION_UNBACKED_EXEC | WKD_VAD_SUSPICION_RWX |
          WKD_VAD_SUSPICION_RECENT_RW_TO_RX | WKD_VAD_SUSPICION_OVERLAP_WITH_IMAGE)) == 0) {
        return FALSE;
    }
    if (Region->ContainsShellcode) {
        return TRUE;
    }

    /* 地址用户态范围护栏（对齐堆喷门控采样） */
    if (Region->BaseAddress < 0x10000) {
        return FALSE;
    }

    sampleLen = (Region->RegionSize < WKD_VAD_CONTENT_SAMPLE_SIZE)
              ? Region->RegionSize : WKD_VAD_CONTENT_SAMPLE_SIZE;
    if (sampleLen == 0) {
        return FALSE;
    }

    status = MsReadMemory(ProcessId, Region->BaseAddress, sampleLen, &buffer, &outSize);
    if (!NT_SUCCESS(status) || buffer == NULL || outSize == 0) {
        if (buffer != NULL) {
            free(buffer);
        }
        return FALSE;
    }

    RtlZeroMemory(&threat, sizeof(threat));
    if (MsDetectShellcode(buffer, outSize,
                          (Region->Type == WkdMemType_Private), &threat)) {
        Region->ContainsShellcode = TRUE;
        Region->SuspicionFlags |= WKD_VAD_SUSPICION_SHELLCODE_PATTERN;
        Region->SuspicionScore += 90;
    }

    free(buffer);
    return Region->ContainsShellcode;
}

/**************************************************/
/*              全局统计查询                       */
/**************************************************/

_Use_decl_annotations_
VOID
IoaVad_GetStatistics(
    _Out_ PWKD_VAD_STATS Stats
    )
/*++
Routine Description:
    全局统计查询（快照构建/对比累计值，对齐 SS VadGetStatistics L1436）。
--*/
{
    if (Stats == NULL) {
        return;
    }

    Stats->TotalScans        = (ULONG64)InterlockedCompareExchange64((volatile LONG64*)&g_IoaVadStats.TotalScans, 0, 0);
    Stats->SuspiciousRegions = (ULONG64)InterlockedCompareExchange64((volatile LONG64*)&g_IoaVadStats.SuspiciousRegions, 0, 0);
    Stats->ProtectionChanges = (ULONG64)InterlockedCompareExchange64((volatile LONG64*)&g_IoaVadStats.ProtectionChanges, 0, 0);
    Stats->RWXDetections     = (ULONG64)InterlockedCompareExchange64((volatile LONG64*)&g_IoaVadStats.RWXDetections, 0, 0);
}

/**************************************************/
/*               告警构造（死代码接线点）           */
/**************************************************/

_Use_decl_annotations_
PIOA_ALERT
IoaVad_AllocAlert(
    _In_  GUID SuspectNodeId,
    _In_  const WKD_VAD_CHANGE* Change
    )
/*++
Routine Description:
    VAD 变更告警构造（单块堆分配含字符串缓冲，对齐 IoaHeapSpray_AllocAlert
    L364-448 分配语义，满足持久化队列 UtHeapFree(Data) 整体释放）。
    ※ 死代码：接线点未接入，未来由 IoaEngine 阶段6 或 VAD 快照线程对高危
    变更调用后 IoaPersistQueueEnqueue(..., StPersistAlert, TRUE) 入队。

Arguments:
    SuspectNodeId - 嫌疑进程节点 GUID。
    Change        - VAD 变更事件（含时序判定 SuspicionFlags/Score）。

Return Value:
    告警指针（调用方转移所有权）；分配失败返回 NULL。
--*/
{
    static const WCHAR* sMitreInjection = L"T1055";   /* 进程注入 */
    static const WCHAR* sMitreReflective = L"T1620";  /* 反射代码加载 */
    const WCHAR* ruleName;
    const WCHAR* mitreId;
    DEF_THREAT_SEVERITY severity;
    size_t ruleLen, mitreLen, descLen, total;
    PIOA_ALERT alert;
    PWCHAR buf;
    WCHAR descBuf[256];

    if (Change == NULL) {
        return NULL;
    }

    /* 按变更类型 + 时序判定标志映射 RuleName/MitreId */
    switch (Change->ChangeType) {
    case WkdVadChange_ProtectionChanged:
        if (Change->SuspicionFlags & WKD_VAD_SUSPICION_RECENT_RW_TO_RX) {
            ruleName = L"Vad/RWtoRX";       /* 动态解包 */
            mitreId = sMitreInjection;
        } else if (Change->SuspicionFlags & WKD_VAD_SUSPICION_RWX) {
            ruleName = L"Vad/RWX";
            mitreId = sMitreInjection;
        } else {
            ruleName = L"Vad/ProtectionChanged";
            mitreId = sMitreInjection;
        }
        break;
    case WkdVadChange_RegionCreated:
        if (Change->SuspicionFlags & WKD_VAD_SUSPICION_UNBACKED_EXEC) {
            ruleName = L"Vad/UnbackedExec";
            mitreId = sMitreReflective;
        } else {
            ruleName = L"Vad/RegionCreated";
            mitreId = sMitreInjection;
        }
        break;
    default:
        ruleName = L"Vad/Change";
        mitreId = sMitreInjection;
        break;
    }

    severity = (Change->SuspicionScore >= 80) ? DefThreatSeverity_Critical
             : (Change->SuspicionScore >= 50) ? DefThreatSeverity_High
             : DefThreatSeverity_Medium;

    swprintf_s(descBuf, 256,
               L"VAD %d: base=%p size=%llu old=%08X new=%08X flags=%08X score=%lu",
               (int)Change->ChangeType, (void*)(ULONG_PTR)Change->BaseAddress,
               (unsigned long long)Change->RegionSize,
               Change->OldProtection, Change->NewProtection,
               Change->SuspicionFlags, Change->SuspicionScore);

    ruleLen  = wcslen(ruleName);
    mitreLen = wcslen(mitreId);
    descLen  = wcslen(descBuf);
    total = sizeof(IOA_ALERT) +
            (ruleLen + 1 + mitreLen + 1 + descLen + 1) * sizeof(WCHAR);

    alert = (PIOA_ALERT)UtHeapAlloc(total);
    if (alert == NULL) {
        return NULL;
    }
    RtlZeroMemory(alert, total);

    CoCreateGuid(&alert->AlertId);
    alert->Timestamp         = IoaVadGetNow();
    alert->SuspectNodeId     = SuspectNodeId;
    alert->VictimNodeId      = SuspectNodeId;   /* VAD 快照无独立受害实体 */
    alert->Severity          = severity;
    alert->Score             = Change->SuspicionScore;
    alert->Confidence        = 75;
    alert->Category          = DefThreatCat_Exploit;
    alert->ConfidenceLevel   = DefConfidence_Medium;
    alert->RecommendedAction = DefRespAction_Alert;   /* monitor-only, 仅告警 */
    alert->DetectionSource   = DefDetSrc_Behavior;

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, ruleName);
    buf += ruleLen + 1;

    alert->MitreId = buf;
    wcscpy_s(buf, mitreLen + 1, mitreId);
    buf += mitreLen + 1;

    alert->Description = buf;
    wcscpy_s(buf, descLen + 1, descBuf);

    return alert;
}
