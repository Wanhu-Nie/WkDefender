/**************************************************/
/*  IoaVadTracker — VAD 快照对比检测（agent）       */
/*  ShadowStrike VadTracker 迁移 2026-08            */
/*  MITRE ATT&CK: T1055 注入 / T1620 反射加载        */
/**************************************************/
/*                                                    */
/*  职责：进程 VAD（虚拟地址描述符）快照对比 + 怀疑度  */
/*    评分。对齐 SS VadTracker.c（重功能实现非复制）。  */
/*                                                    */
/*  落点：agent IOA/（仿 IoaHeapSprayDetect feature    */
/*    模块风格）。复用 MsEnumerateRegions（Memory/     */
/*    MemoryScan.c）枚举进程区域 + MsBuildModuleSet     */
/*    （模块集）+ MsDetectShellcode（内容扫描）。       */
/*                                                    */
/*  功能面补遗（2026-08 迁移对照 SS 全量复核）：       */
/*    - 静态怀疑度：SS VadpAnalyzeRegionSuspicion       */
/*      (L2063-2132) 真实置位 7 项与 wkd 一致           */
/*      (RWX 100/UnbackedExec 80/RecentRWtoRX 70/       */
/*      LargePrivate 20/Guard 30/SuspiciousBase 25/     */
/*      ProtectionMismatch 40)。                        */
/*    - 跨快照时序判定：CompareSnapshots 补动态         */
/*      RW→RX(+70)/新 RWX(+100)/新 UnbackedExec(+80)    */
/*      （对齐 SS VadpCompareSnapshots L2481-2545）。    */
/*    - wkd 补真实现（SS 仅评分表预留分值、分析函数     */
/*      从未置位）：OverlapWithImage(60, MsBuild         */
/*      ModuleSet 模块集重叠) + ShellcodePattern(90,     */
/*      门控 MsDetectShellcode 内容扫描)。              */
/*    - HiddenRegion(100)：死代码，需内核 VAD/PTE 比对   */
/*      （agent VirtualQueryEx 依赖 VAD、驱动 BuildVad   */
/*      Map 仅汇总统计，均无法检测"区域不在 VAD 中"）。   */
/*    - Committed/Decommitted 变更：枚举保留 + 死代码，  */
/*      依赖 RESERVE 区域枚举缺口（MsEnumerateRegions    */
/*      只收 MEM_COMMIT，本次不改动 MemoryScan）。       */
/*                                                    */
/*  ※ 死代码：快照定时触发点未接入（SS 5s 周期快照，   */
/*    agent 由 ProcessSnapshot_ThreadProc 60s 线程或     */
/*    驱动 MemoryRegion 事件信号驱动），函数面全量落地， */
/*    供后续接线。                                    */
/*                                                    */
/*  与 wkd 既有能力分工：                             */
/*    - 逐区域 RWX/未备份可执行 实时预判 → 驱动         */
/*      MemoryRegion（A1/A2，syscall 轨）               */
/*    - VAD 快照级变更检测（本模块）→ agent 周期分析    */
/**************************************************/

#ifndef IOA_VAD_TRACKER_H
#define IOA_VAD_TRACKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include "IoaPersistQueue.h"   /* IOA_ALERT (IoaVad_AllocAlert 返回类型) */

//
// 常量（对齐 SS VadTracker.h：VAD_SNAPSHOT_MAX_ENTRIES / 怀疑度阈值）
//
#define WKD_VAD_MAX_REGIONS_PER_PROCESS   16384
#define WKD_VAD_SNAPSHOT_MAX_ENTRIES      4096
#define WKD_VAD_SUSPICIOUS_REGION_THRESHOLD 100
/* 注: SS 定义 VAD_SUSPICIOUS_REGION_THRESHOLD=100 但 VadpQueryMemoryRegions 计数
   实际用 score>0 (L1950), 阈值常量未被使用; wkd 对齐 SS 亦用 >0 计数 */
#define WKD_VAD_LARGE_REGION_THRESHOLD    (16 * 1024 * 1024)   /* 16MB */
#define WKD_VAD_SUSPICIOUS_BASE_LOW       0x10000

//
// 可疑标志（对齐 SS VAD_SUSPICION_*，agent 可实现子集）
//
#define WKD_VAD_SUSPICION_RWX                 0x00000001  // 100 分
#define WKD_VAD_SUSPICION_UNBACKED_EXEC       0x00000002  // 80 分
#define WKD_VAD_SUSPICION_LARGE_PRIVATE       0x00000004  // 20 分
#define WKD_VAD_SUSPICION_GUARD_REGION        0x00000008  // 30 分
#define WKD_VAD_SUSPICION_RECENT_RW_TO_RX     0x00000010  // 70 分 (静态 AllocationProtect 判 + 动态时序判)
#define WKD_VAD_SUSPICION_SUSPICIOUS_BASE     0x00000020  // 25 分
#define WKD_VAD_SUSPICION_PROTECTION_MISMATCH 0x00000040  // 40 分
#define WKD_VAD_SUSPICION_SHELLCODE_PATTERN   0x00000080  // 90 分 (门控 MsDetectShellcode 内容扫描)
#define WKD_VAD_SUSPICION_OVERLAP_WITH_IMAGE  0x00000200  // 60 分 (MsBuildModuleSet 模块集重叠判定)
/* 死代码标注（需内核 VAD/PTE 比对，agent 不可实现）：
 * WKD_VAD_SUSPICION_HIDDEN_REGION 0x100  (100 分, 需检测"区域不在 VAD 中") */

//
// 区域快照条目（对齐 SS VAD_SNAPSHOT_ENTRY + VAD_REGION 子集）
//
typedef struct _WKD_VAD_REGION_ENTRY {
    ULONG_PTR   BaseAddress;
    SIZE_T      RegionSize;
    ULONG       Protection;          /* 当前保护 PAGE_* */
    ULONG       AllocationProtect;   /* 分配时保护（ProtectionMismatch 判定） */
    ULONG       Type;                /* MEM_PRIVATE/MEM_MAPPED/MEM_IMAGE */
    ULONG       State;               /* MEM_COMMIT/MEM_RESERVE */
    BOOLEAN     IsBacked;            /* MEM_IMAGE/MEM_MAPPED 有后备 */
    ULONG       SuspicionFlags;      /* WKD_VAD_SUSPICION_* */
    ULONG       SuspicionScore;      /* 0-100 */
    BOOLEAN     ContainsShellcode;   /* ShellcodePattern 二次确认结果（门控扫描填充） */
} WKD_VAD_REGION_ENTRY, *PWKD_VAD_REGION_ENTRY;

//
// 进程快照
//
typedef struct _WKD_VAD_SNAPSHOT {
    DWORD  ProcessId;
    ULONG  RegionCount;
    WKD_VAD_REGION_ENTRY Regions[WKD_VAD_SNAPSHOT_MAX_ENTRIES];
    ULONG  TotalSuspicionScore;
    ULONG  SuspiciousRegionCount;
    /* 进程级统计（对齐 SS VAD_PROCESS_CONTEXT 统计字段） */
    ULONG  RWXRegionCount;         /* 命中 RWX 的区域数 */
    ULONG  UnbackedExecuteCount;   /* 未备份可执行区域数 */
    SIZE_T TotalPrivateSize;       /* MEM_PRIVATE 总尺寸 */
    SIZE_T TotalMappedSize;        /* MEM_MAPPED 总尺寸 */
    SIZE_T TotalImageSize;         /* MEM_IMAGE 总尺寸 */
    SIZE_T TotalExecutableSize;    /* 可执行区域总尺寸 */
    LARGE_INTEGER SnapshotTime;    /* 快照构建时间（对齐 SS SnapshotTime） */
} WKD_VAD_SNAPSHOT, *PWKD_VAD_SNAPSHOT;

//
// 变更类型（对齐 SS VAD_CHANGE_TYPE）
//
typedef enum _WKD_VAD_CHANGE_TYPE {
    WkdVadChange_RegionCreated = 1,
    WkdVadChange_RegionDeleted,
    WkdVadChange_ProtectionChanged,
    WkdVadChange_RegionGrew,
    WkdVadChange_RegionShrunk,
    WkdVadChange_Committed,       /* 死代码：依赖 RESERVE 区域枚举缺口（MsEnumerateRegions 只收 MEM_COMMIT） */
    WkdVadChange_Decommitted,
} WKD_VAD_CHANGE_TYPE;

typedef struct _WKD_VAD_CHANGE {
    WKD_VAD_CHANGE_TYPE ChangeType;
    ULONG_PTR   BaseAddress;
    SIZE_T      RegionSize;
    ULONG       OldProtection;
    ULONG       NewProtection;
    ULONG       SuspicionFlags;   /* 时序判定结果：WKD_VAD_SUSPICION_RECENT_RW_TO_RX / _RWX / _UNBACKED_EXEC */
    ULONG       SuspicionScore;   /* 纯变更语义分（对齐 SS 事件分, 非区域静态分）:
                                     ProtectionChanged 0+70+100 / Created UnbackedExec=80 / 其余 0 */
    LARGE_INTEGER Timestamp;      /* 变更检出时间 */
} WKD_VAD_CHANGE, *PWKD_VAD_CHANGE;

/**************************************************/
/*                 函数声明                        */
/**************************************************/

//
// 单区域怀疑度分析（对齐 SS VadpAnalyzeRegionSuspicion L2063 +
// VadpCalculateSuspicionScore L2135）
//
BOOL
IoaVad_AnalyzeRegion(
    _In_  const WKD_VAD_REGION_ENTRY* Region,
    _Out_opt_ PULONG SuspicionFlags,
    _Out_opt_ PULONG SuspicionScore
    );

//
// 构建进程 VAD 快照（复用 MsEnumerateRegions，激活既有死代码）
// 返回 TRUE 时 Snapshot 已填充（含每区域怀疑度评分）。
//
BOOL
IoaVad_SnapshotProcess(
    _In_  DWORD ProcessId,
    _Out_ PWKD_VAD_SNAPSHOT Snapshot
    );

//
// 快照对比（对齐 SS VadpCompareSnapshots L2364 merge-compare）
// 两次快照按 BaseAddress 排序后合并比较，输出变更事件。
// 返回变更数。
//
ULONG
IoaVad_CompareSnapshots(
    _In_  const WKD_VAD_SNAPSHOT* Old,
    _In_  const WKD_VAD_SNAPSHOT* New,
    _Out_writes_to_(MaxChanges, *) PWKD_VAD_CHANGE Changes,
    _In_  ULONG MaxChanges
    );

//
// 查询可疑区域（SuspicionScore >= MinScore 的条目拷贝）
//
ULONG
IoaVad_GetSuspiciousRegions(
    _In_  const WKD_VAD_SNAPSHOT* Snapshot,
    _In_  ULONG MinScore,
    _Out_writes_to_(MaxEntries, *) PWKD_VAD_REGION_ENTRY Out,
    _In_  ULONG MaxEntries
    );

/**************************************************/
/*              查询 API 面（功能补遗）             */
/**************************************************/

//
// 区域过滤器（对齐 SS VAD_REGION_FILTER）：返回 TRUE 命中
//
typedef BOOLEAN (*WKD_VAD_REGION_FILTER)(
    _In_  const WKD_VAD_REGION_ENTRY* Region,
    _In_opt_ PVOID Context
    );

//
// 全局统计（对齐 SS VAD_STATISTICS，快照构建/对比时累计）
//
typedef struct _WKD_VAD_STATS {
    ULONG64 TotalScans;           /* 快照构建次数 */
    ULONG64 TotalRegions;         /* 累计区域计数（对齐 SS TotalRegions） */
    ULONG64 SuspiciousRegions;    /* 累计可疑区域计数（score>0, 对齐 SS L1950） */
    ULONG64 ProtectionChanges;    /* 累计保护变化事件 */
    ULONG64 RWXDetections;        /* 累计 RWX 区域计数 */
} WKD_VAD_STATS, *PWKD_VAD_STATS;

//
// 地址 → 区域查找（对齐 SS VadpFindRegion/VadGetRegionInfo，快照已按 BaseAddress 排序）
//
BOOL
IoaVad_FindRegion(
    _In_  const WKD_VAD_SNAPSHOT* Snapshot,
    _In_  ULONG_PTR Address,
    _Out_opt_ PWKD_VAD_REGION_ENTRY Region
    );

//
// 过滤器枚举（对齐 SS VadEnumerateRegions，返回 value copies）
//
ULONG
IoaVad_EnumerateRegions(
    _In_  const WKD_VAD_SNAPSHOT* Snapshot,
    _In_  WKD_VAD_REGION_FILTER Filter,
    _In_opt_ PVOID Context,
    _Out_writes_to_(MaxRegions, *) PWKD_VAD_REGION_ENTRY Regions,
    _In_  ULONG MaxRegions
    );

//
// ShellcodePattern(90) 门控内容扫描 — 对已命中高怀疑标志的区域
// 做 MsDetectShellcode 二次确认，命中置 ContainsShellcode + 加分。
// 门控条件函数内自带，防误用成本。
//
BOOL
IoaVad_ScanRegionContent(
    _In_  DWORD ProcessId,
    _Inout_ PWKD_VAD_REGION_ENTRY Region
    );

//
// 全局统计查询（快照/对比累计值）
//
VOID
IoaVad_GetStatistics(
    _Out_ PWKD_VAD_STATS Stats
    );

//
// VAD 变更告警构造（对齐 SS 回调/变更队列 → wkd ALPC/告警链）。
// ※ 死代码：接线点未接入，未来由 IoaEngine 阶段6 或 VAD 快照线程
//   对高危变更调用后 IoaPersistQueueEnqueue + StPersistAlert 入队。
//
PIOA_ALERT
IoaVad_AllocAlert(
    _In_  GUID SuspectNodeId,
    _In_  const WKD_VAD_CHANGE* Change
    );

#ifdef __cplusplus
}
#endif

#endif /* IOA_VAD_TRACKER_H */
