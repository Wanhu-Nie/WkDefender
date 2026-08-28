#pragma once

#include "../Common/Constants.h"
#include "../Process/ProcessMonitor.h"

/**************************************************/
/*              内存区域追踪模块（MemoryRegion）     */
/*  MemoryMonitor 迁移 2026-08                      */
/*  参考 ShadowStrike MemoryMonitor.c               */
/*  MITRE ATT&CK: T1055 进程注入 / T1620 反射加载    */
/**************************************************/
/*                                                    */
/*  职责：每进程内存区域状态表 + 轻量预判（死代码）。  */
/*    - 区域追踪：分配/保护变化/跨进程写/Section 映射  */
/*      维护 WasWritten/NowExecutable/ChangeCount      */
/*    - 轻量预判：RWX 初始分配 / W→X 解包 / Image 区   */
/*      早期 RWX（镂空）/ 跨进程注入标记               */
/*    - 风险聚合：MemoryRiskScore 0-1000              */
/*                                                    */
/*  ※ 死代码：依赖 SmInitialize 启用（WkdEntry.c:261  */
/*    注释态），syscall 管线恢复后由 SyscallHijack.c   */
/*    内存 case 调用 WkdMemRegionTrack* 驱动。         */
/*                                                    */
/*  与 wkd 既有能力分工：                             */
/*    - InjectionDetector 链关联 → agent IoaInjection  */
/*      Classifier（#56），本模块仅维护跨进程标记      */
/*    - HeapSpray 喂食 → agent IoaHeapSprayDetect      */
/*      （#55），本模块仅记录分配                      */
/**************************************************/

//
// 区域追踪常量（对齐 SS MemoryMonitor.c 配置）
//
#define WKD_MEM_MIN_ALLOC_SIZE_TO_TRACK  4096          // 最小追踪分配（字节）
#define WKD_MEM_MAX_REGIONS_PER_PROCESS  4096          // 每进程区域上限
#define WKD_MEM_REGION_MAX_AGE_SEC       3600          // 区域过期时间（秒）
#define WKD_MEM_HIGH_ENTROPY_THRESHOLD   7000          // 高熵阈值（×1000）
#define WKD_MEM_SHELLCODE_SCAN_THRESHOLD 5000          // Shellcode 熵阈值（×1000）
#define WKD_MEM_MAX_REGION_ENTROPY_READ  (1024 * 1024) // 跨进程写熵读取上限

//
// 区域类型（对齐 SS MEMORY_REGION_TYPE 子集）
//
typedef enum _WKD_MEM_REGION_TYPE {
    WkdMemRegion_Unknown = 0,
    WkdMemRegion_Image,          // MEM_IMAGE（DLL/EXE）
    WkdMemRegion_Private,        // MEM_PRIVATE（堆/私有）
    WkdMemRegion_Mapped,         // MEM_MAPPED（文件映射）
    WkdMemRegion_Stack,          // 线程栈
} WKD_MEM_REGION_TYPE;

/**************************************************/
/*                 结构体声明                      */
/**************************************************/

//
// 追踪区域节点（对齐 SS MM_TRACKED_REGION）
//
typedef struct _WKD_MEM_REGION {
    LIST_ENTRY        ListEntry;
    ULONG64           BaseAddress;              // 基地址
    ULONG64           Size;                     // 区域大小
    HANDLE            ProcessId;                // 所属进程
    ULONG             Protection;               // 当前保护属性
    ULONG             State;                    // MEM_COMMIT/MEM_RESERVE
    ULONG             Type;                     // MEM_PRIVATE/MEM_MAPPED/MEM_IMAGE
    WKD_MEM_REGION_TYPE RegionType;             // 区域分类
    LARGE_INTEGER     AllocationTime;           // 分配时间
    LARGE_INTEGER     LastProtectionChangeTime; // 最后保护变化时间
    ULONG             ProtectionChangeCount;    // 保护变化次数
    ULONG             Flags;                    // WKD_MEM_FLAG_*
    ULONG             LastContentEntropy;       // 最后内容熵（×1000）
    BOOLEAN           WasWritten;               // 是否被写入过
    BOOLEAN           NowExecutable;            // 当前是否可执行
    BOOLEAN           IsHighRisk;               // 高风险标记
    /* 后备文件名（对齐 SS MM_TRACKED_REGION BackingFileBuffer，FIX-18 填充；
     * 死代码：syscall 轨无文件对象，填充需 ZwQueryVirtualMemory + 对象名查询，
     * agent 进程表模块路径已覆盖查询语义） */
    WCHAR             BackingFile[260];         // 后备文件名（UTF-16，0 结尾）
    USHORT            BackingFileLength;        // 长度（字节）
} WKD_MEM_REGION, *PWKD_MEM_REGION;

// 区域标志（对齐 SS MM_REGION_FLAG_*）
#define WKD_MEM_FLAG_MONITORED         0x00000001
#define WKD_MEM_FLAG_HIGH_ENTROPY      0x00000002
#define WKD_MEM_FLAG_SHELLCODE_SCAN    0x00000004
#define WKD_MEM_FLAG_INJECTION_SRC     0x00000008
#define WKD_MEM_FLAG_INJECTION_DST     0x00000010
#define WKD_MEM_FLAG_HOLLOWING         0x00000020

/**************************************************/
/*                 函数声明                        */
/**************************************************/

//
// 生命周期（进程销毁时由 PspDestroyProcess 调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionCleanupProcess(
    _Inout_ PWKD_MEM_REGION_STATE State
    );

//
// 便捷入口（内部查 WKD_PROCESS，区域归属 = 内存所属进程）
// 供 SyscallHijack.c 内存 case 调用（死代码，SmInitialize 启用后生效）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackAllocation(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection
    );

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
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackCrossProcessWrite(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 TargetAddress,
    _In_ ULONG64 Size,
    _In_opt_ PVOID SourceBuffer
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionTrackSectionMap(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 ViewSize,
    _In_ ULONG Protection,
    _In_ BOOLEAN IsCrossProcess
    );

//
// 查询 API
//
_IRQL_requires_max_(APC_LEVEL)
ULONG
WkdMemRegionGetRiskScore(
    _In_ PWKD_MEM_REGION_STATE State
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdMemRegionIsAddressExecutable(
    _In_ PWKD_MEM_REGION_STATE State,
    _In_ ULONG64 Address
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdMemRegionIsProcessHighRisk(
    _In_ PWKD_MEM_REGION_STATE State
    );

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
    );

//
// 保护变化怀疑分（对齐 SS MmMonitorGetProtectionChangeSuspicion c:2895）
// 返回 0-100：RW→RX +60 / →RWX +80 / Private +10 / Stack +20
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdMemRegionGetProtectionChangeSuspicion(
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection,
    _In_ WKD_MEM_REGION_TYPE RegionType
    );

//
// VAD 枚举工具（对齐 SS MmMonitorBuildVadMap，死代码：供按需查询/后续扫描）
//
#define WKD_MEM_VAD_MAX_REGIONS   1024
#define WKD_MEM_VAD_FLAG_EXECUTABLE  0x00000001
#define WKD_MEM_VAD_FLAG_WRITABLE    0x00000002
#define WKD_MEM_VAD_FLAG_RWX         0x00000004
#define WKD_MEM_VAD_FLAG_UNBACKED    0x00000008
#define WKD_MEM_VAD_FLAG_SUSPICIOUS  0x00000100

typedef struct _WKD_MEM_VAD_ENTRY {
    ULONG64            BaseAddress;
    ULONG64            Size;
    ULONG              Protection;
    ULONG              VadType;              /* MEM_PRIVATE/MEM_MAPPED/MEM_IMAGE */
    WKD_MEM_REGION_TYPE RegionType;
    ULONG              Flags;                /* WKD_MEM_VAD_FLAG_* */
} WKD_MEM_VAD_ENTRY, *PWKD_MEM_VAD_ENTRY;

typedef struct _WKD_MEM_VAD_MAP {
    HANDLE             ProcessId;
    ULONG              VadCount;
    ULONG64            TotalVirtualSize;
    ULONG64            TotalCommittedSize;
    ULONG64            TotalExecutableSize;
    ULONG64            TotalWritableSize;
    ULONG64            TotalRWXSize;
    ULONG              UnbackedExecutableCount;
} WKD_MEM_VAD_MAP, *PWKD_MEM_VAD_MAP;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdMemRegionBuildVadMap(
    _In_ HANDLE ProcessId,
    _Out_writes_to_(WKD_MEM_VAD_MAX_REGIONS, *EntryCount) PWKD_MEM_VAD_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount,
    _Out_ PWKD_MEM_VAD_MAP Summary
    );
