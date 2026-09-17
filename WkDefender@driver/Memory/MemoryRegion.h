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
/*  职责：每进程内存区域状态表 + 轻量预判。           */
/*    - 区域追踪：分配/保护变化/跨进程写/Section 映射  */
/*      维护 WasWritten/NowExecutable/ChangeCount      */
/*    - 轻量预判：RWX 初始分配 / W→X 解包 / Image 区   */
/*      早期 RWX（镂空）/ 跨进程注入标记               */
/*    - 风险聚合：MemoryRiskScore 0-1000              */
/*                                                    */
/*  架构（2026-09-09 方案 A 指针化 + 2026-09-10 二次重构）：*/
/*    - WKD_PROCESS 只保留 PWKD_MEMORY_REGION_CONTEXT */
/*      指针；载荷 = 事件轨（区域链表 + 风险统计，原  */
/*      WKD_MEMORY_REGION_STATE 成员全部上提，State 撤销）。*/
/*    - 基线快照：进程创建回调流水线拍首帧快照        */
/*      （MmBuildMemoryRegionBaseline，地址空间尚未被   */
/*      用户代码污染），配合事件通知（RegionList 增量）*/
/*      与定时器一致性校验构成三阶段覆盖，已剔除      */
/*      冗余的快照轨（VadRegionList 等 8 字段）。       */
/*    - 主动构建：PspCreateProcessContextInternal     */
/*      Phase 0 调用 MmCreateMemoryRegionContext；  */
/*    - 惰性挂载：Track / Handle 热路径经              */
/*      WkdMemRegionGetContext 兜底（CAS 赢家/    */
/*      输家，对齐 ModuleContext 范式）；              */
/*    - 统一销毁：PspDestroyProcess →                 */
/*      WkdDestroyMemoryRegionContext。               */
/*                                                    */
/*  事件轨驱动源：SyscallHijack.c 内存 case 调用       */
/*  WkdMemRegionTrack*（依赖 SmInitialize 启用 ETW    */
/*  劫持管道；管道接通前为预埋状态）。                 */
/*                                                    */
/*  与 wkd 既有能力分工：                             */
/*    - InjectionDetector 链关联 → agent IoaInjection  */
/*      Classifier（#56），本模块仅维护跨进程标记      */
/*    - HeapSpray 喂食 → agent IoaHeapSprayDetect      */
/*      （#55），本模块仅记录分配                      */
/**************************************************/

//
// 区域追踪常量（MemoryMonitor.c 配置）
//
#define WKD_MEM_MIN_ALLOC_SIZE_TO_TRACK  4096          // 最小追踪分配（字节）
#define WKD_MEM_MAX_REGIONS_PER_PROCESS  4096          // 每进程区域上限
#define WKD_MEMORY_REGION_MAX_AGE_SEC       3600          // 区域过期时间（秒）
#define WKD_MEM_HIGH_ENTROPY_THRESHOLD   7000          // 高熵阈值（×1000）
#define WKD_MEM_SHELLCODE_SCAN_THRESHOLD 5000          // Shellcode 熵阈值（×1000）
#define WKD_MEM_MAX_REGION_ENTROPY_READ  (1024 * 1024) // 跨进程写熵读取上限

//
// 区域类型（MEMORY_REGION_TYPE 子集）
//
typedef enum _WKD_MEMORY_REGION_TYPE {
    WkdMemRegion_Unknown = 0,
    WkdMemRegion_Image,          // MEM_IMAGE（DLL/EXE）
    WkdMemRegion_Private,        // MEM_PRIVATE（堆/私有）
    WkdMemRegion_Mapped,         // MEM_MAPPED（文件映射）
    WkdMemRegion_Stack,          // 线程栈
} WKD_MEMORY_REGION_TYPE;

/**************************************************/
/*                 结构体声明                      */
/**************************************************/

//
// 追踪区域节点（MM_TRACKED_REGION）
//
typedef struct _WKD_MEMORY_REGION {
    LIST_ENTRY        ListEntry;
    ULONG64           BaseAddress;              // 基地址
    ULONG64           Size;                     // 区域大小
    HANDLE            ProcessId;                // 所属进程
    ULONG             Protection;               // 当前保护属性
    ULONG             State;                    // MEM_COMMIT/MEM_RESERVE
    ULONG             Type;                     // MEM_PRIVATE/MEM_MAPPED/MEM_IMAGE
    WKD_MEMORY_REGION_TYPE RegionType;             // 区域分类
    LARGE_INTEGER     AllocationTime;           // 分配时间
    LARGE_INTEGER     LastProtectionChangeTime; // 最后保护变化时间
    ULONG             ProtectionChangeCount;    // 保护变化次数
    ULONG             Flags;                    // WKD_MEM_FLAG_*
    ULONG             LastContentEntropy;       // 最后内容熵（×1000）
    BOOLEAN           WasWritten;               // 是否被写入过
    BOOLEAN           NowExecutable;            // 当前是否可执行
    BOOLEAN           IsHighRisk;               // 高风险标记
    BOOLEAN           ScanHit;                  // 本次定时校验周期内被当前 VAD 命中（MemoryRegionVerify.c 维护）
    /* 后备文件名（MM_TRACKED_REGION BackingFileBuffer，FIX-18 填充；
     * 死代码：syscall 轨无文件对象，填充需 ZwQueryVirtualMemory + 对象名查询，
     * agent 进程表模块路径已覆盖查询语义） */
    WCHAR             BackingFile[260];         // 后备文件名（UTF-16，0 结尾）
    USHORT            BackingFileLength;        // 长度（字节）
} WKD_MEMORY_REGION, *PWKD_MEMORY_REGION;

// 区域标志（MM_REGION_FLAG_*）
#define WKD_MEM_FLAG_MONITORED         0x00000001
#define WKD_MEM_FLAG_HIGH_ENTROPY      0x00000002
#define WKD_MEM_FLAG_SHELLCODE_SCAN    0x00000004
#define WKD_MEM_FLAG_INJECTION_SRC     0x00000008
#define WKD_MEM_FLAG_INJECTION_DST     0x00000010
#define WKD_MEM_FLAG_HOLLOWING         0x00000020
#define WKD_MEM_FLAG_BASELINE          0x00000040  // 基线快照区域（进程创建时拍摄）

/**************************************************/
/*      进程内存区域追踪上下文（方案 A 载荷）        */
/**************************************************/

//
// 内存区域追踪上下文（2026-09-09 方案 A 指针化 + 2026-09-10 二次重构）
// 由 WKD_PROCESS 经指针持有（PWKD_MEMORY_REGION_CONTEXT），
// 载荷 = 事件轨（区域链表/锁/计数/风险统计，原 WKD_MEMORY_REGION_STATE
// 成员全部上提并入本结构，State 类型已撤销）。
//
// 生命周期：
//   - 主动构建：PspCreateProcessContextInternal Phase 0 → MmCreateMemoryRegionContext
//   - 基线拍摄：PspCreateProcessContextInternal Phase 0.1 → MmBuildMemoryRegionBaseline
//     （进程创建回调中拍首帧快照：此刻地址空间仅主 EXE/ntdll 等初始映像，
//     尚未被用户代码污染，是理想基线。基线区域标记 WKD_MEM_FLAG_BASELINE）
//   - 事件增量：SyscallHijack.c 内存 case → WkdMemRegionTrack*（RegionList 追加/更新）
//   - 一致性校验：定时器周期枚举当前 VAD 与 RegionList 交叉比对（预留，未实现）
//   - 惰性挂载：Track*/Handle* 热路径 → WkdMemRegionGetContext（CAS 赢家/输家）
//   - 统一销毁：PspDestroyProcess → WkdDestroyMemoryRegionContext
//
// 注意：WKD_MEMORY_REGION_CONTEXT/PWKD_MEMORY_REGION_CONTEXT 类型名
// 已由 Process/ProcessMonitor.h 前向 typedef（本头文件必须且已经 include 它），
// 此处仅定义 tag 结构体，不得重复 typedef。
//
struct _WKD_MEMORY_REGION_CONTEXT {
    HANDLE            ProcessId;               /* 所属进程（区域节点复用） */
    LIST_ENTRY        RegionList;              /* 区域链表（WKD_MEMORY_REGION 节点） */
    EX_PUSH_LOCK      RegionLock;              /* 区域锁（APC_LEVEL） */
    volatile LONG     RegionCount;             /* 活跃区域数 */
    volatile LONG     ShellcodeDetectionCount; /* Shellcode 检测计数（×200） */
    volatile LONG     InjectionAttemptCount;   /* 注入尝试计数（×300） */
    volatile LONG64   SuspiciousOperations;    /* 可疑操作计数（×10） */
    volatile LONG     MemoryRiskScore;         /* 0-1000（MmpUpdateProcessRisk） */
    volatile LONG     Flags;                   /* WKD_MEM_PROCESS_FLAG_* */

    /* ---- 基线快照元数据（首帧快照，2026-09-10 新增） ---- */
    volatile BOOLEAN  BaselineValid;           /* 基线已拍摄（进程创建回调完成） */
    LARGE_INTEGER     BaselineTime;            /* 基线拍摄时间 */

};

/**************************************************/
/*                 函数声明                        */
/**************************************************/

//
// 主动构建内存区域追踪上下文（2026-09-09 方案 A）
// 进程创建路径（PspCreateProcessContextInternal Phase 0）调用；
// 失败非致命：热路径保留 WkdMemRegionGetContext 惰性挂载兜底。
// 幂等：已存在时直接返回成功；并发构建由 CAS 赢家/输家收敛。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmCreateMemoryRegionContext(
    _Inout_ PWKD_PROCESS WkdProcess
    );

//
// 拍摄并创建内存基线快照（2026-09-10 激活，PspCreateProcessContextInternal
// Phase 0.1 调用）。进程创建回调时地址空间尚未被用户代码污染（仅主 EXE/
// ntdll 等初始映像），此刻枚举 COMMIT 区域灌入 RegionList 并标记
// WKD_MEM_FLAG_BASELINE，形成后续事件增量/定时校验的参照基线。
// 失败非致命：仅丢失基线标记，事件轨仍可增量工作。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmBuildMemoryRegionBaseline(
    _Inout_ PWKD_PROCESS WkdProcess
    );

//
// 统一销毁内存区域追踪上下文（进程退出路径，PspDestroyProcess 调用）
// 遍历释放事件轨区域节点，随后释放上下文载荷块并置空指针。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdDestroyMemoryRegionContext(
    _Inout_ PWKD_PROCESS WkdProcess
    );

//
// 惰性挂载获取事件轨上下文指针（Track*/Handle* 热路径使用）
// 上下文未构建时尝试分配（CAS 赢家/输家）；返回 NULL 表示挂载失败，
// 调用方应静默跳过该事件（对齐 ModuleContext 双路范式）。
// 幂等安全：可多次调用，单次分配。
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MEMORY_REGION_CONTEXT
WkdMemRegionGetContext(
    _Inout_ PWKD_PROCESS WkdProcess
    );

//
// 生命周期（进程销毁时由 PspDestroyProcess 调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdMemRegionCleanupProcess(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context
    );

//
// 便捷入口（内部查 WKD_PROCESS，区域归属 = 内存所属进程）
// 供 SyscallHijack.c 内存 case 调用（死代码，SmInitialize 启用后生效）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmTrackMemoryRegionAllocation(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmTrackMemoryRegionProtectionChange(
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
MmTrackSectionMapping(
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
    _In_ PWKD_MEMORY_REGION_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
MmIsVirtualAddressExecutable(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 Address
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdMemRegionIsProcessHighRisk(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context
    );

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
    );

//
// 保护变化怀疑分（MmMonitorGetProtectionChangeSuspicion c:2895）
// 返回 0-100：RW→RX +60 / →RWX +80 / Private +10 / Stack +20
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdMemRegionGetProtectionChangeSuspicion(
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection,
    _In_ WKD_MEMORY_REGION_TYPE RegionType
    );

//
// VAD 枚举工具（MmMonitorBuildVadMap，预留：供后续定时一致性
// 校验/按需查询复用；基线拍摄 MmBuildMemoryRegionBaseline 已自包含枚举）
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
    WKD_MEMORY_REGION_TYPE RegionType;
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

/**************************************************/
/*        内部协作接口（仅供 MemoryRegionVerify.c）  */
/*        2026-09-10：原 MemoryRegion.c 内部 static */
/*        工具函数转模块内公共，供定时一致性校验器  */
/*        复用区域表管理/风险聚合/保护判断，         */
/*        避免复制实现。                            */
/**************************************************/

//
// 保护判断（MmpIs*Protection；MmpAnalyzeProtectionChange 保持
// MemoryRegion.c 内部，经 WkdMemRegionGetProtectionChangeSuspicion 暴露）
//
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MmpIsExecutableProtection(
    _In_ ULONG Protection
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MmpIsWritableProtection(
    _In_ ULONG Protection
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MmpIsRwxProtection(
    _In_ ULONG Protection
    );

//
// 查找地址所在区域（调用者必须持有 Context->RegionLock）
//
_IRQL_requires_max_(APC_LEVEL)
PWKD_MEMORY_REGION
MmpFindMemoryRegion(
    _In_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 Address
    );

//
// 从区域表摘除并释放区域节点（调用者必须持有 Context->RegionLock 独占）
//
_IRQL_requires_max_(APC_LEVEL)
VOID
MmpRemoveMemoryRegionFromVirtualAddressSpace(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context,
    _Inout_ PWKD_MEMORY_REGION Region
    );

//
// 添加区域（4096 上限 + 过期清理 + 重复地址检测，内部加 RegionLock 独占）
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmpAddMemoryRegionToVirtualAddressSpace(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 Size,
    _In_ ULONG Protection,
    _In_ ULONG Type
    );

//
// 风险聚合（MemoryRiskScore = Shellcode×200 + Injection×300 + Suspicious×10）
//
_IRQL_requires_max_(APC_LEVEL)
VOID
WkdMemRegionUpdateProcessRisk(
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Context
    );
