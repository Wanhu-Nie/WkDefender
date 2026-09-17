/**************************************************/
/*  WkDefender IOA — 栈迁移 (Stack Pivot) 攻击检测器  */
/*                                                  */
/*  迁移自 ShadowStrike StackPivotDetector           */
/*  (StackPivotDetector.cpp/.hpp, v3.0.0)           */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  能力面 (六大检测能力):                   */
/*    ├─ 栈指针验证 (TEB 栈限制读取 + RSP/ESP 边界    */
/*    │    + 栈增长方向 + guard page 近距检测)        */
/*    ├─ Pivot 目标分析 (堆/数据段/映像段/映射内存/   */
/*    │    私有分配/有效栈分类, VirtualQuery +        */
/*    │    GetProcessHeaps 判定)                     */
/*    ├─ Pivot 技术识别 (XCHG ESP,EAX / MOV ESP,reg / */
/*    │    POP ESP / LEAVE;RET / ADD-SUB ESP,imm /   */
/*    │    PUSH ESP;RET / JMP-CALL ESP / x64 带 REX   */
/*    │    变体, 17 项 2B 表 + 13 项 x64 3B 表)      */
/*    ├─ 线程监控 (逐线程栈缓存, TEB 栈上限 30s TTL,  */
/*    │    进程句柄 LRU 256, 线程注册/注销)           */
/*    ├─ 置信度评分 (堆=VeryHigh/95, 数据-映像段=    */
/*    │    High/85, 私有内存=Medium/70, 其他=Low/50)  */
/*    └─ 处置 (BlockOnPivot → 计数; Confirmed 级 →   */
/*        可选 TerminateProcess)                     */
/*                                                  */
/*  与 SS 源码的对齐/裁剪 (注释就地标注):            */
/*    - 去 JSON 序列化 (ToJson 族) → 事件结构体输出   */
/*    - 去 Meyers 单例 ↔ C 静态全局天然单例            */
/*    - 去 IPCManager RegisterGenericHandler 注册     */
/*      (WkDefender agent 无内核 IPC 通道), 内核告警  */
/*      入口保留为 SpdProcessKernelMemoryAlert        */
/*    - 去 AlertSystem.RaiseAlert → 单一事件回调上报  */
/*    - 去 CorrelateWithExploitChain (依赖 HeapSpray- */
/*      Detector / ROPProtection 跨模块交叉关联,      */
/*      WkDefender 无该联动)                          */
/*    - 去 Start/Stop/Pause/Resume 显式状态机,        */
/*      Initialize/Shutdown 两态 + GetStatus 等价     */
/*    - 3 类回调 (pivot/validation/error) 合一为      */
/*      SPD_DETECTED_CALLBACK                          */
/*    - excludedProcesses 动态表 → 定长数组           */
/*                                                  */
/*  接入状态: 独立模块 (死代码), 未挂接 IoaObserve   */
/*  事件流水线。调用方按需调用 SpdValidateStackPointer */
/*  / SpdDetectPivot / SpdProcessKernelMemoryAlert。  */
/**************************************************/

#pragma once

#include "../../DefendTypes.h"

/**************************************************/
/*               容量常量                           */
/*  StackPivotConstants (同类项中文化注释)。 */
/**************************************************/

#define SPD_VERSION_MAJOR              3
#define SPD_VERSION_MINOR              0
#define SPD_VERSION_PATCH              0

/* 每进程最大跟踪线程数 (SS MAX_TRACKED_THREADS) */
#define SPD_MAX_TRACKED_THREADS        4096
/* 最大监控进程数 (SS MAX_MONITORED_PROCESSES) */
#define SPD_MAX_MONITORED_PROCESSES    2048
/* 栈验证周期 (ms, SS VALIDATION_INTERVAL_MS) */
#define SPD_VALIDATION_INTERVAL_MS     100
/* 默认栈保留大小 (SS DEFAULT_STACK_RESERVE_SIZE, 1MB) */
#define SPD_DEFAULT_STACK_RESERVE_SIZE (1024 * 1024)
/* 栈 guard page 大小 (SS GUARD_PAGE_SIZE) */
#define SPD_GUARD_PAGE_SIZE            4096
/* 最小有效栈大小 (SS MIN_STACK_SIZE) */
#define SPD_MIN_STACK_SIZE             4096

/* 栈上限缓存 TTL (SS STACK_CACHE_LIFETIME = 30s) */
#define SPD_STACK_CACHE_TTL_MS         30000
/* 栈缓存定长槽位 (C 静态化, SS 为无界 unordered_map + TTL) */
#define SPD_STACK_CACHE_ENTRIES        4096
/* 进程句柄 LRU 缓存上限 (SS MAX_PROCESS_HANDLE_CACHE_ENTRIES) */
#define SPD_PROCESS_HANDLE_CACHE_ENTRIES 256
/* 内核告警单轮线程检查硬上限 (SS MAX_KERNEL_ALERT_THREADS_INSPECTED) */
#define SPD_MAX_KERNEL_ALERT_THREADS   SPD_MAX_TRACKED_THREADS
/* 最近检测环形容量 (SS MAX_RECENT_DETECTIONS) */
#define SPD_MAX_RECENT_DETECTIONS      1000
/* DetectPivot 单次 gadget 捕获字节数 (SS std::array<uint8_t,8>) */
#define SPD_GADGET_CAPTURE_BYTES       8
/* 按技术统计槽位数 (SS byTechnique std::array<...,16>) */
#define SPD_TECHNIQUE_SLOTS            16
/* 排除进程定长上限 (SS excludedProcesses vector → 定长) */
#define SPD_MAX_EXCLUDED_PROCESSES     32
#define SPD_MAX_EXCLUDED_NAME_LEN      64

/**************************************************/
/*               模块状态枚举                       */
/*  ModuleStatus (RPD RpdStatus 同构)。     */
/**************************************************/

typedef enum _SPD_STATUS {
    SpdStatus_Uninitialized = 0,
    SpdStatus_Initializing  = 1,
    SpdStatus_Running       = 2,
    SpdStatus_Paused        = 3,
    SpdStatus_Stopping      = 4,
    SpdStatus_Stopped       = 5,
    SpdStatus_Error         = 6
} SPD_STATUS;

/**************************************************/
/*               Pivot 目的地类型枚举               */
/*  PivotDestinationType (0-12)。           */
/**************************************************/

typedef enum _SPD_PIVOT_DEST_TYPE {
    SpdDest_Unknown         = 0,    /* 无法判定            */
    SpdDest_ValidStack      = 1,    /* 有效线程栈 (非迁移)  */
    SpdDest_Heap            = 2,    /* 进程堆              */
    SpdDest_ImageSection    = 3,    /* PE 映像段            */
    SpdDest_DataSection     = 4,    /* 数据/BSS 段          */
    SpdDest_MappedFile      = 5,    /* 内存映射文件         */
    SpdDest_PrivateMemory   = 6,    /* VirtualAlloc 分配    */
    SpdDest_SharedMemory    = 7,    /* 共享节区             */
    SpdDest_GuardPage       = 8,    /* guard page (栈增长)  */
    SpdDest_ReservedMemory  = 9,    /* 保留未提交           */
    SpdDest_FreeMemory      = 10,   /* 空闲地址空间         */
    SpdDest_OtherThreadStack = 11,  /* 其他线程栈           */
    SpdDest_KernelStack     = 12    /* 内核地址 (用户态非法) */
} SPD_PIVOT_DEST_TYPE;

/**************************************************/
/*               Pivot 技术枚举                     */
/*  PivotTechnique (0-14)。                 */
/**************************************************/

typedef enum _SPD_PIVOT_TECHNIQUE {
    SpdTech_Unknown         = 0,
    SpdTech_XchgEspEax      = 1,    /* XCHG ESP,EAX        */
    SpdTech_XchgRspRax      = 2,    /* XCHG RSP,RAX        */
    SpdTech_MovEspReg       = 3,    /* MOV ESP,reg         */
    SpdTech_MovRspReg       = 4,    /* MOV RSP,reg         */
    SpdTech_PopEsp          = 5,    /* POP ESP             */
    SpdTech_PopRsp          = 6,    /* POP RSP             */
    SpdTech_LeaveRet        = 7,    /* LEAVE; RET 序列     */
    SpdTech_AddEspImm       = 8,    /* 大位移 ADD ESP,imm  */
    SpdTech_SubEspImm       = 9,    /* 可疑 SUB ESP,imm    */
    SpdTech_PushSpRet       = 10,   /* PUSH ESP; RET       */
    SpdTech_CallStackPivot  = 11,   /* CALL 栈迁移 gadget  */
    SpdTech_LongjmpAbuse    = 12,   /* setjmp/longjmp 滥用 */
    SpdTech_ExceptionDispatch = 13, /* 异常处理操纵        */
    SpdTech_FiberSwitch     = 14    /* 纤程上下文操纵      */
} SPD_PIVOT_TECHNIQUE;

/**************************************************/
/*               栈验证结果枚举                     */
/*  StackValidationResult (0-6)。           */
/**************************************************/

typedef enum _SPD_VALIDATION_RESULT {
    SpdValid_Unknown        = 0,    /* 无法判定            */
    SpdValid_Valid          = 1,    /* 栈指针有效          */
    SpdValid_PivotDetected  = 2,    /* 检测到栈迁移        */
    SpdValid_NearGuardPage  = 3,    /* 邻近 guard page     */
    SpdValid_Overflow       = 4,    /* 栈溢出              */
    SpdValid_Underflow      = 5,    /* 超出栈基址 (可疑)   */
    SpdValid_InvalidBounds  = 6     /* 无法确定边界        */
} SPD_VALIDATION_RESULT;

/**************************************************/
/*               置信度枚举                         */
/*  StackPivotDetectionConfidence          */
/*  (RPD RpdConf 同构)。                           */
/**************************************************/

typedef enum _SPD_CONFIDENCE {
    SpdConf_Unknown   = 0,
    SpdConf_Low       = 1,
    SpdConf_Medium    = 2,
    SpdConf_High      = 3,
    SpdConf_VeryHigh  = 4,
    SpdConf_Confirmed = 5
} SPD_CONFIDENCE;

/**************************************************/
/*               栈范围结构                         */
/*  StackRange, 时间戳定长化 (LARGE_INTEGER)。 */
/**************************************************/

typedef struct _SPD_STACK_RANGE {
    ULONG       ThreadId;           /* 线程 ID              */
    UINT64      StackBase;          /* 栈基址 (高地址)      */
    UINT64      StackLimit;         /* 栈下限 (低地址)      */
    UINT64      AllocationBase;     /* 栈分配基址           */
    SIZE_T      StackSize;          /* 栈总大小             */
    SIZE_T      CommittedSize;      /* 已提交大小           */
    SIZE_T      ReservedSize;       /* 保留大小             */
    UINT64      GuardPage;          /* guard page 地址      */
    BOOLEAN     HasGuardPage;       /* 是否存在 guard page  */
    BOOLEAN     IsMainThread;       /* 是否主线程栈         */
    LARGE_INTEGER LastUpdated;      /* 最近更新 (替代 SS SystemTimePoint) */
} SPD_STACK_RANGE, *PSPD_STACK_RANGE;

/* 地址是否落在栈边界内 (StackRange::ContainsAddress) */
#define SPD_RANGE_CONTAINS(Range, Addr) \
    ((Addr) >= (Range)->StackLimit && (Addr) <= (Range)->StackBase)

/**************************************************/
/*               内存区域信息结构                   */
/*  MemoryRegionInfo, moduleName 定长化。   */
/**************************************************/

typedef struct _SPD_MEMORY_REGION {
    UINT64              BaseAddress;        /* 区域基址          */
    SIZE_T              RegionSize;         /* 区域大小          */
    UINT64              AllocationBase;     /* 分配基址          */
    SPD_PIVOT_DEST_TYPE RegionType;         /* 区域类型          */
    ULONG               State;              /* MEM_COMMIT 等     */
    ULONG               Protection;         /* 内存保护          */
    ULONG               Type;               /* MEM_PRIVATE 等    */
    BOOLEAN             IsExecutable;       /* 可执行            */
    BOOLEAN             IsWritable;         /* 可写              */
    WCHAR               ModuleName[DEF_MAX_PATH]; /* 映像模块名  */
} SPD_MEMORY_REGION, *PSPD_MEMORY_REGION;

/**************************************************/
/*               检测事件结构                       */
/*  PivotEvent 核心字段 (dest region 摘要), */
/*  去 JSON 序列化。                               */
/**************************************************/

typedef struct _SPD_DETECTION_EVENT {
    ULONG               EventId;            /* 全局自增序号 (替代 SS 字符串 ID) */
    ULONG               ProcessId;
    ULONG               ThreadId;
    WCHAR               ProcessName[DEF_MAX_IMAGE_NAME];
    WCHAR               ProcessPath[DEF_MAX_PATH * 2];

    UINT64              OriginalStackBase;  /* 原始栈基址        */
    UINT64              OriginalStackLimit; /* 原始栈下限        */
    UINT64              NewStackPointer;    /* 迁移后栈指针      */

    SPD_PIVOT_DEST_TYPE DestinationType;    /* 目的地类型        */
    UINT64              DestinationBase;    /* 目的地区域基址    */
    UINT64              DestinationSize;    /* 目的地区域大小    */
    WCHAR               DestinationModuleName[DEF_MAX_IMAGE_NAME]; /* 映像名 (如有) */

    SPD_PIVOT_TECHNIQUE Technique;          /* 识别到的迁移技术  */
    UINT64              PivotGadgetAddress; /* gadget 地址 (如有) */
    UCHAR               PivotGadgetBytes[SPD_GADGET_CAPTURE_BYTES]; /* 原始字节 */
    ULONG               PivotGadgetBytesLength;
    UINT64              InstructionPointer; /* 检测时刻指令指针  */

    SPD_CONFIDENCE      Confidence;         /* 置信度等级        */
    ULONG               ConfidenceScore;    /* 置信度分数 [0,100] */
    BOOLEAN             WasBlocked;         /* 是否触发拦截      */
    BOOLEAN             ProcessTerminated;  /* 是否终止进程      */

    LARGE_INTEGER       Timestamp;
    WCHAR               Details[512];       /* 人类可读细节 (宽字符) */
} SPD_DETECTION_EVENT, *PSPD_DETECTION_EVENT;

/**************************************************/
/*               配置结构                           */
/*  StackPivotDetectorConfiguration 核心开关。*/
/*  excludedProcesses 动态表 → 定长数组。           */
/**************************************************/

typedef struct _SPD_CONFIG {
    BOOLEAN         StrictMode;             /* 严格模式 (立即拦截) */
    BOOLEAN         EnablePeriodicValidation; /* 周期验证          */
    ULONG           ValidationIntervalMs;   /* 验证周期 (10-60000ms) */
    BOOLEAN         EnableApiBoundaryChecks;  /* API 边界检查      */
    BOOLEAN         EnableExceptionValidation; /* 异常上下文验证    */
    BOOLEAN         BlockOnPivot;           /* 检测即拦截          */
    BOOLEAN         TerminateOnPivot;       /* 确认迁移即终止      */
    BOOLEAN         MonitorThreadCreation;  /* 线程创建监控        */
    BOOLEAN         VerboseLogging;         /* 冗余日志            */
    ULONG           ExcludedProcessCount;   /* 排除进程数          */
    WCHAR           ExcludedProcesses[SPD_MAX_EXCLUDED_PROCESSES][SPD_MAX_EXCLUDED_NAME_LEN];
} SPD_CONFIG, *PSPD_CONFIG;

#define SPD_DEFAULT_EXCLUDED_COUNT         0

#define SPD_DEFAULT_CONFIG                                          \
    { TRUE, TRUE, SPD_VALIDATION_INTERVAL_MS, TRUE, TRUE,           \
      TRUE, TRUE, TRUE, FALSE, SPD_DEFAULT_EXCLUDED_COUNT,          \
      { { 0 } } }

/**************************************************/
/*               统计结构                           */
/*  StackPivotStatisticsSnapshot           */
/*  (byTechnique 16 槽对应 SPD_PIVOT_TECHNIQUE 0-14)。 */
/**************************************************/

typedef struct _SPD_STATISTICS {
    volatile LONG   ChecksPerformed;        /* 验证次数          */
    volatile LONG   ThreadsMonitored;       /* 已跟踪线程数      */
    volatile LONG   PivotsDetected;         /* 迁移检测次数      */
    volatile LONG   HeapPivots;             /* 堆迁移次数        */
    volatile LONG   DataPivots;             /* 数据段迁移次数    */
    volatile LONG   ImagePivots;            /* 映像段迁移次数    */
    volatile LONG   AttacksBlocked;         /* 拦截次数          */
    volatile LONG   ProcessesTerminated;    /* 终止进程数        */
    volatile LONG   ByTechnique[SPD_TECHNIQUE_SLOTS]; /* 按技术计数 */
    ULONG           UptimeSeconds;          /* 启动后运行秒数    */
} SPD_STATISTICS, *PSPD_STATISTICS;

/**************************************************/
/*               检测回调                           */
/**************************************************/

typedef VOID (*SPD_DETECTED_CALLBACK)(
    _In_    const SPD_DETECTION_EVENT* Event,
    _In_opt_ PVOID                     Context
    );

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
SpdInitialize(
    _In_opt_ const SPD_CONFIG* Config          /* NULL = SPD_DEFAULT_CONFIG */
    );

VOID
SpdShutdown(VOID);

BOOLEAN
SpdIsInitialized(VOID);

SPD_STATUS
SpdGetStatus(VOID);

BOOLEAN
SpdUpdateConfiguration(
    _In_ const SPD_CONFIG* Config
    );

NTSTATUS
SpdGetConfiguration(
    _Out_ PSPD_CONFIG Config
    );

PCSTR
SpdGetVersionString(VOID);

/**************************************************/
/*               栈验证                             */
/**************************************************/

/*
 * SpdValidateStackPointer — 验证线程栈指针 (ValidateStackPointer):
 *  - 经栈上限缓存 (TEB 读取, 30s TTL) 获取 (pid, tid) 的栈范围
 *  - 边界判定: 范围内 → Valid / 邻近 guard page → NearGuardPage
 *  - 超出基址 → Underflow, 低于下限 → Overflow; 无法获取 → InvalidBounds
 *  - 每次验证递增 ChecksPerformed。
 */
SPD_VALIDATION_RESULT
SpdValidateStackPointer(
    _In_ ULONG   ProcessId,
    _In_ ULONG   ThreadId,
    _In_ UINT64  StackPointer
    );

/*
 * SpdIsOnValidStack — 快速判断地址是否落在某已知栈内
 * (IsOnValidStack, 遍历该 PID 缓存栈范围)。
 */
BOOLEAN
SpdIsOnValidStack(
    _In_ ULONG  ProcessId,
    _In_ UINT64 Address
    );

/*
 * SpdDetectPivot — 检测栈迁移攻击 (DetectPivot):
 *  - 排除列表过滤 (进程名精确比对, 忽略大小写)
 *  - Valid/NearGuardPage/InvalidBounds/Unknown 直接放行
 *  - 溢出/下溢 → 构造事件, 按目的地类型填置信度
 *    (堆=VeryHigh/95, 数据-映像段=High/85, 私有内存=Medium/70, 其他=Low/50)
 *  - BlockOnPivot → 计数; TerminateOnPivot+High 以上 → TerminateProcess
 *  - RIP 可执行区读取 8 字节 → gadget 匹配 → 技术识别
 *  - 命中事件写入调用方缓冲 (可选) 并经回调上报
 *  - 返回 TRUE = 检测到迁移。
 */
BOOLEAN
SpdDetectPivot(
    _In_  ULONG                 ProcessId,
    _In_  ULONG                 ThreadId,
    _In_  UINT64                CurrentRsp,
    _In_  UINT64                CurrentRip,
    _Out_opt_ PSPD_DETECTION_EVENT Event
    );

/**************************************************/
/*               栈跟踪                             */
/**************************************************/

NTSTATUS
SpdGetStackLimits(
    _In_  ULONG           ProcessId,
    _In_  ULONG           ThreadId,
    _Out_ PSPD_STACK_RANGE Range
    );

VOID
SpdRefreshStackLimitsForProcess(
    _In_ ULONG ProcessId
    );

VOID
SpdRefreshStackLimits(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId
    );

NTSTATUS
SpdGetProcessStackRanges(
    _In_                               ULONG           ProcessId,
    _Out_writes_to_opt_(MaxRanges, *pReturned) PSPD_STACK_RANGE Ranges,
    _In_                               ULONG           MaxRanges,
    _Out_opt_                          PULONG          pReturned
    );

VOID
SpdRegisterThread(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId
    );

VOID
SpdUnregisterThread(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId
    );

/**************************************************/
/*               内存分析                           */
/**************************************************/

NTSTATUS
SpdGetMemoryRegionInfo(
    _In_  ULONG            ProcessId,
    _In_  UINT64           Address,
    _Out_ PSPD_MEMORY_REGION Region
    );

SPD_PIVOT_DEST_TYPE
SpdGetRegionType(
    _In_ ULONG  ProcessId,
    _In_ UINT64 Address
    );

BOOLEAN
SpdIsHeapAddress(
    _In_ ULONG  ProcessId,
    _In_ UINT64 Address
    );

BOOLEAN
SpdIsImageAddress(
    _In_ ULONG  ProcessId,
    _In_ UINT64 Address
    );

/**************************************************/
/*               进程监控                           */
/**************************************************/

BOOLEAN
SpdMonitorProcess(
    _In_ ULONG ProcessId
    );

VOID
SpdStopMonitoring(
    _In_ ULONG ProcessId
    );

BOOLEAN
SpdIsMonitoring(
    _In_ ULONG ProcessId
    );

NTSTATUS
SpdGetMonitoredProcesses(
    _Out_writes_to_opt_(MaxPids, *pReturned) PULONG  Pids,
    _In_                               ULONG   MaxPids,
    _Out_opt_                          PULONG  pReturned
    );

/**************************************************/
/*               内核集成                           */
/*  WkDefender agent 无内核 IPC 通道 (SS IPCManager) */
/*  已裁掉 RegisterGenericHandler 注册; 本入口供调用方 */
/*  转发内核内存告警 (RW/RWX 私有分配, 检查监控线程    */
/*  RSP 是否落入新分配区)。                           */
/**************************************************/

VOID
SpdProcessKernelMemoryAlert(
    _In_ ULONG   ProcessId,
    _In_ UINT64  Address,
    _In_ SIZE_T  Size,
    _In_ ULONG   Protection
    );

/**************************************************/
/*               统计 / 历史                        */
/**************************************************/

VOID
SpdGetStatistics(
    _Out_ PSPD_STATISTICS Stats
    );

VOID
SpdResetStatistics(VOID);

/*
 * SpdGetRecentDetections — 取最近检测事件 (环形历史,
 * 最新的在前, GetRecentDetections 倒序语义)。
 */
ULONG
SpdGetRecentDetections(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PSPD_DETECTION_EVENT Events,
    _In_                               ULONG                   MaxEvents,
    _Out_opt_                          PULONG                  pReturned
    );

BOOLEAN
SpdSelfTest(VOID);

/**************************************************/
/*               回调                              */
/**************************************************/

VOID
SpdRegisterCallback(
    _In_opt_ SPD_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    );

/**************************************************/
/*               工具函数                           */
/**************************************************/

PCSTR
SpdGetDestinationTypeName(
    _In_ SPD_PIVOT_DEST_TYPE Type
    );

PCSTR
SpdGetTechniqueName(
    _In_ SPD_PIVOT_TECHNIQUE Technique
    );

PCSTR
SpdGetValidationResultName(
    _In_ SPD_VALIDATION_RESULT Result
    );

/*
 * SpdIsPivotGadgetBytes — 匹配栈迁移 gadget 字节模式
 * (IsStackPivotGadget: 1B 表 → 2B 表 + x64 POP RSP → 3B x64 表 → LEAVE+RET)。
 */
BOOLEAN
SpdIsPivotGadgetBytes(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG   ByteCount
    );

/*
 * SpdIdentifyPivotTechnique — 识别 gadget 字节对应的迁移技术
 * (IdentifyPivotTechnique 完整编码表, x64 3B 先于 x86 2B 匹配)。
 */
SPD_PIVOT_TECHNIQUE
SpdIdentifyPivotTechnique(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG   ByteCount
    );