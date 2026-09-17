/*++
    模块名称：内存扫描引擎（MemoryScanner）
    功能描述：提供企业级内存扫描能力，用于检测进程内存中的恶意内容。
    核心能力：
      - Boyer-Moore-Horspool 单模式快速匹配
      - Aho-Corasick 多模式自动机高效扫描
      - 通配符模式支持（掩码匹配）
      - 多段签名检测
      - Shannon 熵分析（加壳/加密检测）
      - 异步扫描 + 工作队列集成
      - 高效区域枚举
      - 线程安全的模式管理
      - 完整的统计与遥测
    MITRE ATT&CK 覆盖：
      - T1055: 进程注入（内存模式检测）
      - T1620: 反射代码加载（熵 + 模式）
      - T1027: 混淆文件（熵分析）
      - T1059: 命令和脚本解释器（shellcode 模式）
    来源：由 ShadowStrike PhantomSensor MemoryScanner.c 全量迁移
--*/

//
// 【WkD 迁移说明】
// 本文件由 ShadowStrike PhantomSensor MemoryScanner.c 全量迁移。
// - ntifs.h 必须先于 ntddk.h，避免 PEPROCESS/PETHREAD C2371 重定义。
// - SS 专有依赖已替换为 WkD 等价物：
//   * ShadowStrikeAllocatePoolWithTag / ShadowStrikeFreePoolWithTag
//     -> ExAllocatePool2 / ExFreePoolWithTag
//   * ShadowPowerIsOnBattery()        -> MspIsOnBattery()（本地占位，未接电源状态）
//   * BeEngineSubmitEvent()           -> MspSubmitShellcodeEvent()（本地占位，待接 IoaEngine）
// - 已删除 SS 专属 include：MemoryUtils.h、StringUtils.h、BehaviorTypes.h、
//   BehaviorEngine.h、PowerCallback.h。
//
#include <ntifs.h>
#include "MemoryScanner.h"
#include <ntstrsafe.h>

//
// 内核态头文件未定义 MEM_IMAGE（MS-4 修复）
//
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x1000000
#endif

//
// 【WkD 迁移适配】行为事件占位宏
// 原 SS 依赖 Shared/BehaviorTypes.h 中的枚举：
//   BehaviorEvent_ShellcodeDetected  = 0x0206
//   BehaviorCategory_MemoryOperation = 3
// WkD 工程无 BehaviorTypes.h，此处以宏保留原值语义，供 MspSubmitShellcodeEvent 使用。
//
#define MS_BE_EVENT_SHELLCODE_DETECTED     0x0206
#define MS_BE_CATEGORY_MEMORY_OPERATION    3

/* ======================================================================== */
/*                           私有常量定义                                      */
/* ======================================================================== */

//
// BMH 坏字符表字母表大小
//
#define MS_ALPHABET_SIZE                256

//
// Aho-Corasick 最大状态数
// 上限限制 NonPagedPool 消耗：8192 * ~1052 字节 ≈ 8.4MB
//
#define MS_AC_MAX_STATES                8192

//
// Aho-Corasick 失败链接哨兵值
//
#define MS_AC_FAIL_SENTINEL             0xFFFFFFFF

//
// 匹配结果捕获的上下文字节数
//
#define MS_CONTEXT_BYTES                32

//
// 模式 Lookaside List 深度
//
#define MS_PATTERN_LOOKASIDE_DEPTH      128

//
// 匹配结果 Lookaside List 深度
//
#define MS_MATCH_LOOKASIDE_DEPTH        256

//
// 扫描结果 Lookaside List 深度
//
#define MS_RESULT_LOOKASIDE_DEPTH       32

//
// 最大并发扫描数
//
#define MS_MAX_CONCURRENT_SCANS         64

//
// 最小可扫描区域大小
//
#define MS_MIN_REGION_SIZE              64

//
// 模式哈希表桶数
//
#define MS_PATTERN_HASH_BUCKETS         256

//
// 熵计算块大小
//
#define MS_ENTROPY_BLOCK_SIZE           256

//
// 高熵阈值（百分比）
//
#define MS_HIGH_ENTROPY_THRESHOLD       75

//
// 扫描器魔数，用于结构体校验
//
#define MS_SCANNER_MAGIC                0x4D534352  // 'MSCR'

//
// 模式魔数，用于结构体校验
//
#define MS_PATTERN_MAGIC                0x4D535054  // 'MSPT'

/* ======================================================================== */
/*                           私有结构体定义                                     */
/* ======================================================================== */

//
// Aho-Corasick 状态节点
//
typedef struct _MS_AC_STATE {
    ULONG Goto[MS_ALPHABET_SIZE];       // 转移表
    ULONG Failure;                       // 失败链接
    LIST_ENTRY OutputPatterns;           // 该状态匹配的模式链表
    ULONG OutputCount;                   // 输出模式数量
    ULONG Depth;                         // 从根节点到当前状态的深度
} MS_AC_STATE, *PMS_AC_STATE;

//
// Aho-Corasick 模式输出条目
//
typedef struct _MS_AC_OUTPUT {
    LIST_ENTRY ListEntry;
    ULONG PatternId;
    PMS_PATTERN Pattern;
} MS_AC_OUTPUT, *PMS_AC_OUTPUT;

//
// Aho-Corasick 自动机
//
typedef struct _MS_AC_AUTOMATON {
    PMS_AC_STATE States;                 // 状态数组
    ULONG StateCount;                    // 当前状态数
    ULONG MaxStates;                     // 最大可分配状态数
    BOOLEAN Built;                       // 自动机已构建并就绪
    EX_PUSH_LOCK Lock;                   // 同步锁
} MS_AC_AUTOMATON, *PMS_AC_AUTOMATON;

//
// 活跃扫描跟踪条目
//
typedef struct _MS_ACTIVE_SCAN {
    LIST_ENTRY ListEntry;
    ULONG ScanId;
    PMS_SCAN_REQUEST Request;
    PMS_SCAN_RESULT Result;
    volatile LONG Cancelled;
    volatile LONG Completed;
    LARGE_INTEGER StartTime;
    KEVENT CompletionEvent;
    MS_SCAN_COMPLETE_CALLBACK Callback;
    PVOID CallbackContext;
    PIO_WORKITEM WorkItem;
} MS_ACTIVE_SCAN, *PMS_ACTIVE_SCAN;

//
// 扫描器内部上下文（扩展字段）
//
typedef struct _MS_SCANNER_INTERNAL {
    //
    // 基础扫描器结构（必须位于首位）
    //
    MS_SCANNER Base;

    //
    // 结构体魔数校验
    //
    ULONG Magic;

    //
    // Aho-Corasick 自动机
    //
    MS_AC_AUTOMATON AhoCorasick;

    //
    // 模式哈希表（快速查找）
    //
    LIST_ENTRY PatternHashTable[MS_PATTERN_HASH_BUCKETS];

    //
    // Lookaside List（频繁分配优化）
    //
    NPAGED_LOOKASIDE_LIST PatternLookaside;
    NPAGED_LOOKASIDE_LIST MatchLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    BOOLEAN LookasideInitialized;

    //
    // 扫描 ID 生成器
    //
    volatile LONG NextScanId;

    //
    // 引用计数
    //
    volatile LONG ReferenceCount;
    volatile LONG ShuttingDown;
    KEVENT ShutdownEvent;

    //
    // 排队中的 IoQueueWorkItem 计数
    // 递增时机：IoQueueWorkItem 之前
    // 递减时机：MspAsyncScanWorker 末尾
    // 作用：MsShutdown 可据此判断工作项是否仍在访问扫描器状态
    //
    volatile LONG QueuedWorkItems;

    //
    // 设备对象（用于创建工作项）
    //
    PDEVICE_OBJECT DeviceObject;

} MS_SCANNER_INTERNAL, *PMS_SCANNER_INTERNAL;

//
// 内部模式结构（附加跟踪字段）
//
typedef struct _MS_PATTERN_INTERNAL {
    //
    // 基础模式（必须位于首位）
    //
    MS_PATTERN Base;

    //
    // 结构体魔数校验
    //
    ULONG Magic;

    //
    // 哈希表链接
    //
    LIST_ENTRY HashEntry;

    //
    // 反向引用扫描器
    //
    PMS_SCANNER_INTERNAL Scanner;

    //
    // 引用计数
    //
    volatile LONG ReferenceCount;

} MS_PATTERN_INTERNAL, *PMS_PATTERN_INTERNAL;

//
// 异步扫描工作项上下文
//
typedef struct _MS_ASYNC_WORK_CONTEXT {
    PMS_SCANNER_INTERNAL Scanner;
    PMS_ACTIVE_SCAN ActiveScan;
} MS_ASYNC_WORK_CONTEXT, *PMS_ASYNC_WORK_CONTEXT;

/* ======================================================================== */
/*                           私有函数原型声明                                    */
/* ======================================================================== */

static ULONG
MspHashPatternId(
    _In_ ULONG PatternId
    );

static VOID
MspComputeBadCharTable(
    _Inout_ PMS_PATTERN Pattern
    );

static NTSTATUS
MspBoyerMooreHorspoolSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
    );

static NTSTATUS
MspWildcardSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
    );

static NTSTATUS
MspAhoCorasickSearch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
    );

static NTSTATUS
MspScanNonAcPatterns(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
    );

static NTSTATUS
MspBuildAhoCorasickAutomaton(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
    );

static VOID
MspDestroyAhoCorasickAutomaton(
    _Inout_ PMS_AC_AUTOMATON Automaton
    );

static NTSTATUS
MspAllocateMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_MATCH* Match
    );

static VOID
MspFreeMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PMS_MATCH Match
    );

static NTSTATUS
MspAllocateScanResult(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_SCAN_RESULT* Result
    );

static VOID
MspAddMatchToResult(
    _In_ PMS_PATTERN Pattern,
    _In_ PUCHAR MatchLocation,
    _In_ SIZE_T Offset,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection,
    _In_ MS_SCAN_FLAGS Flags,
    _In_ PUCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PMS_SCANNER_INTERNAL Scanner
    );

static NTSTATUS
MspScanProcessRegions(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
    );

static NTSTATUS
MmpScanMemroyRegion(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG Protection,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
    );

static BOOLEAN
MspShouldScanRegion(
    _In_ ULONG Protection,
    _In_ ULONG State,
    _In_ ULONG Type,
    _In_ MS_SCAN_TYPE ScanType,
    _In_ MS_SCAN_FLAGS Flags
    );

static VOID
MspAsyncScanWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static PMS_PATTERN_INTERNAL
MspFindPatternById(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ ULONG PatternId
    );

static VOID
MspAcquireReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
    );

static VOID
MspReleaseReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
    );

//
// 原子获取引用，随后检查关机状态。
// 返回 TRUE：引用已获取且扫描器可用。
// 返回 FALSE：正在关机（未持有引用）。
//
static BOOLEAN
MspTryAcquireReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
    );

static ULONG
MspCalculateIntegerEntropy(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
    );

//
// 【WkD 迁移适配】本地桩函数声明
// 原 SS 依赖 PowerCallback.h 的 ShadowPowerIsOnBattery() 与
// Behavioral/BehaviorEngine.h 的 BeEngineSubmitEvent()。
// WkD 工程暂无对应模块，此处以本地桩保留调用语义，后续由用户接入真实实现。
//
static BOOLEAN
MspIsOnBattery(
    VOID
    );

static VOID
MspSubmitShellcodeEvent(
    _In_ ULONG EventType,
    _In_ ULONG Category,
    _In_ ULONG ProcessId,
    _In_ UINT32 Score
    );

/* ======================================================================== */
/*                          页分配节属性                                      */
/* ======================================================================== */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, MsInitialize)
#pragma alloc_text(PAGE, MsShutdown)
#pragma alloc_text(PAGE, MsAddPattern)
#pragma alloc_text(PAGE, MsAddPatternWithMask)
#pragma alloc_text(PAGE, MsRemovePattern)
#pragma alloc_text(PAGE, MsEnablePattern)
#pragma alloc_text(PAGE, MsRebuildSearchTables)
#pragma alloc_text(PAGE, MmScanProcess)
#pragma alloc_text(PAGE, MsScanRegion)
#pragma alloc_text(PAGE, MsScanBuffer)
#pragma alloc_text(PAGE, MsScanAsync)
#pragma alloc_text(PAGE, MsCancelScan)
#pragma alloc_text(PAGE, MsFreeScanResult)
#pragma alloc_text(PAGE, MsFindHighEntropyRegions)
#endif

/* ======================================================================== */
/*                      纯整数熵计算（无浮点运算）                            */
/* ======================================================================== */

//
// 预计算表：-count * log2(count/256) * 256，使用定点运算。
//
// 对于 256 字节的块，若字节值出现 count 次，
// 其熵贡献（×256）存储在此表中。
// 熵 = sum_over_byte_values(table[frequency[byte]]) / 256。
// 结果范围：[0, 8*256 = 2048]，表示 [0.0, 8.0] 比特。
//
// 离线计算：table[n] = round(-n * log2(n/256))
// 使用定点 ×1024 提高精度。
//
// 简化方案：entropy * 100 / 8 = percent，纯整数运算。
// 使用 256 项查找表：g_EntropyContrib[count] = round(-count * log2(count/256) * (1 << 16) / 256)
//
// 预计算值：g_EntropyContrib[n] = round(-n * log2(n/256.0) * 256)，n ∈ [0..256]
// 熵 = sum(g_EntropyContrib[freq[i]])（i ∈ [0..255]），除以 256 得到 bits*256
// 百分比 = result * 100 / (8 * 256)
//
// 这些值在编译期计算，存储于 .rdata（只读）。
// 运行时无浮点运算。
//
static const USHORT g_EntropyContrib[257] = {
    //  n=0..15
       0, 2048, 1792, 1621, 1536, 1463, 1408, 1363, 1280, 1258, 1198, 1152, 1109, 1073, 1044, 1015,
    //  n=16..31
     990,  965,  945,  924,  903,  886,  867,  851,  834,  819,  804,  789,  776,  762,  749,  736,
    //  n=32..47
     724,  712,  700,  689,  678,  667,  657,  647,  636,  627,  617,  607,  598,  589,  580,  572,
    //  n=48..63
     563,  555,  547,  539,  531,  523,  516,  508,  501,  494,  487,  480,  474,  467,  460,  454,
    //  n=64..79
     448,  441,  435,  429,  423,  417,  411,  406,  400,  395,  389,  384,  378,  373,  368,  363,
    //  n=80..95
     358,  353,  348,  343,  338,  334,  329,  324,  320,  315,  311,  306,  302,  298,  293,  289,
    //  n=96..111
     285,  281,  277,  273,  269,  265,  261,  257,  253,  250,  246,  242,  239,  235,  231,  228,
    //  n=112..127
     224,  221,  217,  214,  211,  207,  204,  201,  197,  194,  191,  188,  185,  182,  179,  176,
    //  n=128..143
     173,  170,  167,  164,  161,  158,  155,  153,  150,  147,  144,  142,  139,  136,  134,  131,
    //  n=144..159
     129,  126,  124,  121,  119,  116,  114,  111,  109,  107,  104,  102,  100,   97,   95,   93,
    //  n=160..175
      91,   89,   86,   84,   82,   80,   78,   76,   74,   72,   70,   68,   66,   64,   62,   60,
    //  n=176..191
      58,   56,   54,   53,   51,   49,   47,   46,   44,   42,   40,   39,   37,   36,   34,   32,
    //  n=192..207
      31,   29,   28,   26,   25,   23,   22,   20,   19,   18,   16,   15,   14,   12,   11,   10,
    //  n=208..223
       9,    7,    6,    5,    4,    3,    2,    1,    0,    0,    0,    0,    0,    0,    0,    0,
    //  n=224..239
       0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    //  n=240..255
       0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    //  n=256
       0
};

/* ======================================================================== */
/*                          初始化和清理                                      */
/* ======================================================================== */

/*++
    MsInitialize

    初始化内存扫描器：分配内部结构、初始化模式链表/哈希表/自动机/
    活跃扫描链表/Lookaside List/配置默认值，并建立引用计数。

    参数：
        DeviceObject - 设备对象（用于异步工作项）
        Scanner      - 输出扫描器指针

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PMS_SCANNER* Scanner
)
{
    PMS_SCANNER_INTERNAL scanner = NULL;
    ULONG i;

    PAGED_CODE();

    //
    // 参数校验
    //
    if (Scanner == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Scanner = NULL;

    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // 分配内部扫描器结构
    //
    scanner = (PMS_SCANNER_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(MS_SCANNER_INTERNAL),
        MS_POOL_TAG_CONTEXT
    );

    if (scanner == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(scanner, sizeof(MS_SCANNER_INTERNAL));

    //
    // 设置魔数
    //
    scanner->Magic = MS_SCANNER_MAGIC;

    //
    // 初始化模式链表
    //
    InitializeListHead(&scanner->Base.PatternList);
    ExInitializePushLock(&scanner->Base.PatternLock);

    //
    // 初始化模式哈希表
    //
    for (i = 0; i < MS_PATTERN_HASH_BUCKETS; i++) {
        InitializeListHead(&scanner->PatternHashTable[i]);
    }

    //
    // 初始化 Aho-Corasick 自动机
    //
    ExInitializePushLock(&scanner->AhoCorasick.Lock);
    scanner->AhoCorasick.States = NULL;
    scanner->AhoCorasick.StateCount = 0;
    scanner->AhoCorasick.MaxStates = 0;
    scanner->AhoCorasick.Built = FALSE;

    ExInitializePushLock(&scanner->Base.AhoCorasickLock);
    scanner->Base.AhoCorasickReady = FALSE;

    //
    // 初始化活跃扫描跟踪链表
    //
    InitializeListHead(&scanner->Base.ActiveScans);
    ExInitializePushLock(&scanner->Base.ActiveScansLock);

    //
    // 初始化 Lookaside List
    //
    ExInitializeNPagedLookasideList(
        &scanner->PatternLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MS_PATTERN_INTERNAL),
        MS_POOL_TAG_PATTERN,
        MS_PATTERN_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &scanner->MatchLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MS_MATCH),
        MS_POOL_TAG_RESULT,
        MS_MATCH_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &scanner->ResultLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MS_SCAN_RESULT),
        MS_POOL_TAG_RESULT,
        MS_RESULT_LOOKASIDE_DEPTH
    );

    scanner->LookasideInitialized = TRUE;

    //
    // 初始化配置默认值
    //
    scanner->Base.Config.MaxPatterns = MS_MAX_PATTERNS;
    scanner->Base.Config.ChunkSize = MS_SCAN_CHUNK_SIZE;
    scanner->Base.Config.DefaultTimeoutMs = MS_SCAN_TIMEOUT_MS;
    scanner->Base.Config.EnableAhoCorasick = TRUE;

    //
    // 初始化统计
    //
    KeQuerySystemTime(&scanner->Base.Stats.StartTime);

    //
    // 初始化引用计数
    //
    scanner->ReferenceCount = 1;
    scanner->ShuttingDown = FALSE;
    KeInitializeEvent(&scanner->ShutdownEvent, NotificationEvent, FALSE);

    //
    // 初始化扫描 ID 计数器
    //
    scanner->NextScanId = 1;

    //
    // 保存设备对象（工作项使用）
    //
    scanner->DeviceObject = DeviceObject;

    //
    // 标记初始化完成（Interlocked 保证可见性）
    //
    InterlockedExchange(&scanner->Base.Initialized, 1);

    *Scanner = (PMS_SCANNER)scanner;

    return STATUS_SUCCESS;
}

/*++
    MsShutdown

    关闭内存扫描器：取消所有活跃扫描、等待工作项排空、
    释放所有模式和 Lookaside List，最后释放扫描器结构。

    参数：
        Scanner - 扫描器指针

    返回值：
        无
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsShutdown(
    _Inout_ PMS_SCANNER Scanner
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    PMS_ACTIVE_SCAN activeScan;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return;
    }

    //
    // 发出关机信号——阻止新操作启动
    //
    InterlockedExchange(&scanner->ShuttingDown, 1);
    InterlockedExchange(&scanner->Base.Initialized, 0);

    //
    // 取消所有活跃扫描（Push Lock）
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.ActiveScansLock);

    for (entry = scanner->Base.ActiveScans.Flink;
         entry != &scanner->Base.ActiveScans;
         entry = entry->Flink) {

        activeScan = CONTAINING_RECORD(entry, MS_ACTIVE_SCAN, ListEntry);
        InterlockedExchange(&activeScan->Cancelled, 1);
        KeSetEvent(&activeScan->CompletionEvent, IO_NO_INCREMENT, FALSE);
    }

    ExReleasePushLockExclusive(&scanner->Base.ActiveScansLock);
    KeLeaveCriticalRegion();

    //
    // 等待活跃扫描完成
    // 取消信号发出后，等待最后一个引用释放时设置的 ShutdownEvent
    //
    {
        LARGE_INTEGER waitTimeout;
        waitTimeout.QuadPart = -((LONGLONG)30 * 10000000);  // 最长 30 秒
        ULONG retries = 0;
        while (scanner->Base.ActiveScanCount > 0 && retries < 300) {
            LARGE_INTEGER delay;
            delay.QuadPart = -((LONGLONG)100 * 10000);  // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            retries++;
        }
    }

    //
    // 显式排空在途 IoWorkItem 工作项
    // QueuedWorkItems 在工作项末尾递减，是"工作项仍访问扫描器状态"的权威指标。
    // 缺少该排空，下方 Lookaside List 删除可能释放工作项仍读取中的内存池。
    //
    {
        ULONG spin = 0;
        while (ReadNoFence(&scanner->QueuedWorkItems) > 0) {
            LARGE_INTEGER poll;
            poll.QuadPart = -((LONGLONG)10 * 10000);  // 10ms
            KeDelayExecutionThread(KernelMode, FALSE, &poll);
            ++spin;
            if (spin == 100) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike-MS] WorkItem drain slow: queued=%ld\n",
                    ReadNoFence(&scanner->QueuedWorkItems));
            }
            if (spin >= 3000) {  // 30s budget
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[ShadowStrike-MS] CRITICAL: %ld IoWorkItem(s) stuck; BugCheck "
                    "to prevent UAF on lookaside deletion\n",
                    ReadNoFence(&scanner->QueuedWorkItems));
                KeBugCheckEx(
                    DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS,
                    (ULONG_PTR)ReadNoFence(&scanner->QueuedWorkItems),
                    (ULONG_PTR)scanner,
                    (ULONG_PTR)&scanner->QueuedWorkItems,
                    (ULONG_PTR)0x4D530001u);  // 哨兵值：MS 工作项排空超时
            }
        }
    }

    //
    // 释放初始引用（MsInitialize 中建立），等待所有未结引用排空。
    // KeWaitForSingleObject 阻塞直到 MspReleaseReference 在 RefCount==0 时
    // 触发 ShutdownEvent。
    //
    {
        LONG newCount = InterlockedDecrement(&scanner->ReferenceCount);
        if (newCount > 0) {
            LARGE_INTEGER waitTimeout;
            waitTimeout.QuadPart = -((LONGLONG)30 * 10000000);  // 30 秒
            KeWaitForSingleObject(
                &scanner->ShutdownEvent,
                Executive,
                KernelMode,
                FALSE,
                &waitTimeout
            );
        }
    }

    //
    // 销毁 Aho-Corasick 自动机
    //
    MspDestroyAhoCorasickAutomaton(&scanner->AhoCorasick);

    //
    // 释放所有模式
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    while (!IsListEmpty(&scanner->Base.PatternList)) {
        entry = RemoveHeadList(&scanner->Base.PatternList);
        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        //
        // 释放模式资源
        //
        if (pattern->Base.PatternData != NULL) {
            ExFreePoolWithTag(pattern->Base.PatternData, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.WildcardMask != NULL) {
            ExFreePoolWithTag(pattern->Base.WildcardMask, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.BadCharTable != NULL) {
            ExFreePoolWithTag(pattern->Base.BadCharTable, MS_POOL_TAG_PATTERN);
        }

        //
        // 释放多段签名资源
        //
        if (pattern->Base.Signature.Parts != NULL) {
            ULONG partIdx;
            for (partIdx = 0; partIdx < pattern->Base.Signature.PartCount; partIdx++) {
                if (pattern->Base.Signature.Parts[partIdx] != NULL) {
                    ExFreePoolWithTag(pattern->Base.Signature.Parts[partIdx], MS_POOL_TAG_PATTERN);
                }
            }
            ExFreePoolWithTag(pattern->Base.Signature.Parts, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.Signature.PartSizes != NULL) {
            ExFreePoolWithTag(pattern->Base.Signature.PartSizes, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.Signature.PartOffsets != NULL) {
            ExFreePoolWithTag(pattern->Base.Signature.PartOffsets, MS_POOL_TAG_PATTERN);
        }

        if (scanner->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&scanner->PatternLookaside, pattern);
        } else {
            ExFreePoolWithTag(pattern, MS_POOL_TAG_PATTERN);
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    //
    // 删除 Lookaside List
    //
    if (scanner->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&scanner->PatternLookaside);
        ExDeleteNPagedLookasideList(&scanner->MatchLookaside);
        ExDeleteNPagedLookasideList(&scanner->ResultLookaside);
        scanner->LookasideInitialized = FALSE;
    }

    //
    // 清除状态
    //
    scanner->Magic = 0;

    ExFreePoolWithTag(scanner, MS_POOL_TAG_CONTEXT);
}

/*++
    MsSetWorkQueue

    设置扫描器的工作队列。

    参数：
        Scanner   - 扫描器指针
        WorkQueue - 工作队列指针

    返回值：
        STATUS_SUCCESS 或 STATUS_INVALID_PARAMETER
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MsSetWorkQueue(
    _Inout_ PMS_SCANNER Scanner,
    _In_ PVOID WorkQueue
)
{
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Scanner->WorkQueue = WorkQueue;
    return STATUS_SUCCESS;
}

/* ======================================================================== */
/*                            模式管理                                       */
/* ======================================================================== */

/*++
    MsAddPattern

    向扫描器注册一个新模式（精确匹配或通配符）。
    分配模式结构、复制数据、计算 BMH 坏字符表（精确模式）、
    插入模式链表和哈希表，并使 Aho-Corasick 自动机失效（需重建）。

    参数：
        Scanner     - 扫描器指针
        PatternName - 模式名称
        PatternData - 模式字节数据
        PatternSize - 模式大小
        Type        - 模式类型（Exact/Wildcard）
        Flags       - 模式标志
        ThreatName  - 威胁名称（可选）
        Severity    - 严重等级（1-100）
        PatternId   - 输出模式 ID

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsAddPattern(
    _In_ PMS_SCANNER Scanner,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR PatternData,
    _In_ ULONG PatternSize,
    _In_ MS_PATTERN_TYPE Type,
    _In_ MS_PATTERN_FLAGS Flags,
    _In_opt_ PCSTR ThreatName,
    _In_ ULONG Severity,
    _Out_ PULONG PatternId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern = NULL;
    ULONG hashBucket;

    PAGED_CODE();

    //
    // 参数校验
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (PatternName == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (PatternData == NULL || PatternSize == 0) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (PatternSize < MS_MIN_PATTERN_SIZE || PatternSize > MS_MAX_PATTERN_SIZE) {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (PatternId == NULL) {
        return STATUS_INVALID_PARAMETER_8;
    }

    *PatternId = 0;

    //
    // 检查模式数量上限
    //
    if ((ULONG)scanner->Base.PatternCount >= scanner->Base.Config.MaxPatterns) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // 先获取引用，再检查关机状态
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 从 Lookaside 分配模式
    //
    if (scanner->LookasideInitialized) {
        pattern = (PMS_PATTERN_INTERNAL)ExAllocateFromNPagedLookasideList(
            &scanner->PatternLookaside
        );
    } else {
        pattern = (PMS_PATTERN_INTERNAL)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(MS_PATTERN_INTERNAL),
            MS_POOL_TAG_PATTERN
        );
    }

    if (pattern == NULL) {
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pattern, sizeof(MS_PATTERN_INTERNAL));

    //
    // 初始化模式
    //
    pattern->Magic = MS_PATTERN_MAGIC;
    pattern->Scanner = scanner;
    pattern->ReferenceCount = 1;
    InitializeListHead(&pattern->Base.ListEntry);
    InitializeListHead(&pattern->HashEntry);

    //
    // 分配并复制模式数据
    //
    pattern->Base.PatternData = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        PatternSize,
        MS_POOL_TAG_PATTERN
    );

    if (pattern->Base.PatternData == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlCopyMemory(pattern->Base.PatternData, PatternData, PatternSize);
    pattern->Base.PatternSize = PatternSize;

    //
    // 复制模式名称
    //
    status = RtlStringCchCopyA(
        pattern->Base.PatternName,
        sizeof(pattern->Base.PatternName),
        PatternName
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // 复制威胁名称（如果提供）
    //
    if (ThreatName != NULL) {
        RtlStringCchCopyA(
            pattern->Base.ThreatName,
            sizeof(pattern->Base.ThreatName),
            ThreatName
        );
    }

    pattern->Base.Type = Type;
    pattern->Base.Flags = Flags;
    pattern->Base.Severity = Severity;

    //
    // 为精确模式计算 BMH 坏字符表
    //
    if (Type == MsPattern_Exact) {
        MspComputeBadCharTable(&pattern->Base);
    }

    //
    // 分配模式 ID
    //
    pattern->Base.PatternId = (ULONG)InterlockedIncrement(&scanner->Base.NextPatternId);

    //
    // 插入模式链表和哈希表
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    InsertTailList(&scanner->Base.PatternList, &pattern->Base.ListEntry);

    hashBucket = MspHashPatternId(pattern->Base.PatternId);
    InsertTailList(&scanner->PatternHashTable[hashBucket], &pattern->HashEntry);

    InterlockedIncrement(&scanner->Base.PatternCount);

    //
    // 使 Aho-Corasick 自动机失效（需重建）
    //
    scanner->Base.AhoCorasickReady = FALSE;
    scanner->AhoCorasick.Built = FALSE;

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    *PatternId = pattern->Base.PatternId;
    status = STATUS_SUCCESS;

Cleanup:
    if (!NT_SUCCESS(status)) {
        if (pattern != NULL) {
            if (pattern->Base.PatternData != NULL) {
                ExFreePoolWithTag(pattern->Base.PatternData, MS_POOL_TAG_PATTERN);
            }
            if (scanner->LookasideInitialized) {
                ExFreeToNPagedLookasideList(&scanner->PatternLookaside, pattern);
            } else {
                ExFreePoolWithTag(pattern, MS_POOL_TAG_PATTERN);
            }
        }
    }

    MspReleaseReference(scanner);

    return status;
}

/*++
    MsAddPatternWithMask

    添加带通配符掩码的模式。先按精确模式添加，再补充掩码。
    掩码字节非零表示该位置为通配符。

    参数：
        Scanner      - 扫描器指针
        PatternName  - 模式名称
        PatternData  - 模式字节数据
        WildcardMask - 通配符掩码（非零 = 通配符位置）
        PatternSize  - 模式大小
        ThreatName   - 威胁名称（可选）
        Severity     - 严重等级（1-100）
        PatternId    - 输出模式 ID

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsAddPatternWithMask(
    _In_ PMS_SCANNER Scanner,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR PatternData,
    _In_reads_bytes_(PatternSize) PUCHAR WildcardMask,
    _In_ ULONG PatternSize,
    _In_opt_ PCSTR ThreatName,
    _In_ ULONG Severity,
    _Out_ PULONG PatternId
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    //
    // 先按精确模式添加
    //
    status = MsAddPattern(
        Scanner,
        PatternName,
        PatternData,
        PatternSize,
        MsPattern_Wildcard,
        MsPatternFlag_None,
        ThreatName,
        Severity,
        PatternId
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // 找到模式并添加通配符掩码
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    pattern = MspFindPatternById(scanner, *PatternId);
    if (pattern != NULL) {
        //
        // 分配并复制通配符掩码
        //
        pattern->Base.WildcardMask = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            PatternSize,
            MS_POOL_TAG_PATTERN
        );

        if (pattern->Base.WildcardMask != NULL) {
            RtlCopyMemory(pattern->Base.WildcardMask, WildcardMask, PatternSize);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    //
    // 失败回滚：移除部分添加的模式
    //
    if (!NT_SUCCESS(status)) {
        MsRemovePattern(Scanner, *PatternId);
    }

    return status;
}

/*++
    MsRemovePattern

    从扫描器中移除指定模式。释放模式数据、通配符掩码、
    BMH 坏字符表和多段签名资源，并使 Aho-Corasick 自动机失效。

    参数：
        Scanner   - 扫描器指针
        PatternId - 模式 ID

    返回值：
        STATUS_SUCCESS 或 STATUS_NOT_FOUND / NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsRemovePattern(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG PatternId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // 持有引用，防止 MsShutdown 在移除过程中拆除 PatternLock、
    // 模式 Lookaside 和扫描器块
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    pattern = MspFindPatternById(scanner, PatternId);
    if (pattern != NULL) {
        //
        // 从链表中移除
        //
        RemoveEntryList(&pattern->Base.ListEntry);
        RemoveEntryList(&pattern->HashEntry);
        InterlockedDecrement(&scanner->Base.PatternCount);

        //
        // 释放资源
        //
        if (pattern->Base.PatternData != NULL) {
            ExFreePoolWithTag(pattern->Base.PatternData, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.WildcardMask != NULL) {
            ExFreePoolWithTag(pattern->Base.WildcardMask, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.BadCharTable != NULL) {
            ExFreePoolWithTag(pattern->Base.BadCharTable, MS_POOL_TAG_PATTERN);
        }

        //
        // 释放多段签名子资源
        //
        if (pattern->Base.Signature.Parts != NULL) {
            ULONG partIdx;
            for (partIdx = 0; partIdx < pattern->Base.Signature.PartCount; partIdx++) {
                if (pattern->Base.Signature.Parts[partIdx] != NULL) {
                    ExFreePoolWithTag(pattern->Base.Signature.Parts[partIdx], MS_POOL_TAG_PATTERN);
                }
            }
            ExFreePoolWithTag(pattern->Base.Signature.Parts, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.Signature.PartSizes != NULL) {
            ExFreePoolWithTag(pattern->Base.Signature.PartSizes, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.Signature.PartOffsets != NULL) {
            ExFreePoolWithTag(pattern->Base.Signature.PartOffsets, MS_POOL_TAG_PATTERN);
        }

        //
        // 使 Aho-Corasick 失效（强制重建）
        //
        InterlockedExchange(&scanner->Base.AhoCorasickReady, 0);
        scanner->AhoCorasick.Built = FALSE;

        if (scanner->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&scanner->PatternLookaside, pattern);
        } else {
            ExFreePoolWithTag(pattern, MS_POOL_TAG_PATTERN);
        }

        status = STATUS_SUCCESS;
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    MspReleaseReference(scanner);

    return status;
}

/*++
    MsEnablePattern

    启用或禁用指定模式。禁用后扫描时将跳过该模式。

    参数：
        Scanner   - 扫描器指针
        PatternId - 模式 ID
        Enable    - TRUE=启用，FALSE=禁用

    返回值：
        STATUS_SUCCESS 或 STATUS_NOT_FOUND
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsEnablePattern(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG PatternId,
    _In_ BOOLEAN Enable
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // 持有引用防止关机竞争
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    pattern = MspFindPatternById(scanner, PatternId);
    if (pattern != NULL) {
        if (Enable) {
            pattern->Base.Flags &= ~MsPatternFlag_Disabled;
        } else {
            pattern->Base.Flags |= MsPatternFlag_Disabled;
        }

        //
        // 已启用的模式集合发生变化：若自动机已构建，
        // 必须使其失效（Ready=0、Built=FALSE）强制重建，
        // 否则旧自动机仍会匹配已禁用的模式（MS-AC 修复）
        //
        InterlockedExchange(&scanner->Base.AhoCorasickReady, 0);
        scanner->AhoCorasick.Built = FALSE;

        status = STATUS_SUCCESS;
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    MspReleaseReference(scanner);

    return status;
}

/*++
    MsRebuildSearchTables

    重建所有搜索表：为未计算的精确模式补算 BMH 坏字符表，
    并在启用 Aho-Corasick 时重建自动机。

    参数：
        Scanner - 扫描器指针

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsRebuildSearchTables(
    _In_ PMS_SCANNER Scanner
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    NTSTATUS status;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 持有引用防止关机竞争
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    //
    // 为所有精确模式重建 BMH 表
    //
    for (entry = scanner->Base.PatternList.Flink;
         entry != &scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        if (pattern->Base.Type == MsPattern_Exact && !pattern->Base.TableComputed) {
            MspComputeBadCharTable(&pattern->Base);
        }
    }

    //
    // 启用时重建 Aho-Corasick 自动机。
    // 构建需与 AC 搜索互斥（搜索持 AhoCorasickLock shared 读 States），
    // 故在 PatternLock 之内再取 AhoCorasickLock exclusive（MS-AC 修复）
    //
    if (scanner->Base.Config.EnableAhoCorasick) {
        ExAcquirePushLockExclusive(&scanner->Base.AhoCorasickLock);
        MspDestroyAhoCorasickAutomaton(&scanner->AhoCorasick);
        status = MspBuildAhoCorasickAutomaton(scanner);
        ExReleasePushLockExclusive(&scanner->Base.AhoCorasickLock);
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&scanner->Base.AhoCorasickReady, TRUE);
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    MspReleaseReference(scanner);

    return STATUS_SUCCESS;
}

// ============================================================================
//                             扫描操作
// ============================================================================

/*++
    MmScanProcess

    对指定进程执行内存扫描。支持扫描类型降级（电池供电时自动从
    Full/Standard 降为 Quick）、引用计数防关机竞争、结果结构分配、
    Aho-Corasick 自动机按需构建、进程内存区域扫描、统计更新与
    shellcode 行为事件上报。

    参数：
        Scanner   - 扫描器指针
        ProcessId - 目标进程 ID
        Type      - 扫描类型（Quick/Standard/Full）
        Flags     - 扫描标志
        Result    - 输出扫描结果

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmScanProcess(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PEPROCESS process = NULL;
    PMS_SCAN_RESULT result = NULL;

    PAGED_CODE();

    //
    // 参数校验
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    *Result = NULL;

    //
    // 电池供电时将 Full/Standard 扫描降级为 Quick（仅可执行区域），
    // 在保留 shellcode/注入检测能力的同时将 CPU 时间减半。
    // 定向扫描（事件驱动）永不降级。
    //
    if (MspIsOnBattery() &&
        (Type == MsScanType_Full || Type == MsScanType_Standard)) {
        Type = MsScanType_Quick;
    }

    //
    // 先获取引用，再检查关机状态（CRIT-3 修复）
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 获取进程引用
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        MspReleaseReference(scanner);
        return status;
    }

    //
    // 分配结果结构
    //
    status = MspAllocateScanResult(scanner, &result);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        MspReleaseReference(scanner);
        return status;
    }

    result->ProcessId = ProcessId;
    result->Type = Type;
    KeQuerySystemTime(&result->StartTime);

    //
    // 确保搜索表已构建
    // 构建需与 AC 搜索互斥（搜索持 AhoCorasickLock shared 读 States），
    // 故在 PatternLock 之内再取 AhoCorasickLock exclusive（MS-AC 修复）
    //
    if (!scanner->Base.AhoCorasickReady && scanner->Base.Config.EnableAhoCorasick) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&scanner->Base.PatternLock);
        ExAcquirePushLockExclusive(&scanner->Base.AhoCorasickLock);

        if (!scanner->AhoCorasick.Built) {
            MspBuildAhoCorasickAutomaton(scanner);
        }

        ExReleasePushLockExclusive(&scanner->Base.AhoCorasickLock);
        ExReleasePushLockExclusive(&scanner->Base.PatternLock);
        KeLeaveCriticalRegion();
    }

    //
    // 扫描进程内存区域
    //
    status = MspScanProcessRegions(scanner, process, Type, Flags, result);

    //
    // 完成结果
    //
    KeQuerySystemTime(&result->EndTime);
    result->DurationMs = (ULONG)((result->EndTime.QuadPart - result->StartTime.QuadPart) / 10000);
    result->Completed = TRUE;
    result->Status = status;

    //
    // 更新统计
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)result->BytesScanned);
    InterlockedAdd64(&scanner->Base.Stats.TotalMatches, result->MatchCount);
    InterlockedAdd64(&scanner->Base.Stats.CumulativeScanTimeMs, (LONG64)result->DurationMs);

    if (result->MatchCount > 0) {
        //
        // 【WkD 迁移适配】
        // 原 SS 调用 BeEngineSubmitEvent(BehaviorEvent_ShellcodeDetected,
        // BehaviorCategory_MemoryOperation, ...) 上报行为事件。
        // WkD 侧暂无 BehaviorEngine 模块，暂以本地桩 MspSubmitShellcodeEvent
        // 保留语义与参数（事件值/类别值见文件头宏定义），
        // 后续由用户接入 IoaEngine 或其他行为分析管道。
        //
        MspSubmitShellcodeEvent(
            MS_BE_EVENT_SHELLCODE_DETECTED,
            MS_BE_CATEGORY_MEMORY_OPERATION,
            HandleToULong(ProcessId),
            (UINT32)min(result->MatchCount * 25, 100)
        );
    }

    ObDereferenceObject(process);
    MspReleaseReference(scanner);

    *Result = result;

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanRegion(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PEPROCESS process = NULL;
    PMS_SCAN_RESULT result = NULL;

    PAGED_CODE();

    //
    // 参数校验
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Address == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Size > MS_MAX_SCAN_SIZE) {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER_6;
    }

    *Result = NULL;

    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 获取进程引用
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        MspReleaseReference(scanner);
        return status;
    }

    //
    // 分配结果结构
    //
    status = MspAllocateScanResult(scanner, &result);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        MspReleaseReference(scanner);
        return status;
    }

    result->ProcessId = ProcessId;
    result->Type = MsScanType_Targeted;
    KeQuerySystemTime(&result->StartTime);

    //
    // 扫描指定区域
    //
    status = MmpScanMemroyRegion(
        scanner,
        process,
        Address,
        Size,
        0,  // 保护属性未知
        Flags,
        result
    );

    //
    // 完成结果
    //
    KeQuerySystemTime(&result->EndTime);
    result->DurationMs = (ULONG)((result->EndTime.QuadPart - result->StartTime.QuadPart) / 10000);
    result->Completed = TRUE;
    result->Status = status;

    //
    // 更新统计
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)result->BytesScanned);
    InterlockedAdd64(&scanner->Base.Stats.CumulativeScanTimeMs, (LONG64)result->DurationMs);

    ObDereferenceObject(process);
    MspReleaseReference(scanner);

    *Result = result;

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanBuffer(
    _In_ PMS_SCANNER Scanner,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_SCAN_RESULT result = NULL;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    //
    // 参数校验
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Size > MS_MAX_SCAN_SIZE) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    *Result = NULL;

    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 分配结果结构
    //
    status = MspAllocateScanResult(scanner, &result);
    if (!NT_SUCCESS(status)) {
        MspReleaseReference(scanner);
        return status;
    }

    result->ProcessId = PsGetCurrentProcessId();
    result->Type = MsScanType_Targeted;
    KeQuerySystemTime(&result->StartTime);

    //
    // 可用且模式数大于 3 时使用 Aho-Corasick 自动机
    //
    if (scanner->Base.AhoCorasickReady && scanner->Base.PatternCount > 3) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&scanner->Base.AhoCorasickLock);

        status = MspAhoCorasickSearch(
            scanner,
            (PUCHAR)Buffer,
            Size,
            Flags,
            result,
            Buffer,
            Size,
            0
        );

        ExReleasePushLockShared(&scanner->Base.AhoCorasickLock);
        KeLeaveCriticalRegion();

        //
        // AC 自动机仅覆盖大小写敏感的精确模式；
        // 通配符与大小写不敏感模式在此补扫，防止漏检（MS-AC 修复）
        //
        MspScanNonAcPatterns(
            scanner,
            (PUCHAR)Buffer,
            Size,
            Flags,
            result,
            Buffer,
            Size,
            0
        );

    } else {
        //
        // 逐个模式扫描
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&scanner->Base.PatternLock);

        for (entry = scanner->Base.PatternList.Flink;
             entry != &scanner->Base.PatternList;
             entry = entry->Flink) {

            pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

            if (pattern->Base.Flags & MsPatternFlag_Disabled) {
                continue;
            }

            if (pattern->Base.Type == MsPattern_Wildcard && pattern->Base.WildcardMask != NULL) {
                MspWildcardSearch(
                    (PUCHAR)Buffer,
                    Size,
                    &pattern->Base,
                    Flags,
                    result,
                    Buffer,
                    Size,
                    0
                );
            } else {
                MspBoyerMooreHorspoolSearch(
                    (PUCHAR)Buffer,
                    Size,
                    &pattern->Base,
                    Flags,
                    result,
                    Buffer,
                    Size,
                    0
                );
            }

            //
            // 命中后检查是否在首个匹配处停止
            //
            if ((Flags & MsScanFlag_StopOnFirstMatch) && result->MatchCount > 0) {
                break;
            }
        }

        ExReleasePushLockShared(&scanner->Base.PatternLock);
        KeLeaveCriticalRegion();
    }

    //
    // 完成结果
    //
    result->BytesScanned = Size;
    result->RegionsScanned = 1;
    KeQuerySystemTime(&result->EndTime);
    result->DurationMs = (ULONG)((result->EndTime.QuadPart - result->StartTime.QuadPart) / 10000);
    result->Completed = TRUE;
    result->Status = STATUS_SUCCESS;

    //
    // 更新统计
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)Size);
    InterlockedAdd64(&scanner->Base.Stats.CumulativeScanTimeMs, (LONG64)result->DurationMs);

    MspReleaseReference(scanner);

    *Result = result;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanAsync(
    _In_ PMS_SCANNER Scanner,
    _In_ PMS_SCAN_REQUEST Request,
    _In_ MS_SCAN_COMPLETE_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG ScanId
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_ACTIVE_SCAN activeScan = NULL;
    PIO_WORKITEM workItem = NULL;
    PMS_ASYNC_WORK_CONTEXT workContext = NULL;

    PAGED_CODE();

    //
    // 参数校验
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Request == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (ScanId == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    *ScanId = 0;

    //
    // 先获取引用，再检查关机状态（CRIT-3 修复）
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 检查并发扫描上限
    //
    if (scanner->Base.ActiveScanCount >= MS_MAX_CONCURRENT_SCANS) {
        MspReleaseReference(scanner);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // 异步工作项需要设备对象（MED-4 修复）
    //
    if (scanner->DeviceObject == NULL) {
        MspReleaseReference(scanner);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // 分配活跃扫描跟踪结构
    //
    activeScan = (PMS_ACTIVE_SCAN)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(MS_ACTIVE_SCAN),
        MS_POOL_TAG_CONTEXT
    );

    if (activeScan == NULL) {
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(activeScan, sizeof(MS_ACTIVE_SCAN));

//
    // 分配工作项 — DeviceObject 已在上方确认非空
    //
    workItem = IoAllocateWorkItem(scanner->DeviceObject);
    if (workItem == NULL) {
        ExFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 分配工作上下文
    //
    workContext = (PMS_ASYNC_WORK_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(MS_ASYNC_WORK_CONTEXT),
        MS_POOL_TAG_CONTEXT
    );

    if (workContext == NULL) {
        IoFreeWorkItem(workItem);
        ExFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 初始化活跃扫描
    //
    InitializeListHead(&activeScan->ListEntry);
    activeScan->ScanId = (ULONG)InterlockedIncrement(&scanner->NextScanId);
    activeScan->Request = Request;
    activeScan->Callback = Callback;
    activeScan->CallbackContext = Context;
    activeScan->WorkItem = workItem;
    KeInitializeEvent(&activeScan->CompletionEvent, NotificationEvent, FALSE);
    KeQuerySystemTime(&activeScan->StartTime);

    //
    // 分配结果结构
    //
    status = MspAllocateScanResult(scanner, &activeScan->Result);
    if (!NT_SUCCESS(status)) {
        IoFreeWorkItem(workItem);
        ExFreePoolWithTag(workContext, MS_POOL_TAG_CONTEXT);
        ExFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);
        MspReleaseReference(scanner);
        return status;
    }

    //
    // 设置工作上下文
    //
    workContext->Scanner = scanner;
    workContext->ActiveScan = activeScan;

    //
    // 加入活跃扫描链表（MS-H2 修复：Push Lock 替代自旋锁）
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.ActiveScansLock);
    InsertTailList(&scanner->Base.ActiveScans, &activeScan->ListEntry);
    InterlockedIncrement(&scanner->Base.ActiveScanCount);
    ExReleasePushLockExclusive(&scanner->Base.ActiveScansLock);
    KeLeaveCriticalRegion();

    //
    // 排队工作项以异步执行。
    //
    // BUG #3 修复：跟踪排队工作项数量，使 MsShutdown 可以显式排空。
    // 必须在 IoQueueWorkItem 之前递增，因为工作线程可能在本次调用
    // 返回前就在其他 CPU 上运行并递减。
    //
    InterlockedIncrement(&scanner->QueuedWorkItems);
    IoQueueWorkItem(
        workItem,
        MspAsyncScanWorker,
        DelayedWorkQueue,
        workContext
    );

    *ScanId = activeScan->ScanId;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsCancelScan(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG ScanId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_ACTIVE_SCAN activeScan;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // 持有引用防止关机竞争：避免 MsShutdown 在我们遍历链表时
    // 拆除 ActiveScansLock 或扫描器结构
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.ActiveScansLock);

    for (entry = scanner->Base.ActiveScans.Flink;
         entry != &scanner->Base.ActiveScans;
         entry = entry->Flink) {

        activeScan = CONTAINING_RECORD(entry, MS_ACTIVE_SCAN, ListEntry);

        if (activeScan->ScanId == ScanId) {
            InterlockedExchange(&activeScan->Cancelled, 1);
            KeSetEvent(&activeScan->CompletionEvent, IO_NO_INCREMENT, FALSE);
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.ActiveScansLock);
    KeLeaveCriticalRegion();

    MspReleaseReference(scanner);

    return status;
}

// ============================================================================
//                             结果管理
// ============================================================================

/*++
    MsFreeScanResult

    释放扫描结果：遍历并释放全部匹配项（经由正确的分配器），
    然后释放结果结构本身。

    参数：
        Scanner - 扫描器指针（用于 Lookaside List；可为空）
        Result  - 要释放的扫描结果

    返回值：
        无
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsFreeScanResult(
    _In_ PMS_SCANNER Scanner,
    _In_ PMS_SCAN_RESULT Result
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_MATCH match;

    PAGED_CODE();

    if (Result == NULL) {
        return;
    }

    //
    // 经由正确的分配器释放全部匹配项
    //
    while (!IsListEmpty(&Result->MatchList)) {
        entry = RemoveHeadList(&Result->MatchList);
        match = CONTAINING_RECORD(entry, MS_MATCH, ListEntry);

        if (scanner != NULL && scanner->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&scanner->MatchLookaside, match);
        } else {
            ExFreePoolWithTag(match, MS_POOL_TAG_RESULT);
        }
    }

    if (scanner != NULL && scanner->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&scanner->ResultLookaside, Result);
    } else {
        ExFreePoolWithTag(Result, MS_POOL_TAG_RESULT);
    }
}

/*++
    MsGetNextMatch

    按迭代器逐项取出结果中的下一个匹配项。

    参数：
        Result   - 扫描结果
        Iterator - 迭代器指针（首次调用传 NULL，之后使用上次返回值）
        Match    - 输出匹配项

    返回值：
        STATUS_SUCCESS、STATUS_NO_MORE_ENTRIES 或 NTSTATUS 错误码
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MsGetNextMatch(
    _In_ PMS_SCAN_RESULT Result,
    _Inout_ PLIST_ENTRY* Iterator,
    _Out_ PMS_MATCH* Match
)
{
    PLIST_ENTRY current;

    if (Result == NULL || Iterator == NULL || Match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Match = NULL;

    if (*Iterator == NULL) {
        current = Result->MatchList.Flink;
    } else {
        current = (*Iterator)->Flink;
    }

    if (current == &Result->MatchList) {
        return STATUS_NO_MORE_ENTRIES;
    }

    *Iterator = current;
    *Match = CONTAINING_RECORD(current, MS_MATCH, ListEntry);

    return STATUS_SUCCESS;
}

// ============================================================================
//                             熵分析
// ============================================================================

/*++
    MsCalculateEntropy

    计算缓冲区字节分布的熵值百分比（纯整数运算、无浮点）。
    用于识别高熵区域（可能包含加密 payload / shellcode）。

    参数：
        Buffer         - 数据缓冲区
        Size           - 缓冲区大小
        EntropyPercent - 输出熵值百分比（0-100）

    返回值：
        STATUS_SUCCESS、STATUS_INVALID_PARAMETER 或 STATUS_BUFFER_TOO_SMALL
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MsCalculateEntropy(
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PULONG EntropyPercent
)
{
    ULONG entropy;

    if (Buffer == NULL || Size == 0 || EntropyPercent == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntropyPercent = 0;

    if (Size < MS_MIN_REGION_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    entropy = MspCalculateIntegerEntropy((PUCHAR)Buffer, Size);

    *EntropyPercent = entropy;
    if (*EntropyPercent > 100) {
        *EntropyPercent = 100;
    }

    return STATUS_SUCCESS;
}

/*++
    MsFindHighEntropyRegions

    遍历目标进程的已提交内存区域，检测熵值超过阈值的区域
    （加密 payload / shellcode 的典型特征）。大区域仅采样首个
    扫描块（MS-7 修复）。

    参数：
        Scanner         - 扫描器指针
        ProcessId       - 目标进程 ID
        EntropyThreshold - 熵阈值
        Results         - 输出结果数组
        MaxResults      - 结果数组容量
        ResultCount     - 实际结果数量

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsFindHighEntropyRegions(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ ULONG EntropyThreshold,
    _Out_writes_to_(MaxResults, *ResultCount) PMS_ENTROPY_REGION Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG ResultCount
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;
    PVOID address = NULL;
    PVOID highestUserAddr = MmHighestUserAddress;
    PUCHAR buffer = NULL;
    ULONG count = 0;
    ULONG entropy;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Results == NULL || MaxResults == 0 || ResultCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ResultCount = 0;

    //
    // 获取进程引用
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // 分配扫描缓冲区
    //
    buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        MS_SCAN_CHUNK_SIZE,
        MS_POOL_TAG_BUFFER
    );

    if (buffer == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 挂接到目标进程
    //
    KeStackAttachProcess(process, &apcState);

    __try {
        while (address < highestUserAddr && count < MaxResults) {
            status = ZwQueryVirtualMemory(
                NtCurrentProcess(),
                address,
                MemoryBasicInformation,
                &memInfo,
                sizeof(memInfo),
                &returnLength
            );

            if (!NT_SUCCESS(status)) {
                break;
            }

            //
            // 检查区域是否值得扫描。
            // 对于大于扫描块的区域，仅采样首个块（MS-7 修复）。
            //
            if (memInfo.State == MEM_COMMIT &&
                memInfo.RegionSize >= MS_MIN_REGION_SIZE) {

                SIZE_T sampleSize = min(memInfo.RegionSize, (SIZE_T)MS_SCAN_CHUNK_SIZE);

                //
                // 读取区域（或大区域的首个块）
                //
                __try {
                    RtlCopyMemory(buffer, memInfo.BaseAddress, sampleSize);

                    //
                    // 计算熵值（纯整数、无浮点）
                    //
                    status = MsCalculateEntropy(buffer, sampleSize, &entropy);

                    if (NT_SUCCESS(status) && entropy >= EntropyThreshold) {
                        Results[count].BaseAddress = memInfo.BaseAddress;
                        Results[count].RegionSize = memInfo.RegionSize;
                        Results[count].EntropyPercent = entropy;
                        count++;
                    }

                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // 跳过不可访问的区域
                }
            }

            //
            // 移动到下一区域 — MS-H1 修复：检查地址空间末端的地址溢出，
            // 防止无限循环。
            //
            address = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
            if ((ULONG_PTR)address < (ULONG_PTR)memInfo.BaseAddress) {
                break;
            }
        }

    } __finally {
        KeUnstackDetachProcess(&apcState);
    }

    ExFreePoolWithTag(buffer, MS_POOL_TAG_BUFFER);
    ObDereferenceObject(process);

    *ResultCount = count;

    return STATUS_SUCCESS;
}

// ============================================================================
//                               统计信息
// ============================================================================

/*++
    MsGetStatistics

    读取扫描器统计信息：模式数量、活跃扫描数、总扫描数、
    总匹配数、扫描字节数、超时数、运行时长与平均扫描耗时。

    参数：
        Scanner - 扫描器指针
        Stats   - 输出统计信息

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MsGetStatistics(
    _In_ PMS_SCANNER Scanner,
    _Out_ PMS_STATISTICS Stats
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    LARGE_INTEGER currentTime;

    if (Scanner == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Scanner->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 持有引用期间读取统计块，防止 MsShutdown 在读取过程中释放扫描器。
    // 此处均为原子 LONG/LONG64 字段，但扫描器结构本身（及 Stats.StartTime）
    // 需要生命周期保护。
    //
    if (!MspTryAcquireReference(scanner)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(MS_STATISTICS));

    Stats->PatternCount = (ULONG)scanner->Base.PatternCount;
    Stats->ActiveScans = (ULONG)scanner->Base.ActiveScanCount;
    Stats->TotalScans = scanner->Base.Stats.TotalScans;
    Stats->TotalMatches = scanner->Base.Stats.TotalMatches;
    Stats->BytesScanned = scanner->Base.Stats.BytesScanned;
    Stats->Timeouts = scanner->Base.Stats.Timeouts;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - scanner->Base.Stats.StartTime.QuadPart;

    //
    // 由累计扫描耗时计算平均扫描时间（MS-8 修复）
    //
    if (Stats->TotalScans > 0) {
        Stats->AverageScanTimeMs = (ULONG)(scanner->Base.Stats.CumulativeScanTimeMs / Stats->TotalScans);
    }

    MspReleaseReference(scanner);

    return STATUS_SUCCESS;
}

// ============================================================================
//                   私有实现 - 哈希函数
// ============================================================================

/*++
    MspHashPatternId

    对模式 ID 计算哈希值，用于模式哈希表桶索引。
    （MurmurHash 风格的整数混合后取模）

    参数：
        PatternId - 模式 ID

    返回值：
        哈希桶索引（0 到 MS_PATTERN_HASH_BUCKETS-1）
--*/
static ULONG
MspHashPatternId(
    _In_ ULONG PatternId
)
{
    ULONG hash = PatternId;
    hash = hash ^ (hash >> 16);
    hash *= 0x85ebca6b;
    hash = hash ^ (hash >> 13);
    return hash % MS_PATTERN_HASH_BUCKETS;
}

// ============================================================================
//                私有实现 - Boyer-Moore-Horspool 搜索
// ============================================================================

/*++
    MspComputeBadCharTable

    计算并填充 BMH 坏字符表。表项初始化为模式长度（默认跳转距离），
    对模式中出现的字符（除末位外）写入对应跳转距离。
    大小写不敏感的模式同时填充大小写两份表项（MS-5 修复）。

    参数：
        Pattern - 模式结构（输入输出）

    返回值：
        无
--*/
static VOID
MspComputeBadCharTable(
    _Inout_ PMS_PATTERN Pattern
)
{
    ULONG i;

    if (Pattern->TableComputed) {
        return;
    }

    //
    // 分配坏字符表
    //
    if (Pattern->BadCharTable == NULL) {
        Pattern->BadCharTable = (PULONG)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            MS_ALPHABET_SIZE * sizeof(ULONG),
            MS_POOL_TAG_PATTERN
        );

        if (Pattern->BadCharTable == NULL) {
            return;
        }
    }

    //
    // 所有表项初始化为模式长度（默认跳转距离）
    //
    for (i = 0; i < MS_ALPHABET_SIZE; i++) {
        Pattern->BadCharTable[i] = Pattern->PatternSize;
    }

    //
    // 设置模式中字符（末位除外）的跳转距离；
    // 大小写不敏感时同时填充大小写两份表项（MS-5 修复）。
    //
    for (i = 0; i < Pattern->PatternSize - 1; i++) {
        UCHAR ch = Pattern->PatternData[i];
        ULONG shift = Pattern->PatternSize - 1 - i;

        Pattern->BadCharTable[ch] = shift;

        if (!(Pattern->Flags & MsPatternFlag_CaseSensitive)) {
            if (ch >= 'A' && ch <= 'Z') {
                Pattern->BadCharTable[ch | 0x20] = shift;       // 小写变体
            } else if (ch >= 'a' && ch <= 'z') {
                Pattern->BadCharTable[ch & ~0x20] = shift;      // 大写变体
            }
        }
    }

    Pattern->TableComputed = TRUE;
}

/*++
    MspBoyerMooreHorspoolSearch

    使用 Boyer-Moore-Horspool 算法在文本中搜索单个精确模式。
    从右向左匹配，命中后经 MspAddMatchToResult 记入结果，
    并更新模式命中统计。

    参数：
        Text             - 待搜索文本
        TextLen          - 文本长度
        Pattern          - 模式结构
        Flags            - 扫描标志
        Result           - 扫描结果
        RegionBase       - 所属区域基址
        RegionSize       - 所属区域大小
        RegionProtection - 所属区域保护属性

    返回值：
        STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES
--*/
static NTSTATUS
MspBoyerMooreHorspoolSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    SIZE_T i;
    LONG j;
    SIZE_T patternLen = Pattern->PatternSize;
    PUCHAR patternData = Pattern->PatternData;
    PULONG badCharTable;
    BOOLEAN caseSensitive = (Pattern->Flags & MsPatternFlag_CaseSensitive) != 0;
    PMS_SCANNER_INTERNAL scanner = NULL;

    if (TextLen < patternLen) {
        return STATUS_SUCCESS;  // 不可能匹配
    }

    //
    // 从模式取得扫描器指针，用于分配匹配项
    //
    PMS_PATTERN_INTERNAL patternInt = CONTAINING_RECORD(Pattern, MS_PATTERN_INTERNAL, Base);
    if (patternInt->Magic == MS_PATTERN_MAGIC) {
        scanner = patternInt->Scanner;
    }

    //
    // 确保坏字符表已计算
    //
    if (!Pattern->TableComputed || Pattern->BadCharTable == NULL) {
        MspComputeBadCharTable(Pattern);
        if (Pattern->BadCharTable == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    badCharTable = Pattern->BadCharTable;

    //
    // Boyer-Moore-Horspool 搜索
    //
    i = 0;
    while (i <= TextLen - patternLen) {
        //
        // 从右向左匹配
        //
        j = (LONG)patternLen - 1;

        while (j >= 0) {
            UCHAR textChar = Text[i + j];
            UCHAR patChar = patternData[j];

            //
            // 需要时进行大小写不敏感比较
            //
            if (!caseSensitive) {
                if (textChar >= 'A' && textChar <= 'Z') {
                    textChar |= 0x20;
                }
                if (patChar >= 'A' && patChar <= 'Z') {
                    patChar |= 0x20;
                }
            }

            if (textChar != patChar) {
                break;
            }
            j--;
        }

        if (j < 0) {
            //
            // 命中
            //
            MspAddMatchToResult(
                Pattern,
                Text + i,
                i,
                RegionBase,
                RegionSize,
                RegionProtection,
                Flags,
                Text,
                TextLen,
                Result,
                scanner
            );

            //
            // 更新模式命中统计
            //
            InterlockedIncrement64(&Pattern->MatchCount);
            {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                InterlockedExchange64(&Pattern->LastMatchTime, now.QuadPart);
            }

            if (Flags & MsScanFlag_StopOnFirstMatch) {
                break;
            }

            //
            // 越过本次命中
            //
            i += patternLen;
        } else {
            //
            // 依据坏字符表跳转
            //
            UCHAR badChar = Text[i + patternLen - 1];
            i += badCharTable[badChar];
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
//                私有实现 - 通配符搜索
// ============================================================================

/*++
    MspWildcardSearch

    使用简单滑窗在文本中搜索带通配符掩码的模式。
    掩码字节非零的位置跳过比较。

    参数：
        Text             - 待搜索文本
        TextLen          - 文本长度
        Pattern          - 模式结构
        Flags            - 扫描标志
        Result           - 扫描结果
        RegionBase       - 所属区域基址
        RegionSize       - 所属区域大小
        RegionProtection - 所属区域保护属性

    返回值：
        STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES
--*/
static NTSTATUS
MspWildcardSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    SIZE_T i, j;
    SIZE_T patternLen = Pattern->PatternSize;
    PUCHAR patternData = Pattern->PatternData;
    PUCHAR wildcardMask = Pattern->WildcardMask;
    BOOLEAN match;
    PMS_SCANNER_INTERNAL scanner = NULL;

    if (TextLen < patternLen || wildcardMask == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // 从模式取得扫描器指针
    //
    PMS_PATTERN_INTERNAL patternInt = CONTAINING_RECORD(Pattern, MS_PATTERN_INTERNAL, Base);
    if (patternInt->Magic == MS_PATTERN_MAGIC) {
        scanner = patternInt->Scanner;
    }

    //
    // 支持通配符的简单滑动窗口
    //
    for (i = 0; i <= TextLen - patternLen; i++) {
        match = TRUE;

        for (j = 0; j < patternLen; j++) {
            //
            // 跳过通配符位置（掩码字节非零）
            //
            if (wildcardMask[j] != 0) {
                continue;
            }

            if (Text[i + j] != patternData[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            //
            // 命中
            //
            MspAddMatchToResult(
                Pattern,
                Text + i,
                i,
                RegionBase,
                RegionSize,
                RegionProtection,
                Flags,
                Text,
                TextLen,
                Result,
                scanner
            );

            InterlockedIncrement64(&Pattern->MatchCount);
            {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                InterlockedExchange64(&Pattern->LastMatchTime, now.QuadPart);
            }

            if (Flags & MsScanFlag_StopOnFirstMatch) {
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
//                私有实现 - Aho-Corasick 自动机
// ============================================================================

/*++
    MspBuildAhoCorasickAutomaton

    构建 Aho-Corasick 多模式匹配自动机：基于模式总数计算最大
    状态数，逐状态建立 goto/fail/output 表，并用 BFS 计算失败转移。

    参数：
        Scanner - 扫描器内部结构

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
static NTSTATUS
MspBuildAhoCorasickAutomaton(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMS_AC_AUTOMATON automaton = &Scanner->AhoCorasick;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    ULONG stateIndex;
    ULONG currentState;
    ULONG patternIdx;
    PULONG queue = NULL;
    ULONG queueHead, queueTail;
    ULONG queueCapacity;
    ULONG i, c;
    SIZE_T allocSize;

    //
    // 重建前先销毁旧自动机，防止 States 与输出链表内存泄漏
    // （模式变更仅置 Built=FALSE，旧表须在此统一回收；MS 修复）
    //
    MspDestroyAhoCorasickAutomaton(automaton);

    //
    // 计算所需的最大状态数
    //
    ULONG totalPatternBytes = 0;
    for (entry = Scanner->Base.PatternList.Flink;
         entry != &Scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);
        if (!(pattern->Base.Flags & MsPatternFlag_Disabled)) {
            //
            // 溢出检查（CRIT-4 修复）
            //
            if (totalPatternBytes + pattern->Base.PatternSize < totalPatternBytes) {
                return STATUS_INTEGER_OVERFLOW;
            }
            totalPatternBytes += pattern->Base.PatternSize;
        }
    }

    automaton->MaxStates = min(totalPatternBytes + 1, MS_AC_MAX_STATES);
    if (automaton->MaxStates < 2) {
        automaton->MaxStates = 2;
    }

    //
    // 校验分配大小不会过大（CRIT-4 修复）。
    // MaxStates 上限为 8192，每个状态约 1052 字节。
    // 最大分配量：8192 * 1052 ≈ 8.6MB。
    //
    allocSize = (SIZE_T)automaton->MaxStates * sizeof(MS_AC_STATE);

    //
    // 使用分页池，因为 AC 构建在 PASSIVE_LEVEL 运行（CRIT-4 修复）
    //
    automaton->States = (PMS_AC_STATE)ExAllocatePool2(
        POOL_FLAG_PAGED,
        allocSize,
        MS_POOL_TAG_CONTEXT
    );

    if (automaton->States == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(automaton->States, allocSize);

    //
    // 初始化根状态（状态 0）。
    // 所有 goto 项使用 MS_AC_FAIL_SENTINEL，随后为不匹配任何模式前缀的
    // 字符显式建立自环（MED-2 修复）。
    //
    for (i = 0; i < MS_ALPHABET_SIZE; i++) {
        automaton->States[0].Goto[i] = MS_AC_FAIL_SENTINEL;
    }
    automaton->States[0].Failure = 0;
    InitializeListHead(&automaton->States[0].OutputPatterns);
    automaton->StateCount = 1;

    //
    // 添加所有模式以构建 goto 函数
    //
    for (entry = Scanner->Base.PatternList.Flink;
         entry != &Scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        if (pattern->Base.Flags & MsPatternFlag_Disabled) {
            continue;
        }

        //
        // AC 自动机不做大小写归一化，通配符模式又无法编码为确定性
        // 转移表。因此这两类模式不进入自动机，由 MspScanNonAcPatterns
        // 在 AC 扫描之后补扫（MS-AC 修复），保证不漏检。
        //
        if (pattern->Base.Type == MsPattern_Wildcard) {
            continue;
        }

        if (!(pattern->Base.Flags & MsPatternFlag_CaseSensitive)) {
            continue;
        }

        currentState = 0;

        for (patternIdx = 0; patternIdx < pattern->Base.PatternSize; patternIdx++) {
            UCHAR ch = pattern->Base.PatternData[patternIdx];

            if (automaton->States[currentState].Goto[ch] == MS_AC_FAIL_SENTINEL) {
                //
                // 需要新状态
                //
                if (automaton->StateCount >= automaton->MaxStates) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Cleanup;
                }

                stateIndex = automaton->StateCount++;
                for (i = 0; i < MS_ALPHABET_SIZE; i++) {
                    automaton->States[stateIndex].Goto[i] = MS_AC_FAIL_SENTINEL;
                }
                automaton->States[stateIndex].Failure = 0;
                automaton->States[stateIndex].Depth = patternIdx + 1;
                InitializeListHead(&automaton->States[stateIndex].OutputPatterns);

                automaton->States[currentState].Goto[ch] = stateIndex;
            }

            currentState = automaton->States[currentState].Goto[ch];
        }

        //
        // 将模式加入末状态的输出链表
        //
        {
            PMS_AC_OUTPUT output = (PMS_AC_OUTPUT)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(MS_AC_OUTPUT),
                MS_POOL_TAG_CONTEXT
            );

            if (output != NULL) {
                output->PatternId = pattern->Base.PatternId;
                output->Pattern = &pattern->Base;
                InsertTailList(&automaton->States[currentState].OutputPatterns, &output->ListEntry);
                automaton->States[currentState].OutputCount++;
            }
        }
    }

    //
    // 将根状态的 FAIL_SENTINEL 项转换为自环（状态 0）。
    // 确保 AC 搜索永远不会卡在根状态。
    //
    for (c = 0; c < MS_ALPHABET_SIZE; c++) {
        if (automaton->States[0].Goto[c] == MS_AC_FAIL_SENTINEL) {
            automaton->States[0].Goto[c] = 0;
        }
    }

    //
    // 使用 BFS 构建失败函数
    //
    queueCapacity = automaton->StateCount;
    queue = (PULONG)ExAllocatePool2(
        POOL_FLAG_PAGED,
        queueCapacity * sizeof(ULONG),
        MS_POOL_TAG_BUFFER
    );

    if (queue == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    queueHead = 0;
    queueTail = 0;

    //
    // 初始化深度 1 状态的失败链接
    //
    for (c = 0; c < MS_ALPHABET_SIZE; c++) {
        ULONG s = automaton->States[0].Goto[c];
        if (s != 0) {
            automaton->States[s].Failure = 0;
            if (queueTail < queueCapacity) {
                queue[queueTail++] = s;
            }
        }
    }

    //
    // BFS 计算其余状态的失败链接
    //
    while (queueHead < queueTail) {
        ULONG r = queue[queueHead++];

        for (c = 0; c < MS_ALPHABET_SIZE; c++) {
            ULONG s = automaton->States[r].Goto[c];

            if (s != MS_AC_FAIL_SENTINEL) {
                //
                // BFS 队列边界检查（MED-7 修复）
                //
                if (queueTail < queueCapacity) {
                    queue[queueTail++] = s;
                }

                //
                // 沿失败链接查找最长真后缀
                //
                {
                    ULONG state = automaton->States[r].Failure;
                    while (automaton->States[state].Goto[c] == MS_AC_FAIL_SENTINEL && state != 0) {
                        state = automaton->States[state].Failure;
                    }

                    automaton->States[s].Failure = automaton->States[state].Goto[c];
                    if (automaton->States[s].Failure == MS_AC_FAIL_SENTINEL) {
                        automaton->States[s].Failure = 0;
                    }
                }

                //
                // 合并失败状态的输出函数（HIGH-6 修复）。
                // 将失败状态的全部输出复制到本状态输出链表，
                // 以便上报后缀模式命中。
                //
                {
                    ULONG failState = automaton->States[s].Failure;
                    PLIST_ENTRY outEntry;
                    PMS_AC_OUTPUT failOutput;
                    PMS_AC_OUTPUT newOutput;

                    for (outEntry = automaton->States[failState].OutputPatterns.Flink;
                         outEntry != &automaton->States[failState].OutputPatterns;
                         outEntry = outEntry->Flink) {

                        failOutput = CONTAINING_RECORD(outEntry, MS_AC_OUTPUT, ListEntry);

                        newOutput = (PMS_AC_OUTPUT)ExAllocatePool2(
                            POOL_FLAG_NON_PAGED,
                            sizeof(MS_AC_OUTPUT),
                            MS_POOL_TAG_CONTEXT
                        );

                        if (newOutput != NULL) {
                            newOutput->PatternId = failOutput->PatternId;
                            newOutput->Pattern = failOutput->Pattern;
                            InsertTailList(&automaton->States[s].OutputPatterns, &newOutput->ListEntry);
                            automaton->States[s].OutputCount++;
                        }
                    }
                }
            }
        }
    }

    automaton->Built = TRUE;
    InterlockedExchange(&Scanner->Base.AhoCorasickReady, 1);

Cleanup:
    if (queue != NULL) {
        ExFreePoolWithTag(queue, MS_POOL_TAG_BUFFER);
    }

    if (!NT_SUCCESS(status)) {
        MspDestroyAhoCorasickAutomaton(automaton);
    }

    return status;
}

static VOID
MspDestroyAhoCorasickAutomaton(
    _Inout_ PMS_AC_AUTOMATON Automaton
)
{
    ULONG i;
    PLIST_ENTRY entry;
    PMS_AC_OUTPUT output;

    if (Automaton->States == NULL) {
        return;
    }

    //
    // 释放各状态的输出链表
    //
    for (i = 0; i < Automaton->StateCount; i++) {
        while (!IsListEmpty(&Automaton->States[i].OutputPatterns)) {
            entry = RemoveHeadList(&Automaton->States[i].OutputPatterns);
            output = CONTAINING_RECORD(entry, MS_AC_OUTPUT, ListEntry);
            ExFreePoolWithTag(output, MS_POOL_TAG_CONTEXT);
        }
    }

    ExFreePoolWithTag(Automaton->States, MS_POOL_TAG_CONTEXT);
    Automaton->States = NULL;
    Automaton->StateCount = 0;
    Automaton->MaxStates = 0;
    Automaton->Built = FALSE;
}

/*++
    MspAhoCorasickSearch

    使用 Aho-Corasick 自动机在文本中进行多模式搜索。
    每读入一个字符沿失败链接寻找有效转移，命中后上报当前状态的
    全部输出（后缀模式输出已在构建期合并进各状态，
    运行期无需再遍历失败链）。

    参数：
        Scanner          - 扫描器内部结构
        Text             - 待搜索文本
        TextLen          - 文本长度
        Flags            - 扫描标志
        Result           - 扫描结果
        RegionBase       - 所属区域基址
        RegionSize       - 所属区域大小
        RegionProtection - 所属区域保护属性

    返回值：
        STATUS_SUCCESS 或 STATUS_DEVICE_NOT_READY
--*/
static NTSTATUS
MspAhoCorasickSearch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    PMS_AC_AUTOMATON automaton = &Scanner->AhoCorasick;
    ULONG currentState = 0;
    SIZE_T i;
    PLIST_ENTRY entry;
    PMS_AC_OUTPUT output;

    if (!automaton->Built || automaton->States == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    for (i = 0; i < TextLen; i++) {
        UCHAR ch = Text[i];

        //
        // 沿失败链接查找直到找到有效转移
        //
        while (currentState != 0 &&
               automaton->States[currentState].Goto[ch] == MS_AC_FAIL_SENTINEL) {
            currentState = automaton->States[currentState].Failure;
        }

        //
        // 执行 goto 转移
        //
        ULONG nextState = automaton->States[currentState].Goto[ch];
        if (nextState != MS_AC_FAIL_SENTINEL) {
            currentState = nextState;
        } else {
            currentState = 0;
        }

        //
        // 检查当前状态是否有命中
        //
        if (automaton->States[currentState].OutputCount > 0) {
            for (entry = automaton->States[currentState].OutputPatterns.Flink;
                 entry != &automaton->States[currentState].OutputPatterns;
                 entry = entry->Flink) {

                output = CONTAINING_RECORD(entry, MS_AC_OUTPUT, ListEntry);

                SIZE_T matchOffset = i - output->Pattern->PatternSize + 1;

                MspAddMatchToResult(
                    output->Pattern,
                    Text + matchOffset,
                    matchOffset,
                    RegionBase,
                    RegionSize,
                    RegionProtection,
                    Flags,
                    Text,
                    TextLen,
                    Result,
                    Scanner
                );

                InterlockedIncrement64(&output->Pattern->MatchCount);

                if (Flags & MsScanFlag_StopOnFirstMatch) {
                    return STATUS_SUCCESS;
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

/*++
    MspScanNonAcPatterns

    补扫 AC 自动机未覆盖的模式（MS-AC 修复）：
    AC 跳过通配符模式与大小写不敏感模式（自动机不做大小写归一化），
    本函数在 AC 扫描之后对此两类模式分别执行
    MspWildcardSearch / MspBoyerMooreHorspoolSearch，防止漏检。

    参数：
        Scanner          - 扫描器内部结构
        Text             - 待搜索文本
        TextLen          - 文本长度
        Flags            - 扫描标志
        Result           - 扫描结果
        RegionBase       - 所属区域基址
        RegionSize       - 所属区域大小
        RegionProtection - 所属区域保护属性

    返回值：
        STATUS_SUCCESS
--*/
static NTSTATUS
MspScanNonAcPatterns(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Scanner->Base.PatternLock);

    for (entry = Scanner->Base.PatternList.Flink;
         entry != &Scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        //
        // 跳过禁用模式
        //
        if (pattern->Base.Flags & MsPatternFlag_Disabled) {
            continue;
        }

        //
        // AC 已覆盖大小写敏感的精确模式，跳过
        //
        if (pattern->Base.Type == MsPattern_Exact &&
            (pattern->Base.Flags & MsPatternFlag_CaseSensitive)) {
            continue;
        }

        //
        // 通配符模式走滑动窗口，大小写不敏感精确模式走 BMH
        //
        if (pattern->Base.Type == MsPattern_Wildcard) {
            MspWildcardSearch(
                Text,
                TextLen,
                &pattern->Base,
                Flags,
                Result,
                RegionBase,
                RegionSize,
                RegionProtection
            );
        } else {
            MspBoyerMooreHorspoolSearch(
                Text,
                TextLen,
                &pattern->Base,
                Flags,
                Result,
                RegionBase,
                RegionSize,
                RegionProtection
            );
        }

        if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
            break;
        }
    }

    ExReleasePushLockShared(&Scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
//             私有实现 - 内存分配辅助函数
// ============================================================================

/*++
    MspAllocateMatch

    从 Match Lookaside List（或非分页池）分配并初始化一个匹配项。

    参数：
        Scanner - 扫描器内部结构
        Match   - 输出匹配项指针

    返回值：
        STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES
--*/
static NTSTATUS
MspAllocateMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_MATCH* Match
)
{
    PMS_MATCH match;

    *Match = NULL;

    if (Scanner->LookasideInitialized) {
        match = (PMS_MATCH)ExAllocateFromNPagedLookasideList(&Scanner->MatchLookaside);
    } else {
        match = (PMS_MATCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(MS_MATCH),
            MS_POOL_TAG_RESULT
        );
    }

    if (match == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(match, sizeof(MS_MATCH));
    InitializeListHead(&match->ListEntry);

    *Match = match;

    return STATUS_SUCCESS;
}

/*++
    MspFreeMatch

    将匹配项归还 Match Lookaside List（或非分页池）。

    参数：
        Scanner - 扫描器内部结构
        Match   - 要释放的匹配项

    返回值：
        无
--*/
static VOID
MspFreeMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PMS_MATCH Match
)
{
    if (Match == NULL) {
        return;
    }

    if (Scanner->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Scanner->MatchLookaside, Match);
    } else {
        ExFreePoolWithTag(Match, MS_POOL_TAG_RESULT);
    }
}

/*++
    MspAllocateScanResult

    从 Result Lookaside List（或非分页池）分配并初始化一个扫描结果。

    参数：
        Scanner - 扫描器内部结构
        Result  - 输出扫描结果指针

    返回值：
        STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES
--*/
static NTSTATUS
MspAllocateScanResult(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    PMS_SCAN_RESULT result;

    *Result = NULL;

    if (Scanner->LookasideInitialized) {
        result = (PMS_SCAN_RESULT)ExAllocateFromNPagedLookasideList(&Scanner->ResultLookaside);
    } else {
        result = (PMS_SCAN_RESULT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(MS_SCAN_RESULT),
            MS_POOL_TAG_RESULT
        );
    }

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(MS_SCAN_RESULT));
    InitializeListHead(&result->MatchList);

    *Result = result;

    return STATUS_SUCCESS;
}

static VOID
MspAddMatchToResult(
    _In_ PMS_PATTERN Pattern,
    _In_ PUCHAR MatchLocation,
    _In_ SIZE_T Offset,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection,
    _In_ MS_SCAN_FLAGS Flags,
    _In_ PUCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PMS_SCANNER_INTERNAL Scanner
)
{
    PMS_MATCH match = NULL;
    NTSTATUS status;

    //
    // 检查匹配数量上限
    //
    if ((ULONG)Result->MatchCount >= MS_MAX_MATCHES_PER_SCAN) {
        return;
    }

    //
    // 分配匹配项
    //
    if (Scanner != NULL) {
        status = MspAllocateMatch(Scanner, &match);
    } else {
        match = (PMS_MATCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(MS_MATCH),
            MS_POOL_TAG_RESULT
        );
        if (match != NULL) {
            RtlZeroMemory(match, sizeof(MS_MATCH));
            InitializeListHead(&match->ListEntry);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (!NT_SUCCESS(status) || match == NULL) {
        return;
    }

    //
    // 填充匹配信息
    //
    match->PatternId = Pattern->PatternId;
    RtlStringCchCopyA(match->PatternName, sizeof(match->PatternName), Pattern->PatternName);
    match->MatchAddress = MatchLocation;
    match->MatchOffset = Offset;
    match->MatchSize = Pattern->PatternSize;
    match->RegionBase = RegionBase;
    match->RegionSize = RegionSize;
    match->RegionProtection = RegionProtection;
    RtlStringCchCopyA(match->ThreatName, sizeof(match->ThreatName), Pattern->ThreatName);
    match->Severity = Pattern->Severity;

    //
    // 请求时捕获上下文
    //
    if (Flags & MsScanFlag_IncludeContext) {
        SIZE_T contextBefore = min(Offset, MS_CONTEXT_BYTES);
        SIZE_T contextAfter;

        //
        // 防止 SIZE_T 下溢（MED-5 修复）
        //
        if (Offset + Pattern->PatternSize >= BufferSize) {
            contextAfter = 0;
        } else {
            contextAfter = min(BufferSize - Offset - Pattern->PatternSize, MS_CONTEXT_BYTES);
        }

        if (contextBefore > 0) {
            RtlCopyMemory(match->ContextBefore, Buffer + Offset - contextBefore, contextBefore);
            match->ContextBeforeSize = (ULONG)contextBefore;
        }

        if (contextAfter > 0) {
            RtlCopyMemory(
                match->ContextAfter,
                Buffer + Offset + Pattern->PatternSize,
                contextAfter
            );
            match->ContextAfterSize = (ULONG)contextAfter;
        }
    }

    //
    // 加入结果链表
    //
    InsertTailList(&Result->MatchList, &match->ListEntry);
    InterlockedIncrement(&Result->MatchCount);

    //
    // 更新威胁汇总
    //
    if (Pattern->Severity > Result->MaxSeverity) {
        Result->MaxSeverity = Pattern->Severity;
    }
    Result->ThreatCount++;
}

// ============================================================================
//               私有实现 - 进程内存区域扫描
// ============================================================================

/*++
    MspScanProcessRegions

    遍历目标进程的全部虚拟内存区域，对符合扫描条件的区域逐一执行扫描。
    挂接状态下枚举、扫描前分离（MS-9 修复），并跟踪挂接状态
    防止栈回卷时双重分离导致蓝屏。

    参数：
        Scanner - 扫描器内部结构
        Process - 目标进程
        Type    - 扫描类型
        Flags   - 扫描标志
        Result  - 扫描结果

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
static NTSTATUS
MspScanProcessRegions(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
)
{
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;
    PVOID address = NULL;
    BOOLEAN isAttached = FALSE;

    //
    // 挂接状态下枚举区域，扫描前分离（MS-9 修复）。
    // 跟踪挂接状态以防止栈回卷时双重分离。
    //
    KeStackAttachProcess(Process, &apcState);
    isAttached = TRUE;

    __try {
        //
        // 枚举全部区域
        //
        while (address < MmHighestUserAddress) {
            status = ZwQueryVirtualMemory(
                NtCurrentProcess(),
                address,
                MemoryBasicInformation,
                &memInfo,
                sizeof(memInfo),
                &returnLength
            );

            if (!NT_SUCCESS(status)) {
                status = STATUS_SUCCESS;
                break;
            }

            //
            // 检查是否需要扫描该区域
            //
            if (MspShouldScanRegion(
                    memInfo.Protect,
                    memInfo.State,
                    memInfo.Type,
                    Type,
                    Flags)) {

                //
                // 扫描前分离 - MmpScanMemroyRegion 内部自行挂接/分离
                //
                KeUnstackDetachProcess(&apcState);
                isAttached = FALSE;

                status = MmpScanMemroyRegion(
                    Scanner,
                    Process,
                    memInfo.BaseAddress,
                    memInfo.RegionSize,
                    memInfo.Protect,
                    Flags,
                    Result
                );

                //
                // 重新挂接以继续枚举
                //
                KeStackAttachProcess(Process, &apcState);
                isAttached = TRUE;

                if (!NT_SUCCESS(status)) {
                    status = STATUS_SUCCESS;
                }

                //
                // 检查停止条件
                //
                if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
                    break;
                }
            }

            //
                // 移动到下一区域 - MS-H1 修复：检查地址空间末端的地址溢出，
                // 防止无限循环。
            //
            address = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
            if ((ULONG_PTR)address < (ULONG_PTR)memInfo.BaseAddress) {
                break;
            }
        }

    } __finally {
        if (isAttached) {
            KeUnstackDetachProcess(&apcState);
        }
    }

    return status;
}

/*++
    MmpScanMemroyRegion

    对单个内存区域执行分块扫描。块间携带重叠（overlap）字节以检测
    跨块边界处的模式串（MED-1 修复）。每块使用 KeStackAttachProcess
    独立挂接/分离，缩短挂接窗口（HIGH-2 修复）。

    参数：
        Scanner     - 扫描器内部结构
        Process     - 目标进程
        BaseAddress - 区域基址
        RegionSize  - 区域大小
        Protection  - 区域保护属性
        Flags       - 扫描标志
        Result      - 扫描结果

    返回值：
        STATUS_SUCCESS 或 NTSTATUS 错误码
--*/
static NTSTATUS
MmpScanMemroyRegion(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG Protection,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR buffer = NULL;
    SIZE_T bytesRead = 0;
    SIZE_T offset = 0;
    SIZE_T chunkSize;
    SIZE_T overlapSize;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    KAPC_STATE apcState;

    //
    // 校验区域大小
    //
    if (RegionSize < MS_MIN_REGION_SIZE || RegionSize > MS_MAX_SCAN_SIZE) {
        return STATUS_SUCCESS;
    }

    //
    // 确定块大小并携带重叠，用于跨边界检测（MED-1 修复）。
    // 读取（块大小 + 重叠）字节，但按块大小前进。
    //
    chunkSize = min(RegionSize, Scanner->Base.Config.ChunkSize);
    overlapSize = (Scanner->Base.PatternCount > 0 && MS_MAX_PATTERN_SIZE > 1)
        ? (MS_MAX_PATTERN_SIZE - 1)
        : 0;

    //
    // 分配扫描缓冲区，容量为块大小 + 重叠
    //
    buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        chunkSize + overlapSize,
        MS_POOL_TAG_BUFFER
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 使用 KeStackAttachProcess 分块扫描区域，实现安全的跨进程读取。
    // 每块独立挂接/分离以缩短挂接时间（HIGH-2 修复）。
    //
    while (offset < RegionSize) {
        SIZE_T remaining = RegionSize - offset;
        SIZE_T toRead = min(chunkSize + overlapSize, remaining);

        //
        // 挂接到目标进程以读取其内存（CRIT-2 修复）。
        // 替代未文档化的 MmCopyVirtualMemory。
        //
        KeStackAttachProcess(Process, &apcState);

        __try {
            ProbeForRead(
                (PVOID)((ULONG_PTR)BaseAddress + offset),
                toRead,
                1
            );
            RtlCopyMemory(buffer, (PVOID)((ULONG_PTR)BaseAddress + offset), toRead);
            bytesRead = toRead;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            bytesRead = 0;
            status = GetExceptionCode();
        }

        KeUnstackDetachProcess(&apcState);

        if (bytesRead == 0) {
            //
            // 无法读取该块则跳过继续，不使整个扫描失败
            //
            offset += chunkSize;
            status = STATUS_SUCCESS;
            continue;
        }

        //
        // 使用全部模式扫描该块。
        // AC 搜索需要持有 AhoCorasickLock 以防并发重建（MS-6 修复）。
        //
        if (InterlockedCompareExchange(&Scanner->Base.AhoCorasickReady, 0, 0) &&
            Scanner->Base.PatternCount > 3) {

            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&Scanner->Base.AhoCorasickLock);

            MspAhoCorasickSearch(
                Scanner,
                buffer,
                bytesRead,
                Flags,
                Result,
                BaseAddress,
                RegionSize,
                Protection
            );

            ExReleasePushLockShared(&Scanner->Base.AhoCorasickLock);
            KeLeaveCriticalRegion();

            //
            // AC 自动机仅覆盖大小写敏感的精确模式；
            // 通配符与大小写不敏感模式在此补扫，防止漏检（MS-AC 修复）
            //
            MspScanNonAcPatterns(
                Scanner,
                buffer,
                bytesRead,
                Flags,
                Result,
                BaseAddress,
                RegionSize,
                Protection
            );

        } else {
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&Scanner->Base.PatternLock);

            for (entry = Scanner->Base.PatternList.Flink;
                 entry != &Scanner->Base.PatternList;
                 entry = entry->Flink) {

                pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

                if (pattern->Base.Flags & MsPatternFlag_Disabled) {
                    continue;
                }

                if (pattern->Base.Type == MsPattern_Wildcard) {
                    MspWildcardSearch(
                        buffer,
                        bytesRead,
                        &pattern->Base,
                        Flags,
                        Result,
                        BaseAddress,
                        RegionSize,
                        Protection
                    );
                } else {
                    MspBoyerMooreHorspoolSearch(
                        buffer,
                        bytesRead,
                        &pattern->Base,
                        Flags,
                        Result,
                        BaseAddress,
                        RegionSize,
                        Protection
                    );
                }

                if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
                    break;
                }
            }

            ExReleasePushLockShared(&Scanner->Base.PatternLock);
            KeLeaveCriticalRegion();
        }

        Result->BytesScanned += bytesRead;

        //
        // 按块大小前进（而非 bytesRead），使重叠字节在下一块中
        // 被重新扫描，实现跨边界检测。
        //
        offset += chunkSize;

        //
        // 检查停止条件
        //
        if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
            break;
        }
    }

    Result->RegionsScanned++;

    ExFreePoolWithTag(buffer, MS_POOL_TAG_BUFFER);

    return STATUS_SUCCESS;
}

static BOOLEAN
MspShouldScanRegion(
    _In_ ULONG Protection,
    _In_ ULONG State,
    _In_ ULONG Type,
    _In_ MS_SCAN_TYPE ScanType,
    _In_ MS_SCAN_FLAGS Flags
)
{
    //
    // 必须是已提交状态
    //
    if (State != MEM_COMMIT) {
        return FALSE;
    }

    //
    // 跳过守卫页和无访问页
    //
    if (Protection & (PAGE_GUARD | PAGE_NOACCESS)) {
        return FALSE;
    }

    //
    // 应用扫描类型过滤
    //
    switch (ScanType) {
        case MsScanType_Quick:
            //
            // 仅可执行区域
            //
            if (!(Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                return FALSE;
            }
            break;

        case MsScanType_Standard:
            //
            // 仅私有区域
            //
            if (Type != MEM_PRIVATE) {
                return FALSE;
            }
            break;

        case MsScanType_Full:
            //
            // 全部已提交区域
            //
            break;

        case MsScanType_Targeted:
            //
            // 指定区域（始终扫描）
            //
            break;
    }

    //
    // 应用标志过滤
    //
    if ((Flags & MsScanFlag_SkipMapped) && Type == MEM_MAPPED) {
        return FALSE;
    }

    if ((Flags & MsScanFlag_SkipImages) && Type == MEM_IMAGE) {
        return FALSE;
    }

    if (Flags & MsScanFlag_OnlyExecutable) {
        if (!(Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            return FALSE;
        }
    }

    return TRUE;
}

// ============================================================================
//                私有实现 - 异步扫描工作线程
// ============================================================================

/*++
    MspAsyncScanWorker

    异步扫描工作线程：在系统工作队列中执行，负责解析请求、
    执行定向/全进程扫描、完成结果、回调通知、移除活跃扫描、
    更新统计并释放工作项/上下文。

    OWNERSHIP CONTRACT（结果所有权契约）：
    回调函数获得 activeScan->Result 的所有权，必须调用
    MsFreeScanResult(Scanner, Result) 释放；若未提供回调，
    则本函数直接释放结果以防泄漏（MS-1 修复）。

    参数：
        DeviceObject - 设备对象（未使用）
        Context      - 异步工作上下文

    返回值：
        无
--*/
static VOID
MspAsyncScanWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
)
{
    PMS_ASYNC_WORK_CONTEXT workContext = (PMS_ASYNC_WORK_CONTEXT)Context;
    PMS_SCANNER_INTERNAL scanner;
    PMS_ACTIVE_SCAN activeScan;
    PEPROCESS process = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (workContext == NULL) {
        return;
    }

    scanner = workContext->Scanner;
    activeScan = workContext->ActiveScan;

    //
    // 获取进程引用
    //
    status = PsLookupProcessByProcessId(activeScan->Request->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        activeScan->Result->Status = status;
        goto Complete;
    }

    //
    // 执行扫描
    //
    KeQuerySystemTime(&activeScan->Result->StartTime);
    activeScan->Result->ProcessId = activeScan->Request->ProcessId;
    activeScan->Result->Type = activeScan->Request->Type;

    if (activeScan->Request->TargetAddress != NULL) {
        //
        // 定向扫描
        //
        status = MmpScanMemroyRegion(
            scanner,
            process,
            activeScan->Request->TargetAddress,
            activeScan->Request->TargetSize,
            0,
            activeScan->Request->Flags,
            activeScan->Result
        );
    } else {
        //
        // 全进程扫描
        //
        status = MspScanProcessRegions(
            scanner,
            process,
            activeScan->Request->Type,
            activeScan->Request->Flags,
            activeScan->Result
        );
    }

    activeScan->Result->Status = status;
    ObDereferenceObject(process);

Complete:
    //
    // 完成扫描
    //
    KeQuerySystemTime(&activeScan->Result->EndTime);
    activeScan->Result->DurationMs = (ULONG)(
        (activeScan->Result->EndTime.QuadPart - activeScan->Result->StartTime.QuadPart) / 10000
    );
    activeScan->Result->Completed = TRUE;

    InterlockedExchange(&activeScan->Completed, 1);
    KeSetEvent(&activeScan->CompletionEvent, IO_NO_INCREMENT, FALSE);

    //
    // 在回调之前捕获统计信息，因为回调获得 Result 所有权后
    // 可能立即释放它（MS-1 修复：use-after-free）。
    //
    {
        LONG64 bytesScannedSnapshot = (LONG64)activeScan->Result->BytesScanned;
        LONG64 matchCountSnapshot = (LONG64)activeScan->Result->MatchCount;
        ULONG durationSnapshot = activeScan->Result->DurationMs;

        //
        // 调用完成回调。
        //
        // 所有权契约：回调获得 activeScan->Result 的所有权，
        // 必须调用 MsFreeScanResult(Scanner, Result) 释放。
        // 未提供回调时在此释放结果以防泄漏。
        //
        if (activeScan->Callback != NULL) {
            activeScan->Callback(activeScan->Result, activeScan->CallbackContext);
        } else {
            MsFreeScanResult(&scanner->Base, activeScan->Result);
        }

        //
        // 从活跃扫描链表移除（Push Lock，与所有调用者保持一致）
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&scanner->Base.ActiveScansLock);
        RemoveEntryList(&activeScan->ListEntry);
        InterlockedDecrement(&scanner->Base.ActiveScanCount);
        ExReleasePushLockExclusive(&scanner->Base.ActiveScansLock);
        KeLeaveCriticalRegion();

        //
        // 依据捕获的快照更新统计（MS-1 修复）
        //
        InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
        InterlockedAdd64(&scanner->Base.Stats.BytesScanned, bytesScannedSnapshot);
        InterlockedAdd64(&scanner->Base.Stats.TotalMatches, matchCountSnapshot);
        InterlockedAdd64(&scanner->Base.Stats.CumulativeScanTimeMs, (LONG64)durationSnapshot);
    }

    //
    // 释放工作项
    //
    if (activeScan->WorkItem != NULL) {
        IoFreeWorkItem(activeScan->WorkItem);
    }

    ExFreePoolWithTag(workContext, MS_POOL_TAG_CONTEXT);
    ExFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);

    //
    // BUG #3 修复：通知 MsShutdown 的排空循环本工作项已释放
    // 对扫描器状态的全部引用。必须在上方所有扫描器指针读取之后、
    // MspReleaseReference 之前执行（若关机时持有最后引用，
    // MspReleaseReference 可能拆除扫描器）。
    //
    InterlockedDecrement(&scanner->QueuedWorkItems);

    MspReleaseReference(scanner);
}

// ============================================================================
//                私有实现 - 模式查找
// ============================================================================

/*++
    MspFindPatternById

    按模式 ID 在哈希桶链表中查找模式。

    参数：
        Scanner   - 扫描器内部结构（调用方须持有 PatternLock）
        PatternId - 模式 ID

    返回值：
        匹配的模式指针；未找到返回 NULL
--*/
static PMS_PATTERN_INTERNAL
MspFindPatternById(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ ULONG PatternId
)
{
    ULONG bucket = MspHashPatternId(PatternId);
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;

    for (entry = Scanner->PatternHashTable[bucket].Flink;
         entry != &Scanner->PatternHashTable[bucket];
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, HashEntry);

        if (pattern->Base.PatternId == PatternId) {
            return pattern;
        }
    }

    return NULL;
}

// ============================================================================
//               私有实现 - 引用计数
// ============================================================================

/*++
    MspAcquireReference

    递增扫描器引用计数（不校验关机状态）。

    参数：
        Scanner - 扫描器内部结构

    返回值：
        无
--*/
static VOID
MspAcquireReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    InterlockedIncrement(&Scanner->ReferenceCount);
}

/*++
    MspReleaseReference

    递减扫描器引用计数；若计数归零且扫描器正在关机，
    触发 ShutdownEvent 唤醒 MsShutdown 的等待。

    参数：
        Scanner - 扫描器内部结构

    返回值：
        无
--*/
static VOID
MspReleaseReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    LONG newCount = InterlockedDecrement(&Scanner->ReferenceCount);

    if (newCount == 0 && Scanner->ShuttingDown) {
        KeSetEvent(&Scanner->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

/*++
    MspTryAcquireReference

    原子地获取扫描器引用，然后校验其是否正在关机。
    若正在关机则释放引用并返回 FALSE。
    消除 ShuttingDown 检查与引用获取之间的 TOCTOU 竞争（CRIT-3 修复）。

    参数：
        Scanner - 扫描器内部结构

    返回值：
        TRUE  - 引用已持有且扫描器可用
        FALSE - 扫描器正在关机（未持有引用）
--*/
static BOOLEAN
MspTryAcquireReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    InterlockedIncrement(&Scanner->ReferenceCount);

    if (Scanner->ShuttingDown) {
        MspReleaseReference(Scanner);
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
//               私有实现 - 熵值计算
// ============================================================================

/*++
    MspCalculateIntegerEntropy

    使用预计算查找表进行纯整数 Shannon 熵计算（全程无浮点运算）。

    计算流程：
    1. 统计各字节出现频率；
    2. 将频率归一化到 256 基数；
    3. 对每个字节值查表 g_EntropyContrib[归一化频率]；
    4. 返回熵值百分比（0-100），其中 0 = 均匀分布，100 = 最大熵。

    参数：
        Buffer - 待分析的数据缓冲区
        Size   - 缓冲区字节数

    返回值：
        熵值百分比（0-100）
--*/
static ULONG
MspCalculateIntegerEntropy(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
)
{
    ULONG frequency[256] = { 0 };
    ULONG normalizedFreq;
    SIZE_T i;
    ULONG totalContrib = 0;

    if (Size == 0) {
        return 0;
    }

    //
    // 统计各字节频率
    //
    for (i = 0; i < Size; i++) {
        frequency[Buffer[i]]++;
    }

    //
    // 使用预计算表计算熵贡献。
    // 表以 256 字节块大小频率为索引；其他大小需归一化：
    // normalizedFreq = freq * 256 / Size。
    //
    if (Size == 256) {
        //
        // 快速路径：无需归一化
        //
        for (i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                totalContrib += g_EntropyContrib[frequency[i]];
            }
        }
    } else {
        //
        // 通用路径：将各频率归一化到 256 基数
        //
        for (i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                normalizedFreq = (ULONG)((ULONG64)frequency[i] * 256 / Size);
                if (normalizedFreq > 256) {
                    normalizedFreq = 256;
                }
                if (normalizedFreq > 0) {
                    totalContrib += g_EntropyContrib[normalizedFreq];
                }
            }
        }
    }

    //
    // totalContrib 的单位中最大熵 = 8 * 256 = 2048。
    // 换算为百分比：percent = totalContrib * 100 / 2048。
    //
    return (totalContrib * 100 + 1024) / 2048;  // +1024 用于四舍五入
}

//
// ============================================================================
// 【WkD 迁移适配】本地桩函数实现
// ============================================================================
//

/*++
    MspIsOnBattery

    WkD 迁移占位：原 SS 调用 PowerCallback.h 的 ShadowPowerIsOnBattery()，
    用于在电池供电时把 Full/Standard 扫描降级为 Quick。
    WkD 当前未接入电源状态回调，固定返回 FALSE（不降级），
    由用户后续依据 PoRegisterPowerSettingCallback 等机制替换实现。

    --*/
static BOOLEAN
MspIsOnBattery(
    VOID
)
{
    return FALSE;
}

/*++
    MspSubmitShellcodeEvent

    WkD 迁移占位：原 SS 调用 Behavioral/BehaviorEngine.h 的
    BeEngineSubmitEvent(BehaviorEvent_ShellcodeDetected,
    BehaviorCategory_MemoryOperation, ...) 上报内存相关行为事件。
    WkD 当前未具备 BehaviorEngine 模块，此处仅保留调用语义，
    后续由用户接入 IoaEngine 或其它行为分析管道。

    --*/
static VOID
MspSubmitShellcodeEvent(
    _In_ ULONG EventType,
    _In_ ULONG Category,
    _In_ ULONG ProcessId,
    _In_ UINT32 Score
)
{
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(Category);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Score);

    //
    // TODO(WkD)：接入行为分析管道（如 IoaEngine / MessageQueue / NotificationManager）
    //
    return;
}

