/**************************************************/
/*  IoaRopDetect — ROP/JOP/COP/SROP 检测（agent）   */
/*  ShadowStrike ROPDetector 全量功能迁移 2026-08-07 */
/*  MITRE ATT&CK: T1055.012 / T1574 执行流劫持      */
/**************************************************/
/*                                                    */
/*  职责：ROP/JOP/COP/SROP 攻击检测（重功能实现非复制）*/
/*    1. 字节模式路径（活代码，保留）：                 */
/*         IoaRop_AnalyzeBuffer 对缓冲内容做危险       */
/*         gadget 模式 + RET/JMP/CALL/SYSCALL 计数 +   */
/*         分类 + 评分 + 载荷推断（WKD_ROP_ANALYSIS_   */
/*         RESULT，无 gadget 库，无栈输入）。           */
/*    2. 地址驱动路径（死代码，新增，对齐 SS）：        */
/*         gadget 数据库（模块可执行节扫描构建）+ 栈    */
/*         分析（栈槽值查库 → 连续链 ≥3 判定）。         */
/*         WKD_ROP_DETECTION_RESULT，依赖真实线程栈    */
/*         快照与 gadget 库，当前无触发点。             */
/*                                                    */
/*  与 wkd 既有能力分工（复用不重复实现）：            */
/*    - 模块判定      → MsBuildModuleSet /            */
/*                      MsIsAddrInModuleSet (512)      */
/*    - 栈界/上下文   → WptGetThreadContext /          */
/*                      WptGetThreadStackBounds        */
/*    - 栈读取        → MsReadMemory (malloc/free)     */
/*    - PE 校验/节表  → IocpAnalyzeBufferEx               */
/*    - 壳码互证      → IocDetectShellcode          */
/*    - 告警分发      → VerdictEngine + ALPC (预留)    */
/*                                                    */
/*  ※ 死代码说明：地址驱动路径的全部公共 API 为         */
/*    "导出无调用者"（编译通过，无接线）。依赖链：      */
/*    模块扫描成本高 / 真实栈事件源未通 / 触发点待定。  */
/**************************************************/

#ifndef IOA_ROP_DETECT_H
#define IOA_ROP_DETECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winnt.h>

/**************************************************/
/*                  常量定义                       */
/**************************************************/
#define WKD_ROP_MAX_CHAIN_LENGTH        1024    /* 对齐 SS ROP_MAX_CHAIN_LENGTH */
#define WKD_ROP_MIN_CHAIN_LENGTH        3       /* 对齐 SS ROP_MIN_CHAIN_LENGTH */
#define WKD_ROP_GADGET_MAX_SIZE         16      /* 对齐 SS ROP_GADGET_MAX_SIZE */
#define WKD_ROP_MAX_GADGETS_PER_MODULE  4096    /* 对齐 SS ROP_MAX_GADGETS_PER_MODULE */
#define WKD_ROP_STACK_SAMPLE_SIZE       (4 * 1024) /* 对齐 SS ROP_STACK_SAMPLE_SIZE */
#define WKD_ROP_GADGET_HASH_BUCKETS     1024    /* 对齐 SS ROP_GADGET_HASH_BUCKETS */
#define WKD_ROP_GADGET_HASH_CHAIN       8       /* 桶内定长链槽数 (agent 无链表, 定长) */
#define WKD_ROP_GADGET_POOL_SIZE        8192    /* agent gadget 池总量 (定长, 超限拒绝) */
#define WKD_ROP_MAX_MODULES_TRACKED     256     /* 对齐 SS ROP_MAX_MODULES_TRACKED */
#define WKD_ROP_MAX_MODULE_BREAKDOWN    16      /* 对齐 SS ROP_DETECTION_RESULT.ModuleBreakdown[16] */
#define WKD_ROP_DETECTOR_SIGNATURE      0x576B4452  /* 'WkDR' 结构签名 (对齐 SS ROP_DETECTOR_SIGNATURE) */

/**************************************************/
/*                  攻击类型                       */
/**************************************************/
typedef enum _WKD_ROP_ATTACK_TYPE {
    WkdRopAttack_Unknown = 0,
    WkdRopAttack_ROP,          /* Return-Oriented Programming */
    WkdRopAttack_JOP,          /* Jump-Oriented Programming */
    WkdRopAttack_COP,          /* Call-Oriented Programming */
    WkdRopAttack_SROP,         /* Sigreturn-Oriented Programming */
    WkdRopAttack_BROP,         /* Blind ROP */
    WkdRopAttack_StackPivot,   /* Stack pivot attack */
    WkdRopAttack_Mixed,        /* Mixed gadget types */
} WKD_ROP_ATTACK_TYPE;

/**************************************************/
/*                  gadget 类型                    */
/**************************************************/
typedef enum _WKD_ROP_GADGET_TYPE {
    WkdRopGadget_Unknown = 0,
    WkdRopGadget_Ret,          /* RET (0xC3) */
    WkdRopGadget_RetN,         /* RET imm16 (0xC2) */
    WkdRopGadget_JmpReg,       /* JMP reg */
    WkdRopGadget_JmpMem,       /* JMP [reg] */
    WkdRopGadget_CallReg,      /* CALL reg */
    WkdRopGadget_CallMem,      /* CALL [reg] */
    WkdRopGadget_Syscall,      /* SYSCALL/SYSENTER */
    WkdRopGadget_Int,          /* INT (0xCD, 对齐 SS GadgetType_Int) */
    WkdRopGadget_Pivot,        /* 栈转移（XCHG ESP/MOV ESP） */
    WkdRopGadget_Leave,        /* LEAVE; RET */
    WkdRopGadget_Arg,          /* POP reg; RET（参数设置） */
    WkdRopGadget_Shell,        /* JMP/CALL RSP（shellcode 跳转） */
    WkdRopGadget_Stack,        /* ADD RSP,imm（栈清理） */
} WKD_ROP_GADGET_TYPE;

/**************************************************/
/*              危险 gadget 模式                   */
/**************************************************/
typedef struct _WKD_ROP_DANGEROUS_PATTERN {
    const BYTE* Bytes;
    ULONG       Length;
    WKD_ROP_GADGET_TYPE Type;
    ULONG       DangerScore;   /* 0-100 */
    const char* Name;
} WKD_ROP_DANGEROUS_PATTERN;

/**************************************************/
/*            gadget 语义（寄存器/内存/栈位图）     */
/**************************************************/
typedef struct _WKD_ROP_SEMANTICS {
    BOOLEAN WritesMemory;
    BOOLEAN ReadsMemory;
    BOOLEAN ModifiesStack;
    BOOLEAN ModifiesFlags;
    ULONG   RegistersModified;   /* WKD_ROP_REG_* 位图 */
    ULONG   RegistersRead;       /* WKD_ROP_REG_* 位图 */
} WKD_ROP_SEMANTICS, *PWKD_ROP_SEMANTICS;

/**************************************************/
/*                gadget 库条目                    */
/**************************************************/
typedef struct _WKD_ROP_GADGET {
    ULONG_PTR Address;              /* gadget 起始地址 */
    ULONG_PTR ModuleBase;           /* 所属模块基址 */
    ULONG     ModuleOffset;         /* 模块内偏移 */
    WKD_ROP_GADGET_TYPE Type;
    ULONG     Size;
    UCHAR     Bytes[WKD_ROP_GADGET_MAX_SIZE];
    WKD_ROP_SEMANTICS Semantics;
    ULONG     DangerScore;          /* 0-100 */
    BOOLEAN   IsPrivileged;         /* syscall gadget */
    BOOLEAN   CouldBypassCFG;       /* JMP/CALL reg 类 */
} WKD_ROP_GADGET, *PWKD_ROP_GADGET;

/**************************************************/
/*                链条目                           */
/**************************************************/
typedef struct _WKD_ROP_CHAIN_ENTRY {
    ULONG_PTR GadgetAddress;        /* 栈槽值（返回地址） */
    WKD_ROP_GADGET_TYPE GadgetType;
    ULONG     GadgetSize;
    ULONG     GadgetDangerScore;
    BOOLEAN   GadgetIsPrivileged;
    ULONG     GadgetRegistersModified;   /* WKD_ROP_REG_* 位图 */
    ULONG64   StackOffset;               /* 相对栈采样起点的槽偏移 */
    ULONG_PTR StackValue;
    ULONG     Index;
} WKD_ROP_CHAIN_ENTRY, *PWKD_ROP_CHAIN_ENTRY;

/**************************************************/
/*               载荷推断结果                      */
/**************************************************/
typedef struct _WKD_ROP_PAYLOAD_ANALYSIS {
    BOOLEAN PayloadInferred;
    CHAR    Description[256];
    BOOLEAN MayExecuteCode;
    BOOLEAN MayDisableDefenses;
    BOOLEAN MayEscalatePrivileges;
} WKD_ROP_PAYLOAD_ANALYSIS, *PWKD_ROP_PAYLOAD_ANALYSIS;

/**************************************************/
/*               模块分布统计                      */
/**************************************************/
typedef struct _WKD_ROP_MODULE_BREAKDOWN {
    ULONG_PTR ModuleBase;
    WCHAR     Name[64];
    ULONG     GadgetCount;
} WKD_ROP_MODULE_BREAKDOWN, *PWKD_ROP_MODULE_BREAKDOWN;

/**************************************************/
/*            地址驱动检测结果                      */
/*  注意: 约 50KB (ChainEntries[1024]), 仅堆分配。  */
/**************************************************/
typedef struct _WKD_ROP_DETECTION_RESULT {
    BOOLEAN     ChainDetected;
    WKD_ROP_ATTACK_TYPE AttackType;
    ULONG       ConfidenceScore;    /* 0-100 */
    ULONG       SeverityScore;      /* 0-100 */

    DWORD       ProcessId;
    DWORD       ThreadId;

    ULONG_PTR   StackBase;
    ULONG_PTR   StackLimit;
    ULONG_PTR   CurrentSp;

    WKD_ROP_CHAIN_ENTRY ChainEntries[WKD_ROP_MAX_CHAIN_LENGTH];
    ULONG       ChainLength;
    ULONG       UniqueGadgets;      /* 库命中总数 */
    ULONG       UnknownGadgets;     /* 可执行但不在库 */

    BOOLEAN     StackPivotDetected;
    ULONG_PTR   PivotSource;
    ULONG_PTR   PivotDestination;

    WKD_ROP_MODULE_BREAKDOWN ModuleBreakdown[WKD_ROP_MAX_MODULE_BREAKDOWN];
    ULONG       ModulesUsed;

    WKD_ROP_PAYLOAD_ANALYSIS PayloadAnalysis;
} WKD_ROP_DETECTION_RESULT, *PWKD_ROP_DETECTION_RESULT;

/**************************************************/
/*             模块扫描跟踪表                      */
/**************************************************/
typedef struct _WKD_ROP_SCANNED_MODULE {
    ULONG_PTR ModuleBase;
    ULONG     ModuleSize;
    WCHAR     ModuleName[64];
    ULONG     GadgetCount;
    ULONG64   ScanTime;            /* GetTickCount64 */
    ULONG     ModuleHash;
} WKD_ROP_SCANNED_MODULE, *PWKD_ROP_SCANNED_MODULE;

/**************************************************/
/*                配置与统计                       */
/**************************************************/
typedef struct _WKD_ROP_CONFIG {
    ULONG   MinChainLength;
    ULONG   MaxChainLength;
    ULONG   ConfidenceThreshold;
    BOOLEAN ScanSystemModules;
    BOOLEAN EnableSemanticAnalysis;
} WKD_ROP_CONFIG, *PWKD_ROP_CONFIG;

typedef struct _WKD_ROP_STATISTICS {
    ULONG   GadgetCount;
    ULONG   ModulesScanned;
    ULONG64 StacksAnalyzed;
    ULONG64 ChainsDetected;
    ULONG64 UpTimeMs;
} WKD_ROP_STATISTICS, *PWKD_ROP_STATISTICS;

/**************************************************/
/*                ROP 检测器状态                   */
/*  注意: 约 500KB+ (GadgetPool[8192]), 仅堆分配,  */
/*  严禁模块级静态或栈分配。调用方持有并传入。       */
/**************************************************/
typedef struct _WKD_ROP_DETECTOR {
    ULONG   Signature;
    BOOLEAN Initialized;

    CRITICAL_SECTION GadgetLock;
    CRITICAL_SECTION ModuleLock;

    /* gadget 池 + 哈希索引 (agent 无链表, 定长数组) */
    WKD_ROP_GADGET GadgetPool[WKD_ROP_GADGET_POOL_SIZE];
    ULONG     GadgetHash[WKD_ROP_GADGET_HASH_BUCKETS][WKD_ROP_GADGET_HASH_CHAIN];
    ULONG     GadgetHashCount[WKD_ROP_GADGET_HASH_BUCKETS];
    ULONG     GadgetPoolCount;

    /* 模块扫描去重表 */
    WKD_ROP_SCANNED_MODULE ScannedModules[WKD_ROP_MAX_MODULES_TRACKED];
    ULONG     ScannedActiveModules;

    WKD_ROP_CONFIG Config;

    struct {
        volatile LONG64 StacksAnalyzed;
        volatile LONG64 ChainsDetected;
        volatile LONG64 GadgetsIndexed;
        ULONG64         StartTime;
    } Stats;

    /* 速率限制 (对齐 SS RoppCheckRateLimit, 死代码) */
    volatile LONG64 AnalysisCount;
    ULONG64         LastResetTime;
    ULONG           MaxAnalysesPerSecond;
} WKD_ROP_DETECTOR, *PWKD_ROP_DETECTOR;

/**************************************************/
/*            字节模式结果 (保留现有)              */
/**************************************************/
typedef struct _WKD_ROP_ANALYSIS_RESULT {
    BOOLEAN  ChainDetected;
    WKD_ROP_ATTACK_TYPE AttackType;
    ULONG    ConfidenceScore;      /* 0-100 */
    ULONG    SeverityScore;        /* 0-100 */
    ULONG    GadgetCount;          /* 命中危险 gadget 数 */
    ULONG    RetCount;             /* RET/RETN 计数 */
    ULONG    JmpCount;             /* JMP reg 计数 */
    ULONG    CallCount;            /* CALL reg 计数 */
    ULONG    SyscallCount;         /* SYSCALL/SYSENTER 计数 */
    ULONG    MaxConsecutiveRet;    /* 连续 RET 最大长度（链长近似） */
    BOOLEAN  PayloadInferred;
    char     PayloadDescription[160];
} WKD_ROP_ANALYSIS_RESULT, *PWKD_ROP_ANALYSIS_RESULT;

/**************************************************/
/*                 函数声明                        */
/**************************************************/

/* ---- 字节模式路径 (活代码, 保留) ---- */

//
// 在缓冲中查找首个危险 gadget 模式。
//
BOOL
IoaRop_DetectGadgetPattern(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_opt_ const WKD_ROP_DANGEROUS_PATTERN** Pattern,
    _Out_opt_ PULONG Offset
    );

//
// 缓冲 ROP 分析（字节模式）：gadget 计数 + 分类 + 评分 + 载荷推断。
//
BOOL
IoaRop_AnalyzeBuffer(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_ROP_ANALYSIS_RESULT Result
    );

WKD_ROP_ATTACK_TYPE
IoaRop_ClassifyAttack(
    _Inout_ PWKD_ROP_ANALYSIS_RESULT Result
    );

VOID
IoaRop_CalculateConfidence(
    _Inout_ PWKD_ROP_ANALYSIS_RESULT Result
    );

VOID
IoaRop_InferPayload(
    _Inout_ PWKD_ROP_ANALYSIS_RESULT Result
    );

/* ---- 地址驱动路径 (死代码, 新增, 对齐 SS) ---- */

//
// 初始化 ROP 检测器状态 (对齐 SS RopInitialize)。
// Detector 须调用方堆分配 (约 500KB+), 本函数初始化锁/配置/统计。
//
NTSTATUS
IoaRop_Initialize(
    _Inout_ PWKD_ROP_DETECTOR Detector
    );

//
// 关闭检测器, 释放锁资源 (对齐 SS RopShutdown)。
//
VOID
IoaRop_Shutdown(
    _Inout_ PWKD_ROP_DETECTOR Detector
    );

//
// 扫描模块内存镜像 buffer 的可执行节构建 gadget 库 (对齐 SS RopScanModuleForGadgets)。
// ModuleData 须为内存镜像 (节数据按 VirtualAddress 布局), ModuleBase 为加载基址 (栈槽值匹配)。
// PE 校验/节表复用 IocpAnalyzeBufferEx。
//
NTSTATUS
IoaRop_ScanModuleForGadgets(
    _Inout_ PWKD_ROP_DETECTOR Detector,
    _In_ ULONG_PTR ModuleBase,
    _In_ const BYTE* ModuleData,
    _In_ SIZE_T ModuleSize,
    _In_opt_ PCWSTR ModuleName
    );

//
// 单条 gadget 入库 (对齐 SS RopAddGadget): 语义分析 + 危险度评分 + 哈希入桶。
//
NTSTATUS
IoaRop_AddGadget(
    _Inout_ PWKD_ROP_DETECTOR Detector,
    _In_ ULONG_PTR Address,
    _In_ ULONG_PTR ModuleBase,
    _In_reads_bytes_(Size) const BYTE* Bytes,
    _In_ ULONG Size,
    _In_ WKD_ROP_GADGET_TYPE Type
    );

//
// 按地址查库, 拷贝 gadget 数据 (对齐 SS RopLookupGadget)。
//
NTSTATUS
IoaRop_LookupGadget(
    _In_ const PWKD_ROP_DETECTOR Detector,
    _In_ ULONG_PTR Address,
    _Out_ PWKD_ROP_GADGET GadgetCopy
    );

//
// 栈缓冲地址驱动分析 (对齐 SS RopAnalyzeStackBuffer): 栈槽值查库 → 连续链。
// 需已构建 gadget 库; Result 堆分配, 调用方 IoaRop_FreeResult。
//
NTSTATUS
IoaRop_AnalyzeStackBuffer(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ const ULONG_PTR* StackBuffer,
    _In_ SIZE_T Size,
    _In_ ULONG_PTR StackBase,
    _Out_ PWKD_ROP_DETECTION_RESULT* Result
    );

//
// 线程栈完整分析 (对齐 SS RopAnalyzeStack): Wpt 取上下文/栈界 + MsReadMemory
// 读栈 + MsBuildModuleSet 模块判定 + 链检测 + 分类/评分/载荷。
//
NTSTATUS
IoaRop_AnalyzeStack(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _Out_ PWKD_ROP_DETECTION_RESULT* Result
    );

//
// 调用栈完整性验证 (对齐 SS RopValidateCallStack): 链 → IsValid=FALSE+confidence; pivot→70。
//
NTSTATUS
IoaRop_ValidateCallStack(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _Out_ PBOOLEAN IsValid,
    _Out_opt_ PULONG SuspicionScore
    );

//
// 释放堆分配的检测结果。
//
VOID
IoaRop_FreeResult(
    _In_ PWKD_ROP_DETECTION_RESULT Result
    );

//
// 读取检测器统计 (对齐 SS RopGetStatistics)。
//
NTSTATUS
IoaRop_GetStatistics(
    _In_ const PWKD_ROP_DETECTOR Detector,
    _Out_ PWKD_ROP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif

#endif /* IOA_ROP_DETECT_H */
