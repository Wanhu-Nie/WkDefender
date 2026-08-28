/**************************************************/
/*  WkDefender IOA — 注入类型分类器                 */
/*                                                  */
/*  职责: 基于边类型集合 + 事件参数, 判定注入类型,      */
/*        计算注入置信度/风险分。                      */
/*                                                  */
/*  移植自: ShadowStrike ProcessInjectionDetector     */
/*          ClassifyFromEvents + CalculateConfidence  */
/*          + CalculateRiskScore                     */
/*                                                  */
/*  与 T1 语义规则的关系:                             */
/*    T1 (R10-R17) 已推导注入语义位 (DLL/APC/镂空等),  */
/*    分类器补充:                                    */
/*      1. 精确注入类型判定 (含起始地址合法性区分子类)  */
/*      2. 置信度/风险启发式 (目标敏感进程/事件数等)    */
/*      3. 数据源缺失的模式以完整逻辑保留 (死代码)      */
/*                                                  */
/*  数据源依赖 (死代码模式的激活条件):                 */
/*    - ProcessHollowing : 需驱动补 NtUnmapViewOf-   */
/*        Section/NtSetContextThread 事件 (Hollows 边 */
/*        当前仅由 T1 语义标志产生)                   */
/*    - APC/EarlyBird   : 需驱动补 NtQueueApcThread   */
/*    - ThreadHijacking : 需驱动补 Suspend/Resume/    */
/*        SetContext 事件                            */
/*    - SectionMapping  : 文件轨 AcquireSection 已激活 (0x1308→0x6005),    */
/*    - AtomBombing     : 需驱动补 NtQueueApcThread   */
/*        事件 + ApcRoutine 参数解析 (T1055.009);     */
/*        原子内容分析当前走 Agent 按需枚举 (活),      */
/*        周期轮询 (IoaAtom_ScanPeriodic) 为死代码     */
/**************************************************/

#pragma once

#include "IoaTypes.h"
#include "../Notification/EventTypes.h"

/**************************************************/
/*               注入类型枚举                        */
/**************************************************/

typedef enum _WKD_INJECTION_TYPE {
    WkdInjection_Unknown            = 0,

    /* ── 线程注入 ── */
    WkdInjection_RemoteThread       = 1,   /* CreateRemoteThread / NtCreateThreadEx */
    WkdInjection_DirectSyscallThread= 2,   /* 直接 syscall 创建线程 */

    /* ── APC 注入 ── */
    WkdInjection_APC                = 10,  /* QueueUserAPC */
    WkdInjection_EarlyBird          = 11,  /* 挂起进程 + APC */
    WkdInjection_AtomBombing        = 12,  /* GlobalAddAtom + NtQueueApcThread(原子检索) T1055.009 */

    /* ── 进程操纵 ── */
    WkdInjection_ProcessHollowing   = 20,  /* Unmap+Alloc+Write+SetCtx */

    /* ── DLL 注入 ── */
    WkdInjection_DLLInjection       = 30,  /* Write+远程线程(LoadLibrary) */
    WkdInjection_ReflectiveDLL      = 31,  /* Write+远程线程(非模块起始) */

    /* ── 执行流劫持/内存注入 ── */
    WkdInjection_ThreadHijacking    = 40,  /* Suspend+SetCtx+Resume */
    WkdInjection_SectionMapping     = 41,  /* Map+Write */
    WkdInjection_ShellcodeInjection = 42,  /* 跨进程写+无远程线程 */

    WkdInjection_ProcessDoppelganging = 43, /* 事务化进程镂空: TxF 序列 T1055.013 (死代码, 待驱动补 NtCreateProcessEx+TxF case) */

    /* ── SS InjectionDetector.c 补遗 (2026-08) ── */
    WkdInjection_PeInjection         = 44,  /* PE 注入: Alloc+Write+目标内存 EXECUTE 保护 T1055.002 (SS InjTechPeInjection, 活) */
    WkdInjection_TlsCallback         = 45,  /* TLS 回调注入 T1055.005 (SS InjTechTlsCallback 纸面枚举, 判定未实现, 死代码) */
    WkdInjection_ExtraWindowMemory   = 46,  /* 扩展窗口内存注入 T1055.011 (SS InjTechExtraWindowMemory 纸面枚举, 死代码) */
    WkdInjection_CallbackInjection   = 47,  /* 回调注入 SetWindowsHookEx 等 (SS InjTechCallbackInjection 纸面枚举, MITRE 无独立子技术, 归 T1055) */
    WkdInjection_VdsoHijacking       = 48,  /* VDSO 页劫持 T1055.014 (Linux 专有, Windows 不可适用, 纸面枚举) */
    WkdInjection_Listplanting        = 49,  /* ListPlanting T1055.015 (Linux 专有, Windows 不可适用, 纸面枚举) */

    WkdInjection_Max
} WKD_INJECTION_TYPE, *PWKD_INJECTION_TYPE;

/**************************************************/
/*               注入器分类                           */
/*  移植自 ShadowStrike InjectorType + CreateAlert   */
/*  分级 (Malware/Exploit/Unknown 判定)              */
/**************************************************/

typedef enum _WKD_INJECTOR_TYPE {
    WkdInjector_Unknown     = 0,
    WkdInjector_Legitimate  = 1,
    WkdInjector_PUP         = 2,
    WkdInjector_Malware     = 3,
    WkdInjector_Exploit     = 4,
    WkdInjector_APT         = 5,
} WKD_INJECTOR_TYPE, *PWKD_INJECTOR_TYPE;

/**************************************************/
/*           进程注入状态 (查询辅助)                  */
/*  移植自 ShadowStrike ProcessInjectionState +      */
/*  IsProcessInjected/IsProcessInjecting             */
/*  基于进程节点双向 PairContext 链聚合, 供 UI/查询   */
/**************************************************/

typedef struct _WKD_INJECTION_PROCESS_STATE {
    BOOLEAN IsBeingInjected;        /* 正被注入 (语义位已置) */
    BOOLEAN HasBeenInjected;        /* 曾被注入 (历史存在注入对) */
    BOOLEAN IsInjecting;            /* 正在注入他人 */
    ULONG   TotalInjectionsAsTarget;/* 作为目标的注入对计数 */
    ULONG   TotalInjectionsAsSource;/* 作为源的注入对计数 */
} WKD_INJECTION_PROCESS_STATE, *PWKD_INJECTION_PROCESS_STATE;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaClassifyInjection — 基于进程对状态 + 事件参数判定注入类型。
 *
 * 判定依据:
 *   1. PairCtx->InteractionBitmap 数据层 (边类型集合)
 *   2. Event 载荷参数 (RemoteThreadCreate: 起始地址/InjectIndicators)
 *   3. Event->BehaviorFlags (驱动采集的注入标志)
 *
 * 副作用:
 *   - 设置对应注入语义位 (BM_SEM_*), 补充 T1 语义规则未覆盖的精确判定
 *   - 回填 Event->BehaviorFlags 注入标志
 *
 * 参数:
 *   PairCtx     - 进程对上下文 (必填, 读取数据层位图)。
 *   Event       - 当前事件 (可为 NULL, 仅 RemoteThreadCreate 使用载荷)。
 *   SrcNode     - 源进程节点 (可为 NULL, 用于白名单/敏感进程)。
 *   TgtNode     - 目标进程节点 (可为 NULL, 用于敏感进程加分)。
 *   InjectedType - [可选] 输出注入类型。
 *   Confidence  - [可选] 输出注入置信度 [0,100]。
 *   RiskScore   - [可选] 输出注入风险分 [0,100]。
 *
 * 返回值:
 *   STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
 */
NTSTATUS
IoaClassifyInjection(
    _In_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_EVENT_HEADER Event,
    _In_opt_ PWKD_PROCESS SrcNode,
    _In_opt_ PWKD_PROCESS TgtNode,
    _Out_opt_ PWKD_INJECTION_TYPE InjectedType,
    _Out_opt_ PULONG Confidence,
    _Out_opt_ PULONG RiskScore
    );

/*
 * IoaInjectionTypeToMitre — 注入类型 → MITRE ATT&CK 子技术。
 *
 * 返回值:
 *   静态字符串指针 (如 "T1055.001")。
 */
PCWSTR
IoaInjectionTypeToMitre(
    _In_ WKD_INJECTION_TYPE Type
    );

/*
 * IoaInjectionTypeToString — 注入类型 → 可读名称。
 *
 * 返回值:
 *   静态字符串指针 (如 "DLL Injection")。
 */
PCWSTR
IoaInjectionTypeToString(
    _In_ WKD_INJECTION_TYPE Type
    );

/**************************************************/
/*      遗漏项补充 (移植 ShadowStrike 工具/查询)      */
/**************************************************/

/*
 * IoaIsExecutableProtection — 判断内存保护属性是否可执行。
 * 移植自 ShadowStrike IsExecutableProtection。
 * ※ 死代码: 当前分类器用 InjectIndicators 的 RWX_START 标志近似,
 *   本函数供 MemoryProtection 字段直接判定时使用。
 */
BOOLEAN
IoaIsExecutableProtection(
    _In_ ULONG Protection
    );

/*
 * IoaIsSuspiciousHandleAccess — 判断句柄访问权限组合是否可疑。
 * 移植自 ShadowStrike IsSuspiciousHandleAccess
 *   (Write+Operation 或 Write+CreateThread)。
 * ※ 死代码: 当前 ProcessOpen 事件不携带 DesiredAccess 详情,
 *   驱动侧句柄告警 (ObCallback) 未启用。
 */
BOOLEAN
IoaIsSuspiciousHandleAccess(
    _In_ ULONG AccessRights
    );

/*
 * IoaClassifyInjector — 注入器分级。
 * 移植自 ShadowStrike CreateAlert (confidence>=90→Malware,
 * >=70→Exploit, 否则 Unknown)。
 * ※ 死代码: 供告警生成补充注入器分类字段。
 */
WKD_INJECTOR_TYPE
IoaClassifyInjector(
    _In_ ULONG Confidence
    );

/*
 * IoaQueryProcessInjectionState — 进程注入状态查询。
 * 移植自 ShadowStrike IsProcessInjected/IsProcessInjecting +
 * ProcessInjectionState。遍历进程节点双向 PairContext 链聚合。
 * ※ 死代码: 供 UI/主动查询, 当前无调用者。
 */
NTSTATUS
IoaQueryProcessInjectionState(
    _In_ PWKD_PROCESS Node,
    _Out_ PWKD_INJECTION_PROCESS_STATE Out
    );

/*
 * IoaAnalyzeProcessInjection — 进程注入主动分析。
 * 移植自 ShadowStrike AnalyzeProcess。
 * ※ 死代码: 状态查询部分已实现; 主动扫描 (内存 PE 比对/反射检测/
 *   线程上下文体检) 依赖波次1/2 的 MemoryScanner/ProcessHollowing/
 *   ThreadHijack 检测器, 当前未迁移, 待兄弟检测器就位后接入。
 */
NTSTATUS
IoaAnalyzeProcessInjection(
    _In_ PWKD_PROCESS Node,
    _Out_opt_ PULONG Verdict    /* 0=Clean, 1=Suspicious, 2=Detected, 3=Confirmed */
    );

/*
 * IoaRecordModuleLoad — 记录一次模块加载 (DLL 注入模块窗口确认的数据源)。
 * 移植自 ShadowStrike ModuleTracker + InjectionCorrelator。
 * 供 ImageLoad 事件流接入后调用 (当前驱动 ImageLoad 事件未接入 IOA,
 * 见 process_manager.c WkdMessage_ImageLoaded; 接入后即激活确认)。
 */
NTSTATUS
IoaRecordModuleLoad(
    _In_ ULONG ProcessId,
    _In_ PCWSTR ModulePath,
    _In_ LARGE_INTEGER LoadTime
    );

/*
 * IoaConfirmDllInjectionByModule — 远程线程 DLL 注入的模块窗口确认。
 * 移植自 ShadowStrike DetectRemoteThreadInjectionImpl (T1055.001)。
 * 当目标进程在关联时间窗 (1s) 内加载了未信任 (非系统目录) 模块时,
 * 将 DLL 注入置信度提升至确认级 (≥90) 并提高风险分。
 * 数据源缺失 (模块缓存为空) 时返回 STATUS_NOT_FOUND, 不改变判定, 不引入误报。
 */
NTSTATUS
IoaConfirmDllInjectionByModule(
    _In_ ULONG TargetProcessId,
    _Inout_ PULONG Confidence,
    _Inout_ PULONG RiskScore
    );

/*
 * IoaConfirmReflectiveLoading — 反射 DLL 精确确认 (事件驱动定向验证)。
 * 对齐 ShadowStrike AnalyzeCandidate 的内存扫描确认阶段 (ReflectiveDLLDetector.cpp L2403-2418):
 *   分类器以 UNBACKED_START 近似判定 ReflectiveDLL; 本函数用线程入口地址定向验证:
 *     MsGetRegionInfo 定位入口区域 → 私有可执行 → MsScanRegionAt 定向扫描 →
 *     确认隐藏无背衬 PE (WkdMemThreat_PEInjection 且 !PeInPeb)。
 * 不可验证 (无入口地址/区域不可读/无 PE 命中) 时返回 FALSE, 不改变原判定。
 */
BOOLEAN
IoaConfirmReflectiveLoading(
    _In_ ULONG TargetProcessId,
    _In_ ULONG_PTR StartRoutine
    );

/*
 * IoaConfirmThreadHijacking — 线程劫持定向确认 (T1055.003)。
 * 对齐 ShadowStrike ValidateThreadInternal + CalculateRiskScore:
 *   分类器/时序确认 (阶段4.5b) 判出劫持候选后, 读取目标线程上下文定向验证:
 *     RIP 无背衬 / 栈翻转 / 段异常 / 调试寄存器 / RWX (WptValidateThread,
 *     含 WoW64 / TEB 栈边界 / 壳码)。
 * 不可验证时返回 FALSE, 不改变原判定, 不引入误报。
 * ※ 死代码: 供阶段4.5b 闭合深化与 IoaAnalyzeProcessInjection Step2 接线,
 *   当前无调用者。
 */
BOOLEAN
IoaConfirmThreadHijacking(
    _In_ ULONG   TargetProcessId,
    _In_ ULONG   TargetTid,
    _In_ BOOLEAN CrossProcess
    );

/*
 * IoaCheckAtomBombing — 原子炸弹主动查询 (T1055.009)。
 * 移植自 ShadowStrike ProcessInjectionDetector::CheckAtomBombing。
 * 判断一次 APC 队列 (ApcRoutine 命中原子检索 API + 全局表存在可疑原子)
 * 是否构成 AtomBombing。供 UI/主动查询/紧急分析接线 (当前无调用者)。
 */
BOOLEAN
IoaCheckAtomBombing(
    _In_ ULONG_PTR ApcRoutine
    );

/**************************************************/
/*      SS InjectionDetector.c 迁移补充 (2026-08)    */
/*                                                  */
/*  功能面全量对齐 ShadowStrike 内核版                 */
/*  InjectionDetector.c (操作追踪+链关联+技术判定):   */
/*  单操作即时嫌疑分 / 次级注入技术判定 / 统计与查询。  */
/*  均为死代码 (无调用者), 数据源缺失标注见实现。      */
/**************************************************/

/*
 * 操作类型枚举 (对齐 SS INJ_OPERATION_TYPE, InjectionDetector.h:145-161)。
 */
typedef enum _IOA_INJ_OP {
    IoaInjOp_None = 0,
    IoaInjOp_Allocate,      /* NtAllocateVirtualMemory */
    IoaInjOp_Write,         /* NtWriteVirtualMemory */
    IoaInjOp_Protect,       /* NtProtectVirtualMemory */
    IoaInjOp_MapSection,    /* NtMapViewOfSection */
    IoaInjOp_CreateThread,  /* NtCreateThreadEx */
    IoaInjOp_SetContext,    /* NtSetContextThread */
    IoaInjOp_QueueApc,      /* NtQueueApcThread */
    IoaInjOp_Suspend,       /* NtSuspendThread */
    IoaInjOp_Resume,        /* NtResumeThread */
} IOA_INJ_OP, *PIOA_INJ_OP;

/*
 * 注入检测统计 (对齐 SS INJ_STATISTICS, InjectionDetector.h:421-430)。
 * ※ 死代码: wkd 无操作哈希表/链/阻断通道, 无对应计数置 0 留位。
 */
typedef struct _WKD_INJECTION_STATISTICS {
    ULONG64 TotalInjectionCalls;   /* 阶段4.5 IoaClassifyInjection 调用次数 */
    ULONG64 DetectedInjections;    /* 判定出注入类型 (非 Unknown) 的调用次数 */
    ULONG64 BlockedInjections;     /* wkd 无阻断通道 → 恒 0 (SS 留位) */
    ULONG64 DroppedOperations;     /* wkd 无操作追踪上限 → 恒 0 (SS 留位) */
    ULONG64 ChainsCreated;         /* wkd 无链 → 恒 0 (SS 留位) */
    ULONG64 ActiveInjectionPairs;  /* 活跃注入对 (需 PairManager 全量遍历 API, 恒 0) */
    ULONG64 ActiveOperations;      /* 无操作表 → 恒 0 (SS 留位) */
    ULONG   UptimeSeconds;         /* 分类器运行时长 */
} WKD_INJECTION_STATISTICS, *PWKD_INJECTION_STATISTICS;

/*
 * 注入链信息 (对齐 SS INJ_CHAIN, InjectionDetector.h:216-257)。
 * ※ 死代码: SS 链键为 (SrcPid,TgtPid), wkd 进程对键为 (SrcNodeId,TgtNodeId)
 *   GUID; SS 链 5s 滑窗/32 操作上限由 wkd 进程对 60s TTL + 边衰减承担。
 */
typedef struct _WKD_INJECTION_CHAIN_INFO {
    GUID                SrcNodeId;
    GUID                TgtNodeId;
    ULONG64             DataBitmap64;    /* 数据层位图 (SS 操作模式位图对应物) */
    ULONG64             SemBitmap64;     /* 语义层位图 */
    ULONG               TotalEventCount; /* 边事件累计 (SS Chain->OperationCount 对应物) */
    WKD_INJECTION_TYPE  DetectedTechnique;
    ULONG               ConfidenceScore;
    ULONG               RiskScore;
} WKD_INJECTION_CHAIN_INFO, *PWKD_INJECTION_CHAIN_INFO;

/*
 * IoaCalcOperationSuspicion — 单操作即时嫌疑分 (对齐 SS InjRecordOperation)。
 * ※ 死代码: 当前驱动不逐操作上送内存/APC syscall 参数解析, 无调用者。
 */
ULONG
IoaCalcOperationSuspicion(
    _In_ BOOLEAN IsRemote,
    _In_ ULONG Protection,
    _In_ IOA_INJ_OP OpType
    );

/*
 * IoaClassifySecondaryInjection — 次级注入技术判定 (SS 纸面技术补齐)。
 * ※ 死代码: 各技术数据源缺失, 恒返回 Unknown, 无调用者。
 */
WKD_INJECTION_TYPE
IoaClassifySecondaryInjection(
    _In_ ULONG64 DataDword,
    _In_ ULONG BehaviorFlags,
    _In_ ULONG MemoryProtection
    );

/*
 * IoaGetInjectionStatistics — 注入检测统计 (对齐 SS InjGetStatistics)。
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaGetInjectionStatistics(
    _Out_ PWKD_INJECTION_STATISTICS Stats
    );

/*
 * IoaQueryInjectionChain — 进程对注入链查询 (对齐 SS InjGetChainInfo)。
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaQueryInjectionChain(
    _In_ PAE_PROCESS_PAIR PairCtx,
    _Out_ PWKD_INJECTION_CHAIN_INFO Info
    );

/*
 * SS 操作模式位输入 (对齐 SS INJ_PATTERN_* 8 位 + INJ_CHAIN_FLAG_*,
 * InjectionDetector.c:92-99/216-257)。
 * 供 IoaClassifyBySsOperationPattern 输入 (死代码)。
 */
typedef struct _IOA_SS_OP_PATTERN {
    BOOLEAN HasAllocate;       /* NtAllocateVirtualMemory */
    BOOLEAN HasWrite;          /* NtWriteVirtualMemory */
    BOOLEAN HasProtect;        /* NtProtectVirtualMemory */
    BOOLEAN HasMapSection;     /* NtMapViewOfSection */
    BOOLEAN HasCreateThread;   /* NtCreateThreadEx (远程) */
    BOOLEAN HasQueueApc;       /* NtQueueApcThread (远程) */
    BOOLEAN HasSetContext;     /* NtSetContextThread */
    BOOLEAN HasSuspendResume;  /* NtSuspendThread/NtResumeThread (跨进程) */
    BOOLEAN HasExecProtect;    /* INJ_CHAIN_FLAG_HAS_EXECUTE: 链内含可执行保护 */
    BOOLEAN HasTransacted;     /* INJ_CHAIN_FLAG_TRANSACTED: 事务化 (Doppelgang) */
} IOA_SS_OP_PATTERN, *PIOA_SS_OP_PATTERN;

/*
 * IoaDetectInjectionAtRegion — 地址区域定向注入检测 (对齐 SS InjDetectInjection,
 * InjectionDetector.c:1099-1224)。
 * ※ 死代码: 无调用者。见实现注释。
 */
NTSTATUS
IoaDetectInjectionAtRegion(
    _In_ PWKD_PROCESS Node,
    _In_ ULONG_PTR TargetAddress,
    _In_ SIZE_T Size,
    _Out_opt_ PWKD_INJECTION_TYPE Type,
    _Out_opt_ PULONG Confidence
    );

/*
 * IoaClearInjectionChain — 清进程对注入语义位 (对齐 SS InjClearChain,
 * InjectionDetector.c:1542-1595)。
 * ※ 死代码: 无调用者。InjClearAllChains 需 PairManager 全量遍历 API, 不提供。
 */
NTSTATUS
IoaClearInjectionChain(
    _In_ PAE_PROCESS_PAIR PairCtx
    );

/*
 * IoaClassifyBySsOperationPattern — SS 操作模式位→技术判定 (对齐 SS
 * InjpCalculateOperationPatterns + InjpMatchPatternToTechnique, InjectionDetector.c:
 * 2148-2299 完整逻辑保留)。
 * ※ 死代码: 无调用者。见实现注释。
 */
WKD_INJECTION_TYPE
IoaClassifyBySsOperationPattern(
    _In_ const IOA_SS_OP_PATTERN* Pat
    );

/**************************************************/
/*      Section 共享映射聚合表（SectionTracker 迁移） */
/*                                                  */
/*  SS SectionTracker.c 对象级追踪表功能面落 agent   */
/*  （用户确认决策：agent 侧死代码表 + 融合本分类器）。*/
/*  以 SectionObject（内核对象指针）为键聚合「创建→   */
/*  跨进程映射」生命周期：                           */
/*    - Create（WkdEvent_SectionCreate）：建条目      */
/*    - Map（WkdEvent_MapViewOfSection）：挂映射记录  */
/*    - CrossProcessMapCount / RemoteMap 三方判定    */
/*  查询 API 对齐 SS SecGetCrossProcessMaps /        */
/*  SecIsCrossProcessMapped / SecGetSectionInfo。   */
/*  ※ 死代码: 依赖驱动 SmInitialize 启用 + IoaObserve */
/*    阶段4.12 接线（g_IoaSectionSharingEnabled 门控）。*/
/**************************************************/

#define IOA_SECTION_HASH_BUCKETS      1024   /* 对齐 SS SEC_HASH_BUCKET_COUNT */
#define IOA_SECTION_MAX_TRACKED       8192   /* 对齐 SS SEC_MAX_TRACKED_SECTIONS */
#define IOA_SECTION_MAX_MAPS_PER_SEC  256    /* 对齐 SS SEC_MAX_MAPS_PER_SECTION */
#define IOA_SECTION_STALE_100NS       (300LL * 10000000LL)  /* 5min，对齐 SS SEC_STALE_THRESHOLD_100NS */

/* 单条映射记录（对齐 SS SEC_MAP_ENTRY 快照语义） */
typedef struct _IOA_SECTION_MAP_RECORD {
    HANDLE              ProcessId;          /* 映射进程 */
    ULONG64             ViewBase;
    ULONG64             ViewSize;
    ULONG               Protection;
    LARGE_INTEGER       MapTime;
    LIST_ENTRY          ListEntry;
} IOA_SECTION_MAP_RECORD, *PIOA_SECTION_MAP_RECORD;

/* Section 条目（对齐 SS SECTION_ENTRY） */
typedef struct _IOA_SECTION_ENTRY {
    ULONG64             SectionObject;      /* 内核对象指针（键） */
    ULONG               SectionId;          /* 自增 ID（对齐 SS SectionId，SecGetSectionById 用） */
    HANDLE              CreatorProcessId;
    ULONG64             MaximumSize;
    ULONG               SectionType;        /* 0=数据 1=SEC_IMAGE */
    ULONG               IsAnonymous;
    ULONG               SuspicionFlags;     /* WKD_SEC_SUSPICION_* */
    ULONG               SuspicionScore;     /* SS 权重和 */
    WCHAR               FileName[260];      /* 后备文件名（预留，对齐 SS BackingFile.FileName；
                                             * 数据源缺失：驱动 Section Create 不上送路径，恒空，
                                             * 接入后激活 IoaFindSectionByFile） */
    LIST_ENTRY          MapList;            /* IOA_SECTION_MAP_RECORD */
    LONG                TotalMapCount;      /* 历史累计（对齐 SS MapCount） */
    LONG                CrossProcessMapCount;
    LONG                ActiveMapCount;
    LARGE_INTEGER       CreateTime;
    LARGE_INTEGER       LastMapTime;
    LIST_ENTRY          HashEntry;
} IOA_SECTION_ENTRY, *PIOA_SECTION_ENTRY;

/* Section 快照（对齐 SS SEC_SECTION_INFO） */
typedef struct _IOA_SECTION_INFO {
    ULONG64             SectionObject;
    ULONG               SectionId;
    HANDLE              CreatorProcessId;
    ULONG64             MaximumSize;
    ULONG               SectionType;
    ULONG               IsAnonymous;
    ULONG               SuspicionFlags;
    ULONG               SuspicionScore;
    LONG                MapCount;
    LONG                CrossProcessMapCount;
    LARGE_INTEGER       CreateTime;
    LARGE_INTEGER       LastMapTime;
} IOA_SECTION_INFO, *PIOA_SECTION_INFO;

/* 映射快照（对齐 SS SEC_MAP_INFO） */
typedef struct _IOA_SECTION_MAP_INFO {
    HANDLE              ProcessId;
    ULONG64             ViewBase;
    ULONG64             ViewSize;
    ULONG               Protection;
    LARGE_INTEGER       MapTime;
} IOA_SECTION_MAP_INFO, *PIOA_SECTION_MAP_INFO;

/*
 * IoaSectionTrackCreate — 记录 Section 创建（WkdEvent_SectionCreate 消费）。
 * 对齐 SS SecTrackSectionCreate。SectionObject==0 时忽略（创建失败无对象）。
 */
NTSTATUS
IoaSectionTrackCreate(
    _In_ PEVENT_PAYLOAD_SECTION_CREATE Payload
    );

/*
 * IoaSectionTrackMap — 记录一次映射（WkdEvent_MapViewOfSection 消费，Origin=1）。
 * 对齐 SS SecTrackSectionMap。SectionObject==0 时无聚合键，忽略。
 * 跨进程（Source≠Target）→ CrossProcessMapCount++；RemoteMap 由
 * IoaSectionIsRemoteMapped 即时判定（映射进程≠Creator≠当前进程）。
 */
NTSTATUS
IoaSectionTrackMap(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 SectionObject,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 RegionSize,
    _In_ ULONG Protection
    );

/*
 * IoaSectionTrackUnmap — 记录解除映射（WkdEvent_UnmapViewOfSection 消费，Origin=2）。
 * 对齐 SS SecTrackSectionUnmap。按 (ProcessId, ViewBase) 匹配标记 IsMapped=FALSE。
 */
NTSTATUS
IoaSectionTrackUnmap(
    _In_ HANDLE ProcessId,
    _In_ ULONG64 ViewBase
    );

/*
 * IoaGetCrossProcessSections — 查询某 Section 的全部跨进程映射（对齐 SS
 * SecGetCrossProcessMaps）。返回映射快照数组（排除 Creator 自身映射）。
 */
NTSTATUS
IoaGetCrossProcessSections(
    _In_ ULONG64 SectionObject,
    _Out_writes_to_(MaxMaps, *MapCount) PIOA_SECTION_MAP_INFO Maps,
    _In_ ULONG MaxMaps,
    _Out_ PULONG MapCount
    );

/*
 * IoaIsSectionCrossProcessMapped — 某 Section 是否被跨进程映射（对齐 SS
 * SecIsCrossProcessMapped）。
 */
BOOLEAN
IoaIsSectionCrossProcessMapped(
    _In_ ULONG64 SectionObject,
    _Out_opt_ PULONG ProcessCount
    );

/*
 * IoaSectionIsRemoteMapped — RemoteMap 三方判定：映射进程 ≠ Creator 且 ≠ 当前
 * 进程（第三进程映射，对齐 SS SecSuspicion_RemoteMap 120 分语义）。
 */
BOOLEAN
IoaSectionIsRemoteMapped(
    _In_ ULONG64 SectionObject,
    _In_ HANDLE CurrentProcessId,
    _Out_opt_ PHANDLE RemoteProcessId
    );

/*
 * IoaGetSectionInfo — 查询 Section 快照（对齐 SS SecGetSectionInfo 子集）。
 */
NTSTATUS
IoaGetSectionInfo(
    _In_ ULONG64 SectionObject,
    _Out_ PIOA_SECTION_INFO Info
    );

/*
 * IoaSectionCleanupExpired — 清理过期（5min 无活跃映射）条目（对齐 SS
 * SecpCleanupTimerCallback）。由外部周期调用（死代码），接入后挂 agent 维护线程。
 */
VOID
IoaSectionCleanupExpired(
    VOID
    );

/*
 * IoaGetSectionById — 按 SectionId 查询（对齐 SS SecGetSectionById）。
 * ※ 死代码: SectionId 为追踪表自增 ID（SectionObject 指针的代理），供 UI/日志引用。
 */
NTSTATUS
IoaGetSectionById(
    _In_ ULONG SectionId,
    _Out_ PIOA_SECTION_INFO Info
    );

/*
 * IoaFindSectionByFile — 按后备文件名查询（对齐 SS SecFindSectionByFile）。
 * ※ 死代码: 数据源缺失——驱动 Section Create 不上送 FilePath，IOA_SECTION_ENTRY.
 *   FileName 恒空 → 恒 STATUS_NOT_FOUND。接入前提: 驱动在 Section Create body
 *   补 FilePath 上送 + TrackCreate 填充 FileName。
 */
NTSTATUS
IoaFindSectionByFile(
    _In_ PCWSTR FileName,
    _Out_ PIOA_SECTION_INFO Info
    );

/*
 * IoaGetSuspiciousSections — 按 MinScore 过滤返回可疑 Section 列表（对齐 SS
 * SecGetSuspiciousSections）。遍历全表，SuspicionScore>=MinScore 的条目填快照。
 * ※ 死代码: 供 UI/主动查询。
 */
NTSTATUS
IoaGetSuspiciousSections(
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxEntries, *EntryCount) PIOA_SECTION_INFO Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount
    );

/*
 * 聚合表统计（对齐 SS SEC_STATISTICS）。
 */
typedef struct _IOA_SECTION_STATISTICS {
    ULONG               ActiveSections;     /* 活跃条目数 */
    ULONG64             TotalCreated;       /* 历史创建累计 */
    ULONG64             TotalMapped;        /* 历史映射累计 */
    ULONG64             TotalUnmapped;      /* 历史解除映射累计 */
    ULONG64             SuspiciousDetections; /* 创建带可疑标志的条目数 */
    ULONG64             CrossProcessMaps;   /* 历史跨进程映射累计 */
    ULONG64             TransactedDetections; /* TxF 事务检测累计 */
    LARGE_INTEGER       UpTime;             /* 表运行时长 */
} IOA_SECTION_STATISTICS, *PIOA_SECTION_STATISTICS;

/*
 * IoaSectionGetStatistics — 聚合表统计（对齐 SS SecGetStatistics）。
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaSectionGetStatistics(
    _Out_ PIOA_SECTION_STATISTICS Stats
    );
