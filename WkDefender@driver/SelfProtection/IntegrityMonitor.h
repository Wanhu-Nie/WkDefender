/*++
    SelfProtection/IntegrityMonitor.h - 驱动自我完整性监控（IntegrityMonitor, IM）子组件

    Purpose:
        监控驱动自身内核映像的完整性，检测 Rootkit/恶意软件对本驱动的
        PE 头、代码节、只读数据节的恶意篡改（内存补丁：IAT/导出钩子、
        代码补丁、数据损坏、头篡改），记录为事件并上报
        （经 WkdReportSelfProtectionEvent -> ALPC 到 Agent）。

        Baseline-and-verify 模型：启动阶段为驱动自身内存映像建立
        SHA-256 基线（代码节/只读数据节/PE 头），周期任务重新哈希比对，
        发现偏离即判定为篡改。

    架构（对齐自防护引擎铁律）:
        - 本组件【不持有】也不获取 EX_RUNDOWN_REF / 生命周期标志；
          生命周期由自防护引擎（SelfProtectionEngine）统一编排。
        - 周期校验采用 Common/PeriodicTimer.h 的 Thread 模式
          （PASSIVE_LEVEL 回调），不在本组件内自建系统线程。
        - 不对外暴露用户态回调注册；检测结果统一经上报事件通道发送。
        - 事件以值类型 IM_EVENT_INFO 快照返回给调用方（不暴露内部指针）。

    PE 解析复用（重要）:
        - 本组件【不】自实现 PE 解析器，而是复用 Common/PeParser.h 的
          公共模板 CoParsePe，通过注册 OnSection 回调采集逐节信息，
          在启动阶段一次性构建基线。
        - 基线基于【内存映像】（驱动已加载的内核地址，经 WkdDriverObject
          获取），而非磁盘文件。

    SHA-256 / 安全读取 / 上报复用:
        - CoComputeSha256      （Common/BCryptUtils.h，经 SelfProtectionCompat 透传）计算哈希
        - CoReadKernelRegionSafe     （SelfProtectionCompat）安全读取内核节内存
        - WkdReportSelfProtectionEvent（SelfProtectionCompat）事件上报

    对外 API 生命周期：
        SpInitializeIntegrityProtection -> SpStartPeriodicIntegrityProtection -> ...(周期校验/查询 API)... -> ImShutdown

    上报（IRQL 约束）:
        WkdReportSelfProtectionEvent 要求 PASSIVE_LEVEL，周期校验运行于
        PASSIVE_LEVEL（Thread 模式）可直接调用；潜在高 IRQL 路径需先做
        KeGetCurrentIrql() > PASSIVE_LEVEL 门控。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量
 * ============================================================================ */

#define IM_POOL_TAG_CTX    'cMNI'   /* WKD_INTEGRITY_PROTECTION context */
#define IM_POOL_TAG_EVENT  'eMNI'   /* 内部 IM_EVENT 节点 */
#define IM_POOL_TAG_SECT   'sMNI'   /* 节基线数组/哈希临时缓冲 */

#define IM_MAX_SECTIONS        96      /* 驱动节数上限（对齐 PeParser 96） */
#define IM_MAX_EVENTS          1024    /* 内部事件链表上限硬顶 */
#define IM_CHECK_INTERVAL_MS   30000   /* 周期校验间隔（毫秒，Thread 模式） */
#define IM_MAX_DETAIL_LENGTH   256     /* 详情窄字符上限 */
#define IM_MAX_PROCESS_NAME    260     /* 进程名宽字符上限 */

//
// 上报事件子类型（编排到 WkdReportSelfProtectionEvent 的 EventSubType）。
// 0x5020 段预留给 IM；各检测类型一个固定子类型 + 独立严重度。
//
#define IM_EVENT_SUBTYPE_CODE_SECTION   0x5020   /* 代码节篡改（IAT/导出钩子/代码补丁） */
#define IM_EVENT_SUBTYPE_DATA_SECTION   0x5021   /* 只读数据节篡改 */
#define IM_EVENT_SUBTYPE_HEADER_TAMPER  0x5022   /* PE 头篡改 */

/* ============================================================================
 * 修改类型
 * ============================================================================ */

typedef enum _IM_MODIFICATION {
    ImMod_None = 0,
    ImMod_CodePatch,        /* 代码节补丁（非 IAT/导出区域） */
    ImMod_ImportHook,       /* 导入目录所在节被改（IAT 钩子） */
    ImMod_ExportHook,       /* 导出目录所在节被改（导出钩子） */
    ImMod_HeaderTamper,     /* PE 头被改 */
    ImMod_DataCorruption,   /* 只读数据节被改 */
    ImMod_Max
} IM_MODIFICATION, *PIM_MODIFICATION;

/* ============================================================================
 * 事件快照（返回给调用方，自包含值类型）
 * ============================================================================ */

typedef struct _IM_EVENT_INFO {
    IM_MODIFICATION     Modification;   /* 修改类型 */
    ULONG               SectionIndex;   /* 受影响节索引（头篡改为 0xFFFFFFFF） */
    CHAR                SectionName[8]; /* 受影响节名（头篡改时为空） */
    WCHAR               ProcessName[IM_MAX_PROCESS_NAME];
    USHORT              ProcessNameLength;      /* 字符数，非字节 */
    CHAR                Details[IM_MAX_DETAIL_LENGTH];
    LARGE_INTEGER       Timestamp;
} IM_EVENT_INFO, *PIM_EVENT_INFO;

/* ============================================================================
 * 统计
 * ============================================================================ */

typedef struct _IM_STATISTICS {
    volatile LONG64     TotalChecks;        /* 累计校验次数 */
    volatile LONG64     TotalViolations;    /* 累计篡改次数 */
    volatile LONG64     ReportInvocations;  /* 累计上报次数 */
    LONG                CurrentEventCount;  /* 当前事件数 */
    ULONG               CodeSectionCount;   /* 受监控代码节数 */
    ULONG               DataSectionCount;   /* 受监控数据节数 */
    LARGE_INTEGER       LastCheckTime;
    LARGE_INTEGER       StartTime;
} IM_STATISTICS, *PIM_STATISTICS;

/* ============================================================================
 * 保护器上下文（不透明句柄，结构定义在 IntegrityMonitor.c）
 * ============================================================================ */

typedef struct _WKD_INTEGRITY_PROTECTION WKD_INTEGRITY_PROTECTION, *PWKD_INTEGRITY_PROTECTION;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化自保护（建立上下文、登记代码节，尚未启动）。
// EngineRundown: 注入的自防护引擎 EX_RUNDOWN_REF（必传，周期线程据此判活）
// 为代码/只读数据节与 PE 头建立 SHA-256 基线。尚未启动周期校验。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpInitializeIntegrityProtection(
    _Out_ PWKD_INTEGRITY_PROTECTION* Protector
    );

//
// 启动周期完整性校验（创建并启动 Thread 模式周期定时器）。
// 须在 SpInitializeIntegrityProtection 之后调用。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpStartPeriodicIntegrityProtection(
    _In_ PWKD_INTEGRITY_PROTECTION Protection,
    _In_ const PEX_RUNDOWN_REF RundownRef,
    _In_ ULONG IntervalMs
    );

//
// 关闭 IM 子组件（停止周期定时器、清空并释放事件与节基线、释放上下文）。
// NULL 安全。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ImShutdown(
    _In_ _Post_invalid_ PWKD_INTEGRITY_PROTECTION Protector
    );

//
// 按需校验单个组件完整性。
// Stage: 0 = 代码节，1 = 数据节，2 = PE 头，>= ImStage_Max 返回无效参数。
// 运行环境: PASSIVE_LEVEL
//
#define IM_STAGE_CODE_SECTIONS  0
#define IM_STAGE_DATA_SECTIONS  1
#define IM_STAGE_HEADER         2
#define IM_STAGE_MAX            3

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImCheckIntegrity(
    _In_ PWKD_INTEGRITY_PROTECTION Protector,
    _In_ ULONG Stage,
    _Out_ PBOOLEAN IsIntact,
    _Out_ PIM_MODIFICATION ModificationType
    );

//
// 全量校验所有组件，任一不完整即 AllIntact = FALSE。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImCheckAll(
    _In_ PWKD_INTEGRITY_PROTECTION Protector,
    _Out_ PBOOLEAN AllIntact
    );

//
// 取事件数组的值类型快照（最多 MaxEvents 条）。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImGetEvents(
    _In_ PWKD_INTEGRITY_PROTECTION Protector,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PIM_EVENT_INFO EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    );

//
// 取完整性校验统计快照。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImGetStatistics(
    _In_ PWKD_INTEGRITY_PROTECTION Protector,
    _Out_ PIM_STATISTICS Stats
    );

//
// 清空并释放全部事件。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImClearEvents(
    _In_ PWKD_INTEGRITY_PROTECTION Protector
    );

#ifdef __cplusplus
}
#endif
