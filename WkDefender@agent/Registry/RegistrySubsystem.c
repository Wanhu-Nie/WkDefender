/**************************************************/
/*  WkDefender Agent — Registry 子系统【门面】      */
/*                                                  */
/*  职责：                                          */
/*   - 实现 Registry.h 声明的 WkdRegistry_* 全套     */
/*     公共接口（此前仅有声明、无实现）               */
/*   - 聚合编排五引擎：                             */
/*       PersistenceDetector  (PD) 持久化检测       */
/*       SystemSettingsMonitor (SSM) 系统设置监控   */
/*       RegistryAnalyzer     (RA) 注册表取证分析   */
/*       RegistryMonitor      (RM) 注册表实时裁决   */
/*       StartupAnalyzer      (SA) 启动项审计       */
/*   - 将各引擎告警/事件/变更统一转译为              */
/*     WKD_REG_NOTIFY 文本行载荷（Notify 桥），      */
/*     经单槽位回调上报，不暴露任何引擎私有结构       */
/*                                                  */
/*  依赖：RegistryInternal.h（公共门面段 + 五引擎内部  */
/*        API；2026-09-15 公共头 Registry.h 并入）    */
/*                                                  */
/*  迁移来源：SS ShadowStrike Core/Registry 总装     */
/*  门面（原 C++ RegistryManager + 观察者桥），      */
/*  2026-09-09 以纯 C 转写                           */
/*                                                  */
/*  并发模型：                                      */
/*   - 单例静态状态 g_Reg；CRITICAL_SECTION 保护     */
/*     Notify 槽与扫描线程句柄                       */
/*   - 扫描/分析在途 Busy 位（CAS 0→1）+ ManualReset  */
/*     释放事件：起始扫描抢占式（抢不到放弃），手动  */
/*     Trigger 排队式（BusyReleasedEvent 等待,       */
/*     ShuttingDown/Initialized 双查退出）           */
/*   - 引擎回调桥一律在引擎/扫描线程同步执行，        */
/*     回调内禁止阻塞（对齐 Registry.h 约束）        */
/**************************************************/

#include "RegistryInternal.h"
#include <strsafe.h>
#include <stdlib.h>

/* NT_SUCCESS 兜底（用户态不可 include ntdef.h——结构与 winnt.h 冲突；
 * 与 RegistryInternal.h 的 STATUS_NOT_INITIALIZED 兜底惯例一致） */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* ==================================================
 * 本地常量
 * ================================================== */
#define REG_SCAN_STARTUP_THREAD_WAIT_MS   30000   /* Shutdown 等待异步扫描线程上限 */

/* ==================================================
 * 子系统状态（单例，跨引擎回调共享）
 * ================================================== */
typedef struct _WKD_REG_SUBSYSTEM_STATE {
    /* 生命周期标志（volatile，原子读写） */
    volatile LONG        Initialized;          /* Initialize 完成 */
    volatile LONG        Started;              /* Start 完成（回调管线已挂载） */
    volatile LONG        ShuttingDown;         /* Shutdown 在途（桥早退护栏） */
    volatile LONG        Busy;                 /* 有扫描/分析在途（CAS 0→1，防并发扫描） */
    volatile ULONG       LastError;            /* 最近一次 NTSTATUS 码 */
    volatile LONGLONG    LastActivityTime;     /* FILETIME 语义 */

    /* 引擎启用位（Initialize 时定型） */
    BOOLEAN              EnablePd;
    BOOLEAN              EnableSsm;
    BOOLEAN              EnableRa;
    BOOLEAN              EnableRm;
    BOOLEAN              EnableSa;
    BOOLEAN              EnableStartupScan;

    /* Notify 单槽（g_RegLock 保护；重复注册覆盖） */
    PFN_WKD_REG_NOTIFY_CALLBACK NotifyCallback;
    PVOID                        NotifyContext;

    /* 引擎桥回调注册 id 槽（Shutdown 时按 id 精确注销） */
    ULONG                PdAlertId;            /* PD 告警桥 */
    ULONG                RaAnomalyId;          /* RA 异常桥 */
    ULONG                RmEventId;            /* RM 事件桥 */
    ULONG                RmAlertId;            /* RM 告警桥 */
    ULONG                SaNewItemId;          /* SA 新项桥 */
    ULONG                SaAlertId;            /* SA 告警桥 */
    ULONG                SaChangeId;           /* SA 变更桥 */
    ULONG                SsmChangeId;          /* SSM 变更桥 */
    ULONG                SsmAlertId;           /* SSM 告警桥 */
    ULONG                SsmComplianceId;      /* SSM 合规桥 */

    /* 起始异步扫描线程（ScanOnStartup 时创建；Shutdown 等待） */
    HANDLE               StartupScanThread;

    /* Busy 释放事件（ManualReset: Busy==0 时置位；排队的
     * Trigger 线程在此等待；Shutdown 置 ShuttingDown 后排空） */
    HANDLE               BusyReleasedEvent;
} WKD_REG_SUBSYSTEM_STATE;

/* 全局单例状态与槽保护锁 */
static WKD_REG_SUBSYSTEM_STATE g_Reg;
static CRITICAL_SECTION g_RegLock;
static BOOLEAN           g_RegLockInited = FALSE;

/* ==================================================
 * 工具函数
 * ================================================== */

/*++ 当前 FILETIME 时间（100ns 间隔） --*/
static ULONGLONG
RgTimestampNow(
    VOID
    )
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

/*++ 记录最后活动时间 --*/
static VOID
RgTouch(
    VOID
    )
{
    InterlockedExchange64(&g_Reg.LastActivityTime, (LONGLONG)RgTimestampNow());
}

/*++ 记录最近错误码 --*/
static VOID
RgSetLastError(
    _In_ NTSTATUS Status
    )
{
    InterlockedExchange((volatile LONG*)&g_Reg.LastError, (LONG)Status);
}

/*++ 严重度钳位到 [0,4]，对齐引擎风险等级语义 --*/
static ULONG
RgClampSeverity(
    _In_ ULONG Severity
    )
{
    return (Severity > 4) ? 4 : Severity;
}

/*++ 严重度 → 事件类别：
 *    >=3 High/Critical/Malicious → Malicious
 *    >=2 Medium/Suspicious       → Suspicious
 *    其余                        → Entry
 * --*/
static ULONG
RgKindFromSeverity(
    _In_ ULONG Severity
    )
{
    if (Severity >= 3) {
        return WkdRegEvent_Malicious;
    }
    if (Severity >= 2) {
        return WkdRegEvent_Suspicious;
    }
    return WkdRegEvent_Entry;
}

/*++ RM 判定 → 事件类别（裁决链的对外呈现） --*/
static ULONG
RgKindFromVerdict(
    _In_ WKD_RM_VERDICT Verdict
    )
{
    switch (Verdict) {
    case WkdRmVerdict_Block:
        return WkdRegEvent_Blocked;
    case WkdRmVerdict_Redirect:
    case WkdRmVerdict_Alert:
        return WkdRegEvent_Suspicious;
    case WkdRmVerdict_Allow:
    case WkdRmVerdict_SilentDrop:
    case WkdRmVerdict_Delay:
    default:
        return WkdRegEvent_Info;
    }
}

/*++ RM 判定 → 严重度：
 *    Block=Critical(4) Redirect=High(3) Alert=Suspicious(2)
 *    Delay=Low(1) Allow/SilentDrop=Safe(0)
 * --*/
static ULONG
RgSeverityFromVerdict(
    _In_ WKD_RM_VERDICT Verdict
    )
{
    switch (Verdict) {
    case WkdRmVerdict_Block:      return 4;
    case WkdRmVerdict_Redirect:   return 3;
    case WkdRmVerdict_Alert:      return 2;
    case WkdRmVerdict_Delay:      return 1;
    case WkdRmVerdict_Allow:
    case WkdRmVerdict_SilentDrop:
    default:                      return 0;
    }
}

/*++ RM 操作码 → 窄文本（用于 Notify 描述/字段） --*/
static PCSTR
RgRmOperationName(
    _In_ ULONG Operation
    )
{
    switch (Operation) {
    case WkdRmOp_Unknown:          return "Unknown";
    case WkdRmOp_CreateKey:        return "CreateKey";
    case WkdRmOp_OpenKey:          return "OpenKey";
    case WkdRmOp_DeleteKey:        return "DeleteKey";
    case WkdRmOp_RenameKey:        return "RenameKey";
    case WkdRmOp_CloseKey:         return "CloseKey";
    case WkdRmOp_SetValue:         return "SetValue";
    case WkdRmOp_DeleteValue:      return "DeleteValue";
    case WkdRmOp_QueryValue:       return "QueryValue";
    case WkdRmOp_EnumerateValue:   return "EnumerateValue";
    case WkdRmOp_LoadKey:          return "LoadKey";
    case WkdRmOp_UnloadKey:        return "UnloadKey";
    case WkdRmOp_SaveKey:          return "SaveKey";
    case WkdRmOp_RestoreKey:       return "RestoreKey";
    case WkdRmOp_ReplaceKey:       return "ReplaceKey";
    case WkdRmOp_SetKeySecurity:   return "SetKeySecurity";
    case WkdRmOp_QueryKeySecurity: return "QueryKeySecurity";
    case WkdRmOp_CreateTransaction:return "CreateTransaction";
    case WkdRmOp_CommitTransaction:return "CommitTransaction";
    case WkdRmOp_RollbackTransaction:return "RollbackTransaction";
    default:                       return "Op";
    }
}

/* ==================================================
 * Notify 发射器
 * 统一构造 WKD_REG_NOTIFY 并经单槽位回调分发。
 * ================================================== */

/*++ 原始分发：锁槽 + 锁外回调（无生命周期护栏）。
 *   供 RgDispatchNotify（正常路径）与 Shutdown 收尾
 *   （ShuttingDown 已置位仍须发出关闭通知）使用。 --*/
static VOID
RgDispatchNotifyRaw(
    _In_ PWKD_REG_NOTIFY Notify
    )
{
    PFN_WKD_REG_NOTIFY_CALLBACK cb;
    PVOID                       ctx;

    if (Notify->Timestamp == 0) {
        Notify->Timestamp = RgTimestampNow();
    }
    RgTouch();

    EnterCriticalSection(&g_RegLock);
    cb = g_Reg.NotifyCallback;
    ctx = g_Reg.NotifyContext;
    LeaveCriticalSection(&g_RegLock);

    if (cb != NULL) {
        cb(Notify, ctx);
    }
}

/*++ 读取 Notify 槽并回调（锁外调用用户回调，防注销/覆盖竞态） --*/
static VOID
RgDispatchNotify(
    _In_ PWKD_REG_NOTIFY Notify
    )
{
    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;                     /* 未初始化或正在关闭，早退 */
    }

    RgDispatchNotifyRaw(Notify);
}

/*++ 通用发射器：参数化打包 Notify 载荷 --*/
static VOID
RgEmitNotify(
    _In_ ULONG Engine,
    _In_ ULONG EventKind,
    _In_ ULONG Severity,
    _In_ ULONG EntryType,
    _In_ PCWSTR Title,
    _In_opt_ PCSTR Description,
    _In_opt_ PCSTR MitreTechnique,
    _In_opt_ PCSTR MitreSubTechnique,
    _In_reads_opt_(FieldCount) PCWSTR* Fields,
    _In_ ULONG FieldCount,
    _In_ ULONGLONG Timestamp
    )
{
    WKD_REG_NOTIFY n;
    ULONG          i;
    ULONG          cap;

    ZeroMemory(&n, sizeof(n));
    n.Engine = Engine;
    n.EventKind = EventKind;
    n.Severity = RgClampSeverity(Severity);
    n.EntryType = EntryType;

    StringCchCopyW(n.Title, ARRAYSIZE(n.Title), Title);
    if (Description != NULL) {
        /* 公共结构 Description 为 WCHAR，窄输入经 %hs 宽化 */
        StringCchPrintfW(n.Description, ARRAYSIZE(n.Description), L"%hs", Description);
    }
    if (MitreTechnique != NULL) {
        StringCchCopyA(n.MitreTechnique, ARRAYSIZE(n.MitreTechnique), MitreTechnique);
    }
    if (MitreSubTechnique != NULL) {
        StringCchCopyA(n.MitreSubTechnique, ARRAYSIZE(n.MitreSubTechnique), MitreSubTechnique);
    }

    if (Fields != NULL && FieldCount > 0) {
        cap = (FieldCount > WKD_REG_PUBLIC_MAX_FIELDS)
                  ? WKD_REG_PUBLIC_MAX_FIELDS
                  : FieldCount;
        for (i = 0; i < cap; i++) {
            if (Fields[i] != NULL) {
                StringCchCopyW(n.Fields[i], WKD_REG_PUBLIC_MAX_FIELD_CHARS, Fields[i]);
            }
        }
        n.FieldCount = cap;
    }

    n.Timestamp = (Timestamp != 0) ? Timestamp : RgTimestampNow();
    RgDispatchNotify(&n);
}

/* ==================================================
 * Notify 桥 — 引擎事件 → WKD_REG_NOTIFY 转译
 * 全部为静态回调，注册进各引擎回调槽。
 * 频率控制定性 (#96): 桥为同步直通, 无节流 — 在"回调内禁止
 * 阻塞"的串行契约下, 节流会丢事件或引入延迟, 由下游订阅过滤
 * 按需抑制（RM 事件桥为真实高频源, 属设计特性非缺陷）。
 * ================================================== */

/*--- PD：持久化条目（扫描逐条输出，只桥接可疑+） ---*/

static VOID
RgPdEntryBridge(
    _In_ const WKD_PERSISTENCE_ENTRY* Entry,
    _In_opt_ PVOID Context
    )
{
    PCWSTR  fields[5];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    fields[0] = Entry->Location;
    fields[1] = Entry->EntryName;
    fields[2] = Entry->RawCommand;
    fields[3] = Entry->Publisher;
    fields[4] = Entry->UserName;

    RgEmitNotify(
        WkdRegEngine_PersistenceDetector,
        WkdRegEvent_Entry,
        Entry->Risk,
        Entry->Type,
        L"Persistence Entry",
        NULL,
        (Entry->MitreTechnique[0] != '\0') ? Entry->MitreTechnique : NULL,
        (Entry->MitreSubTechnique[0] != '\0') ? Entry->MitreSubTechnique : NULL,
        fields,
        ARRAYSIZE(fields),
        Entry->LastScanned);
}

/*--- PD：持久化告警（实时分析 / 扫描判定） ---*/

static VOID
RgPdAlertBridge(
    _In_ const WKD_PERSISTENCE_ALERT* Alert,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[4];
    char   desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    /* 描述拼 "说明 @ 位置\\条目"（收紧在公共 160 字符内） */
    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "%hs @ %ls\\%ls",
        Alert->Description,
        Alert->Location,
        Alert->EntryName);

    fields[0] = Alert->Location;
    fields[1] = Alert->EntryName;
    fields[2] = Alert->Command;
    fields[3] = Alert->ProcessPath;

    RgEmitNotify(
        WkdRegEngine_PersistenceDetector,
        RgKindFromSeverity(Alert->Risk),
        Alert->Risk,
        Alert->Type,
        L"Persistence Alert",
        desc,
        NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Alert->Timestamp);
}

/*--- RA：取证异常 ---*/

static VOID
RgRaAnomalyBridge(
    _In_ const WKD_RA_ANOMALY* Anomaly,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[3];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    fields[0] = Anomaly->KeyPath;
    fields[1] = Anomaly->ValueName;
    fields[2] = Anomaly->HivePath;

    RgEmitNotify(
        WkdRegEngine_RegistryAnalyzer,
        RgKindFromSeverity(Anomaly->Severity),
        Anomaly->Severity,
        0,
        L"Registry Anomaly",
        (Anomaly->Description[0] != '\0') ? Anomaly->Description : NULL,
        (Anomaly->Technique[0] != '\0') ? Anomaly->Technique : NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Anomaly->DetectedTime);
}

/*--- RM：注册表访问事件（裁决结果随事件输出） ---*/

static VOID
RgRmEventBridge(
    _In_ const WKD_RM_EVENT* Event,
    _In_ WKD_RM_VERDICT Verdict,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[2];
    char   desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    /* 描述拼 "操作 键路径\\值名 (判定)" */
    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "%hs %ls\\%ls",
        RgRmOperationName(Event->Operation),
        Event->KeyPath,
        Event->ValueName);

    fields[0] = Event->KeyPath;
    fields[1] = Event->ProcessPath;

    RgEmitNotify(
        WkdRegEngine_RegistryMonitor,
        RgKindFromVerdict(Verdict),
        RgSeverityFromVerdict(Verdict),
        0,
        L"Registry Access",
        desc,
        NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Event->Timestamp);
}

/*--- RM：威胁告警 ---*/

static VOID
RgRmAlertBridge(
    _In_ const WKD_RM_ALERT* Alert,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[3];
    char   desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "%hs | %ls\\%ls",
        Alert->Description,
        Alert->KeyPath,
        Alert->ValueName);

    fields[0] = Alert->KeyPath;
    fields[1] = Alert->ValueName;
    fields[2] = Alert->ProcessPath;

    RgEmitNotify(
        WkdRegEngine_RegistryMonitor,
        RgKindFromSeverity(Alert->Risk),
        Alert->Risk,
        0,
        L"Registry Threat Alert",
        desc,
        (Alert->MitreTechnique[0] != '\0') ? Alert->MitreTechnique : NULL,
        (Alert->MitreSubTechnique[0] != '\0') ? Alert->MitreSubTechnique : NULL,
        fields,
        ARRAYSIZE(fields),
        Alert->Timestamp);
}

/*--- SA：新发现启动项 ---*/

static VOID
RgSaNewItemBridge(
    _In_ const WKD_SA_ITEM* Item,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[4];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    fields[0] = Item->Location;
    fields[1] = Item->EntryName;
    fields[2] = Item->Command;
    fields[3] = Item->TargetPath;

    RgEmitNotify(
        WkdRegEngine_StartupAnalyzer,
        WkdRegEvent_Entry,
        Item->RiskScore / 25,   /* 0-100 → 0-4 */
        0,
        L"Startup Item",
        NULL,
        NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Item->CreatedTime);
}

/*--- SA：启动项告警 ---*/

static VOID
RgSaAlertBridge(
    _In_ const WKD_SA_ALERT* Alert,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[2];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    fields[0] = Alert->ItemName;
    fields[1] = Alert->TargetPath;

    RgEmitNotify(
        WkdRegEngine_StartupAnalyzer,
        RgKindFromSeverity(Alert->Severity),
        Alert->Severity,
        0,
        L"Startup Alert",
        (Alert->Description[0] != '\0') ? Alert->Description : NULL,
        NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Alert->Timestamp);
}

/*--- SA：启动项变更 ---*/

static VOID
RgSaChangeBridge(
    _In_ const WKD_SA_CHANGE* Change,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[3];
    char   desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "%hs %ls",
        Change->ChangeType,
        Change->ItemName);

    fields[0] = Change->ItemName;
    fields[1] = Change->ProcessPath;
    fields[2] = (Change->HasBackup) ? L"(backup)" : L"(no backup)";

    RgEmitNotify(
        WkdRegEngine_StartupAnalyzer,
        WkdRegEvent_Info,
        0,
        0,
        L"Startup Change",
        desc,
        NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Change->Timestamp);
}

/*--- SSM：系统设置变更 ---*/

static VOID
RgSsmChangeBridge(
    _In_ const WKD_SSM_CHANGE* Change,
    _In_opt_ PVOID Context
    )
{
    PCWSTR fields[3];
    char   desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    /* 描述拼 "SettingName: previous -> new"（窄缓冲 %ls 转换） */
    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "%ls: %ls -> %ls",
        Change->SettingName,
        Change->PreviousValue,
        Change->NewValue);

    fields[0] = Change->SettingPath;
    fields[1] = Change->PreviousValue;
    fields[2] = Change->NewValue;

    RgEmitNotify(
        WkdRegEngine_SystemSettingsMonitor,
        RgKindFromSeverity(Change->Severity),
        Change->Severity,
        0,
        L"Setting Change",
        desc,
        NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Change->Timestamp);
}

/*--- SSM：安全告警 ---*/

static VOID
RgSsmAlertBridge(
    _In_ const WKD_SSM_ALERT* Alert,
    _In_opt_ PVOID Context
    )
{
    WCHAR  title[WKD_REG_PUBLIC_MAX_TITLE_CHARS];
    PCWSTR fields[3];
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    StringCchPrintfW(title, ARRAYSIZE(title), L"%hs", Alert->Title);

    fields[0] = Alert->SettingPath;
    fields[1] = Alert->PreviousValue;
    fields[2] = Alert->CurrentValue;

    RgEmitNotify(
        WkdRegEngine_SystemSettingsMonitor,
        RgKindFromSeverity(Alert->Severity),
        Alert->Severity,
        0,
        title,
        (Alert->Description[0] != '\0') ? Alert->Description : NULL,
        (Alert->MitreId[0] != '\0') ? Alert->MitreId : NULL,
        NULL,
        fields,
        ARRAYSIZE(fields),
        Alert->Timestamp);
}

/* 合规桥字段暂存区（8×128 WCHAR，文件级静态；
 * 置于函数前避免使用先于定义） */
static WCHAR RgComplianceFieldScratch[WKD_REG_PUBLIC_MAX_FIELDS][WKD_REG_PUBLIC_MAX_FIELD_CHARS];

/*--- SSM：合规状态 ---
 * 输出上限定性 (#96): WKD_SSM_MAX_COMPLIANCE_FAILURES=8 即引擎侧
 * 数据源上限 (实测 ≤4), 门面 min(FieldCount,8) 为全量无损输出,
 * 非档案 #93 所述"截断缺陷" — 无需分批多通知。*/

static VOID
RgSsmComplianceBridge(
    _In_ const WKD_SSM_COMPLIANCE* Status,
    _In_opt_ PVOID Context
    )
{
    char      desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    PCWSTR    fields[WKD_REG_PUBLIC_MAX_FIELDS];
    ULONG     i;
    ULONG     cap;
    (VOID)Context;

    if (g_Reg.Initialized == 0 || g_Reg.ShuttingDown != 0) {
        return;
    }

    /* PCWSTR 数组清零改用循环：ZeroMemory 会触发 C4090
     * （const WCHAR** → void* 的 const 限定符差异） */
    for (i = 0; i < WKD_REG_PUBLIC_MAX_FIELDS; i++) {
        fields[i] = NULL;
    }
    cap = (Status->FailureCount > WKD_REG_PUBLIC_MAX_FIELDS)
              ? WKD_REG_PUBLIC_MAX_FIELDS
              : Status->FailureCount;
    for (i = 0; i < cap; i++) {
        /* 窄→宽直接写入文件级暂存区（独立缓冲，供 Fields 引用） */
        StringCchPrintfW(
            RgComplianceFieldScratch[i],
            WKD_REG_PUBLIC_MAX_FIELD_CHARS,
            L"%hs",
            Status->Failures[i]);
        fields[i] = RgComplianceFieldScratch[i];
    }

    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "Compliance: %lu/%lu checks passed, %lu failed (%lu warnings)",
        Status->PassedChecks,
        Status->TotalChecks,
        Status->FailedChecks,
        Status->Warnings);

    RgEmitNotify(
        WkdRegEngine_SystemSettingsMonitor,
        WkdRegEvent_Info,
        0,
        0,
        (Status->IsCompliant) ? L"Compliance Check: OK" : L"Compliance Check: Failed",
        desc,
        NULL,
        NULL,
        fields,
        cap,
        Status->LastChecked);
}

/* ==================================================
 * 扫描执行器（命令式路径；Busy 位互斥）
 * ================================================== */

/*++ 抢占 Busy 位（非阻塞 0→1 CAS）：
 *   起始扫描线程专用 — 抢不到（手动 Trigger 在途）放弃起始扫描 --*/
static BOOLEAN
RgTryBeginBusy(
    VOID
    )
{
    return (InterlockedCompareExchange(&g_Reg.Busy, 1, 0) == 0) ? TRUE : FALSE;
}

/*++ 排队抢占 Busy 位（阻塞）：
 *   手动 Trigger 线程专用 — 等待 BusyReleasedEvent 置位后抢；
 *   100ms 轮询以观察 ShuttingDown/Initialized（Shutdown 排空窗口对齐）;
 *   关闭中或未初始化一律返回 FALSE 放弃执行 --*/
static BOOLEAN
RgBeginBusyWait(
    VOID
    )
{
    for (;;) {
        if (g_Reg.ShuttingDown != 0 || g_Reg.Initialized == 0) {
            return FALSE;
        }
        if (WaitForSingleObject(g_Reg.BusyReleasedEvent, 100) == WAIT_TIMEOUT) {
            continue;
        }
        if (g_Reg.ShuttingDown != 0 || g_Reg.Initialized == 0) {
            return FALSE;
        }
        if (RgTryBeginBusy()) {
            ResetEvent(g_Reg.BusyReleasedEvent);
            return TRUE;
        }
        /* 竞态：另一线程刚抢走 — 循环等待下次释放 */
    }
}

/*++ 释放 Busy 位并唤醒排队者 --*/
static VOID
RgEndBusy(
    VOID
    )
{
    InterlockedExchange(&g_Reg.Busy, 0);
    SetEvent(g_Reg.BusyReleasedEvent);
}

/*++ 持久化扫描（同步执行；结果经 Notify 桥输出；
 *   引擎条目缓冲由 PdFreeScanResult 回收） --*/
static NTSTATUS
RgRunPersistenceScan(
    _In_ ULONG Scope
    )
{
    WKD_SCAN_RESULT  result;
    NTSTATUS         status;
    ULONG            i;
    char             summary[WKD_REG_PUBLIC_MAX_DESC_CHARS];

    ZeroMemory(&result, sizeof(result));

    /* 扫描范围 0-4 与严重度 0-4 值域一致，复用钳位器 */
    status = PdScan((WKD_REG_SCAN_SCOPE)RgClampSeverity(Scope), &result);
    if (!NT_SUCCESS(status)) {
        RgSetLastError(status);
        RgEmitNotify(
            WkdRegEngine_PersistenceDetector,
            WkdRegEvent_Error,
            0,
            0,
            L"Persistence Scan Failed",
            NULL,
            NULL,
            NULL,
            NULL,
            0,
            RgTimestampNow());
        return status;
    }

    StringCchPrintfA(
        summary,
        ARRAYSIZE(summary),
        "Locations=%lu Entries=%lu Safe=%lu Suspicious=%lu Malicious=%lu Unknown=%lu",
        result.LocationsScanned,
        result.TotalEntries,
        result.SafeEntries,
        result.SuspiciousEntries,
        result.MaliciousEntries,
        result.UnknownEntries);

    RgEmitNotify(
        WkdRegEngine_PersistenceDetector,
        WkdRegEvent_Info,
        0,
        0,
        L"Persistence Scan Complete",
        summary,
        NULL,
        NULL,
        NULL,
        0,
        result.EndTime);

    /* 逐条输出（只桥接可疑+，Safe 仅计入摘要，控制噪声） */
    for (i = 0; i < result.EntryCount; i++) {
        PCWKD_PERSISTENCE_ENTRY entry = &result.Entries[i];
        if (entry->Risk >= WkdRegRisk_Suspicious) {
            RgPdEntryBridge(entry, NULL);
        }
    }

    PdFreeScanResult(&result);
    return STATUS_SUCCESS;
}

/*++ 启动项审计（同步执行；刷新后枚举并输出可疑+ 项） --*/
static NTSTATUS
RgRunStartupAudit(
    VOID
    )
{
    NTSTATUS     status;
    ULONG        count = 0;
    PWKD_SA_ITEM items = NULL;
    ULONG        i;
    char         summary[WKD_REG_PUBLIC_MAX_DESC_CHARS];

    status = SaRefreshItems();
    if (!NT_SUCCESS(status)) {
        RgSetLastError(status);
        RgEmitNotify(
            WkdRegEngine_StartupAnalyzer,
            WkdRegEvent_Error,
            0,
            0,
            L"Startup Audit Failed",
            NULL,
            NULL,
            NULL,
            NULL,
            0,
            RgTimestampNow());
        return status;
    }

    /* 两段式计数 → 堆分配 → 填充 */
    status = SaGetStartupItems(NULL, 0, &count);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        RgSetLastError(status);
        return status;
    }
    if (count == 0) {
        RgEmitNotify(
            WkdRegEngine_StartupAnalyzer,
            WkdRegEvent_Info,
            0,
            0,
            L"Startup Audit Complete",
            "No startup items detected",
            NULL,
            NULL,
            NULL,
            0,
            RgTimestampNow());
        return STATUS_SUCCESS;
    }

    items = (PWKD_SA_ITEM)malloc(sizeof(WKD_SA_ITEM) * count);
    if (items == NULL) {
        RgSetLastError(STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = SaGetStartupItems(items, count, &count);
    if (!NT_SUCCESS(status)) {
        RgSetLastError(status);
        free(items);
        return status;
    }

    /* 输出可疑+ 项（RiskScore>=50 或标记恶意） */
    for (i = 0; i < count; i++) {
        PCWKD_SA_ITEM item = &items[i];
        if (item->IsMalicious || item->RiskScore >= 50) {
            RgSaNewItemBridge(item, NULL);
        }
    }

    free(items);

    StringCchPrintfA(
        summary,
        ARRAYSIZE(summary),
        "Startup items audited: %lu",
        count);
    RgEmitNotify(
        WkdRegEngine_StartupAnalyzer,
        WkdRegEvent_Info,
        0,
        0,
        L"Startup Audit Complete",
        summary,
        NULL,
        NULL,
        NULL,
        0,
        RgTimestampNow());

    return STATUS_SUCCESS;
}

/*++ 起始异步扫描线程（ScanOnStartup）：PD 扩展扫描 + SA 审计；
 *   抢占 Busy 位失败（手动 Trigger 在途）则放弃起始扫描；
 *   线程句柄由 Shutdown 负责等待与关闭。 --*/
static DWORD WINAPI
RgStartupScanThreadProc(
    _In_ LPVOID Unused
    )
{
    (VOID)Unused;

    /* 互斥洞修复 (#96): 原实现不占 Busy, 可与手动 Trigger 并发双扫描 */
    if (!RgTryBeginBusy()) {
        return 0;
    }

    if (g_Reg.EnablePd && g_Reg.Initialized != 0 && g_Reg.ShuttingDown == 0) {
        RgRunPersistenceScan(WkdRegScope_Extended);
    }
    if (g_Reg.EnableSa && g_Reg.Initialized != 0 && g_Reg.ShuttingDown == 0) {
        RgRunStartupAudit();
    }

    RgEndBusy();
    return 0;
}

/* ==================================================
 * 手动 Trigger 异步线程 (#96: 消除"头注异步、实为同步"虚标)
 * ================================================== */

/* Trigger 线程参数（堆分配；CreateThread 后回填 Self 句柄） */
typedef struct _RG_TRIGGER_ARGS {
    ULONG  Kind;               /* 0=PD 持久化扫描, 1=SA 启动项审计 */
    ULONG  Scope;              /* Kind=0 时有效: WKD_REG_SCAN_SCOPE */
    HANDLE Self;               /* 线程自身句柄（末尾 CloseHandle 自清理） */
} RG_TRIGGER_ARGS;

/*++ Trigger 工作线程：
 *   - RgBeginBusyWait 排队（等待在途扫描释放，ShuttingDown 放弃）
 *   - 执行完毕后 RgEndBusy → 关闭自身句柄 → 释放参数 --*/
static DWORD WINAPI
RgTriggerThreadProc(
    _In_ LPVOID Param
    )
{
    RG_TRIGGER_ARGS* args = (RG_TRIGGER_ARGS*)Param;

    if (RgBeginBusyWait()) {
        if (args->Kind == 0 && g_Reg.EnablePd) {
            (VOID)RgRunPersistenceScan(args->Scope);
        } else if (args->Kind == 1 && g_Reg.EnableSa) {
            (VOID)RgRunStartupAudit();
        }
        RgEndBusy();
    }

    CloseHandle(args->Self);
    free(args);
    return 0;
}

/*++ 创建手动 Trigger 线程（异步：立即返回；CREATE_SUSPENDED
 *   保证参数中 Self 句柄先于线程读取回填完成） --*/
static NTSTATUS
RgSpawnTriggerThread(
    _In_ ULONG Kind,
    _In_ ULONG Scope
    )
{
    RG_TRIGGER_ARGS* args;
    HANDLE           h;
    NTSTATUS         status = STATUS_SUCCESS;

    args = (RG_TRIGGER_ARGS*)malloc(sizeof(RG_TRIGGER_ARGS));
    if (args == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    args->Kind = Kind;
    args->Scope = Scope;
    args->Self = NULL;

    h = CreateThread(NULL, 0, RgTriggerThreadProc, args, CREATE_SUSPENDED, NULL);
    if (h == NULL) {
        free(args);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    args->Self = h;
    if (ResumeThread(h) == (DWORD)-1) {
        /* 极罕见：恢复失败，收回句柄并释放（线程未运行） */
        TerminateThread(h, 0);
        CloseHandle(h);
        free(args);
        return STATUS_UNSUCCESSFUL;
    }

    return status;
}

/* ==================================================
 * ═══ 公共接口（Registry.h 声明的门面） ═══
 * ================================================== */

/*++ 初始化：
 *   - Params == NULL 视为全默认（五引擎全启用；
 *     默认扫描范围 Extended；启用缓存 TTL 3600s；
 *     不自动起始扫描；不请求内核阻断）
 *   - 引擎初始化顺序：PD → RA → SSM → RM → SA
 *     （SA 依赖 RM 的接线层，故放在 RM 之后且接线
 *     推迟至 Start）
 *   - 失败时逆序 Shutdown 已初始化引擎并返回错误
 * --*/
NTSTATUS
WkdRegistry_Initialize(
    _In_opt_ const WKD_REG_INIT_PARAMS* Params
    )
{
    WKD_REG_INIT_PARAMS defaults;
    const WKD_REG_INIT_PARAMS* p;
    WKD_PERSISTENCE_CONFIG pdConfig;
    WKD_RA_CONFIG          raConfig;
    WKD_RM_CONFIG          rmConfig;
    WKD_SA_CONFIG          saConfig;
    WKD_SSM_CONFIG         ssmConfig;
    NTSTATUS               status;

    if (g_Reg.Initialized != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    /* 临界区延迟初始化（支持 Shutdown 后再次 Initialize） */
    if (!g_RegLockInited) {
        InitializeCriticalSection(&g_RegLock);
        g_RegLockInited = TRUE;
    }

    /* Busy 释放事件（ManualReset 初始置位=无扫描在途；Shutdown 关闭） */
    if (g_Reg.BusyReleasedEvent == NULL) {
        g_Reg.BusyReleasedEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
        if (g_Reg.BusyReleasedEvent == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    /* 默认参数：全启用、Extended 扫描、缓存开、不自动起始扫描 */
    ZeroMemory(&defaults, sizeof(defaults));
    defaults.EnablePersistenceDetector = TRUE;
    defaults.EnableSystemSettingsMonitor = TRUE;
    defaults.EnableRegistryAnalyzer = TRUE;
    defaults.EnableRegistryMonitor = TRUE;
    defaults.EnableStartupAnalyzer = TRUE;
    defaults.BlockHighRiskOperations = FALSE;
    defaults.ScanOnStartup = FALSE;
    defaults.PersistenceDefaultScope = WkdRegScope_Extended;
    defaults.UseCaching = TRUE;
    defaults.CacheTtlSeconds = 3600;
    p = (Params != NULL) ? Params : &defaults;

    /* 门面状态定型 */
    g_Reg.EnablePd = p->EnablePersistenceDetector;
    g_Reg.EnableSsm = p->EnableSystemSettingsMonitor;
    g_Reg.EnableRa = p->EnableRegistryAnalyzer;
    g_Reg.EnableRm = p->EnableRegistryMonitor;
    g_Reg.EnableSa = p->EnableStartupAnalyzer;
    g_Reg.EnableStartupScan = p->ScanOnStartup;

    /* --- 引擎配置构造（默认工厂 + 覆盖 Init 参数项） --- */
    ZeroMemory(&pdConfig, sizeof(pdConfig));
    ZeroMemory(&raConfig, sizeof(raConfig));
    ZeroMemory(&rmConfig, sizeof(rmConfig));
    ZeroMemory(&saConfig, sizeof(saConfig));
    ZeroMemory(&ssmConfig, sizeof(ssmConfig));

    PdCreateDefaultConfig(&pdConfig);
    pdConfig.DefaultScope = (WKD_REG_SCAN_SCOPE)
        ((p->PersistenceDefaultScope > WkdRegScope_Custom)
             ? WkdRegScope_Full
             : p->PersistenceDefaultScope);
    pdConfig.UseCache = p->UseCaching;
    pdConfig.CacheTtlSeconds = p->CacheTtlSeconds;

    RaCreateDefaultConfig(&raConfig);
    RmCreateDefaultConfig(&rmConfig);
    rmConfig.Enabled = p->EnableRegistryMonitor;
    rmConfig.SelfDefenseEnabled = p->BlockHighRiskOperations;
    SaCreateDefaultConfig(&saConfig);
    SsmCreateDefaultConfig(&ssmConfig);

    /* --- 引擎初始化（失败逆序回滚） --- */
    if (g_Reg.EnablePd) {
        status = PdInitialize(&pdConfig);
        if (!NT_SUCCESS(status)) {
            RgSetLastError(status);
            return status;
        }
    }
    if (g_Reg.EnableRa) {
        status = RaInitialize(&raConfig);
        if (!NT_SUCCESS(status)) {
            RgSetLastError(status);
            if (g_Reg.EnablePd) { PdShutdown(); }
            return status;
        }
    }
    if (g_Reg.EnableSsm) {
        status = SsmInitialize(&ssmConfig);
        if (!NT_SUCCESS(status)) {
            RgSetLastError(status);
            if (g_Reg.EnableRa) { RaShutdown(); }
            if (g_Reg.EnablePd) { PdShutdown(); }
            return status;
        }
    }
    if (g_Reg.EnableRm) {
        if (!RmInitialize(&rmConfig)) {
            RgSetLastError(STATUS_UNSUCCESSFUL);
            if (g_Reg.EnableSsm) { SsmShutdown(); }
            if (g_Reg.EnableRa) { RaShutdown(); }
            if (g_Reg.EnablePd) { PdShutdown(); }
            return STATUS_UNSUCCESSFUL;
        }
    }
    if (g_Reg.EnableSa) {
        status = SaInitialize(&saConfig);
        if (!NT_SUCCESS(status)) {
            RgSetLastError(status);
            if (g_Reg.EnableRm) { RmShutdown(); }
            if (g_Reg.EnableSsm) { SsmShutdown(); }
            if (g_Reg.EnableRa) { RaShutdown(); }
            if (g_Reg.EnablePd) { PdShutdown(); }
            return status;
        }
    }

    /* --- 桥回调注册（id 槽精确注销） --- */
    g_Reg.PdAlertId = (g_Reg.EnablePd)
        ? PdRegisterAlertCallback(RgPdAlertBridge, NULL) : 0;
    g_Reg.RaAnomalyId = (g_Reg.EnableRa)
        ? RaRegisterAnomalyCallback(RgRaAnomalyBridge, NULL) : 0;
    g_Reg.RmEventId = (g_Reg.EnableRm)
        ? RmRegisterEventCallback(RgRmEventBridge, NULL) : 0;
    g_Reg.RmAlertId = (g_Reg.EnableRm)
        ? RmRegisterAlertCallback(RgRmAlertBridge, NULL) : 0;
    g_Reg.SaNewItemId = (g_Reg.EnableSa)
        ? SaRegisterNewItemCallback(RgSaNewItemBridge, NULL) : 0;
    g_Reg.SaAlertId = (g_Reg.EnableSa)
        ? SaRegisterAlertCallback(RgSaAlertBridge, NULL) : 0;
    g_Reg.SaChangeId = (g_Reg.EnableSa)
        ? SaRegisterChangeCallback(RgSaChangeBridge, NULL) : 0;
    g_Reg.SsmChangeId = (g_Reg.EnableSsm)
        ? SsmRegisterChangeCallback(RgSsmChangeBridge, NULL) : 0;
    g_Reg.SsmAlertId = (g_Reg.EnableSsm)
        ? SsmRegisterAlertCallback(RgSsmAlertBridge, NULL) : 0;
    g_Reg.SsmComplianceId = (g_Reg.EnableSsm)
        ? SsmRegisterComplianceCallback(RgSsmComplianceBridge, NULL) : 0;

    InterlockedExchange((volatile LONG*)&g_Reg.Initialized, 1);
    InterlockedExchange((volatile LONG*)&g_Reg.LastError, 0);
    RgTouch();

    RgEmitNotify(
        WkdRegEngine_None,
        WkdRegEvent_Info,
        0,
        0,
        L"Registry Subsystem Initialized",
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        RgTimestampNow());

    return STATUS_SUCCESS;
}

/*++ 启动运行态：
 *   - RM 实时链路（Start）、SSM 轮询线程（Start）
 *   - SA 接线 RM（SaWireRegistryMonitor）
 *   - ScanOnStartup 时创建后台线程执行
 *     PD 扩展扫描 + SA 审计
 *   - 重复调用幂等返回 STATUS_SUCCESS
 * --*/
NTSTATUS
WkdRegistry_Start(
    VOID
    )
{
    if (g_Reg.Initialized == 0) {
        return STATUS_NOT_INITIALIZED;
    }
    if (g_Reg.Started != 0) {
        return STATUS_SUCCESS;      /* 幂等 */
    }
    if (g_Reg.ShuttingDown != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (g_Reg.EnableRm) {
        (VOID)RmStart();
    }
    if (g_Reg.EnableSsm) {
        SsmStart();
    }
    if (g_Reg.EnableSa) {
        (VOID)SaWireRegistryMonitor();
    }

    if (g_Reg.EnableStartupScan && g_Reg.StartupScanThread == NULL) {
        HANDLE h = CreateThread(
            NULL, 0, RgStartupScanThreadProc, NULL, 0, NULL);
        if (h != NULL) {
            EnterCriticalSection(&g_RegLock);
            g_Reg.StartupScanThread = h;
            LeaveCriticalSection(&g_RegLock);
        } else {
            /* 线程创建失败不致命：仅丢失起始扫描 */
            RgSetLastError(STATUS_INSUFFICIENT_RESOURCES);
        }
    }

    InterlockedExchange((volatile LONG*)&g_Reg.Started, 1);
    RgTouch();

    RgEmitNotify(
        WkdRegEngine_None,
        WkdRegEvent_Info,
        0,
        0,
        L"Registry Subsystem Started",
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        RgTimestampNow());

    return STATUS_SUCCESS;
}

/*++ 停止运行态（不销毁桥与引擎，可再次 Start） --*/
VOID
WkdRegistry_Stop(
    VOID
    )
{
    if (g_Reg.Initialized == 0 || g_Reg.Started == 0) {
        return;
    }

    if (g_Reg.EnableSsm) {
        SsmStop();
    }
    if (g_Reg.EnableRm) {
        RmStop();
    }

    InterlockedExchange((volatile LONG*)&g_Reg.Started, 0);
    RgTouch();

    RgEmitNotify(
        WkdRegEngine_None,
        WkdRegEvent_Info,
        0,
        0,
        L"Registry Subsystem Stopped",
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        RgTimestampNow());
}

/*++ 关闭：
 *   - 停止运行态 → 取消在途扫描 → 等待起始扫描线程
 *   - 按 id 精确注销全部桥回调
 *   - 引擎逆序 Shutdown（SA → RM → SSM → RA → PD）
 *   - 状态清零；临界区保留以支持再次 Initialize
 * --*/
VOID
WkdRegistry_Shutdown(
    VOID
    )
{
    HANDLE thread = NULL;
    WKD_REG_NOTIFY n;

    if (g_Reg.Initialized == 0) {
        return;
    }

    InterlockedExchange((volatile LONG*)&g_Reg.ShuttingDown, 1);

    WkdRegistry_Stop();
    WkdRegistry_CancelActiveScan();

    /* 等执行中的扫描完成（Busy 释放事件置位；上限 30s，
     * CancelActiveScan 已请求取消加速收敛） */
    if (g_Reg.BusyReleasedEvent != NULL) {
        (VOID)WaitForSingleObject(g_Reg.BusyReleasedEvent, REG_SCAN_STARTUP_THREAD_WAIT_MS);
        /* 排空排队中的 Trigger 线程：RgBeginBusyWait 为 100ms 轮询
         * 检查 ShuttingDown，5×100ms 大于最坏观测延迟（#96 消除
         * 悬空事件句柄竞态：全部排队者退出后才 CloseHandle） */
        Sleep(500);
    }

    /* 回收起始扫描线程（若有） */
    EnterCriticalSection(&g_RegLock);
    thread = g_Reg.StartupScanThread;
    g_Reg.StartupScanThread = NULL;
    LeaveCriticalSection(&g_RegLock);
    if (thread != NULL) {
        WaitForSingleObject(thread, REG_SCAN_STARTUP_THREAD_WAIT_MS);
        CloseHandle(thread);
    }

    /* 桥回调精确注销（引擎 Shutdown 亦会释放槽，双保险） */
    if (g_Reg.SsmChangeId != 0)     { SsmUnregisterCallback(g_Reg.SsmChangeId); }
    if (g_Reg.SsmAlertId != 0)      { SsmUnregisterCallback(g_Reg.SsmAlertId); }
    if (g_Reg.SsmComplianceId != 0) { SsmUnregisterCallback(g_Reg.SsmComplianceId); }
    if (g_Reg.SaNewItemId != 0)     { SaUnregisterCallback(g_Reg.SaNewItemId); }
    if (g_Reg.SaAlertId != 0)       { SaUnregisterCallback(g_Reg.SaAlertId); }
    if (g_Reg.SaChangeId != 0)      { SaUnregisterCallback(g_Reg.SaChangeId); }
    if (g_Reg.RmEventId != 0)       { RmUnregisterCallback(g_Reg.RmEventId); }
    if (g_Reg.RmAlertId != 0)       { RmUnregisterCallback(g_Reg.RmAlertId); }
    if (g_Reg.RaAnomalyId != 0)     { RaUnregisterCallback(g_Reg.RaAnomalyId); }
    if (g_Reg.PdAlertId != 0)       { PdUnregisterCallback(g_Reg.PdAlertId); }

    /* 引擎逆序 Shutdown */
    if (g_Reg.EnableSa) { SaShutdown(); }
    if (g_Reg.EnableRm) { RmShutdown(); }
    if (g_Reg.EnableSsm) { SsmShutdown(); }
    if (g_Reg.EnableRa) { RaShutdown(); }
    if (g_Reg.EnablePd) { PdShutdown(); }

    /* 关闭通知经 Raw 分发（#96 修复: ShuttingDown 已置位时护栏
     * 路径会拦截此通知, 原实现从未发出收尾事件） */
    ZeroMemory(&n, sizeof(n));
    n.Engine = WkdRegEngine_None;
    n.EventKind = WkdRegEvent_Info;
    StringCchCopyW(n.Title, ARRAYSIZE(n.Title), L"Registry Subsystem Shut Down");
    n.Timestamp = RgTimestampNow();
    RgDispatchNotifyRaw(&n);

    /* 释放事件句柄后状态清零（清零后排队者以 Initialized==0 退出，
     * 事件句柄必须排空后才可关闭，见上方 Sleep 注释） */
    if (g_Reg.BusyReleasedEvent != NULL) {
        CloseHandle(g_Reg.BusyReleasedEvent);
        g_Reg.BusyReleasedEvent = NULL;
    }
    ZeroMemory(&g_Reg, sizeof(g_Reg));
}

/*++ 注册/清除 Notify 回调（单槽位，重复注册覆盖） --*/
VOID
WkdRegistry_SetNotifyCallback(
    _In_opt_ PFN_WKD_REG_NOTIFY_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (g_Reg.Initialized == 0) {
        return;
    }

    EnterCriticalSection(&g_RegLock);
    g_Reg.NotifyCallback = Callback;
    g_Reg.NotifyContext = Context;
    LeaveCriticalSection(&g_RegLock);
}

/*++ 触发持久化扫描（异步：立即返回，结果经 Notify 桥输出；
 *   在途扫描占用期间 Trigger 线程排队等待；关闭中返回
 *   STATUS_INVALID_DEVICE_STATE） --*/
NTSTATUS
WkdRegistry_TriggerPersistenceScan(
    _In_ ULONG Scope
    )
{
    if (g_Reg.Initialized == 0) {
        return STATUS_NOT_INITIALIZED;
    }
    if (g_Reg.ShuttingDown != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_Reg.EnablePd) {
        return STATUS_NOT_SUPPORTED;
    }

    return RgSpawnTriggerThread(0, Scope);
}

/*++ 触发启动项审计（异步：立即返回，结果经 Notify 桥输出） --*/
NTSTATUS
WkdRegistry_TriggerStartupAudit(
    VOID
    )
{
    if (g_Reg.Initialized == 0) {
        return STATUS_NOT_INITIALIZED;
    }
    if (g_Reg.ShuttingDown != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_Reg.EnableSa) {
        return STATUS_NOT_SUPPORTED;
    }

    return RgSpawnTriggerThread(1, 0);
}

/*++ 取消在途扫描/分析（PD 扫描取消 + RA 分析中止） --*/
VOID
WkdRegistry_CancelActiveScan(
    VOID
    )
{
    if (g_Reg.Initialized == 0) {
        return;
    }
    if (g_Reg.EnablePd) {
        PdCancelScan();
    }
    if (g_Reg.EnableRa) {
        (VOID)RaAbortAnalysis();
    }
}

/*++ 获取子系统状态快照 --*/
NTSTATUS
WkdRegistry_GetStatus(
    _Out_ PWKD_REG_STATUS Status
    )
{
    if (Status == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    ZeroMemory(Status, sizeof(*Status));

    if (g_Reg.Initialized == 0) {
        return STATUS_NOT_INITIALIZED;
    }

    Status->Initialized = (g_Reg.Initialized != 0);
    Status->Started = (g_Reg.Started != 0);

    Status->PersistenceDetectorActive =
        (g_Reg.EnablePd && PdIsInitialized());
    Status->SystemSettingsMonitorActive =
        (g_Reg.EnableSsm && SsmIsMonitoring());
    Status->RegistryAnalyzerActive =
        (g_Reg.EnableRa && RaIsInitialized());
    Status->RegistryMonitorActive =
        (g_Reg.EnableRm && RmIsRunning());
    Status->StartupAnalyzerActive =
        (g_Reg.EnableSa && SaIsInitialized());

    Status->Busy = (g_Reg.Busy != 0);
    Status->LastError = g_Reg.LastError;
    Status->LastActivityTime = (ULONGLONG)g_Reg.LastActivityTime;

    return STATUS_SUCCESS;
}

/*++ 获取统计摘要（以 Info 事件载荷输出；仅使用门面
 *   自有状态与引擎布尔，不依赖未确认的统计字段） --*/
NTSTATUS
WkdRegistry_GetStatistics(
    _Out_ PWKD_REG_NOTIFY Notify
    )
{
    char   desc[WKD_REG_PUBLIC_MAX_DESC_CHARS];
    PCWSTR fields[5];
    WCHAR  fText[5][WKD_REG_PUBLIC_MAX_FIELD_CHARS];

    if (Notify == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_Reg.Initialized == 0) {
        return STATUS_NOT_INITIALIZED;
    }

    ZeroMemory(Notify, sizeof(*Notify));
    ZeroMemory(fText, sizeof(fText));

    Notify->Engine = WkdRegEngine_None;
    Notify->EventKind = WkdRegEvent_Info;
    Notify->Severity = 0;
    Notify->Timestamp = RgTimestampNow();

    StringCchPrintfW(Notify->Title, ARRAYSIZE(Notify->Title),
        L"Registry Subsystem Statistics");

    StringCchPrintfA(
        desc,
        ARRAYSIZE(desc),
        "Busy=%lu Init=%lu Start=%lu LastErr=%08lX",
        (ULONG)g_Reg.Busy,
        (ULONG)g_Reg.Initialized,
        (ULONG)g_Reg.Started,
        (ULONG)g_Reg.LastError);
    /* 公共结构 Description 为 WCHAR，窄输入经 %hs 宽化 */
    StringCchPrintfW(Notify->Description, ARRAYSIZE(Notify->Description),
        L"%hs", desc);

    StringCchPrintfW(fText[0], WKD_REG_PUBLIC_MAX_FIELD_CHARS,
        L"PD=%hs", (g_Reg.EnablePd && PdIsInitialized()) ? "active" : "off");
    StringCchPrintfW(fText[1], WKD_REG_PUBLIC_MAX_FIELD_CHARS,
        L"SSM=%hs", (g_Reg.EnableSsm && SsmIsMonitoring()) ? "active" : "off");
    StringCchPrintfW(fText[2], WKD_REG_PUBLIC_MAX_FIELD_CHARS,
        L"RM=%hs", (g_Reg.EnableRm && RmIsRunning()) ? "active" : "off");
    StringCchPrintfW(fText[3], WKD_REG_PUBLIC_MAX_FIELD_CHARS,
        L"SA=%hs", (g_Reg.EnableSa && SaIsInitialized()) ? "active" : "off");
    StringCchPrintfW(fText[4], WKD_REG_PUBLIC_MAX_FIELD_CHARS,
        L"RA=%hs", (g_Reg.EnableRa && RaIsInitialized()) ? "active" : "off");

    fields[0] = fText[0];
    fields[1] = fText[1];
    fields[2] = fText[2];
    fields[3] = fText[3];
    fields[4] = fText[4];
    Notify->FieldCount = ARRAYSIZE(fields);
    {
        ULONG i;
        for (i = 0; i < Notify->FieldCount; i++) {
            StringCchCopyW(Notify->Fields[i], WKD_REG_PUBLIC_MAX_FIELD_CHARS, fields[i]);
        }
    }

    return STATUS_SUCCESS;
}

/* ==================================================
 * 完成注释：
 *  - 本文件实现 Registry.h 全部公开接口（10 个）
 *  - 五引擎统一编排、Notify 桥 10 路（PD 告警/RA 异常/
 *    RM 事件+告警/SA 新项+告警+变更/SSM 变更+告警+合规）
 *  - Busy 位 + BusyReleasedEvent：起始扫描抢占式、手动
 *    Trigger 排队式（#96）；Shutdown 等 Busy 释放 + 排空
 *    排队者 + 等待起始扫描线程 + Raw 关闭通知
 *  - 桥回调同步执行、回调内禁止阻塞（对齐公共头约束）
 *  - 未注册 PD 条目桥：条目经扫描结果遍历输出
 * ================================================== */