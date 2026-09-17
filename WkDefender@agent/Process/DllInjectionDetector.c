/**************************************************/
/*  WkDefender Agent — DLL 注入检测器实现           */
/*                                                  */
/*  2026-09-15 重构: 自 IOA/IoaInjectionClassifier  */
/*  迁出"模块窗口确认"能力 (对齐 ShadowStrike        */
/*  DLLInjectionDetector::DetectRemoteThread-       */
/*  InjectionImpl, T1055.001)。                     */
/*                                                  */
/*  数据源状态: 模块缓存由 IoaRecordModuleLoad      */
/*  填充; 当前驱动 ImageLoad 事件未接入 IOA 流水线   */
/*  (见 process_manager.c WkdMessage_ImageLoaded /  */
/*  EventParser), 该入口尚无调用者。接入后缓存即被   */
/*  填充, IoaConfirmDllInjectionByModule 自动生效。  */
/**************************************************/

#include "../Include/Process/InjectionDetector.h"
#include "../Common/PathUtil.h"   /* WkdIsSystemDirectory (系统目录过滤) */

/**************************************************/
/*           模块加载缓存 (窗口确认数据源)          */
/*  对齐 ShadowStrike LOAD_CORRELATION_WINDOW_MS   */
/**************************************************/

#define IOA_MOD_BUCKETS         64
#define IOA_MOD_WINDOW_MS       1000    /* 关联时间窗 (对齐 LOAD_CORRELATION_WINDOW_MS) */
#define IOA_MOD_CACHE_MAX       512     /* 全局缓存上限 (防无界增长) */

typedef struct _IOA_MODULE_LOAD_REC {
    LIST_ENTRY   ListEntry;
    ULONG        ProcessId;
    LARGE_INTEGER LoadTime;             /* FILETIME 100ns 单位 */
    WCHAR        ModulePath[260];
} IOA_MODULE_LOAD_REC, *PIOA_MODULE_LOAD_REC;

typedef struct _IOA_MOD_CACHE {
    SRWLOCK     Lock;
    LIST_ENTRY  Buckets[IOA_MOD_BUCKETS];
    ULONG       Count;
} IOA_MOD_CACHE;

static IOA_MOD_CACHE g_IoaModCache;
static BOOLEAN g_IoaModCacheInit = FALSE;

/* 惰性初始化缓存桶 */
static
VOID
IoaModCacheEnsureInit(
    VOID
    )
{
    ULONG i;

    if (!g_IoaModCacheInit) {
        InitializeSRWLock(&g_IoaModCache.Lock);
        for (i = 0; i < IOA_MOD_BUCKETS; i++) {
            InitializeListHead(&g_IoaModCache.Buckets[i]);
        }
        g_IoaModCache.Count = 0;
        g_IoaModCacheInit = TRUE;
    }
}

/* 淘汰超过关联时间窗的记录 (调用方持锁) */
static
VOID
IoaModCacheEvictLocked(
    _In_ LARGE_INTEGER Now
    )
{
    ULONG i;

    for (i = 0; i < IOA_MOD_BUCKETS; i++) {
        PLIST_ENTRY entry = g_IoaModCache.Buckets[i].Flink;

        while (entry != &g_IoaModCache.Buckets[i]) {
            PIOA_MODULE_LOAD_REC rec =
                CONTAINING_RECORD(entry, IOA_MODULE_LOAD_REC, ListEntry);
            PLIST_ENTRY next = entry->Flink;
            LONGLONG ageUs = (Now.QuadPart - rec->LoadTime.QuadPart) / 10;

            if (ageUs < 0 || ageUs > (LONGLONG)IOA_MOD_WINDOW_MS * 1000) {
                RemoveEntryList(entry);
                g_IoaModCache.Count--;
                HeapFree(GetProcessHeap(), 0, rec);
            }
            entry = next;
        }
    }
}

NTSTATUS
IoaRecordModuleLoad(
    _In_ ULONG ProcessId,
    _In_ PCWSTR ModulePath,
    _In_ LARGE_INTEGER LoadTime
    )
/*++
Routine Description:
    记录一次模块加载, 供 DLL 注入模块窗口确认使用。

    数据源状态: 当前驱动 ImageLoad 事件未接入 IOA 流水线
    (见 process_manager.c WkdMessage_ImageLoaded / EventParser),
    本函数尚无调用者。接入后缓存即被填充, IoaConfirmDllInjectionByModule
    自动生效。

Arguments:
    ProcessId  - 加载进程 PID。
    ModulePath - 模块完整路径。
    LoadTime   - 加载时间 (FILETIME 100ns)。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    PIOA_MODULE_LOAD_REC rec;
    LARGE_INTEGER now;

    if (!ModulePath) {
        return STATUS_INVALID_PARAMETER;
    }
    IoaModCacheEnsureInit();

    rec = (PIOA_MODULE_LOAD_REC)HeapAlloc(GetProcessHeap(), 0, sizeof(*rec));
    if (!rec) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(rec, sizeof(*rec));
    rec->ProcessId = ProcessId;
    rec->LoadTime = LoadTime;
    wcsncpy_s(rec->ModulePath, ARRAYSIZE(rec->ModulePath), ModulePath, _TRUNCATE);

    GetSystemTimeAsFileTime((PFILETIME)&now);

    AcquireSRWLockExclusive(&g_IoaModCache.Lock);
    IoaModCacheEvictLocked(now);
    InsertHeadList(&g_IoaModCache.Buckets[ProcessId % IOA_MOD_BUCKETS],
                   &rec->ListEntry);
    g_IoaModCache.Count++;
    if (g_IoaModCache.Count > IOA_MOD_CACHE_MAX) {
        /* 超过上限: 淘汰最老桶的一条记录 */
        ULONG k;
        for (k = 0; k < IOA_MOD_BUCKETS; k++) {
            if (!IsListEmpty(&g_IoaModCache.Buckets[k])) {
                PLIST_ENTRY tail = g_IoaModCache.Buckets[k].Blink;
                PIOA_MODULE_LOAD_REC oldest =
                    CONTAINING_RECORD(tail, IOA_MODULE_LOAD_REC, ListEntry);
                RemoveEntryList(tail);
                g_IoaModCache.Count--;
                HeapFree(GetProcessHeap(), 0, oldest);
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_IoaModCache.Lock);

    return STATUS_SUCCESS;
}

NTSTATUS
IoaConfirmDllInjectionByModule(
    _In_ ULONG TargetProcessId,
    _Inout_ PULONG Confidence,
    _Inout_ PULONG RiskScore
    )
/*++
Routine Description:
    远程线程 DLL 注入的模块窗口确认 (对齐 ShadowStrike
    DetectRemoteThreadInjectionImpl, T1055.001)。

    当目标进程在关联时间窗 (1s) 内加载了未信任 (非系统目录) 模块时,
    将 DLL 注入置信度提升至确认级 (≥90), 风险分提升至 ≥85。

    数据源状态: 模块缓存由 IoaRecordModuleLoad 填充; 当前为空时本函数
    返回 STATUS_NOT_FOUND 且不改变判定, 不引入误报。

Arguments:
    TargetProcessId  - 注入目标进程 PID。
    Confidence - [in,out] 注入置信度 [0,100]。
    RiskScore  - [in,out] 注入风险分 [0,100]。

Return Value:
    STATUS_SUCCESS — 模块确认命中, 置信度/风险分已提升。
    STATUS_NOT_FOUND — 缓存空或无窗口内未信任模块, 判定未改变。
--*/
{
    ULONG bucket;
    PLIST_ENTRY entry;
    LARGE_INTEGER now;
    BOOLEAN confirmed = FALSE;

    if (!Confidence || !RiskScore) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_IoaModCacheInit) {
        return STATUS_NOT_FOUND;
    }

    GetSystemTimeAsFileTime((PFILETIME)&now);

    /* 只读遍历 (共享锁下不做淘汰; 过期清理由写路径 IoaRecordModuleLoad 负责) */
    AcquireSRWLockShared(&g_IoaModCache.Lock);

    bucket = TargetProcessId % IOA_MOD_BUCKETS;
    for (entry = g_IoaModCache.Buckets[bucket].Flink;
         entry != &g_IoaModCache.Buckets[bucket];
         entry = entry->Flink) {
        PIOA_MODULE_LOAD_REC rec =
            CONTAINING_RECORD(entry, IOA_MODULE_LOAD_REC, ListEntry);
        LONGLONG ageUs;

        if (rec->ProcessId != TargetProcessId) {
            continue;
        }
        ageUs = (now.QuadPart - rec->LoadTime.QuadPart) / 10;
        if (ageUs < 0 || ageUs > (LONGLONG)IOA_MOD_WINDOW_MS * 1000) {
            continue;
        }
        /* 非系统目录模块 = 未信任, 构成注入载荷确认 */
        if (!WkdIsSystemDirectory(rec->ModulePath)) {
            confirmed = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_IoaModCache.Lock);

    if (confirmed) {
        if (*Confidence < 90) {
            *Confidence = 90;
        }
        if (*RiskScore < 85) {
            *RiskScore = 85;
        }
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}