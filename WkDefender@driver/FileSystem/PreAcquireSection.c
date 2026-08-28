/**************************************************/
/*  PreAcquireSection 代码执行映射检测              */
/*  迁移自 SS PreAcquireSection.c（重功能实现）      */
/*                                                  */
/*  活代码：WkdPasProcessMapping 检测流水线（分类/   */
/*    行为检测/评分），由 Filter.c FspPreAcquireSection */
/*    回调壳调用；逐进程画像内嵌 WKD_PROCESS。        */
/*  死代码分区：扫描缓存/LRU/独立链表上下文/查询 API  */
/*    （保留功能面落位，标注不接入原因）。            */
/**************************************************/

#include <fltKernel.h>
#include <ntifs.h>
#include "../Process/ProcessMonitor.h"   /* WKD_PAS_PROCESS_PROFILE 内嵌于 WKD_PROCESS */
#include "PreAcquireSection.h"

/*++
 * 模块职责：
 *   代码执行映射检测——IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION 的 Pre
 *   回调（SyncTypeCreateSection + 执行保护）用于在映射发生时拦截：
 *     - 进程空心化 / DLL 注入 / 反射加载 / 快速映射行为检测
 *     - 逐进程映射画像（WKD_PROCESS 内嵌 SectionMapProfile，窗口计数）
 *     - 评分融合（PAS 基础分 + Filter.c B2 路径分析分），阻断决策 Audit 门控
 *   迁移来源：ShadowStrike Callbacks/FileSystem/PreAcquireSection.c
 *
 *   阻断决策在 Filter.c FspPreAcquireSection（评分 + EnableBlocking 门控 +
 *     自保护执行映射强信号阻断）；跨进程映射注入归 SyscallHijack.c
 *     NtMapViewOfSection case（agent 0x6005/0x6006 消费链）。
 *
 * 依赖缺口标注：
 *   - 空心化"全线程挂起"信号依赖 ZwQuerySystemInformation（成本高，死代码）
 *   - 扫描缓存（SS ScanCache）在 wkd 无对应，缓存命中分支以 WkdYaraVerdict 占位
 *--*/

#pragma warning(push)
#pragma warning(disable: 4505)  /* unreferenced local function（死代码分区） */
#pragma warning(disable: 4100)  /* unreferenced formal parameter */

/**************************************************/
/*                      常量定义                   */
/**************************************************/

#define WKD_PAS_POOL_TAG            'aSWK'  /* WkSa */

/* 执行保护掩码 / 分类标志 / 行为标志 / 评分阈值均定义于 PreAcquireSection.h
 * （供 Filter.c 回调壳共用），此处仅保留本模块内部阈值，避免宏重复定义。 */
#define PAS_TIME_WINDOW_100NS       (1000LL * 10000LL)   /* 1 秒窗口 */
#define PAS_MAX_TRACKED_MAPPINGS    4096
#define PAS_HOLLOWING_RECENT_EXEC   3
#define PAS_HOLLOWING_IMAGE_MAP     5
#define PAS_HOLLOWING_TOTAL_MAP     20

/**************************************************/
/*                      结构体声明                 */
/**************************************************/

typedef struct _WKD_PAS_MAPPING_RECORD {
    HANDLE       ProcessId;
    HANDLE       ThreadId;
    PVOID        FileObject;
    LARGE_INTEGER Timestamp;

    ULONG        VolumeSerial;
    UINT64       FileId;
    UINT64       FileSize;

    ULONG        PageProtection;
    ULONG        SectionType;
    ULONG        MappingFlags;
    ULONG        SuspicionScore;

    ULONG        Verdict;            /* 0=未知 1=恶意(阻断) 2=干净 */
    BOOLEAN      WasCacheHit;
    BOOLEAN      WasBlocked;

    LIST_ENTRY   ListEntry;
    LIST_ENTRY   HashEntry;
} WKD_PAS_MAPPING_RECORD, *PWKD_PAS_MAPPING_RECORD;

typedef struct _WKD_PAS_PROCESS_CONTEXT {
    HANDLE       ProcessId;
    LARGE_INTEGER ProcessCreateTime;    /* 防 PID 复用 */

    volatile UINT64 TotalMappings;
    volatile UINT64 ExecutableMappings;
    volatile UINT64 ImageMappings;
    volatile UINT64 SuspiciousMappings;
    volatile UINT64 BlockedMappings;

    volatile LONG RecentMappings;
    volatile LONG RecentExecutables;
    LARGE_INTEGER WindowStartTime;

    ULONG        BehaviorFlags;
    ULONG        SuspicionScore;
    BOOLEAN      IsHollowingSuspect;
    BOOLEAN      IsInjectionSuspect;
    BOOLEAN      IsReflectiveSuspect;

    volatile BOOLEAN Removed;
    volatile BOOLEAN IsEarlyProcess;

    volatile LONG RefCount;
    LIST_ENTRY   ListEntry;
} WKD_PAS_PROCESS_CONTEXT, *PWKD_PAS_PROCESS_CONTEXT;

typedef struct _WKD_PAS_SUSPICIOUS_PATH {
    PCWSTR Pattern;
    USHORT LengthInBytes;
} WKD_PAS_SUSPICIOUS_PATH;

/* 可疑路径表（对齐 SS g_SuspiciousPaths 11 条） */
static const WKD_PAS_SUSPICIOUS_PATH g_WkdPasSuspiciousPaths[] = {
    { L"\\Temp\\",                  12 },
    { L"\\TMP\\",                   10 },
    { L"\\AppData\\Local\\Temp\\",  40 },
    { L"\\Windows\\Temp\\",         28 },
    { L"\\Users\\Public\\",         28 },
    { L"\\ProgramData\\",           26 },
    { L"\\Downloads\\",             22 },
    { L"\\Recycle",                 16 },
    { L"$Recycle.Bin",              24 },
    { L"\\staging\\",               18 },
    { L"\\cache\\",                 14 },
};

#define WKD_PAS_SUSPICIOUS_PATH_COUNT \
    (sizeof(g_WkdPasSuspiciousPaths) / sizeof(g_WkdPasSuspiciousPaths[0]))

/**************************************************/
/*                 配置 / 统计结构                 */
/**************************************************/

/* 运行时配置（阻断默认 Audit——EnableBlocking=FALSE，对齐 wkd NamedPipeMonitor/
 * AppControl 惯例；自保护执行映射阻断不受本门控，强信号独立于评分）。 */
typedef struct _WKD_PAS_CONFIG {
    BOOLEAN EnableBlocking;            /* 评分≥MinBlockScore 是否阻断（默认 FALSE） */
    BOOLEAN EnableHollowingDetection;  /* 空心化检测（默认 TRUE） */
    BOOLEAN EnableInjectionDetection;  /* DLL 注入检测（默认 TRUE） */
    BOOLEAN EnableReflectiveDetection; /* 反射加载检测（默认 TRUE） */
    ULONG   MinBlockScore;             /* 阻断阈值（默认 85） */
    ULONG   SuspicionMedium;           /* 事件上送/可疑计数门槛（默认 30） */
    ULONG   AnomalyThreshold;          /* 快速映射异常阈值（默认 10/s） */
} WKD_PAS_CONFIG, *PWKD_PAS_CONFIG;

/* 统计计数（原子，供 DbgPrint 与未来查询 API 消费） */
typedef struct _WKD_PAS_STATS {
    volatile UINT64 TotalCalls;
    volatile UINT64 ExecuteMappings;
    volatile UINT64 ImageMappings;
    volatile UINT64 SuspiciousDetected;
    volatile UINT64 HollowingDetected;
    volatile UINT64 InjectionDetected;
    volatile UINT64 ReflectiveDetected;
    volatile UINT64 RapidDetected;
    volatile UINT64 Blocked;
    volatile UINT64 SelfProtectionBlocks;
    volatile UINT64 Allowed;
} WKD_PAS_STATS, *PWKD_PAS_STATS;

/* 逐映射记录哈希桶（死代码：SS 128 桶 + LRU 追踪。活路径用栈上记录 +
 * WKD_PROCESS 内嵌画像，不落逐记录表；保留实现供未来逐映射诊断/缓存消费）。 */
#define WKD_PAS_HASH_BUCKET_COUNT      128
#define WKD_PAS_HASH_BUCKET_MASK       (WKD_PAS_HASH_BUCKET_COUNT - 1)

typedef struct _WKD_PAS_HASH_BUCKET {
    LIST_ENTRY   List;
    EX_PUSH_LOCK Lock;
} WKD_PAS_HASH_BUCKET, *PWKD_PAS_HASH_BUCKET;

/**************************************************/
/*                      全局状态                   */
/**************************************************/

typedef struct _WKD_PAS_GLOBAL_STATE {
    /* 活代码：检测引擎状态 */
    BOOLEAN            Initialized;
    volatile BOOLEAN   ShutdownRequested;
    WKD_PAS_CONFIG     Config;
    WKD_PAS_STATS      Stats;
    EX_PUSH_LOCK       ConfigLock;     /* 保护配置更新（未来 agent 策略下发） */

    /* 死代码（SS 原版独立上下文机制，已被 WKD_PROCESS 内嵌 SectionMapProfile
     * 取代，保留字段供死代码分区编译） */
    LIST_ENTRY         ProcessContextList;
    EX_PUSH_LOCK       ProcessContextLock;
    volatile LONG      ProcessContextCount;
    LIST_ENTRY         MappingList;
    EX_PUSH_LOCK       MappingLock;
    volatile LONG      MappingCount;
    WKD_PAS_HASH_BUCKET HashTable[WKD_PAS_HASH_BUCKET_COUNT];  /* 死代码：逐记录哈希索引 */
} WKD_PAS_GLOBAL_STATE, *PWKD_PAS_GLOBAL_STATE;

static WKD_PAS_GLOBAL_STATE g_WkdPasState = {0};

/**************************************************/
/*                      函数声明                   */
/*  活代码：WkdPasProcessMapping/Initialize/Shutdown */
/*  死代码：旧独立链表上下文管理 + 路径检测（被      */
/*    WKD_PROCESS 内嵌 SectionMapProfile 与 Filter.c */
/*    B2 路径分析取代，保留供死代码分区编译）。       */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static PWKD_PAS_PROCESS_CONTEXT
WkdPasLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasReferenceProcessContext(
    _Inout_ PWKD_PAS_PROCESS_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasDereferenceProcessContext(
    _Inout_ PWKD_PAS_PROCESS_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasContainsSubstringW(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring,
    _In_ USHORT SubstringLength
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasIsSuspiciousPath(
    _In_ PCUNICODE_STRING FilePath
    );

/**************************************************/
/*                      函数实现                   */
/**************************************************/

/*
 * 映射分类（对齐 SS PaspClassifyMapping）：
 *   执行保护 → EXECUTABLE；PAGE_EXECUTE_READWRITE/WRITECOPY → WRITABLE；
 *   SEC_IMAGE → IMAGE（PE 镜像加载 vs 数据节加执行权限）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdPasClassifyMapping(
    _In_ ULONG PageProtection
    )
{
    ULONG flags = 0;

    if (PageProtection & PAS_EXECUTE_PROTECTION_MASK) {
        flags |= PAS_MAP_FLAG_EXECUTABLE;
    }
    if ((PageProtection & PAGE_EXECUTE_READWRITE) ||
        (PageProtection & PAGE_EXECUTE_WRITECOPY)) {
        flags |= PAS_MAP_FLAG_WRITABLE;
    }
    if (PageProtection & SEC_IMAGE) {
        flags |= PAS_MAP_FLAG_IMAGE;
    }
    return flags;
}

/*
 * 文件名可疑（SectionTracker 迁移 2026-08，对齐 SS SecpIsSuspiciousName L2639）：
 *   双扩展名 + 可疑尾扩展（.exe/.dll/.scr）或超长文件名（>200 字符）。
 *   全程长度边界安全的 UNICODE_STRING 遍历（MED-6 约定，无 wcsrchr/wcslen）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasIsSuspiciousName(
    _In_ PCUNICODE_STRING FilePath
    )
{
    USHORT charLen;
    USHORT fileNameStart = 0;
    USHORT fileNameLen;
    USHORT dotCount = 0;
    USHORT lastDot = 0;
    USHORT i;
    UNICODE_STRING extension;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    charLen = (USHORT)(FilePath->Length / sizeof(WCHAR));

    /* 提取文件名部分（最后一个 \ 之后） */
    for (i = 0; i < charLen; i++) {
        if (FilePath->Buffer[i] == L'\\') {
            fileNameStart = i + 1;
        }
    }

    fileNameLen = (USHORT)(charLen - fileNameStart);
    if (fileNameLen == 0) {
        return FALSE;
    }

    /* 统计点并找最后一点 */
    for (i = fileNameStart; i < charLen; i++) {
        if (FilePath->Buffer[i] == L'.') {
            dotCount++;
            lastDot = i;
        }
    }

    /* 双扩展名 + 可疑尾扩展（对齐 SS：.exe/.dll/.scr） */
    if (dotCount >= 2 && lastDot > fileNameStart) {
        static const UNICODE_STRING PasExeExt = RTL_CONSTANT_STRING(L".exe");
        static const UNICODE_STRING PasDllExt = RTL_CONSTANT_STRING(L".dll");
        static const UNICODE_STRING PasScrExt = RTL_CONSTANT_STRING(L".scr");

        extension.Buffer = &FilePath->Buffer[lastDot];
        extension.Length = (USHORT)((charLen - lastDot) * sizeof(WCHAR));
        extension.MaximumLength = extension.Length;

        if (RtlEqualUnicodeString(&extension, &PasExeExt, TRUE) ||
            RtlEqualUnicodeString(&extension, &PasDllExt, TRUE) ||
            RtlEqualUnicodeString(&extension, &PasScrExt, TRUE)) {
            return TRUE;
        }
    }

    /* 超长文件名（>200 字符）— 规避手法 */
    if (fileNameLen > 200) {
        return TRUE;
    }

    return FALSE;
}

/*
 * 评分（对齐 SS PaspCalculateSuspicionScore，上限 100）：
 *   WRITABLE+25 / 可疑路径+20 / Temp+15 / ADS+30 / Hollowing+35 /
 *   Reflective+40 / EarlyProcess+10 / 行为 RAPID+15 / HOLLOWING+20 / REFLECTIVE+25
 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdPasCalculateSuspicionScore(
    _In_ PWKD_PAS_MAPPING_RECORD Record,
    _In_opt_ PWKD_PAS_PROCESS_PROFILE Profile
    )
{
    ULONG score = 0;

    if (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE)            score += 25;
    if (Record->MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH)     score += 20;
    if (Record->MappingFlags & PAS_MAP_FLAG_TEMP_LOCATION)       score += 15;
    if (Record->MappingFlags & PAS_MAP_FLAG_ADS)                 score += 30;
    if (Record->MappingFlags & PAS_MAP_FLAG_HOLLOWING_SUSPECT)   score += 35;
    if (Record->MappingFlags & PAS_MAP_FLAG_REFLECTIVE_SUSPECT)  score += 40;
    if (Record->MappingFlags & PAS_MAP_FLAG_EARLY_PROCESS)       score += 10;

    if (Profile != NULL) {
        if (Profile->BehaviorFlags & PAS_BEHAVIOR_RAPID_MAPPING) score += 15;
        if (Profile->BehaviorFlags & PAS_BEHAVIOR_HOLLOWING)     score += 20;
        if (Profile->BehaviorFlags & PAS_BEHAVIOR_REFLECTIVE)    score += 25;
    }

    return (score > 100) ? 100 : score;
}

/*
 * 逐进程映射画像更新（对齐 SS PaspUpdateProcessMetrics）：
 *   1s 窗口滚动计数，超早期进程窗口清除 IsEarlyProcess。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasUpdateProcessMetrics(
    _Inout_ PWKD_PAS_PROCESS_PROFILE Profile,
    _In_ PWKD_PAS_MAPPING_RECORD Record
    )
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeDiff;

    KeQuerySystemTime(&currentTime);

    timeDiff.QuadPart = currentTime.QuadPart - Profile->WindowStartTime.QuadPart;
    if (timeDiff.QuadPart > PAS_TIME_WINDOW_100NS) {
        InterlockedExchange(&Profile->RecentMappings, 0);
        InterlockedExchange(&Profile->RecentExecutables, 0);
        Profile->WindowStartTime = currentTime;
        /* 早期进程窗口清除由调用方 WkdPasProcessMapping 依据 Core.CreateTime
         * 判定（profile 无创建时刻冗余字段，WKD_KPROCESS.Core.CreateTime 承担）。 */
    }

    InterlockedIncrement64((PLONG64)&Profile->TotalMappings);
    InterlockedIncrement(&Profile->RecentMappings);

    if (Record->MappingFlags & PAS_MAP_FLAG_EXECUTABLE) {
        InterlockedIncrement64((PLONG64)&Profile->ExecutableMappings);
        InterlockedIncrement(&Profile->RecentExecutables);
    }
    if (Record->MappingFlags & PAS_MAP_FLAG_IMAGE) {
        InterlockedIncrement64((PLONG64)&Profile->ImageMappings);
    }
}

/*
 * 进程空心化检测（对齐 SS PaspDetectHollowingPattern 4 信号）：
 *   ① 窗口内可执行映射>3；② ImageMappings>5 且 Total<20（占比）；
 *   ③ 早期进程+W+RX；④ 早期进程+全线程挂起。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasDetectHollowingPattern(
    _In_ PWKD_PAS_PROCESS_PROFILE Profile,
    _In_ PWKD_PAS_MAPPING_RECORD Record
    )
{
    ULONG recentExecs;
    UINT64 imageMappings;
    UINT64 totalMappings;

    UNREFERENCED_PARAMETER(Record);

    recentExecs = (ULONG)InterlockedCompareExchange(&Profile->RecentExecutables, 0, 0);
    imageMappings = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64*)&Profile->ImageMappings, 0, 0);
    totalMappings = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64*)&Profile->TotalMappings, 0, 0);

    if (recentExecs > PAS_HOLLOWING_RECENT_EXEC) {
        return TRUE;
    }
    if (imageMappings > PAS_HOLLOWING_IMAGE_MAP && totalMappings < PAS_HOLLOWING_TOTAL_MAP) {
        return TRUE;
    }
    if (Profile->IsEarlyProcess &&
        (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE)) {
        return TRUE;
    }
    /* 早期进程+全线程挂起（空心化第 4 信号）：WkdPasIsProcessSuspended 已死代码
     * 落位（见文件末尾补遗分区），ZwQuerySystemInformation 全量枚举成本高，
     * 活路径不调用；接入时评估改用进程挂起缓存或 agent 侧线程验证。 */
    return FALSE;
}

/*
 * DLL 注入检测（对齐 SS PaspDetectInjectionPattern）：
 *   跨进程映射，或 W+RX 且来自网络/可移除。
 *   注：SS 的 NETWORK/REMOVABLE 标志从未置位（死分支）；wkd 由回调壳
 *   WkdFspGetVolumeNetworkRemovable 补齐生产者，本分支在 wkd 激活。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasDetectInjectionPattern(
    _In_ PWKD_PAS_PROCESS_PROFILE Profile,
    _In_ PWKD_PAS_MAPPING_RECORD Record
    )
{
    UNREFERENCED_PARAMETER(Profile);

    if (Record->MappingFlags & PAS_MAP_FLAG_CROSS_PROCESS) {
        return TRUE;
    }
    if ((Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) &&
        (Record->MappingFlags & (PAS_MAP_FLAG_NETWORK | PAS_MAP_FLAG_REMOVABLE))) {
        return TRUE;
    }
    return FALSE;
}

/*
 * 反射加载检测（对齐 SS PaspDetectReflectiveLoading）：
 *   W+RX + 可疑路径 / Temp / 窗口内可执行映射>2。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasDetectReflectiveLoading(
    _In_ PWKD_PAS_PROCESS_PROFILE Profile,
    _In_ PWKD_PAS_MAPPING_RECORD Record
    )
{
    ULONG recentExecs;

    if (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) {
        if (Record->MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH) {
            return TRUE;
        }
        if (Record->MappingFlags & PAS_MAP_FLAG_TEMP_LOCATION) {
            return TRUE;
        }
        recentExecs = (ULONG)InterlockedCompareExchange(&Profile->RecentExecutables, 0, 0);
        if (recentExecs > 2) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * 安全子串搜索（对齐 SS PaspContainsSubstringW，长度感知不依赖空终止）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasContainsSubstringW(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring,
    _In_ USHORT SubstringLength
    )
{
    SIZE_T stringLen;
    SIZE_T subLen;
    SIZE_T i, j;
    BOOLEAN match;

    if (String == NULL || String->Buffer == NULL || Substring == NULL) {
        return FALSE;
    }
    stringLen = String->Length / sizeof(WCHAR);
    subLen = SubstringLength / sizeof(WCHAR);

    if (subLen == 0 || subLen > stringLen) {
        return FALSE;
    }
    for (i = 0; i <= stringLen - subLen; i++) {
        match = TRUE;
        for (j = 0; j < subLen; j++) {
            WCHAR a = String->Buffer[i + j];
            WCHAR b = Substring[j];
            if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
            if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasIsSuspiciousPath(
    _In_ PCUNICODE_STRING FilePath
    )
{
    ULONG i;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < WKD_PAS_SUSPICIOUS_PATH_COUNT; i++) {
        if (WkdPasContainsSubstringW(FilePath,
                                     g_WkdPasSuspiciousPaths[i].Pattern,
                                     g_WkdPasSuspiciousPaths[i].LengthInBytes)) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*              进程上下文管理（链表）              */
/*  死代码：SS 原版独立上下文机制，已被 WKD_PROCESS */
/*  内嵌 SectionMapProfile 取代（进程退出随          */
/*  PspDestroyProcess 统一回收）。保留实现供编译，   */
/*  活路径经 PsLookupWkdProcessByProcessId。         */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static PWKD_PAS_PROCESS_CONTEXT
WkdPasLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    PLIST_ENTRY entry;
    PWKD_PAS_PROCESS_CONTEXT context = NULL;
    PWKD_PAS_PROCESS_CONTEXT newContext = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_WkdPasState.ProcessContextLock);

    for (entry = g_WkdPasState.ProcessContextList.Flink;
         entry != &g_WkdPasState.ProcessContextList;
         entry = entry->Flink) {
        context = CONTAINING_RECORD(entry, WKD_PAS_PROCESS_CONTEXT, ListEntry);
        if (context->ProcessId == ProcessId && !context->Removed) {
            InterlockedIncrement(&context->RefCount);
            ExReleasePushLockShared(&g_WkdPasState.ProcessContextLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&g_WkdPasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    newContext = (PWKD_PAS_PROCESS_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_PAS_PROCESS_CONTEXT), WKD_PAS_POOL_TAG);
    if (newContext == NULL) {
        return NULL;
    }
    RtlZeroMemory(newContext, sizeof(WKD_PAS_PROCESS_CONTEXT));
    newContext->ProcessId = ProcessId;
    newContext->RefCount = 2;   /* 链表引用 + 调用者引用 */
    KeQuerySystemTime(&newContext->ProcessCreateTime);
    KeQuerySystemTime(&newContext->WindowStartTime);
    newContext->IsEarlyProcess = TRUE;
    InitializeListHead(&newContext->ListEntry);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.ProcessContextLock);

    for (entry = g_WkdPasState.ProcessContextList.Flink;
         entry != &g_WkdPasState.ProcessContextList;
         entry = entry->Flink) {
        context = CONTAINING_RECORD(entry, WKD_PAS_PROCESS_CONTEXT, ListEntry);
        if (context->ProcessId == ProcessId && !context->Removed) {
            InterlockedIncrement(&context->RefCount);
            ExReleasePushLockExclusive(&g_WkdPasState.ProcessContextLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(newContext, WKD_PAS_POOL_TAG);
            return context;
        }
    }

    InsertTailList(&g_WkdPasState.ProcessContextList, &newContext->ListEntry);
    InterlockedIncrement(&g_WkdPasState.ProcessContextCount);

    ExReleasePushLockExclusive(&g_WkdPasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    return newContext;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasReferenceProcessContext(
    _Inout_ PWKD_PAS_PROCESS_CONTEXT Context
    )
{
    if (Context != NULL) {
        InterlockedIncrement(&Context->RefCount);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasDereferenceProcessContext(
    _Inout_ PWKD_PAS_PROCESS_CONTEXT Context
    )
{
    LONG newRef;

    if (Context == NULL) {
        return;
    }

    newRef = InterlockedDecrement(&Context->RefCount);
    if (newRef > 0) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.ProcessContextLock);

    if (InterlockedCompareExchange(&Context->RefCount, 0, 0) == 0) {
        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_WkdPasState.ProcessContextCount);
        }
        ExReleasePushLockExclusive(&g_WkdPasState.ProcessContextLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(Context, WKD_PAS_POOL_TAG);
        return;
    }

    ExReleasePushLockExclusive(&g_WkdPasState.ProcessContextLock);
    KeLeaveCriticalRegion();
}

/**************************************************/
/*              主检测流水线（活代码）              */
/**************************************************/

/*
 * 处理一次可执行映射（对齐 SS ShadowStrikePreAcquireSection 行为检测主体）。
 * 由 Filter.c FspPreAcquireSection 在 SyncTypeCreateSection+执行保护、已查名
 * 后调用。内部：
 *   1) 查找进程权威副本 WKD_PROCESS（SectionMapProfile 内嵌，PID 复用防护内建）；
 *   2) 分类 + 预映射标志（B2 路径/卷类型已在回调壳映射为 PreMappedFlags）；
 *   3) 早期进程窗口（创建后 5s）过期清除（依据 Core.CreateTime）；
 *   4) 更新画像计数 → 行为检测（空心化/注入/反射/快速映射）；
 *   5) 评分融合（PAS 基础分 + B2 路径分封顶 +40）；
 *   6) 写回画像、输出 Score/MappingFlags。
 * 阻断决策（EnableBlocking 门控 + 自保护强信号）在回调壳执行，本函数只计算不阻断。
 */
_Use_decl_annotations_
NTSTATUS
WkdPasProcessMapping(
    _In_ PWKD_PAS_INPUT Input,
    _Out_opt_ PULONG Score,
    _Out_opt_ PULONG MappingFlags
    )
{
    PWKD_PROCESS process;
    PWKD_PAS_PROCESS_PROFILE profile;
    WKD_PAS_MAPPING_RECORD record;
    ULONG flags;
    ULONG score = 0;
    LARGE_INTEGER currentTime;

    if (Score != NULL) *Score = 0;
    if (MappingFlags != NULL) *MappingFlags = 0;

    if (!g_WkdPasState.Initialized || g_WkdPasState.ShutdownRequested) {
        return STATUS_SUCCESS;
    }
    if (Input == NULL || Input->ProcessId == (HANDLE)(ULONG_PTR)4) {
        return STATUS_SUCCESS;
    }
    if (!(Input->PageProtection & PAS_EXECUTE_PROTECTION_MASK)) {
        return STATUS_SUCCESS;   /* 仅执行映射 */
    }

    /* 统计 */
    InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.TotalCalls);
    InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.ExecuteMappings);
    if (Input->PageProtection & SEC_IMAGE) {
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.ImageMappings);
    }

    /* 查找进程权威副本（FORCEINLINE 哈希表查找；Dereference 前持有引用防并发销毁） */
    process = PsLookupWkdProcessByProcessId(Input->ProcessId);
    if (process == NULL) {
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.Allowed);
        return STATUS_SUCCESS;
    }
    PsReferenceWkdProcess(process);
    profile = &process->SectionMapProfile;

    /* 早期进程窗口（创建后 5s）过期清除，依据 Core.CreateTime */
    if (profile->IsEarlyProcess) {
        KeQuerySystemTime(&currentTime);
        if (currentTime.QuadPart - process->Core.CreateTime.QuadPart >
            (LONGLONG)PAS_HOLLOWING_EARLY_WINDOW_MS * 10000) {
            profile->IsEarlyProcess = FALSE;
        }
    }

    /* 单映射记录（栈上评分载体；LRU 逐记录追踪为死代码） */
    RtlZeroMemory(&record, sizeof(record));
    record.ProcessId = Input->ProcessId;
    record.PageProtection = Input->PageProtection;
    record.SectionType = (Input->PageProtection & SEC_IMAGE) ? 1 : 0;
    KeQuerySystemTime(&record.Timestamp);

    /* 分类 + 预映射标志（B2 路径/卷类型）+ 早期进程 */
    flags = WkdPasClassifyMapping(Input->PageProtection);
    flags |= Input->PreMappedFlags;
    if (profile->IsEarlyProcess) {
        flags |= PAS_MAP_FLAG_EARLY_PROCESS;
    }

    /* 文件名可疑（SectionTracker 迁移 2026-08，对齐 SS SecpIsSuspiciousName）：
     * 双扩展名 + 可疑尾扩展 / 超长文件名 → 置 SUSPICIOUS_PATH（评分 +20）。
     * 注：匿名可执行 Section（SS ExecuteAnonymous=150/LargeAnonymous=80）在
     * minifilter 文件轨不触发（无文件 IRP），归 syscall 轨 NtCreateSection
     * 捕获（SmInitialize 激活后补，死代码预留）。 */
    if (Input->FileName != NULL &&
        WkdPasIsSuspiciousName(Input->FileName)) {
        flags |= PAS_MAP_FLAG_SUSPICIOUS_PATH;
    }

    record.MappingFlags = flags;

    /* 先更新画像计数，再行为检测（对齐 SS：检测读 RecentExecutables） */
    WkdPasUpdateProcessMetrics(profile, &record);

    /* 空心化（4 信号；全线程挂起信号为死代码） */
    if (g_WkdPasState.Config.EnableHollowingDetection &&
        WkdPasDetectHollowingPattern(profile, &record)) {
        flags |= PAS_MAP_FLAG_HOLLOWING_SUSPECT;
        InterlockedOr((PLONG)&profile->BehaviorFlags, PAS_BEHAVIOR_HOLLOWING);
        profile->IsHollowingSuspect = TRUE;
        score += 30;
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.HollowingDetected);
    }

    /* DLL 注入（跨进程映射 / W+RX 且网络·可移除卷） */
    if (g_WkdPasState.Config.EnableInjectionDetection &&
        WkdPasDetectInjectionPattern(profile, &record)) {
        InterlockedOr((PLONG)&profile->BehaviorFlags, PAS_BEHAVIOR_CROSS_PROCESS);
        profile->IsInjectionSuspect = TRUE;
        score += 25;
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.InjectionDetected);
    }

    /* 反射加载（W+RX + 可疑路径/Temp/快速） */
    if (g_WkdPasState.Config.EnableReflectiveDetection &&
        WkdPasDetectReflectiveLoading(profile, &record)) {
        flags |= PAS_MAP_FLAG_REFLECTIVE_SUSPECT;
        InterlockedOr((PLONG)&profile->BehaviorFlags, PAS_BEHAVIOR_REFLECTIVE);
        profile->IsReflectiveSuspect = TRUE;
        score += 35;
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.ReflectiveDetected);
    }

    /* 快速映射异常（窗口内 > AnomalyThreshold=10） */
    if (InterlockedCompareExchange(&profile->RecentMappings, 0, 0) >
        (LONG)g_WkdPasState.Config.AnomalyThreshold) {
        InterlockedOr((PLONG)&profile->BehaviorFlags, PAS_BEHAVIOR_RAPID_MAPPING);
        score += 15;
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.RapidDetected);
    }

    record.MappingFlags = flags;

    /* 评分融合：PAS 基础分（含行为累计） + B2 路径分（封顶 +40 防双重计数） */
    {
        ULONG baseScore = WkdPasCalculateSuspicionScore(&record, profile);
        if (baseScore > score) score = baseScore;
    }
    if (Input->PathScore > 0) {
        ULONG pathAdd = (Input->PathScore < 40) ? Input->PathScore : 40;
        score = (score > 100 - pathAdd) ? 100 : (score + pathAdd);
    }

    record.SuspicionScore = score;

    /* 写回进程级峰值分（仅更高时更新） */
    if (score > (ULONG)InterlockedCompareExchange(&profile->SuspicionScore, 0, 0)) {
        InterlockedExchange((PLONG)&profile->SuspicionScore, (LONG)score);
    }

    /* 可疑映射统计 */
    if (score >= g_WkdPasState.Config.SuspicionMedium) {
        InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.SuspiciousDetected);
        InterlockedIncrement64((PLONG64)&profile->SuspiciousMappings);
    }

    if (Score != NULL) *Score = score;
    if (MappingFlags != NULL) *MappingFlags = flags;

    PsDereferenceWkdProcess(process);
    return STATUS_SUCCESS;
}

/**************************************************/
/*            状态/配置/统计访问器                 */
/*  供 Filter.c 回调壳使用，不暴露内部全局。        */
/**************************************************/

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasIsActive(
    VOID
    )
{
    return g_WkdPasState.Initialized && !g_WkdPasState.ShutdownRequested;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasShouldReport(
    _In_ ULONG Score
    )
{
    return Score >= g_WkdPasState.Config.SuspicionMedium;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasShouldBlock(
    _In_ ULONG Score
    )
{
    return g_WkdPasState.Config.EnableBlocking &&
           Score >= g_WkdPasState.Config.MinBlockScore;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteSelfProtectBlock(
    VOID
    )
{
    InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.SelfProtectionBlocks);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteBlocked(
    VOID
    )
{
    InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.Blocked);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteAllowed(
    VOID
    )
{
    InterlockedIncrement64((PLONG64)&g_WkdPasState.Stats.Allowed);
}

/**************************************************/
/*              初始化 / 清理（活代码）             */
/**************************************************/

/*
 * 初始化（对齐 SS PaspInitialize）。由 Filter.c FsInitialize 在注册
 * AcquireSection IRP 后调用（PASSIVE_LEVEL）。初始化配置默认值（阻断
 * Audit 门控，对齐 wkd NamedPipeMonitor/AppControl 惯例）与统计计数。
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPasInitialize(
    VOID
    )
{
    if (g_WkdPasState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_WkdPasState, sizeof(g_WkdPasState));

    /* 配置默认值：阻断 Audit（默认关，仅上报+评分），检测全开 */
    g_WkdPasState.Config.EnableBlocking = FALSE;
    g_WkdPasState.Config.EnableHollowingDetection = TRUE;
    g_WkdPasState.Config.EnableInjectionDetection = TRUE;
    g_WkdPasState.Config.EnableReflectiveDetection = TRUE;
    g_WkdPasState.Config.MinBlockScore = PAS_MIN_BLOCK_SCORE;
    g_WkdPasState.Config.SuspicionMedium = PAS_SUSPICION_MEDIUM_DEFAULT;
    g_WkdPasState.Config.AnomalyThreshold = PAS_ANOMALY_THRESHOLD_DEFAULT;

    ExInitializePushLock(&g_WkdPasState.ConfigLock);

    /* 死代码字段（SS 原版独立上下文机制，保留初始化供死代码分区编译） */
    InitializeListHead(&g_WkdPasState.ProcessContextList);
    ExInitializePushLock(&g_WkdPasState.ProcessContextLock);
    InitializeListHead(&g_WkdPasState.MappingList);
    ExInitializePushLock(&g_WkdPasState.MappingLock);
    for (ULONG i = 0; i < WKD_PAS_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_WkdPasState.HashTable[i].List);
        ExInitializePushLock(&g_WkdPasState.HashTable[i].Lock);
    }

    g_WkdPasState.ShutdownRequested = FALSE;
    g_WkdPasState.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender/PreAcquireSection] Initialized (blocking=%s)\n",
        g_WkdPasState.Config.EnableBlocking ? "ENABLE" : "audit");

    return STATUS_SUCCESS;
}

/*
 * 清理（对齐 SS PaspShutdown）。由 Filter.c FsCleanup 调用。
 * 画像随 WKD_PROCESS 释放，此处仅置状态标志 + 清空死代码链表。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPasShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;
    PWKD_PAS_PROCESS_CONTEXT context;

    if (!g_WkdPasState.Initialized) {
        return;
    }
    g_WkdPasState.Initialized = FALSE;
    g_WkdPasState.ShutdownRequested = TRUE;

    /* 死代码链表（正常为空；SS 原版独立上下文已在迁移中废弃） */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.ProcessContextLock);
    while (!IsListEmpty(&g_WkdPasState.ProcessContextList)) {
        entry = RemoveHeadList(&g_WkdPasState.ProcessContextList);
        context = CONTAINING_RECORD(entry, WKD_PAS_PROCESS_CONTEXT, ListEntry);
        ExFreePoolWithTag(context, WKD_PAS_POOL_TAG);
    }
    ExReleasePushLockExclusive(&g_WkdPasState.ProcessContextLock);
    KeLeaveCriticalRegion();
}

/**************************************************/
/*        死代码补遗分区（SS 功能面补全）            */
/*  以下为 SS PreAcquireSection 未随活路径迁移的     */
/*  机制/接口层功能，保留实现供未来接入，标注接入前提 */
/*  与不接入原因。全部 static + 4505 抑制未引用警告。 */
/**************************************************/

/* 全线程挂起检测（空心化第 4 信号）依赖的系统进程信息结构（对齐 SS
 * PAS_SYSTEM_* L132-182）。SYSTEM_PROCESS_INFORMATION 未在 WDK 头完整导出，
 * 自定义布局（对齐 SS）。 */
typedef struct _WKD_PAS_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} WKD_PAS_SYSTEM_THREAD_INFORMATION, *PWKD_PAS_SYSTEM_THREAD_INFORMATION;

typedef struct _WKD_PAS_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    WKD_PAS_SYSTEM_THREAD_INFORMATION Threads[1];
} WKD_PAS_SYSTEM_PROCESS_INFORMATION, *PWKD_PAS_SYSTEM_PROCESS_INFORMATION;

#define WKD_PAS_SYSTEM_PROCESS_INFO_CLASS  5   /* SystemProcessInformation */
#define WKD_PAS_THREAD_STATE_WAITING       5   /* KTHREAD_STATE::Waiting */
#define WKD_PAS_WAIT_REASON_SUSPENDED      5   /* KWAIT_REASON::Suspended */

/* 死代码常量（对齐 SS）：映射记录容量 / 过期超时 */
#define WKD_PAS_MAX_TRACKED_RECORDS      4096
#define WKD_PAS_MAPPING_TIMEOUT_100NS    (300000LL * 10000LL)   /* 5 分钟 */

/* ZwQuerySystemInformation 函数指针（仿 ProcessMonitor.c L249-256，规避链接期
 * 未导出；死代码函数内 MmGetSystemRoutineAddress 自取）。 */
typedef NTSTATUS (*WKD_PAS_PFN_ZwQuerySystemInformation)(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/*
 * 全线程挂起检测（空心化第 4 信号，死代码对齐 SS PaspIsProcessSuspended L794-916）。
 * ZwQuerySystemInformation(SystemProcessInformation) 全量枚举 → 目标进程全部
 * 线程 ThreadState==Waiting && WaitReason==Suspended → 空心化强信号。
 * 成本高（256KB~4MB 缓冲 + 全线程遍历），活路径不调用；接入时评估改用进程挂起
 * 状态缓存或 agent 侧线程验证（ProcessThreads WptValidateThread 死代码）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasIsProcessSuspended(
    _In_ HANDLE ProcessId
    )
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 256 * 1024;
    ULONG returnLength = 0;
    PWKD_PAS_SYSTEM_PROCESS_INFORMATION processInfo;
    BOOLEAN hasSuspendedThreads = FALSE;
    UNICODE_STRING usName;
    WKD_PAS_PFN_ZwQuerySystemInformation pfnQuery;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return FALSE;
    }

    RtlInitUnicodeString(&usName, L"ZwQuerySystemInformation");
    pfnQuery = (WKD_PAS_PFN_ZwQuerySystemInformation)
        MmGetSystemRoutineAddress(&usName);
    if (pfnQuery == NULL) {
        return FALSE;
    }

    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, WKD_PAS_POOL_TAG);
    if (buffer == NULL) {
        return FALSE;
    }

    status = pfnQuery(WKD_PAS_SYSTEM_PROCESS_INFO_CLASS, buffer, bufferSize, &returnLength);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePoolWithTag(buffer, WKD_PAS_POOL_TAG);
        bufferSize = returnLength + (64 * 1024);
        if (bufferSize > 4 * 1024 * 1024) {
            return FALSE;
        }
        buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, WKD_PAS_POOL_TAG);
        if (buffer == NULL) {
            return FALSE;
        }
        status = pfnQuery(WKD_PAS_SYSTEM_PROCESS_INFO_CLASS, buffer, bufferSize, NULL);
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, WKD_PAS_POOL_TAG);
        return FALSE;
    }

    processInfo = (PWKD_PAS_SYSTEM_PROCESS_INFORMATION)buffer;
    for (;;) {
        if (processInfo->UniqueProcessId == ProcessId) {
            ULONG threadCount = processInfo->NumberOfThreads;
            ULONG suspendedCount = 0;
            PWKD_PAS_SYSTEM_THREAD_INFORMATION threadInfo;

            if (threadCount == 0) {
                break;
            }
            threadInfo = processInfo->Threads;
            for (ULONG i = 0; i < threadCount; i++) {
                if (threadInfo[i].ThreadState == WKD_PAS_THREAD_STATE_WAITING &&
                    threadInfo[i].WaitReason == WKD_PAS_WAIT_REASON_SUSPENDED) {
                    suspendedCount++;
                }
            }
            /* 全部线程挂起才判空心化强信号（对齐 SS：单线程挂起意义弱） */
            if (suspendedCount > 0 && suspendedCount == threadCount) {
                hasSuspendedThreads = TRUE;
            }
            break;
        }
        if (processInfo->NextEntryOffset == 0) {
            break;
        }
        processInfo = (PWKD_PAS_SYSTEM_PROCESS_INFORMATION)(
            (PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, WKD_PAS_POOL_TAG);
    return hasSuspendedThreads;
}

/*
 * 映射记录 FileId 哈希（死代码，对齐 SS PaspHashFileId L2266-2283）。
 * 活路径用栈上记录，本函数供逐记录 LRU 追踪激活时使用。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdPasHashFileId(
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    )
{
    ULONG hash;

    hash = (ULONG)(FileId ^ (FileId >> 32));
    hash ^= VolumeSerial;
    hash = hash * 0x85EBCA6B;
    hash ^= hash >> 13;
    return hash & WKD_PAS_HASH_BUCKET_MASK;
}

/* 插入映射记录（死代码：MappingList 尾插 LRU + 哈希桶索引，对齐 SS PaspInsertRecord） */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasInsertRecord(
    _In_ PWKD_PAS_MAPPING_RECORD Record
    )
{
    ULONG bucketIndex;
    PWKD_PAS_HASH_BUCKET bucket;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.MappingLock);
    InsertTailList(&g_WkdPasState.MappingList, &Record->ListEntry);
    InterlockedIncrement(&g_WkdPasState.MappingCount);
    ExReleasePushLockExclusive(&g_WkdPasState.MappingLock);
    KeLeaveCriticalRegion();

    bucketIndex = WkdPasHashFileId(Record->FileId, Record->VolumeSerial);
    bucket = &g_WkdPasState.HashTable[bucketIndex];
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&bucket->Lock);
    InsertTailList(&bucket->List, &Record->HashEntry);
    ExReleasePushLockExclusive(&bucket->Lock);
    KeLeaveCriticalRegion();
}

/* 前向声明（定义在本函数之后，C 前向引用需先行声明） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID WkdPasFreeRecord(_In_ PWKD_PAS_MAPPING_RECORD Record);

/* LRU 淘汰（死代码：MappingList 头部最旧，淘汰 Count 条，对齐 SS PaspEvictOldestRecords） */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasEvictOldestRecords(
    _In_ ULONG Count
    )
{
    LIST_ENTRY evictList;
    PLIST_ENTRY entry;
    PWKD_PAS_MAPPING_RECORD record;
    ULONG evicted = 0;
    ULONG bucketIndex;
    PWKD_PAS_HASH_BUCKET bucket;

    InitializeListHead(&evictList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.MappingLock);
    while (!IsListEmpty(&g_WkdPasState.MappingList) && evicted < Count) {
        entry = RemoveHeadList(&g_WkdPasState.MappingList);
        record = CONTAINING_RECORD(entry, WKD_PAS_MAPPING_RECORD, ListEntry);
        InterlockedDecrement(&g_WkdPasState.MappingCount);
        InsertTailList(&evictList, &record->ListEntry);
        evicted++;
    }
    ExReleasePushLockExclusive(&g_WkdPasState.MappingLock);
    KeLeaveCriticalRegion();

    /* 从哈希桶摘除 + 释放（锁外，避免长时间持桶锁） */
    while (!IsListEmpty(&evictList)) {
        entry = RemoveHeadList(&evictList);
        record = CONTAINING_RECORD(entry, WKD_PAS_MAPPING_RECORD, ListEntry);

        bucketIndex = WkdPasHashFileId(record->FileId, record->VolumeSerial);
        bucket = &g_WkdPasState.HashTable[bucketIndex];
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);
        if (!IsListEmpty(&record->HashEntry)) {
            RemoveEntryList(&record->HashEntry);
            InitializeListHead(&record->HashEntry);
        }
        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();

        WkdPasFreeRecord(record);
    }
}

/* 释放映射记录（死代码） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdPasFreeRecord(
    _In_ PWKD_PAS_MAPPING_RECORD Record
    )
{
    if (Record != NULL) {
        ExFreePoolWithTag(Record, WKD_PAS_POOL_TAG);
    }
}

/* 分配映射记录 + 容量管理（死代码：对齐 SS PaspAllocateRecord L2073-2123 的
 * LRU 淘汰，替代 lookaside 用 ExAllocatePool2） */
_IRQL_requires_(PASSIVE_LEVEL)
static PWKD_PAS_MAPPING_RECORD
WkdPasAllocateRecord(
    VOID
    )
{
    PWKD_PAS_MAPPING_RECORD record;
    LONG currentCount;

    currentCount = InterlockedCompareExchange(&g_WkdPasState.MappingCount, 0, 0);
    if ((ULONG)currentCount >= WKD_PAS_MAX_TRACKED_RECORDS) {
        WkdPasEvictOldestRecords(64);
    }

    record = (PWKD_PAS_MAPPING_RECORD)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_PAS_MAPPING_RECORD), WKD_PAS_POOL_TAG);
    if (record != NULL) {
        RtlZeroMemory(record, sizeof(WKD_PAS_MAPPING_RECORD));
        InitializeListHead(&record->ListEntry);
        InitializeListHead(&record->HashEntry);
    }
    return record;
}

/*
 * 过期记录清理（死代码：对齐 SS PaspCleanupStaleRecords L2776-2843，1min 周期）。
 * 画像随 WKD_PROCESS 回收无需定时器；逐记录表启用时以 1min 工作项周期调用。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasCleanupStaleRecords(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry, next;
    PWKD_PAS_MAPPING_RECORD record;
    LIST_ENTRY staleList;
    ULONG bucketIndex;
    PWKD_PAS_HASH_BUCKET bucket;

    PAGED_CODE();
    InitializeListHead(&staleList);
    KeQuerySystemTime(&currentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.MappingLock);
    for (entry = g_WkdPasState.MappingList.Flink;
         entry != &g_WkdPasState.MappingList;
         entry = next) {
        next = entry->Flink;
        record = CONTAINING_RECORD(entry, WKD_PAS_MAPPING_RECORD, ListEntry);
        if ((currentTime.QuadPart - record->Timestamp.QuadPart) >
            WKD_PAS_MAPPING_TIMEOUT_100NS) {
            RemoveEntryList(&record->ListEntry);
            InterlockedDecrement(&g_WkdPasState.MappingCount);
            InsertTailList(&staleList, &record->ListEntry);
        }
    }
    ExReleasePushLockExclusive(&g_WkdPasState.MappingLock);
    KeLeaveCriticalRegion();

    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        record = CONTAINING_RECORD(entry, WKD_PAS_MAPPING_RECORD, ListEntry);

        bucketIndex = WkdPasHashFileId(record->FileId, record->VolumeSerial);
        bucket = &g_WkdPasState.HashTable[bucketIndex];
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);
        if (!IsListEmpty(&record->HashEntry)) {
            RemoveEntryList(&record->HashEntry);
            InitializeListHead(&record->HashEntry);
        }
        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();

        WkdPasFreeRecord(record);
    }
}

/*
 * 扫描缓存命中查询（死代码：wkd 无内核扫描缓存）。
 * 接入前提：PreCreate 把 YARA verdict 写入内核缓存（FileId+VolumeSerial → Verdict）。
 * 命中 Malicious → ShouldBlock=TRUE + Score=100（对齐 SS CacheResult.Verdict==
 * Verdict_Malicious L1527-1542 立即阻断）。当前恒未命中。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdPasCheckCachedVerdict(
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial,
    _Out_ PBOOLEAN ShouldBlock,
    _Out_ PULONG Score
    )
{
    UNREFERENCED_PARAMETER(FileId);
    UNREFERENCED_PARAMETER(VolumeSerial);
    if (ShouldBlock) *ShouldBlock = FALSE;
    if (Score) *Score = 0;
    return FALSE;
}

/* 统计查询（死代码，对齐 SS ShadowStrikeGetPreAcquireSectionStats L2864-2903） */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdPasGetStats(
    _Out_opt_ PULONG64 TotalCalls,
    _Out_opt_ PULONG64 ExecuteMappings,
    _Out_opt_ PULONG64 Blocked,
    _Out_opt_ PULONG64 HollowingDetected,
    _Out_opt_ PULONG64 InjectionDetected
    )
{
    if (!g_WkdPasState.Initialized) {
        return STATUS_NOT_FOUND;
    }
    if (TotalCalls) *TotalCalls = g_WkdPasState.Stats.TotalCalls;
    if (ExecuteMappings) *ExecuteMappings = g_WkdPasState.Stats.ExecuteMappings;
    if (Blocked) *Blocked = g_WkdPasState.Stats.Blocked;
    if (HollowingDetected) *HollowingDetected = g_WkdPasState.Stats.HollowingDetected;
    if (InjectionDetected) *InjectionDetected = g_WkdPasState.Stats.InjectionDetected;
    return STATUS_SUCCESS;
}

/* 进程映射画像查询（死代码，对齐 SS ShadowStrikeQueryProcessMappingContext
 * L2921-2964。活数据在 WKD_PROCESS.SectionMapProfile，经 PsLookupWkdProcessByProcessId
 * 读取，引用保护防并发销毁）。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdPasQueryProcessMappingContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN IsHollowingSuspect,
    _Out_opt_ PBOOLEAN IsInjectionSuspect,
    _Out_opt_ PBOOLEAN IsReflectiveSuspect,
    _Out_opt_ PULONG SuspicionScore
    )
{
    PWKD_PROCESS process;
    PWKD_PAS_PROCESS_PROFILE profile;

    if (!g_WkdPasState.Initialized) {
        return STATUS_NOT_FOUND;
    }
    process = PsLookupWkdProcessByProcessId(ProcessId);
    if (process == NULL) {
        return STATUS_NOT_FOUND;
    }
    PsReferenceWkdProcess(process);
    profile = &process->SectionMapProfile;
    if (IsHollowingSuspect) *IsHollowingSuspect = profile->IsHollowingSuspect;
    if (IsInjectionSuspect) *IsInjectionSuspect = profile->IsInjectionSuspect;
    if (IsReflectiveSuspect) *IsReflectiveSuspect = profile->IsReflectiveSuspect;
    if (SuspicionScore) *SuspicionScore = (ULONG)profile->SuspicionScore;
    PsDereferenceWkdProcess(process);
    return STATUS_SUCCESS;
}

/* 进程退出清理（死代码：画像随 PspDestroyProcess 统一回收，本函数为 SS
 * ShadowStrikeRemoveProcessMappingContext 接口对齐占位，无实际清理动作） */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdPasRemoveProcessMappingContext(
    _In_ HANDLE ProcessId
    )
{
    UNREFERENCED_PARAMETER(ProcessId);
}

/* 配置更新（死代码，对齐 SS ShadowStrikeUpdatePreAcquireSectionConfig L3037-3071。
 * 接入前提：agent 策略下发通道。接入时需同步访问器（WkdPasShouldBlock 等）加锁，
 * 当前 Config 仅初始化时设置不可变，无竞态）。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdPasUpdateConfig(
    _In_ PWKD_PAS_CONFIG Config
    )
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_WkdPasState.Initialized) {
        return STATUS_NOT_FOUND;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPasState.ConfigLock);
    g_WkdPasState.Config = *Config;
    ExReleasePushLockExclusive(&g_WkdPasState.ConfigLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

/* 配置获取（死代码，对齐 SS ShadowStrikeGetPreAcquireSectionConfig L3086-3107） */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdPasGetConfig(
    _Out_ PWKD_PAS_CONFIG Config
    )
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_WkdPasState.Initialized) {
        return STATUS_NOT_FOUND;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_WkdPasState.ConfigLock);
    *Config = g_WkdPasState.Config;
    ExReleasePushLockShared(&g_WkdPasState.ConfigLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

/* 扩展统计（死代码，对齐 SS ShadowStrikeGetPreAcquireSectionExtendedStats L3120-3142） */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdPasGetExtendedStats(
    _Out_ PWKD_PAS_STATS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_WkdPasState.Initialized) {
        RtlZeroMemory(Stats, sizeof(WKD_PAS_STATS));
        return STATUS_NOT_FOUND;
    }
    *Stats = g_WkdPasState.Stats;
    return STATUS_SUCCESS;
}

#pragma warning(pop)
