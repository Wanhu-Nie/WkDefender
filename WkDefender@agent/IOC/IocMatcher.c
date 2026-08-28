/**************************************************/
/*  WkDefender IOC Matcher — 实时 IOC 匹配引擎       */
/*  移植自 ShadowStrike PhantomSensor IOCMatcher     */
/*  (c) 2026 WkDefender Team. All rights reserved.  */
/*                                                   */
/*  内核→用户态适配版：                                */
/*  - ExAllocatePool2 → UtHeapAlloc                  */
/*  - EX_PUSH_LOCK → CRITICAL_SECTION                */
/*  - KSPIN_LOCK   → CRITICAL_SECTION                */
/*  - KeQuerySystemTime → GetSystemTimeAsFileTime     */
/*                                                   */
/*  SS IOCMatcher.c 功能面覆盖状态（2026-08-05）：    */
/*  - 已覆盖活代码：Initialize/Shutdown/BloomCheck    */
/*    （BloomCheck 为 IocScanner.c:146 唯一调用点，    */
/*      已修复空布隆短路：IOCCount==0 时保守放行）     */
/*  - 已覆盖死代码（无外部调用者，接入点待定）：       */
/*    LoadIOC/LoadFromBuffer/Match/MatchHash/         */
/*    RemoveIOC/CleanupExpired/RegisterCallback/      */
/*    GetStatistics/GetIOCCount                       */
/*  - 死代码函数：IompRequiresPatternMatching         */
/*    （Match 内未调用，以 useHashLookup 替代）        */
/*  - 未迁移：SS 的 CO_CACHE 匹配结果缓存             */
/*    （g_IomMatchCoCache 创建但匹配路径未接线，       */
/*    SS 半成品；用户态如需结果缓存参考               */
/*    ScanManager.c 的 g_ScanCache 固定数组模式）      */
/*  - 枚举对齐：IocMatchMode_Regex/IocType_YARA       */
/*    （SS 亦未实现正则，仅预留）                     */
/**************************************************/

#include "IocMatcher.h"
#include "IocMatcherMatch.h"    /* 通配符/域名/IP 匹配函数 */
#include "../Common/Utils.h"     /* UtHeapAlloc, UtHeapFree */

#include <string.h>
#include <assert.h>

/**************************************************/
/*               常量                               */
/**************************************************/

#define IOM_DEFAULT_HASH_BUCKETS            4096
#define IOM_MAX_BUFFER_SIZE                 (64 * 1024 * 1024)  /* 64MB 缓冲区上限 */

/**************************************************/
/*               内部结构体                         */
/**************************************************/

/* 回调注册（原子可切换） */
typedef struct _IOM_CALLBACK_REG {
    IOC_MATCH_CALLBACK  Callback;
    PVOID               Context;
} IOM_CALLBACK_REG, *PIOM_CALLBACK_REG;

/* 单条 IOC 内部结构 */
typedef struct _IOM_IOC_INTERNAL {
    ULONG64             Id;
    IOC_MATCH_TYPE      Type;
    IOC_SEVERITY        Severity;
    CHAR                Value[IOC_MAX_VALUE_LENGTH];
    SIZE_T              ValueLength;
    CHAR                Description[IOC_MAX_DESCRIPTION_LENGTH];
    CHAR                ThreatName[IOC_MAX_THREAT_NAME_LENGTH];
    CHAR                Source[IOC_MAX_SOURCE_LENGTH];
    LARGE_INTEGER       LastUpdated;
    LARGE_INTEGER       Expiry;
    BOOLEAN             CaseSensitive;
    IOC_MATCH_MODE      MatchMode;

    ULONG64             ValueHash;          /* FNV-1a 哈希值 */
    volatile LONG       RefCount;           /* 引用计数 */
    volatile BOOLEAN    IsExpired;
    volatile BOOLEAN    MarkedForDeletion;
    volatile LONG64     MatchCount;

    /* 链表条目 */
    LIST_ENTRY          GlobalListEntry;
    LIST_ENTRY          HashBucketEntry;
    LIST_ENTRY          TypeListEntry;
    LIST_ENTRY          TypeHashBucketEntry;
} IOM_IOC_INTERNAL, *PIOM_IOC_INTERNAL;

/* 类型索引 */
typedef struct _IOM_TYPE_INDEX {
    LIST_ENTRY          IOCList;
    CRITICAL_SECTION    Lock;
    volatile LONG       Count;
    PLIST_ENTRY         HashBuckets;
    ULONG               BucketCount;
} IOM_TYPE_INDEX, *PIOM_TYPE_INDEX;

/* 主引擎结构 */
typedef struct _IOC_MATCHER_INTERNAL {
    volatile BOOLEAN    Initialized;
    volatile BOOLEAN    ShuttingDown;

    /* 引用计数关闭闸门 */
    volatile LONG       RefCount;
    HANDLE              RefZeroEvent;       /* CreateEvent, manual-reset */

    /* 全局 IOC 存储 */
    LIST_ENTRY          GlobalIOCList;
    CRITICAL_SECTION    GlobalLock;
    volatile LONG       IOCCount;

    /* 主哈希表 */
    PLIST_ENTRY         HashBuckets;
    ULONG               HashBucketCount;
    CRITICAL_SECTION    HashLock;

    /* 类型索引 */
    IOM_TYPE_INDEX      TypeIndices[IocType_MaxValue];

    /* 布隆过滤器 */
    struct {
        PUCHAR          Filter;
        SIZE_T          Size;
        ULONG           HashCount;
        volatile BOOLEAN Enabled;
    } BloomFilter;

    /* 回调注册 */
    volatile PIOM_CALLBACK_REG CallbackReg;
    CRITICAL_SECTION    CallbackLock;

    /* 清理线程 */
    HANDLE              CleanupThread;
    HANDLE              CleanupWakeEvent;   /* CreateEvent, auto-reset */
    volatile BOOLEAN    CleanupTerminate;
    volatile LONG       CleanupInProgress;

    /* IOC ID 生成器 */
    volatile LONG64     NextIOCId;

    /* 配置 */
    IOC_MATCHER_CONFIG  Config;

    /* 统计 */
    IOC_MATCHER_STATS   Stats;
} IOC_MATCHER_INTERNAL, *PIOC_MATCHER_INTERNAL;

/**************************************************/
/*               全局实例                           */
/**************************************************/

static IOC_MATCHER_INTERNAL g_IocMatcher = { 0 };

/**************************************************/
/*               前向声明                           */
/**************************************************/

static ULONG64 IompComputeHash(_In_reads_bytes_(Length) PCUCHAR Data, _In_ SIZE_T Length, _In_ ULONG64 Seed);
static ULONG   IompComputeBucket(_In_ ULONG64 Hash, _In_ ULONG BucketCount);

static VOID    IompBloomFilterAdd(_In_ PIOC_MATCHER_INTERNAL Matcher, _In_reads_bytes_(Length) PCUCHAR Data, _In_ SIZE_T Length);
static BOOLEAN IompBloomFilterCheck(_In_ PIOC_MATCHER_INTERNAL Matcher, _In_reads_bytes_(Length) PCUCHAR Data, _In_ SIZE_T Length);

static VOID    IompInsertIOCIntoIndices(_In_ PIOC_MATCHER_INTERNAL Matcher, _In_ PIOM_IOC_INTERNAL IOC);
static VOID    IompRemoveIOCFromIndices(_In_ PIOC_MATCHER_INTERNAL Matcher, _In_ PIOM_IOC_INTERNAL IOC);

static BOOLEAN IompAcquireIOCReference(_In_ PIOM_IOC_INTERNAL IOC);
static VOID    IompReleaseIOCReference(_In_ PIOM_IOC_INTERNAL IOC);

static VOID    IompPopulateMatchResult(_In_ PIOM_IOC_INTERNAL IOC, _In_z_ PCSTR MatchedValue,
                                        _In_ SIZE_T MatchedValueLength, _In_opt_ HANDLE ProcessId,
                                        _Out_ PIOC_MATCH_RESULT Result);
static VOID    IompNotifyCallback(_In_ PIOC_MATCHER_INTERNAL Matcher, _In_ PIOC_MATCH_RESULT Result);

static ULONG   IompGetBucketCountForType(_In_ IOC_MATCH_TYPE Type);
static BOOLEAN IompValidateHashLength(_In_ IOC_MATCH_TYPE Type, _In_ SIZE_T Length);
static BOOLEAN IompRequiresPatternMatching(_In_ IOC_MATCH_TYPE Type, _In_ IOC_MATCH_MODE Mode);
static SIZE_T  IompSafeStringLength(_In_reads_(MaxLength) PCSTR String, _In_ SIZE_T MaxLength);

static DWORD WINAPI IompCleanupThreadRoutine(_In_ LPVOID Context);
static VOID         IompCleanupExpiredIOCsWorker(_In_ PIOC_MATCHER_INTERNAL Matcher);
static BOOLEAN      IompParseIOCLine(_In_reads_(LineLength) PCSTR Line, _In_ SIZE_T LineLength, _Out_ PIOC_MATCH_INPUT IOC);

/**************************************************/
/*           引擎引用计数（关闭闸门）                */
/**************************************************/

static BOOLEAN
IompTryReferenceMatcher(
    _In_ PIOC_MATCHER_INTERNAL Matcher
    )
{
    LONG oldCount, newCount;

    if (Matcher == NULL) return FALSE;
    if (Matcher->ShuttingDown) return FALSE;

    do {
        oldCount = InterlockedCompareExchange(&Matcher->RefCount, 0, 0);
        if (oldCount <= 0) return FALSE;
        newCount = oldCount + 1;
    } while (InterlockedCompareExchange(&Matcher->RefCount, newCount, oldCount) != oldCount);

    /* 递增后二次检查关闭标志 */
    if (Matcher->ShuttingDown) {
        if (InterlockedDecrement(&Matcher->RefCount) == 0) {
            SetEvent(Matcher->RefZeroEvent);
        }
        return FALSE;
    }

    return TRUE;
}

static VOID
IompDereferenceMatcher(
    _In_ PIOC_MATCHER_INTERNAL Matcher
    )
{
    if (Matcher == NULL) return;
    if (InterlockedDecrement(&Matcher->RefCount) == 0) {
        SetEvent(Matcher->RefZeroEvent);
    }
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
IocMatcher_Initialize(
    _In_opt_ PIOC_MATCHER_CONFIG Config
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    ULONG i, bucketCount;

    if (matcher->Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(matcher, sizeof(*matcher));

    /* 应用配置 */
    if (Config != NULL) {
        matcher->Config = *Config;
    } else {
        /* MSVC C89 不支持结构体赋值聚合字面量, 用 memcpy 从默认实例复制 */
        static const IOC_MATCHER_CONFIG defaultCfg = IOC_MATCHER_DEFAULT_CONFIG;
        matcher->Config = defaultCfg;
    }

    /* 校验配置边界 */
    if (matcher->Config.MaxIOCs == 0)
        matcher->Config.MaxIOCs = IOC_MAX_IOCS_DEFAULT;
    if (matcher->Config.HashBucketCount == 0)
        matcher->Config.HashBucketCount = IOC_DEFAULT_HASH_BUCKETS;
    if (matcher->Config.HashBucketCount > 1048576)
        matcher->Config.HashBucketCount = 1048576;

    /* 初始化全局链表和锁 */
    InitializeListHead(&matcher->GlobalIOCList);
    InitializeCriticalSection(&matcher->GlobalLock);

    /* 初始化主哈希表 */
    matcher->HashBucketCount = matcher->Config.HashBucketCount;
    matcher->HashBuckets = (PLIST_ENTRY)UtHeapAlloc(
        sizeof(LIST_ENTRY) * matcher->HashBucketCount);
    if (matcher->HashBuckets == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (i = 0; i < matcher->HashBucketCount; i++) {
        InitializeListHead(&matcher->HashBuckets[i]);
    }
    InitializeCriticalSection(&matcher->HashLock);

    /* 初始化类型索引 */
    for (i = 0; i < IocType_MaxValue; i++) {
        InitializeListHead(&matcher->TypeIndices[i].IOCList);
        InitializeCriticalSection(&matcher->TypeIndices[i].Lock);
        matcher->TypeIndices[i].Count = 0;

        bucketCount = IompGetBucketCountForType((IOC_MATCH_TYPE)i);
        if (bucketCount > 0) {
            matcher->TypeIndices[i].HashBuckets = (PLIST_ENTRY)UtHeapAlloc(
                sizeof(LIST_ENTRY) * bucketCount);
            if (matcher->TypeIndices[i].HashBuckets != NULL) {
                matcher->TypeIndices[i].BucketCount = bucketCount;
                for (ULONG j = 0; j < bucketCount; j++) {
                    InitializeListHead(&matcher->TypeIndices[i].HashBuckets[j]);
                }
            }
        }
    }

    /* 初始化布隆过滤器 */
    if (matcher->Config.EnableBloomFilter) {
        matcher->BloomFilter.Size = IOC_BLOOM_FILTER_SIZE;
        matcher->BloomFilter.HashCount = IOC_BLOOM_HASH_COUNT;
        matcher->BloomFilter.Filter = (PUCHAR)UtHeapAlloc(IOC_BLOOM_FILTER_SIZE);
        if (matcher->BloomFilter.Filter != NULL) {
            RtlZeroMemory(matcher->BloomFilter.Filter, IOC_BLOOM_FILTER_SIZE);
            matcher->BloomFilter.Enabled = TRUE;
        }
    }

    InitializeCriticalSection(&matcher->CallbackLock);
    matcher->CallbackReg = NULL;

    /* 引用计数：初始化为 1（由引擎自身持有） */
    matcher->RefCount = 1;
    matcher->RefZeroEvent = CreateEventW(NULL, TRUE, FALSE, NULL);  /* manual-reset */
    if (matcher->RefZeroEvent == NULL) {
        IocMatcher_Shutdown();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    GetSystemTimeAsFileTime((PFILETIME)&matcher->Stats.StartTime);

    /* 创建清理事件和线程 */
    matcher->CleanupWakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    if (matcher->CleanupWakeEvent == NULL) {
        IocMatcher_Shutdown();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (matcher->Config.EnableExpiration) {
        matcher->CleanupThread = CreateThread(
            NULL, 0, IompCleanupThreadRoutine, matcher, 0, NULL);
        if (matcher->CleanupThread == NULL) {
            IocMatcher_Shutdown();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    matcher->Initialized = TRUE;

    printf("[IocMatcher] Initialized — bloom=%s expiration=%s maxIOCs=%lu\n",
           matcher->Config.EnableBloomFilter ? "ON" : "OFF",
           matcher->Config.EnableExpiration ? "ON" : "OFF",
           (ULONG)matcher->Config.MaxIOCs);

    return STATUS_SUCCESS;
}

VOID
IocMatcher_Shutdown(
    VOID
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    PLIST_ENTRY entry;
    PIOM_IOC_INTERNAL ioc;
    ULONG i;
    PIOM_CALLBACK_REG oldReg;

    if (!matcher->Initialized) return;

    /* 1. 设置关闭标志 */
    InterlockedExchange8((volatile char*)&matcher->ShuttingDown, TRUE);

    /* 2. 终止清理线程 */
    if (matcher->CleanupThread != NULL) {
        InterlockedExchange8((volatile char*)&matcher->CleanupTerminate, TRUE);
        SetEvent(matcher->CleanupWakeEvent);
        WaitForSingleObject(matcher->CleanupThread, 10000);  /* 10s timeout */
        CloseHandle(matcher->CleanupThread);
        matcher->CleanupThread = NULL;
    }

    /* 3. 释放引擎初始引用，等待 in-flight 调用 drain */
    IompDereferenceMatcher(matcher);
    if (WaitForSingleObject(matcher->RefZeroEvent, 30000) == WAIT_TIMEOUT) {
        printf("[IocMatcher] WARNING: RefCount drain timeout (%ld outstanding)\n",
               InterlockedCompareExchange(&matcher->RefCount, 0, 0));
        WaitForSingleObject(matcher->RefZeroEvent, INFINITE);
    }

    /* 4. 释放回调注册 */
    EnterCriticalSection(&matcher->CallbackLock);
    oldReg = (PIOM_CALLBACK_REG)InterlockedExchangePointer(
        (PVOID*)&matcher->CallbackReg, NULL);
    LeaveCriticalSection(&matcher->CallbackLock);
    if (oldReg != NULL) UtHeapFree(oldReg);

    /* 5. 释放所有 IOC */
    EnterCriticalSection(&matcher->GlobalLock);
    while (!IsListEmpty(&matcher->GlobalIOCList)) {
        entry = RemoveHeadList(&matcher->GlobalIOCList);
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, GlobalListEntry);
        RemoveEntryList(&ioc->HashBucketEntry);
        UtHeapFree(ioc);
    }
    matcher->IOCCount = 0;
    LeaveCriticalSection(&matcher->GlobalLock);

    DeleteCriticalSection(&matcher->GlobalLock);
    DeleteCriticalSection(&matcher->HashLock);

    /* 6. 释放哈希表 */
    if (matcher->HashBuckets != NULL) {
        UtHeapFree(matcher->HashBuckets);
        matcher->HashBuckets = NULL;
    }

    /* 7. 释放类型索引 */
    for (i = 0; i < IocType_MaxValue; i++) {
        if (matcher->TypeIndices[i].HashBuckets != NULL) {
            UtHeapFree(matcher->TypeIndices[i].HashBuckets);
            matcher->TypeIndices[i].HashBuckets = NULL;
        }
        DeleteCriticalSection(&matcher->TypeIndices[i].Lock);
    }

    /* 8. 释放布隆过滤器 */
    if (matcher->BloomFilter.Filter != NULL) {
        UtHeapFree(matcher->BloomFilter.Filter);
        matcher->BloomFilter.Filter = NULL;
    }

    DeleteCriticalSection(&matcher->CallbackLock);

    /* 9. 关闭句柄 */
    if (matcher->RefZeroEvent != NULL) {
        CloseHandle(matcher->RefZeroEvent);
        matcher->RefZeroEvent = NULL;
    }
    if (matcher->CleanupWakeEvent != NULL) {
        CloseHandle(matcher->CleanupWakeEvent);
        matcher->CleanupWakeEvent = NULL;
    }

    matcher->Initialized = FALSE;
    printf("[IocMatcher] Shutdown complete\n");
}

/**************************************************/
/*               IOC 管理                           */
/**************************************************/

NTSTATUS
IocMatcher_LoadIOC(
    _In_ PIOC_MATCH_INPUT IOC
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    PIOM_IOC_INTERNAL newIOC = NULL;
    ULONG bucket;
    SIZE_T actualLength;

    if (IOC == NULL) return STATUS_INVALID_PARAMETER;

    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;

    /* 校验类型 */
    if (IOC->Type == IocType_Unknown || IOC->Type >= IocType_MaxValue) {
        IompDereferenceMatcher(matcher);
        return STATUS_INVALID_PARAMETER;
    }

    /* 校验值长度 */
    actualLength = IompSafeStringLength(IOC->Value, IOC_MAX_VALUE_LENGTH);
    if (actualLength == 0 || actualLength >= IOC_MAX_VALUE_LENGTH) {
        IompDereferenceMatcher(matcher);
        return STATUS_INVALID_PARAMETER;
    }
    if (IOC->ValueLength != actualLength && IOC->ValueLength != 0) {
        if (IOC->ValueLength > actualLength) {
            IompDereferenceMatcher(matcher);
            return STATUS_INVALID_PARAMETER;
        }
        actualLength = IOC->ValueLength;
    }

    /* 校验哈希类型长度 */
    if (!IompValidateHashLength(IOC->Type, actualLength)) {
        IompDereferenceMatcher(matcher);
        return STATUS_INVALID_PARAMETER;
    }

    /* 容量上限检查 */
    {
        LONG newCount = InterlockedIncrement(&matcher->IOCCount);
        if ((ULONG)newCount > matcher->Config.MaxIOCs || newCount <= 0) {
            InterlockedDecrement(&matcher->IOCCount);
            IompDereferenceMatcher(matcher);
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    /* 分配 IOC */
    newIOC = (PIOM_IOC_INTERNAL)UtHeapAlloc(sizeof(IOM_IOC_INTERNAL));
    if (newIOC == NULL) {
        InterlockedDecrement(&matcher->IOCCount);
        IompDereferenceMatcher(matcher);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(newIOC, sizeof(IOM_IOC_INTERNAL));

    newIOC->Id = InterlockedIncrement64(&matcher->NextIOCId);
    newIOC->Type = IOC->Type;
    newIOC->Severity = IOC->Severity;
    newIOC->ValueLength = actualLength;
    RtlCopyMemory(newIOC->Value, IOC->Value, actualLength);
    newIOC->Value[actualLength] = '\0';

    RtlCopyMemory(newIOC->Description, IOC->Description,
                  IompSafeStringLength(IOC->Description, IOC_MAX_DESCRIPTION_LENGTH));
    RtlCopyMemory(newIOC->ThreatName, IOC->ThreatName,
                  IompSafeStringLength(IOC->ThreatName, IOC_MAX_THREAT_NAME_LENGTH));
    RtlCopyMemory(newIOC->Source, IOC->Source,
                  IompSafeStringLength(IOC->Source, IOC_MAX_SOURCE_LENGTH));

    newIOC->Expiry = IOC->Expiry;
    newIOC->CaseSensitive = IOC->CaseSensitive;
    newIOC->MatchMode = IOC->MatchMode;
    GetSystemTimeAsFileTime((PFILETIME)&newIOC->LastUpdated);

    newIOC->RefCount = IOC_REFCOUNT_INITIAL;

    /* 计算哈希 */
    newIOC->ValueHash = IompComputeHash(
        (PCUCHAR)newIOC->Value, newIOC->ValueLength, IOC_BLOOM_SEED_1);

    /* 加入布隆过滤器 */
    if (matcher->BloomFilter.Enabled && matcher->BloomFilter.Filter != NULL) {
        IompBloomFilterAdd(matcher, (PCUCHAR)newIOC->Value, newIOC->ValueLength);
    }

    /* 插入全局列表和哈希表 */
    bucket = IompComputeBucket(newIOC->ValueHash, matcher->HashBucketCount);

    EnterCriticalSection(&matcher->GlobalLock);
    EnterCriticalSection(&matcher->HashLock);

    InsertTailList(&matcher->GlobalIOCList, &newIOC->GlobalListEntry);
    InsertTailList(&matcher->HashBuckets[bucket], &newIOC->HashBucketEntry);

    LeaveCriticalSection(&matcher->HashLock);
    LeaveCriticalSection(&matcher->GlobalLock);

    /* 插入类型索引 */
    IompInsertIOCIntoIndices(matcher, newIOC);

    if (matcher->Config.EnableStatistics) {
        InterlockedIncrement64(&matcher->Stats.IOCsLoaded);
    }

    IompDereferenceMatcher(matcher);
    return STATUS_SUCCESS;
}

NTSTATUS
IocMatcher_LoadFromBuffer(
    _In_ PVOID      Buffer,
    _In_ SIZE_T     Size,
    _Out_opt_ PULONG LoadedCount,
    _Out_opt_ PULONG ErrorCount
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    PCSTR bufferStart;
    PCSTR bufferEnd, lineStart, lineEnd;
    IOC_MATCH_INPUT ioc;
    NTSTATUS status;
    ULONG loaded = 0, errors = 0;

    if (LoadedCount != NULL) *LoadedCount = 0;
    if (ErrorCount != NULL) *ErrorCount = 0;

    if (Buffer == NULL || Size == 0) return STATUS_INVALID_PARAMETER;
    if (Size > IOM_MAX_BUFFER_SIZE) return STATUS_BUFFER_OVERFLOW;

    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;

    bufferStart = (PCSTR)Buffer;
    bufferEnd = bufferStart + Size;
    lineStart = bufferStart;

    while (lineStart < bufferEnd) {
        lineEnd = lineStart;
        while (lineEnd < bufferEnd && *lineEnd != '\n' && *lineEnd != '\r')
            lineEnd++;

        if (lineEnd > lineStart) {
            RtlZeroMemory(&ioc, sizeof(ioc));
            if (IompParseIOCLine(lineStart, lineEnd - lineStart, &ioc)) {
                status = IocMatcher_LoadIOC(&ioc);
                if (NT_SUCCESS(status))
                    loaded++;
                else
                    errors++;
            }
        }

        lineStart = lineEnd;
        while (lineStart < bufferEnd && (*lineStart == '\n' || *lineStart == '\r'))
            lineStart++;
    }

    if (LoadedCount != NULL) *LoadedCount = loaded;
    if (ErrorCount != NULL) *ErrorCount = errors;

    IompDereferenceMatcher(matcher);
    return (loaded == 0 && errors > 0) ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
}

NTSTATUS
IocMatcher_RemoveIOC(
    _In_ ULONG64 IOCId
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    PLIST_ENTRY entry;
    PIOM_IOC_INTERNAL ioc;
    BOOLEAN found = FALSE;

    if (IOCId == 0) return STATUS_INVALID_PARAMETER;
    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;

    EnterCriticalSection(&matcher->GlobalLock);
    for (entry = matcher->GlobalIOCList.Flink;
         entry != &matcher->GlobalIOCList;
         entry = entry->Flink) {
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, GlobalListEntry);
        if (ioc->Id == IOCId) {
            ioc->MarkedForDeletion = TRUE;
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&matcher->GlobalLock);

    IompDereferenceMatcher(matcher);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
IocMatcher_CleanupExpired(
    VOID
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;
    IompCleanupExpiredIOCsWorker(matcher);
    IompDereferenceMatcher(matcher);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               核心匹配                           */
/**************************************************/

static BOOLEAN
IompCanUseBloomForType(
    _In_ IOC_MATCH_TYPE Type
    )
{
    switch (Type) {
        case IocType_FileHash_MD5:
        case IocType_FileHash_SHA1:
        case IocType_FileHash_SHA256:
        case IocType_Mutex:
        case IocType_JA3:
            return TRUE;
        default:
            return FALSE;
    }
}

BOOLEAN
IocMatcher_BloomCheck(
    _In_ IOC_MATCH_TYPE     Type,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T             Length
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;

    if (!matcher->Initialized || matcher->ShuttingDown)
        return TRUE;    /* 无法判断时保守返回"可能存在" */

    if (matcher->IOCCount == 0)
        return TRUE;    /* 从未加载 IOC：布隆全 0 不可信，保守放行（修复空布隆短路，
                            否则 IocScanner_HashQuery 的 SHA256 判定被错误跳过） */

    if (!matcher->BloomFilter.Enabled || matcher->BloomFilter.Filter == NULL)
        return TRUE;

    if (!IompCanUseBloomForType(Type))
        return TRUE;    /* 通配符型 IOC 不做 bloom 检查 */

    return IompBloomFilterCheck(matcher, Data, Length);
}

NTSTATUS
IocMatcher_Match(
    _In_ IOC_MATCH_TYPE     Type,
    _In_reads_z_(ValueLength + 1) PCSTR Value,
    _In_ SIZE_T             ValueLength,
    _Out_ PIOC_MATCH_RESULT Result
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    PIOM_TYPE_INDEX typeIndex;
    PLIST_ENTRY entry;
    PIOM_IOC_INTERNAL ioc;
    ULONG64 valueHash;
    ULONG bucket;
    BOOLEAN matched = FALSE, useHashLookup;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Value == NULL || Result == NULL) return STATUS_INVALID_PARAMETER;
    if (Type == IocType_Unknown || Type >= IocType_MaxValue)
        return STATUS_INVALID_PARAMETER;
    if (ValueLength == 0 || ValueLength >= IOC_MAX_VALUE_LENGTH)
        return STATUS_INVALID_PARAMETER;
    if (Value[ValueLength] != '\0')
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Result, sizeof(*Result));

    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;

    if (matcher->Config.EnableStatistics)
        InterlockedIncrement64(&matcher->Stats.QueriesPerformed);

    /* 布隆过滤器快速否定（IOCCount==0 时布隆全 0 不可信，跳过否定直接走精确匹配） */
    if (matcher->IOCCount > 0 &&
        matcher->BloomFilter.Enabled && matcher->BloomFilter.Filter != NULL) {
        if (IompCanUseBloomForType(Type)) {
            if (!IompBloomFilterCheck(matcher, (PCUCHAR)Value, ValueLength)) {
                if (matcher->Config.EnableStatistics)
                    InterlockedIncrement64(&matcher->Stats.BloomFilterMisses);
                IompDereferenceMatcher(matcher);
                return STATUS_NOT_FOUND;
            }
            if (matcher->Config.EnableStatistics)
                InterlockedIncrement64(&matcher->Stats.BloomFilterHits);
        }
    }

    valueHash = IompComputeHash((PCUCHAR)Value, ValueLength, IOC_BLOOM_SEED_1);
    typeIndex = &matcher->TypeIndices[Type];

    /* 决定是否使用哈希桶查找 */
    useHashLookup = (typeIndex->HashBuckets != NULL && typeIndex->BucketCount > 0);
    switch (Type) {
        case IocType_Domain:
        case IocType_IPAddress:
        case IocType_FilePath:
        case IocType_FileName:
        case IocType_Registry:
        case IocType_URL:
        case IocType_CommandLine:
        case IocType_ProcessName:
            useHashLookup = FALSE;
            break;
        default:
            break;
    }

    EnterCriticalSection(&typeIndex->Lock);

    if (useHashLookup) {
        bucket = IompComputeBucket(valueHash, typeIndex->BucketCount);
        for (entry = typeIndex->HashBuckets[bucket].Flink;
             entry != &typeIndex->HashBuckets[bucket];
             entry = entry->Flink) {

            ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, TypeHashBucketEntry);
            if (ioc->IsExpired || ioc->MarkedForDeletion) continue;
            if (ioc->Type != Type) continue;
            if (!IompAcquireIOCReference(ioc)) continue;

            /* 精确匹配（哈希类型） */
            if (ioc->ValueHash == valueHash && ioc->ValueLength == ValueLength) {
                if (ioc->CaseSensitive)
                    matched = (RtlCompareMemory(ioc->Value, Value, ValueLength) == ValueLength);
                else
                    matched = (_strnicmp(ioc->Value, Value, ValueLength) == 0);
            }

            if (matched) {
                IompPopulateMatchResult(ioc, Value, ValueLength, NULL, Result);
                InterlockedIncrement64(&ioc->MatchCount);
                IompReleaseIOCReference(ioc);
                status = STATUS_SUCCESS;
                break;
            }
            IompReleaseIOCReference(ioc);
        }
    } else {
        /* 线性扫描（通配符/域名/IP 类型） */
        for (entry = typeIndex->IOCList.Flink;
             entry != &typeIndex->IOCList;
             entry = entry->Flink) {

            ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, TypeListEntry);
            if (ioc->IsExpired || ioc->MarkedForDeletion) continue;
            if (!IompAcquireIOCReference(ioc)) continue;

            switch (Type) {
                case IocType_Domain:
                    matched = IompMatchDomain(ioc->Value, ioc->ValueLength,
                                               Value, ValueLength);
                    break;
                case IocType_IPAddress:
                    matched = IompMatchIPAddress(ioc->Value, ioc->ValueLength,
                                                   Value, ValueLength);
                    break;
                default:
                    matched = IompMatchWildcard(ioc->Value, ioc->ValueLength,
                                                 Value, ValueLength,
                                                 ioc->CaseSensitive);
                    break;
            }

            if (matched) {
                IompPopulateMatchResult(ioc, Value, ValueLength, NULL, Result);
                InterlockedIncrement64(&ioc->MatchCount);
                IompReleaseIOCReference(ioc);
                status = STATUS_SUCCESS;
                break;
            }
            IompReleaseIOCReference(ioc);
        }
    }

    LeaveCriticalSection(&typeIndex->Lock);

    if (NT_SUCCESS(status)) {
        if (matcher->Config.EnableStatistics)
            InterlockedIncrement64(&matcher->Stats.MatchesFound);
        IompNotifyCallback(matcher, Result);
    }

    IompDereferenceMatcher(matcher);
    return status;
}

NTSTATUS
IocMatcher_MatchHash(
    _In_reads_bytes_(HashLength) PCUCHAR Hash,
    _In_ SIZE_T             HashLength,
    _In_ IOC_MATCH_TYPE     HashType,
    _Out_ PIOC_MATCH_RESULT Result
    )
{
    CHAR hexString[IOC_MAX_VALUE_LENGTH];
    SIZE_T expectedLength;
    static const CHAR hexChars[] = "0123456789abcdef";

    if (Hash == NULL || Result == NULL) return STATUS_INVALID_PARAMETER;

    switch (HashType) {
        case IocType_FileHash_MD5:    expectedLength = 16; break;
        case IocType_FileHash_SHA1:   expectedLength = 20; break;
        case IocType_FileHash_SHA256: expectedLength = 32; break;
        default: return STATUS_INVALID_PARAMETER;
    }
    if (HashLength != expectedLength) return STATUS_INVALID_PARAMETER;
    if (HashLength * 2 >= sizeof(hexString)) return STATUS_BUFFER_TOO_SMALL;

    for (SIZE_T i = 0; i < HashLength; i++) {
        hexString[i * 2]     = hexChars[(Hash[i] >> 4) & 0x0F];
        hexString[i * 2 + 1] = hexChars[Hash[i] & 0x0F];
    }
    hexString[HashLength * 2] = '\0';

    return IocMatcher_Match(HashType, hexString, HashLength * 2, Result);
}

/**************************************************/
/*               回调注册                           */
/**************************************************/

NTSTATUS
IocMatcher_RegisterCallback(
    _In_opt_ IOC_MATCH_CALLBACK Callback,
    _In_opt_ PVOID              Context
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    PIOM_CALLBACK_REG newReg = NULL;
    PIOM_CALLBACK_REG oldReg;

    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;

    if (Callback != NULL) {
        newReg = (PIOM_CALLBACK_REG)UtHeapAlloc(sizeof(IOM_CALLBACK_REG));
        if (newReg == NULL) {
            IompDereferenceMatcher(matcher);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        newReg->Callback = Callback;
        newReg->Context = Context;
    }

    EnterCriticalSection(&matcher->CallbackLock);
    oldReg = (PIOM_CALLBACK_REG)InterlockedExchangePointer(
        (PVOID*)&matcher->CallbackReg, newReg);
    LeaveCriticalSection(&matcher->CallbackLock);

    if (oldReg != NULL) UtHeapFree(oldReg);

    IompDereferenceMatcher(matcher);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               统计查询                           */
/**************************************************/

NTSTATUS
IocMatcher_GetStatistics(
    _Out_ PIOC_MATCHER_STATS Stats
    )
{
    PIOC_MATCHER_INTERNAL matcher = &g_IocMatcher;
    if (Stats == NULL) return STATUS_INVALID_PARAMETER;
    if (!IompTryReferenceMatcher(matcher))
        return STATUS_DEVICE_NOT_READY;

    Stats->IOCsLoaded        = InterlockedCompareExchange64(&matcher->Stats.IOCsLoaded, 0, 0);
    Stats->IOCsExpired       = InterlockedCompareExchange64(&matcher->Stats.IOCsExpired, 0, 0);
    Stats->MatchesFound      = InterlockedCompareExchange64(&matcher->Stats.MatchesFound, 0, 0);
    Stats->QueriesPerformed  = InterlockedCompareExchange64(&matcher->Stats.QueriesPerformed, 0, 0);
    Stats->BloomFilterHits   = InterlockedCompareExchange64(&matcher->Stats.BloomFilterHits, 0, 0);
    Stats->BloomFilterMisses = InterlockedCompareExchange64(&matcher->Stats.BloomFilterMisses, 0, 0);
    Stats->StartTime         = matcher->Stats.StartTime;

    IompDereferenceMatcher(matcher);
    return STATUS_SUCCESS;
}

LONG
IocMatcher_GetIOCCount(
    VOID
    )
{
    return (LONG)InterlockedCompareExchange(&g_IocMatcher.IOCCount, 0, 0);
}

/**************************************************/
/*               私有辅助函数                       */
/**************************************************/

static ULONG64
IompComputeHash(
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length,
    _In_ ULONG64 Seed
    )
/* FNV-1a 64-bit hash */
{
    ULONG64 hash = Seed;
    for (SIZE_T i = 0; i < Length; i++) {
        hash ^= Data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static ULONG
IompComputeBucket(
    _In_ ULONG64 Hash,
    _In_ ULONG BucketCount
    )
{
    return (BucketCount == 0) ? 0 : (ULONG)(Hash % BucketCount);
}

static VOID
IompBloomFilterAdd(
    _In_ PIOC_MATCHER_INTERNAL Matcher,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    )
{
    if (Matcher->BloomFilter.Filter == NULL || !Matcher->BloomFilter.Enabled)
        return;

    SIZE_T bitCount = Matcher->BloomFilter.Size * 8;
    ULONG64 hash1 = IompComputeHash(Data, Length, IOC_BLOOM_SEED_1);
    ULONG64 hash2 = IompComputeHash(Data, Length, IOC_BLOOM_SEED_2);

    for (ULONG i = 0; i < Matcher->BloomFilter.HashCount; i++) {
        ULONG64 combined = hash1 + ((ULONG64)i * hash2);
        SIZE_T index = (SIZE_T)(combined % bitCount);
        InterlockedOr((volatile LONG*)&Matcher->BloomFilter.Filter[index / 8],
                       (LONG)(1 << (index % 8)));
    }
}

static BOOLEAN
IompBloomFilterCheck(
    _In_ PIOC_MATCHER_INTERNAL Matcher,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    )
{
    if (Matcher->BloomFilter.Filter == NULL || !Matcher->BloomFilter.Enabled)
        return TRUE;

    SIZE_T bitCount = Matcher->BloomFilter.Size * 8;
    ULONG64 hash1 = IompComputeHash(Data, Length, IOC_BLOOM_SEED_1);
    ULONG64 hash2 = IompComputeHash(Data, Length, IOC_BLOOM_SEED_2);

    for (ULONG i = 0; i < Matcher->BloomFilter.HashCount; i++) {
        ULONG64 combined = hash1 + ((ULONG64)i * hash2);
        SIZE_T index = (SIZE_T)(combined % bitCount);
        if ((Matcher->BloomFilter.Filter[index / 8] & (1 << (index % 8))) == 0)
            return FALSE;
    }
    return TRUE;
}

static VOID
IompInsertIOCIntoIndices(
    _In_ PIOC_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC
    )
{
    if (IOC->Type >= IocType_MaxValue) return;

    PIOM_TYPE_INDEX typeIndex = &Matcher->TypeIndices[IOC->Type];

    EnterCriticalSection(&typeIndex->Lock);

    InsertTailList(&typeIndex->IOCList, &IOC->TypeListEntry);
    InterlockedIncrement(&typeIndex->Count);

    if (typeIndex->HashBuckets != NULL && typeIndex->BucketCount > 0) {
        ULONG bucket = IompComputeBucket(IOC->ValueHash, typeIndex->BucketCount);
        InsertTailList(&typeIndex->HashBuckets[bucket], &IOC->TypeHashBucketEntry);
    }

    LeaveCriticalSection(&typeIndex->Lock);
}

static VOID
IompRemoveIOCFromIndices(
    _In_ PIOC_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC
    )
{
    if (IOC->Type >= IocType_MaxValue) return;

    PIOM_TYPE_INDEX typeIndex = &Matcher->TypeIndices[IOC->Type];

    EnterCriticalSection(&typeIndex->Lock);

    RemoveEntryList(&IOC->TypeListEntry);
    if (typeIndex->HashBuckets != NULL && typeIndex->BucketCount > 0) {
        RemoveEntryList(&IOC->TypeHashBucketEntry);
    }
    InterlockedDecrement(&typeIndex->Count);

    LeaveCriticalSection(&typeIndex->Lock);
}

static BOOLEAN
IompAcquireIOCReference(
    _In_ PIOM_IOC_INTERNAL IOC
    )
{
    LONG oldCount, newCount;
    do {
        oldCount = IOC->RefCount;
        if (oldCount <= 0) return FALSE;
        newCount = oldCount + 1;
    } while (InterlockedCompareExchange(&IOC->RefCount, newCount, oldCount) != oldCount);
    return TRUE;
}

static VOID
IompReleaseIOCReference(
    _In_ PIOM_IOC_INTERNAL IOC
    )
{
    LONG newCount = InterlockedDecrement(&IOC->RefCount);
    assert(newCount >= 0);
    UNREFERENCED_PARAMETER(newCount);
}

static VOID
IompPopulateMatchResult(
    _In_ PIOM_IOC_INTERNAL IOC,
    _In_z_ PCSTR MatchedValue,
    _In_ SIZE_T MatchedValueLength,
    _In_opt_ HANDLE ProcessId,
    _Out_ PIOC_MATCH_RESULT Result
    )
{
    SIZE_T copyLen;

    RtlZeroMemory(Result, sizeof(*Result));

    Result->Type = IOC->Type;
    Result->Severity = IOC->Severity;
    Result->IOCId = IOC->Id;

    copyLen = IOC->ValueLength;
    if (copyLen >= IOC_MAX_VALUE_LENGTH) copyLen = IOC_MAX_VALUE_LENGTH - 1;
    RtlCopyMemory(Result->IOCValue, IOC->Value, copyLen);

    copyLen = IompSafeStringLength(IOC->ThreatName, IOC_MAX_THREAT_NAME_LENGTH);
    RtlCopyMemory(Result->ThreatName, IOC->ThreatName, copyLen);

    copyLen = IompSafeStringLength(IOC->Description, IOC_MAX_DESCRIPTION_LENGTH);
    RtlCopyMemory(Result->Description, IOC->Description, copyLen);

    copyLen = MatchedValueLength;
    if (copyLen >= IOC_MAX_VALUE_LENGTH) copyLen = IOC_MAX_VALUE_LENGTH - 1;
    RtlCopyMemory(Result->MatchedValue, MatchedValue, copyLen);

    Result->ProcessId = ProcessId;
    GetSystemTimeAsFileTime((PFILETIME)&Result->MatchTime);
}

static VOID
IompNotifyCallback(
    _In_ PIOC_MATCHER_INTERNAL Matcher,
    _In_ PIOC_MATCH_RESULT Result
    )
{
    PIOM_CALLBACK_REG reg;
    IOC_MATCH_CALLBACK callback = NULL;
    PVOID context = NULL;

    EnterCriticalSection(&Matcher->CallbackLock);
    reg = (PIOM_CALLBACK_REG)Matcher->CallbackReg;
    if (reg != NULL && reg->Callback != NULL) {
        callback = reg->Callback;
        context = reg->Context;
    }
    if (callback != NULL) {
        callback(Result, context);
    }
    LeaveCriticalSection(&Matcher->CallbackLock);
}

static ULONG
IompGetBucketCountForType(
    _In_ IOC_MATCH_TYPE Type
    )
{
    switch (Type) {
        case IocType_FileHash_MD5:    return IOC_HASH_BUCKETS_MD5;
        case IocType_FileHash_SHA1:   return IOC_HASH_BUCKETS_SHA1;
        case IocType_FileHash_SHA256: return IOC_HASH_BUCKETS_SHA256;
        case IocType_Domain:          return IOC_HASH_BUCKETS_DOMAIN;
        case IocType_IPAddress:       return IOC_HASH_BUCKETS_IP;
        case IocType_Mutex:
        case IocType_JA3:             return IOC_HASH_BUCKETS_OTHER;
        default:                      return 0;
    }
}

static BOOLEAN
IompValidateHashLength(
    _In_ IOC_MATCH_TYPE Type,
    _In_ SIZE_T Length
    )
{
    switch (Type) {
        case IocType_FileHash_MD5:    return (Length == IOC_MD5_HEX_LENGTH);
        case IocType_FileHash_SHA1:   return (Length == IOC_SHA1_HEX_LENGTH);
        case IocType_FileHash_SHA256: return (Length == IOC_SHA256_HEX_LENGTH);
        default:                      return TRUE;
    }
}

static BOOLEAN
IompRequiresPatternMatching(
    _In_ IOC_MATCH_TYPE Type,
    _In_ IOC_MATCH_MODE Mode
    )
{
    if (Mode == IocMatchMode_Wildcard || Mode == IocMatchMode_Regex ||
        Mode == IocMatchMode_CIDR)
        return TRUE;

    switch (Type) {
        case IocType_FilePath:
        case IocType_FileName:
        case IocType_Registry:
        case IocType_URL:
        case IocType_CommandLine:
        case IocType_ProcessName:
            return TRUE;
        default:
            return FALSE;
    }
}

static SIZE_T
IompSafeStringLength(
    _In_reads_(MaxLength) PCSTR String,
    _In_ SIZE_T MaxLength
    )
{
    if (String == NULL) return 0;
    for (SIZE_T i = 0; i < MaxLength; i++) {
        if (String[i] == '\0') return i;
    }
    return MaxLength;
}

/**************************************************/
/*               清理线程                           */
/**************************************************/

static DWORD WINAPI
IompCleanupThreadRoutine(
    _In_ LPVOID Context
    )
{
    PIOC_MATCHER_INTERNAL matcher = (PIOC_MATCHER_INTERNAL)Context;

    while (!matcher->CleanupTerminate) {
        WaitForSingleObject(matcher->CleanupWakeEvent, IOC_CLEANUP_INTERVAL_MS);
        if (matcher->CleanupTerminate) break;
        IompCleanupExpiredIOCsWorker(matcher);
    }

    return 0;
}

static VOID
IompCleanupExpiredIOCsWorker(
    _In_ PIOC_MATCHER_INTERNAL Matcher
    )
{
    PLIST_ENTRY entry, nextEntry;
    PIOM_IOC_INTERNAL ioc;
    LIST_ENTRY freeList;
    LARGE_INTEGER currentTime;

    if (Matcher->ShuttingDown) return;

    InitializeListHead(&freeList);
    GetSystemTimeAsFileTime((PFILETIME)&currentTime);

    EnterCriticalSection(&Matcher->GlobalLock);

    for (entry = Matcher->GlobalIOCList.Flink;
         entry != &Matcher->GlobalIOCList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, GlobalListEntry);

        /* 标记过期 */
        if (!ioc->IsExpired && ioc->Expiry.QuadPart > 0) {
            if (currentTime.QuadPart > ioc->Expiry.QuadPart)
                ioc->IsExpired = TRUE;
        }

        /* 收集可释放的 IOC */
        if (ioc->IsExpired || ioc->MarkedForDeletion) {
            if (InterlockedCompareExchange(&ioc->RefCount, IOC_REFCOUNT_DELETED, 1) == 1) {
                IompRemoveIOCFromIndices(Matcher, ioc);

                RemoveEntryList(&ioc->GlobalListEntry);
                RemoveEntryList(&ioc->HashBucketEntry);
                InterlockedDecrement(&Matcher->IOCCount);

                InsertTailList(&freeList, &ioc->GlobalListEntry);

                if (Matcher->Config.EnableStatistics)
                    InterlockedIncrement64(&Matcher->Stats.IOCsExpired);
            }
        }
    }

    LeaveCriticalSection(&Matcher->GlobalLock);

    /* 锁外释放 */
    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, GlobalListEntry);
        UtHeapFree(ioc);
    }
}

/**************************************************/
/*               CSV 行解析                         */
/**************************************************/

static BOOLEAN
IompParseIOCLine(
    _In_reads_(LineLength) PCSTR Line,
    _In_ SIZE_T LineLength,
    _Out_ PIOC_MATCH_INPUT IOC
    )
{
    PCSTR p = Line, end = Line + LineLength, typeEnd, valueStart, valueEnd;
    SIZE_T typeLen;

    RtlZeroMemory(IOC, sizeof(*IOC));

    /* 跳过前导空白 */
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end) return FALSE;

    /* 跳过注释 */
    if (*p == '#' || *p == ';') return FALSE;

    /* 查找类型分隔符 */
    typeEnd = p;
    while (typeEnd < end && *typeEnd != ':' && *typeEnd != ',') typeEnd++;
    if (typeEnd >= end) return FALSE;

    typeLen = typeEnd - p;

    /* 解析类型（大小写不敏感） */
    if (typeLen == 3 && _strnicmp(p, "md5", 3) == 0)
        IOC->Type = IocType_FileHash_MD5;
    else if (typeLen == 4 && _strnicmp(p, "sha1", 4) == 0)
        IOC->Type = IocType_FileHash_SHA1;
    else if (typeLen == 6 && _strnicmp(p, "sha256", 6) == 0)
        IOC->Type = IocType_FileHash_SHA256;
    else if (typeLen == 4 && _strnicmp(p, "path", 4) == 0) {
        IOC->Type = IocType_FilePath;
        IOC->MatchMode = IocMatchMode_Wildcard;
    } else if (typeLen == 4 && _strnicmp(p, "file", 4) == 0) {
        IOC->Type = IocType_FileName;
        IOC->MatchMode = IocMatchMode_Wildcard;
    } else if (typeLen == 8 && _strnicmp(p, "registry", 8) == 0)
        IOC->Type = IocType_Registry;
    else if (typeLen == 5 && _strnicmp(p, "mutex", 5) == 0)
        IOC->Type = IocType_Mutex;
    else if (typeLen == 2 && _strnicmp(p, "ip", 2) == 0) {
        IOC->Type = IocType_IPAddress;
        IOC->MatchMode = IocMatchMode_CIDR;
    } else if (typeLen == 6 && _strnicmp(p, "domain", 6) == 0) {
        IOC->Type = IocType_Domain;
        IOC->MatchMode = IocMatchMode_Subdomain;
    } else if (typeLen == 3 && _strnicmp(p, "url", 3) == 0)
        IOC->Type = IocType_URL;
    else if (typeLen == 5 && _strnicmp(p, "email", 5) == 0)
        IOC->Type = IocType_EmailAddress;
    else if (typeLen == 7 && _strnicmp(p, "process", 7) == 0) {
        IOC->Type = IocType_ProcessName;
        IOC->MatchMode = IocMatchMode_Wildcard;
    } else if (typeLen == 7 && _strnicmp(p, "cmdline", 7) == 0) {
        IOC->Type = IocType_CommandLine;
        IOC->MatchMode = IocMatchMode_Wildcard;
    } else if (typeLen == 3 && _strnicmp(p, "ja3", 3) == 0)
        IOC->Type = IocType_JA3;
    else
        IOC->Type = IocType_Custom;

    /* 获取值起始 */
    valueStart = typeEnd + 1;
    while (valueStart < end && (*valueStart == ' ' || *valueStart == '\t'))
        valueStart++;

    /* 查找值结束 */
    valueEnd = valueStart;
    while (valueEnd < end && *valueEnd != ',' && *valueEnd != '\r' && *valueEnd != '\n')
        valueEnd++;

    /* 去除尾部空白 */
    while (valueEnd > valueStart &&
           (*(valueEnd - 1) == ' ' || *(valueEnd - 1) == '\t'))
        valueEnd--;

    if (valueEnd <= valueStart) return FALSE;

    IOC->ValueLength = valueEnd - valueStart;
    if (IOC->ValueLength >= IOC_MAX_VALUE_LENGTH)
        IOC->ValueLength = IOC_MAX_VALUE_LENGTH - 1;

    RtlCopyMemory(IOC->Value, valueStart, IOC->ValueLength);
    IOC->Value[IOC->ValueLength] = '\0';

    /* 默认值 */
    IOC->Severity = IocSeverity_Medium;
    IOC->CaseSensitive = FALSE;

    /* 解析额外 CSV 字段（严重级） */
    if (*typeEnd == ',' && valueEnd < end && *valueEnd == ',') {
        PCSTR severityStart = valueEnd + 1;
        while (severityStart < end && (*severityStart == ' ' || *severityStart == '\t'))
            severityStart++;
        if (severityStart < end) {
            SIZE_T remaining = end - severityStart;
            if (remaining >= 8 && _strnicmp(severityStart, "critical", 8) == 0)
                IOC->Severity = IocSeverity_Critical;
            else if (remaining >= 4 && _strnicmp(severityStart, "high", 4) == 0)
                IOC->Severity = IocSeverity_High;
            else if (remaining >= 6 && _strnicmp(severityStart, "medium", 6) == 0)
                IOC->Severity = IocSeverity_Medium;
            else if (remaining >= 3 && _strnicmp(severityStart, "low", 3) == 0)
                IOC->Severity = IocSeverity_Low;
            else if (remaining >= 4 && _strnicmp(severityStart, "info", 4) == 0)
                IOC->Severity = IocSeverity_Info;
        }
    }

    return TRUE;
}
