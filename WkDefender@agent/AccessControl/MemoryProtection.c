/**************************************************/
/*  WkDefender Agent — 内存保护决策引擎               */
/*  (MemoryProtection)                              */
/*                                                   */
/*  纯 C 实现 ShadowStrike MemoryProtection.cpp/hpp   */
/*  迁移。完整覆盖 14 组能力域：                     */
/*   生命周期 / 配置 / 进程加固 / 安全分配 /         */
/*   区域保护 / 完整性 / 反转储 / 堆 / 栈 /          */
/*   内存查询 / 回调 / 统计历史报告 / 自检 / 名称。  */
/*                                                   */
/*  与驱动端无新增依赖：本引擎全部为用户态可落地     */
/*  能力（ASLR/DEP/CFG 为查询校验，编译期决定）。    */
/*                                                   */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "MemoryProtection.h"
#include "AccessControlEngine.h"          /* 受保护进程链：AcGetAccessControlEngine/AcEnumerateProtectedProcessPtrs, 2026-09-08 */
#include "../Process/ProcessModule.h"     /* PsGetMainModuleInstance（链消费主模块节枚举） */
#include "../Common/Utils.h"              /* CoOpenProcessForQueryRead（跨进程最小只读句柄） */
#include "../Common/BCrypUtils.h"         /* IocScanner_ComputeBufferSha256（SHA-256 统一出口） */
#include <wchar.h>

#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>

/* GetMappedFileNameW 动态加载（避免链接配置依赖） */

// RtlComputeCrc32 依赖（ntdll.lib，勿写 ntdll.dll——LNK1104 无法作为链接输入）
#pragma comment(lib, "ntdll.lib")

NTSYSAPI
ULONG32
NTAPI
RtlComputeCrc32(
    _In_ ULONG32 PartialCrc,
    _In_ PVOID Buffer,
    _In_ ULONG Length
    );

/**************************************************/
/*               安全分配记录（内部形态）           */
/**************************************************/

typedef struct _MP_SECURE_ALLOC_ENTRY {
    MP_SECURE_ALLOCATION    Alloc;      /* 公开信息 */
    BOOLEAN                 InUse;
    PVOID                   BasePtr;    /* VirtualAlloc 基址（含守卫页） */
} MP_SECURE_ALLOC_ENTRY, *PMP_SECURE_ALLOC_ENTRY;

/**************************************************/
/*               受保护区域记录（内部形态）         */
/**************************************************/

typedef struct _MP_PROTECTED_REGION_ENTRY {
    MP_PROTECTED_REGION     Region;     /* 公开信息 */
    BOOLEAN                 InUse;
} MP_PROTECTED_REGION_ENTRY, *PMP_PROTECTED_REGION_ENTRY;

/**************************************************/
/*               受保护模块记录（代码完整性登记层） */
/*  2026-09-06 策略 Y：进程内映射视图的登记节点。   */
/*  Module  指向全局唯一镜像对象（建链时 PsReferenceWkdModule 保活）， */
/*  ImageBase 进程内映射基址（判重+节地址换算用）。 */
/**************************************************/

typedef struct _MP_PROTECTED_MODULE {
    LIST_ENTRY      ListEntry;       /* 挂 Engine->ModuleList */
    PWKD_MODULE     Module;          /* 全局唯一镜像本体（已引用） */
    PVOID           ImageBase;       /* 进程内映射基址 */
    ULONG           RegionCount;     /* 该模块注册的代码节区域数 */
} MP_PROTECTED_MODULE, *PMP_PROTECTED_MODULE;

/**************************************************/
/*               事件历史记录（内部精简形态）       */
/**************************************************/

typedef struct _MP_EVENT_RECORD {
    ULONG64             EventId;
    MP_EVENT_TYPE       Type;
    LARGE_INTEGER       Timestamp;
    ULONG_PTR           Address;
    SIZE_T              Size;
    CHAR                RegionId[MP_MAX_ID_LENGTH];
    ULONG               SourceProcessId;
    ULONG               SourceThreadId;
    WCHAR               SourceProcessName[64];
    MP_RESPONSE         ResponseTaken;
    BOOLEAN             WasBlocked;
    BOOLEAN             WasRepaired;
    CHAR                Description[MP_MAX_DESCRIPTION];
} MP_EVENT_RECORD, *PMP_EVENT_RECORD;

/**************************************************/
/*               回调注册槽位                       */
/**************************************************/

typedef struct _MP_CALLBACK_SLOT {
    BOOLEAN     InUse;
    ULONG64     Id;
    PVOID       Callback;
    PVOID       Context;
} MP_CALLBACK_SLOT, *PMP_CALLBACK_SLOT;

/**************************************************/
/*               私有引擎上下文                     */
/**************************************************/

struct _AC_MEMORY_INTEGRITY_ENGINE {
    CRITICAL_SECTION            Lock;
    CRITICAL_SECTION            CallbackLock;

    /* 配置 */
    MP_CONFIGURATION            Config;
    MP_PROTECTION_LEVEL         Level;

    /* 安全分配表 */
    MP_SECURE_ALLOC_ENTRY       SecureAllocations[MP_MAX_SECURE_ALLOCATIONS];
    ULONG                       SecureAllocationCount;

    /* 受保护区域表 */
    MP_PROTECTED_REGION_ENTRY   ProtectedRegions[MP_MAX_PROTECTED_REGIONS];
    ULONG                       ProtectedRegionCount;

    /* 受保护模块链表（代码完整性保护登记层，2026-09-06 策略 Y）。
     * 节点=MP_PROTECTED_MODULE，按 Module+ImageBase 判重；MpShutdown 摘链+解除引用。 */
    LIST_ENTRY                  ModuleList;
    ULONG                       ModuleCount;

    /* 事件历史（环形写，超限删前部） */
    MP_EVENT_RECORD             EventHistory[MP_MAX_EVENT_HISTORY];
    ULONG                       EventHistoryCount;
    ULONG64                     NextEventId;

    /* 回调注册（4 类 + 初始化静态回调） */
    MP_CALLBACKS                InitCallbacks;      /* MpInitialize 注入（OnEvent 经静态注入也可再注册） */
    MP_CALLBACK_SLOT            EventCallbacks[MP_MAX_CALLBACKS];
    MP_CALLBACK_SLOT            IntegrityCallbacks[MP_MAX_CALLBACKS];
    MP_CALLBACK_SLOT            HeapCallbacks[MP_MAX_CALLBACKS];
    ULONG64                     NextCallbackId;

    /* 完整性监视线程 */
    HANDLE                      MonitorThread;
    HANDLE                      MonitorStopEvent;
    volatile BOOLEAN            MonitorRunning;

    /* 状态 */
    volatile LONG               Initialized;
    volatile LONG               Status;         /* MP_MODULE_STATUS */
    volatile LONG               AntiDumpEnabled;

    /* PE 头备份（反转储用） */
    PUCHAR                      SavedPEHeaders;
    SIZE_T                      SavedPEHeaderSize;

    /* 安全堆 */
    HANDLE                      SecureHeap;

    /* psapi 动态加载（GetMappedFileNameW） */
    HMODULE                     PsapiModule;
    FARPROC                     pGetMappedFileNameW;

    /* 统计 */
    MP_STATISTICS               Stats;
};

/* ------------------------------------------------------------------ */
/* 私有工具函数声明（内部假定正确使用，不验证参数）                     */
/* ------------------------------------------------------------------ */

static VOID MpSetStatus(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ MP_MODULE_STATUS Status
    );

static VOID MpNow(
    _Out_ PLARGE_INTEGER Time
    );

static BOOLEAN AcpCalculateMemoryRegionHash(
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _Out_ PULONG Crc32,
    _Out_writes_(MP_SHA256_SIZE) PUCHAR Sha256,
    _In_ ULONG_PTR ProcessId
    );

static VOID MpStoreEvent(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_PROTECTION_EVENT Event
    );

static VOID MpFireEvent(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_PROTECTION_EVENT Event
    );

static VOID MpFireIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_PROTECTED_REGION Region
    );

static VOID MpFireHeapCorruption(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_HEAP_INFO Heap
    );

static BOOLEAN MpFindRegionById(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id,
    _Out_ PULONG Index
    );

static BOOLEAN MpEnableAntiDumpInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

static BOOLEAN MpObfuscatePEHeadersInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

static BOOLEAN MpRestorePEHeadersInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

static DWORD WINAPI AcpMemoryIntegrityRoutine(
    _In_ LPVOID Param
    );

static BOOLEAN MpLoadPsapi(
    _Inout_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* ------------------------------------------------------------------ */
/* 静态工具                                                            */
/* ------------------------------------------------------------------ */

/* 安全清零（volatile 写入 + 内存栅栏，防编译器优化）。 */
_Use_decl_annotations_
VOID
MpSecureZero(
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    )
{
    volatile UCHAR* p = (volatile UCHAR*)Ptr;

    if (!Ptr || Size == 0) return;
    while (Size--) {
        *p++ = 0;
    }
    /* 内存栅栏：确保写入已提交（对齐 SS atomic_thread_fence seq_cst 语义） */
    MemoryBarrier();
}

/* 常量时间比较（防时序侧信道）。 */
_Use_decl_annotations_
BOOLEAN
MpConstantTimeCompare(
    _In_ const VOID* A,
    _In_ const VOID* B,
    _In_ SIZE_T Size
    )
{
    const volatile UCHAR* pa = (const volatile UCHAR*)A;
    const volatile UCHAR* pb = (const volatile UCHAR*)B;
    volatile UCHAR result = 0;
    SIZE_T i;

    for (i = 0; i < Size; i++) {
        result |= (UCHAR)(pa[i] ^ pb[i]);
    }
    return result == 0;
}

/* 取当前时间戳（GetSystemTimeAsFileTime → LARGE_INTEGER）。 */
static VOID
MpNow(
    _Out_ PLARGE_INTEGER Time
    )
{
    if (Time) {
        GetSystemTimeAsFileTime((LPFILETIME)Time);
    }
}

/* 计算区域哈希（VirtualQuery/VirtualQueryEx 从严校验 + CRC32 + CryptoAPI SHA-256）。
 * 对齐 SS calculateRegionHash：仅接受已提交、非 NOACCESS/GUARD 的区域。
 * ProcessId：0=本进程（直接指针）；非 0=跨进程（CoOpenProcessForQueryRead +
 * ReadProcessMemory 整节载入堆缓冲后计算，2026-09-08 受保护进程链消费）。 */
static BOOLEAN
AcpCalculateMemoryRegionHash(
    _In_ LPCVOID Region,
    _In_ SIZE_T SizeOfRegion,
    _Out_ PULONG Crc32,
    _Out_writes_(MP_SHA256_SIZE) PCUCHAR Sha256,
    _In_ ULONG_PTR ProcessId
    )
{
    MEMORY_BASIC_INFORMATION mbi;
    PUCHAR buffer = NULL;
    PCUCHAR data = NULL;

    BOOLEAN ok = FALSE;

    if (!Crc32 || !Sha256) return FALSE;


    if (ProcessId != GetCurrentProcessId()) {
        HANDLE hProcess = NULL;
        SIZE_T read = 0;

        if (!CoOpenProcessForQueryRead(HandleToULong(ProcessId), &hProcess)) return FALSE;

        RtlZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQueryEx(hProcess, Region, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
            goto Cleanup_1;
        }

        buffer = (PUCHAR)malloc(SizeOfRegion);
        if (!buffer) goto Cleanup_1;
        if (!ReadProcessMemory(hProcess, Region, buffer, SizeOfRegion, &read) ||
            read != SizeOfRegion) {
            goto Cleanup_1;
        }

        data = buffer;
        CloseHandle(hProcess);
        goto Calculate;

    Cleanup_1:
        if (buffer) free(buffer);
        CloseHandle(hProcess);
        return FALSE;
    } else {
        /* 本进程：直接指针（现有路径不变） */
        RtlZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQuery(Region, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
            return FALSE;
        }
       
        data = (const UCHAR*)Region;
    }

Calculate:
    /* CRC32 */
    *Crc32 = RtlComputeCrc32(0, data, SizeOfRegion);

    /* SHA-256（统一走 BCrypUtils，BCrypt 快速路径；替代原 CryptoAPI CSP。
     * 2026-09-08 收敛至 BCrypUtils（BCrypt 缓存哈希按 ULONG 计长，超限拒绝） */
    if (SizeOfRegion > (SIZE_T)MAXDWORD) goto Cleanup;

    {
        DEF_SHA256_HASH digest;
        if (IocScanner_ComputeBufferSha256(data, (ULONG)SizeOfRegion, &digest)) {
            memcpy((void*)Sha256, digest.Data, DEF_SHA256_SIZE);
            ok = TRUE;
        }
    }

Cleanup:
    if (buffer) free(buffer);
    return ok;
}

/* 读取区域首部字节（校验钩子启发式用；ProcessId==0 本进程 SEH 直读，
 * 非 0 跨进程 ReadProcessMemory）。失败返回 FALSE。 */
static BOOLEAN
MpReadRegionBytes(
    _In_ const PMP_PROTECTED_REGION Region,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    HANDLE hProc;
    SIZE_T rd = 0;

    if (!Region || !Buffer || Size == 0 ||
        Size > Region->Size) {
        return FALSE;
    }

    if (Region->ProcessId == 0 || Region->ProcessId == GetCurrentProcessId()) {
        __try {
            RtlCopyMemory(Buffer, (const VOID*)(Region->BaseAddress), Size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
        return TRUE;
    }

    if (!CoOpenProcessForQueryRead((ULONG)(ULONG_PTR)Region->ProcessId, &hProc)) {
        return FALSE;
    }
    if (!ReadProcessMemory(hProc, (LPCVOID)Region->BaseAddress, Buffer, Size, &rd) ||
        rd != Size) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    return TRUE;
}

/* 追加事件到历史（定长数组；超限删除前部 MP_EVENT_HISTORY_TRIM 条）。 */
static VOID
MpStoreEvent(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_PROTECTION_EVENT Event
    )
{
    PMP_EVENT_RECORD rec;

    if (!Engine || !Event) return;

    if (Engine->EventHistoryCount >= MP_MAX_EVENT_HISTORY) {
        ULONG trim = MP_EVENT_HISTORY_TRIM;
        ULONG remain = Engine->EventHistoryCount - trim;
        if (remain > 0) {
            memmove(Engine->EventHistory,
                &Engine->EventHistory[trim],
                remain * sizeof(MP_EVENT_RECORD));
        }
        Engine->EventHistoryCount = remain;
    }

    if (Engine->EventHistoryCount >= MP_MAX_EVENT_HISTORY) {
        return;   /* 理论不可达（trim 后必有空位） */
    }

    rec = &Engine->EventHistory[Engine->EventHistoryCount++];
    ZeroMemory(rec, sizeof(*rec));

    rec->EventId = Event->EventId;
    rec->Type = Event->Type;
    rec->Timestamp = Event->Timestamp;
    rec->Address = Event->Address;
    rec->Size = Event->Size;
    if (Event->RegionId[0] != 0) {
        strncpy_s(rec->RegionId, MP_MAX_ID_LENGTH, Event->RegionId, _TRUNCATE);
    }
    rec->SourceProcessId = Event->SourceProcessId;
    rec->SourceThreadId = Event->SourceThreadId;
    if (Event->SourceProcessName[0] != 0) {
        wcsncpy_s(rec->SourceProcessName, 64, Event->SourceProcessName, _TRUNCATE);
    }
    rec->ResponseTaken = Event->ResponseTaken;
    rec->WasBlocked = Event->WasBlocked;
    rec->WasRepaired = Event->WasRepaired;
    if (Event->Description[0] != 0) {
        strncpy_s(rec->Description, MP_MAX_DESCRIPTION, Event->Description, _TRUNCATE);
    }

    MpNow(&Engine->Stats.LastEventTime);
}

/* 触发保护事件（历史入队 + 锁外回调转发）。对齐 SS fireEvent。 */
static VOID
MpFireEvent(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_PROTECTION_EVENT Event
    )
{
    MP_CALLBACK_SLOT slots[MP_MAX_CALLBACKS];
    ULONG slotCount = 0;
    ULONG i;

    if (!Engine || !Event) return;

    /* 历史在锁内写入 */
    EnterCriticalSection(&Engine->Lock);
    MpStoreEvent(Engine, Event);
    LeaveCriticalSection(&Engine->Lock);

    /* 锁外回调（快照副本，防死锁） */
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < MP_MAX_CALLBACKS; i++) {
        if (Engine->EventCallbacks[i].InUse &&
            Engine->EventCallbacks[i].Callback) {
            slots[slotCount++] = Engine->EventCallbacks[i];
        }
    }
    /* 初始化静态注入的 OnEvent 一并触发 */
    if (Engine->InitCallbacks.OnEvent) {
        slots[slotCount].Callback = (PVOID)Engine->InitCallbacks.OnEvent;
        slots[slotCount].Context = Engine->InitCallbacks.Context;
        slots[slotCount].Id = 0;
        slotCount++;
    }
    LeaveCriticalSection(&Engine->CallbackLock);

    for (i = 0; i < slotCount; i++) {
        MP_EVENT_CALLBACK cb = (MP_EVENT_CALLBACK)slots[i].Callback;
        (VOID)cb(Event, slots[i].Context);
    }
}

/* 触发完整性违规回调（锁外）。 */
static VOID
MpFireIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_PROTECTED_REGION Region
    )
{
    MP_CALLBACK_SLOT slots[MP_MAX_CALLBACKS];
    ULONG slotCount = 0;
    ULONG i;

    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < MP_MAX_CALLBACKS; i++) {
        if (Engine->IntegrityCallbacks[i].InUse &&
            Engine->IntegrityCallbacks[i].Callback) {
            slots[slotCount++] = Engine->IntegrityCallbacks[i];
        }
    }
    if (Engine->InitCallbacks.OnIntegrityViolation) {
        slots[slotCount].Callback = (PVOID)Engine->InitCallbacks.OnIntegrityViolation;
        slots[slotCount].Context = Engine->InitCallbacks.Context;
        slots[slotCount].Id = 0;
        slotCount++;
    }
    LeaveCriticalSection(&Engine->CallbackLock);

    for (i = 0; i < slotCount; i++) {
        MP_INTEGRITY_CALLBACK cb = (MP_INTEGRITY_CALLBACK)slots[i].Callback;
        (VOID)cb(Region, slots[i].Context);
    }
}

/* 触发堆损坏回调（锁外）。 */
static VOID
MpFireHeapCorruption(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_HEAP_INFO Heap
    )
{
    MP_CALLBACK_SLOT slots[MP_MAX_CALLBACKS];
    ULONG slotCount = 0;
    ULONG i;

    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < MP_MAX_CALLBACKS; i++) {
        if (Engine->HeapCallbacks[i].InUse &&
            Engine->HeapCallbacks[i].Callback) {
            slots[slotCount++] = Engine->HeapCallbacks[i];
        }
    }
    if (Engine->InitCallbacks.OnHeapCorruption) {
        slots[slotCount].Callback = (PVOID)Engine->InitCallbacks.OnHeapCorruption;
        slots[slotCount].Context = Engine->InitCallbacks.Context;
        slots[slotCount].Id = 0;
        slotCount++;
    }
    LeaveCriticalSection(&Engine->CallbackLock);

    for (i = 0; i < slotCount; i++) {
        MP_HEAP_CORRUPTION_CALLBACK cb = (MP_HEAP_CORRUPTION_CALLBACK)slots[i].Callback;
        (VOID)cb(Heap, slots[i].Context);
    }
}

/* 按 ID 查找受保护区域，返回槽位索引。 */
static BOOLEAN
MpFindRegionById(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id,
    _Out_ PULONG Index
    )
{
    ULONG i;

    if (Index) {
        *Index = 0;
    }
    if (!Id) return FALSE;

    for (i = 0; i < Engine->ProtectedRegionCount; i++) {
        if (Engine->ProtectedRegions[i].InUse &&
            _stricmp(Engine->ProtectedRegions[i].Region.Id, Id) == 0) {
            if (Index) {
                *Index = i;
            }
            return TRUE;
        }
    }
    return FALSE;
}

/* 设置模块状态（原子写）。 */
static VOID
MpSetStatus(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ MP_MODULE_STATUS Status
    )
{
    InterlockedExchange(&Engine->Status, (LONG)Status);
}

/* 动态加载 psapi（GetMappedFileNameW）。失败不致命（仅模块名不可用）。 */
static BOOLEAN
MpLoadPsapi(
    _Inout_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    Engine->PsapiModule = LoadLibraryW(L"psapi.dll");
    if (Engine->PsapiModule) {
        Engine->pGetMappedFileNameW =
            GetProcAddress(Engine->PsapiModule, "GetMappedFileNameW");
        return (Engine->pGetMappedFileNameW != NULL);
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* 配置                                                                */
/* ------------------------------------------------------------------ */

/* 取默认配置（对齐 SS 默认：Standard、全功能开启、安全池 1MB、       */
/* 完整性间隔 30s、DefaultResponse=Active）。                          */
_Use_decl_annotations_
VOID
MpGetDefaultConfiguration(
    _Out_ PMP_CONFIGURATION Config
    )
{
    if (!Config) return;

    ZeroMemory(Config, sizeof(*Config));
    Config->Level = MpLevelStandard;
    /* 进程加固开关（EnableASLR/EnableDEP/EnableCFG）已于 2026-09-08 迁出至
     * ProcessProtection 配置（PPP_CONFIGURATION），本配置不再持有。 */
    Config->EnableSecureAllocator = TRUE;
    Config->SecurePoolSize = MP_DEFAULT_SECURE_POOL_SIZE;
    Config->EnableAntiDump = TRUE;
    Config->EnableCodeIntegrity = TRUE;
    Config->IntegrityCheckIntervalMs = MP_INTEGRITY_CHECK_INTERVAL_MS;
    Config->EnableHeapProtection = TRUE;
    Config->EnableGuardPages = TRUE;
    Config->EnableMemoryEncryption = TRUE;
    Config->EnableAntiScan = TRUE;
    Config->DefaultResponse = MpResponseActive;
    Config->VerboseLogging = FALSE;
    Config->SendTelemetry = TRUE;
}

/* 取保护级别对应的配置模板（对齐 SS FromLevel）。 */
_Use_decl_annotations_
VOID
MpGetConfigurationForLevel(
    _In_ MP_PROTECTION_LEVEL Level,
    _Out_ PMP_CONFIGURATION Config
    )
{
    if (!Config) return;

    MpGetDefaultConfiguration(Config);

    switch (Level) {
    case MpLevelDisabled:
        ZeroMemory(Config, sizeof(*Config));
        Config->Level = MpLevelDisabled;
        Config->DefaultResponse = MpResponseNone;
        break;

    case MpLevelMinimal:
        Config->Level = MpLevelMinimal;
        Config->EnableSecureAllocator = FALSE;
        Config->EnableAntiDump = FALSE;
        Config->EnableCodeIntegrity = FALSE;
        Config->EnableHeapProtection = FALSE;
        Config->EnableAntiScan = FALSE;
        Config->DefaultResponse = MpResponsePassive;
        break;

    case MpLevelStandard:
        Config->Level = MpLevelStandard;
        break;   /* 即默认 */

    case MpLevelEnhanced:
        Config->Level = MpLevelEnhanced;
        Config->IntegrityCheckIntervalMs = 15000;
        break;

    case MpLevelMaximum:
        Config->Level = MpLevelMaximum;
        Config->IntegrityCheckIntervalMs = 5000;
        Config->SecurePoolSize = MP_MAX_SECURE_POOL_SIZE;
        Config->DefaultResponse = MpResponseAggressive;
        break;

    default:
        Config->Level = MpLevelStandard;
        break;
    }
}

/* 校验配置有效性（对齐 SS IsValid：池大小上下限、间隔非零）。 */
_Use_decl_annotations_
BOOLEAN
MpIsConfigurationValid(
    _In_ PMP_CONFIGURATION Config
    )
{
    if (!Config) return FALSE;
    if (Config->Level < MpLevelDisabled || Config->Level > MpLevelMaximum) return FALSE;
    if (Config->SecurePoolSize < MP_MIN_SECURE_ALLOCATION ||
        Config->SecurePoolSize > MP_MAX_SECURE_POOL_SIZE) {
        return FALSE;
    }
    return TRUE;
}

/* 更新配置（对齐 SS SetConfiguration）。 */
_Use_decl_annotations_
NTSTATUS
MpSetConfiguration(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_CONFIGURATION Config
    )
{
    if (!Engine || !Config) return STATUS_INVALID_PARAMETER;
    if (!MpIsConfigurationValid(Config)) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);
    Engine->Config = *Config;
    Engine->Level = Config->Level;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 获取当前配置快照。 */
_Use_decl_annotations_
NTSTATUS
MpGetConfiguration(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_ PMP_CONFIGURATION Config
    )
{
    if (!Engine || !Config) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);
    *Config = Engine->Config;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 设置保护级别（校验并应用 FromLevel 模板）。 */
_Use_decl_annotations_
NTSTATUS
MpSetProtectionLevel(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ MP_PROTECTION_LEVEL Level
    )
{
    MP_CONFIGURATION config;

    if (!Engine) return STATUS_INVALID_PARAMETER;
    if (Level < MpLevelDisabled || Level > MpLevelMaximum) return STATUS_INVALID_PARAMETER;

    MpGetConfigurationForLevel(Level, &config);

    EnterCriticalSection(&Engine->Lock);
    Engine->Config = config;
    Engine->Level = Level;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 查询当前保护级别。 */
_Use_decl_annotations_
MP_PROTECTION_LEVEL
MpGetProtectionLevel(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return MpLevelStandard;
    return (MP_PROTECTION_LEVEL)InterlockedCompareExchange(
        (volatile LONG *)&Engine->Level, 0, 0);
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

/* 初始化内存保护引擎（默认配置=Standard；对齐 SS Initialize）。 */
_Use_decl_annotations_
NTSTATUS
MpInitialize(
    _Out_ PAC_MEMORY_INTEGRITY_ENGINE* Engine,
    _In_opt_ PMP_CALLBACKS Callbacks,
    _In_opt_ PMP_CONFIGURATION Config
    )
{
    PAC_MEMORY_INTEGRITY_ENGINE eng;
    MP_CONFIGURATION defaultConfig;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Engine) return STATUS_INVALID_PARAMETER;
    *Engine = NULL;

    eng = (PAC_MEMORY_INTEGRITY_ENGINE)malloc(sizeof(AC_MEMORY_INTEGRITY_ENGINE));
    if (!eng) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(eng, sizeof(AC_MEMORY_INTEGRITY_ENGINE));

    InitializeCriticalSection(&eng->Lock);
    InitializeCriticalSection(&eng->CallbackLock);
    InitializeListHead(&eng->ModuleList);
    eng->ModuleCount = 0;

    /* 配置 */
    MpGetDefaultConfiguration(&defaultConfig);
    if (Config && MpIsConfigurationValid(Config)) {
        eng->Config = *Config;
        eng->Level = Config->Level;
    } else {
        eng->Config = defaultConfig;
        eng->Level = defaultConfig.Level;
    }

    /* 回调集合 */
    if (Callbacks) {
        eng->InitCallbacks = *Callbacks;
    }

    /* 起始状态 */
    eng->NextEventId = 1;
    eng->NextCallbackId = 1;
    eng->MonitorThread = NULL;
    eng->MonitorStopEvent = NULL;
    eng->MonitorRunning = FALSE;
    MpSetStatus(eng, MpModuleRunning);
    MpNow(&eng->Stats.StartTime);
    MpNow(&eng->Stats.LastEventTime);

    /* 动态加载 psapi（失败不致命） */
    (VOID)MpLoadPsapi(eng);

    /* 进程加固（ASLR/DEP/CFG/缓解策略）已迁移至 ProcessProtection 登记流水线
     * （AcRegisterProtectedProcessInternal → AcApplyProcessHardening，2026-09-08），
     * 本引擎初始化不再施加（无 DEP 失败→初始化失败语义）。 */

    /* 安全堆（对齐 SS initializeSecureHeap） */
    if (eng->Config.EnableSecureAllocator) {
        eng->SecureHeap = HeapCreate(0, eng->Config.SecurePoolSize, 0);
        if (eng->SecureHeap) {
            (VOID)HeapSetInformation(eng->SecureHeap, HeapEnableTerminationOnCorruption, NULL, 0);
        }
    }

    /* 反转储（对齐 SS Initialize：enableAntiDump 时混淆 PE 头）。 */
    if (eng->Config.EnableAntiDump) {
        (VOID)MpEnableAntiDump(eng);
    }

    InterlockedExchange(&eng->Initialized, TRUE);
    *Engine = eng;
    return STATUS_SUCCESS;

Cleanup:
    /* 回滚：释放已初始化资源后返回失败状态 */
    DeleteCriticalSection(&eng->Lock);
    DeleteCriticalSection(&eng->CallbackLock);
    if (eng->PsapiModule) {
        FreeLibrary(eng->PsapiModule);
    }
    free(eng);
    return status;
}

/* 停止引擎并释放内部资源（对齐 SS Shutdown；免鉴权）。
 * 注意：不释放引擎对象本身，由 MpCleanup 负责。 */
_Use_decl_annotations_
NTSTATUS
MpShutdown(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    ULONG i;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    /* 停监视线程 */
    (VOID)MpStop(Engine);

    EnterCriticalSection(&Engine->Lock);

    /* 摘除全部受保护模块链节点（解除全局本体引用；区域表由 MpRestore 前清理） */
    while (!IsListEmpty(&Engine->ModuleList)) {
        PLIST_ENTRY e = RemoveHeadList(&Engine->ModuleList);
        PMP_PROTECTED_MODULE m = CONTAINING_RECORD(e, MP_PROTECTED_MODULE, ListEntry);
        Engine->ModuleCount--;
        if (m->Module) {
            (VOID)PsDereferenceWkdModule(m->Module);
        }
        free(m);
    }

    /* 恢复 PE 头（对齐 SS shutdownUnchecked） */
    if (Engine->SavedPEHeaderSize > 0 && Engine->SavedPEHeaders) {
        (VOID)MpRestorePEHeadersInternal(Engine);
    }
    InterlockedExchange(&Engine->AntiDumpEnabled, FALSE);

    /* 释放全部安全分配 */
    for (i = 0; i < MP_MAX_SECURE_ALLOCATIONS; i++) {
        if (Engine->SecureAllocations[i].InUse) {
            /* 对齐 SS freeAllSecureAllocations：零化 + 解锁 + VirtualFree */
            MpSecureZero(Engine->SecureAllocations[i].Alloc.Address,
                Engine->SecureAllocations[i].Alloc.Size);
            if (Engine->SecureAllocations[i].Alloc.IsLocked) {
                (VOID)VirtualUnlock(Engine->SecureAllocations[i].Alloc.Address,
                    Engine->SecureAllocations[i].Alloc.Size);
            }
            if (Engine->SecureAllocations[i].BasePtr) {
                (VOID)VirtualFree(Engine->SecureAllocations[i].BasePtr, 0, MEM_RELEASE);
            }
            Engine->SecureAllocations[i].InUse = FALSE;
        }
    }
    Engine->SecureAllocationCount = 0;

    /* 销毁安全堆 */
    if (Engine->SecureHeap) {
        HeapDestroy(Engine->SecureHeap);
        Engine->SecureHeap = NULL;
    }

    /* 释放 PE 头备份 */
    if (Engine->SavedPEHeaders) {
        free(Engine->SavedPEHeaders);
        Engine->SavedPEHeaders = NULL;
        Engine->SavedPEHeaderSize = 0;
    }

    LeaveCriticalSection(&Engine->Lock);

    InterlockedExchange(&Engine->Initialized, FALSE);
    MpSetStatus(Engine, MpModuleStopped);
    return STATUS_SUCCESS;
}

/* 释放引擎资源。NULL 安全。 */
_Use_decl_annotations_
VOID
MpCleanup(
    _In_opt_ _Post_invalid_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return;

    (VOID)MpShutdown(Engine);

    if (Engine->PsapiModule) {
        FreeLibrary(Engine->PsapiModule);
        Engine->PsapiModule = NULL;
    }

    DeleteCriticalSection(&Engine->Lock);
    DeleteCriticalSection(&Engine->CallbackLock);
    free(Engine);
}

/* 启动完整性监视线程（对齐 SS startIntegrityMonitoring + Pp 模式）。 */
_Use_decl_annotations_
NTSTATUS
AcStartMemoryIntegralityProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);
    if (Engine->MonitorRunning) {
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_SUCCESS;   /* 已运行 */
    }

    if (!Engine->MonitorStopEvent) {
        Engine->MonitorStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!Engine->MonitorStopEvent) {
            LeaveCriticalSection(&Engine->Lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        ResetEvent(Engine->MonitorStopEvent);
    }

    Engine->MonitorThread = CreateThread(NULL, 0, AcpMemoryIntegrityRoutine, Engine, 0, NULL);
    if (!Engine->MonitorThread) {
        CloseHandle(Engine->MonitorStopEvent);
        Engine->MonitorStopEvent = NULL;
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Engine->MonitorRunning = TRUE;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 停止完整性监视线程。 */
_Use_decl_annotations_
NTSTATUS
MpStop(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    HANDLE thread;
    HANDLE stopEvent;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);
    if (!Engine->MonitorRunning) {
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_SUCCESS;
    }
    thread = Engine->MonitorThread;
    stopEvent = Engine->MonitorStopEvent;
    LeaveCriticalSection(&Engine->Lock);

    /* 置停止事件并等待线程退出 */
    if (stopEvent) {
        SetEvent(stopEvent);
    }
    if (thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }
    if (stopEvent) {
        CloseHandle(stopEvent);
    }

    EnterCriticalSection(&Engine->Lock);
    Engine->MonitorThread = NULL;
    Engine->MonitorStopEvent = NULL;
    Engine->MonitorRunning = FALSE;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 查询引擎是否已初始化。 */
_Use_decl_annotations_
BOOLEAN
MpIsInitialized(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return FALSE;
    return InterlockedCompareExchange(&Engine->Initialized, 0, 0) != 0;
}

/* 查询引擎状态。 */
_Use_decl_annotations_
MP_MODULE_STATUS
MpGetStatus(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return MpModuleUninitialized;
    return (MP_MODULE_STATUS)InterlockedCompareExchange(&Engine->Status, 0, 0);
}

/* ------------------------------------------------------------------ */
/* 安全内存分配（对齐 SS AllocateSecure 系列）                         */
/* ------------------------------------------------------------------ */

/* 分配指定类型的安全内存。对齐 SS AllocateSecure(size, type)：
 * - 对齐到 16 字节
 * - Guarded/config.enableGuardPages → 前后各加 1 页 PAGE_NOACCESS
 * - Locked/Encrypted → VirtualLock
 * - 填充 0xCC（未初始化）
 * - 登记入 m_secureAllocations（此处为定长表） */
static PVOID
MpAllocateSecureInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size,
    _In_ MP_ALLOCATION_TYPE Type
    )
{
    SIZE_T alignedSize;
    SIZE_T totalSize;
    SIZE_T userArea = 0;    /* 前守卫页 + 用户区（页对齐），守卫页布局用 */
    BOOLEAN hasGuardPages;
    PVOID basePtr;
    PVOID userPtr;
    ULONG i;
    ULONG slot = MP_MAX_SECURE_ALLOCATIONS;

    if (!Engine || Size == 0 ||
        Size > MP_MAX_SECURE_ALLOCATION) {
        return NULL;
    }

    EnterCriticalSection(&Engine->Lock);

    if (Engine->SecureAllocationCount >= MP_MAX_SECURE_ALLOCATIONS) {
        LeaveCriticalSection(&Engine->Lock);
        return NULL;
    }
    for (i = 0; i < MP_MAX_SECURE_ALLOCATIONS; i++) {
        if (!Engine->SecureAllocations[i].InUse) {
            slot = i;
            break;
        }
    }
    if (slot == MP_MAX_SECURE_ALLOCATIONS) {
        LeaveCriticalSection(&Engine->Lock);
        return NULL;
    }

    /* 对齐大小 */
    alignedSize = (Size + MP_SECURE_ALLOCATION_ALIGNMENT - 1) &
                  ~(SIZE_T)(MP_SECURE_ALLOCATION_ALIGNMENT - 1);
    totalSize = alignedSize;

    hasGuardPages = (Type == MpAllocGuarded) || Engine->Config.EnableGuardPages;
    if (hasGuardPages) {
        /* 守卫页布局：[前守卫页 1 页 NOACCESS][用户区][填充至页边界]
         *              [后守卫页 1 页 NOACCESS]。
         * userArea = 前守卫页 + 用户区向上取整到页，即后守卫页起始；
         * 起始必须页对齐：VirtualProtect 对非页对齐地址会向下取整，
         * 把用户区一并设为 NOACCESS（实测 0x1010 起始会把 0x1000 起的
         * 区域全部误伤）。 */
        userArea = (MP_PAGE_SIZE + alignedSize + MP_PAGE_SIZE - 1) &
                   ~(SIZE_T)(MP_PAGE_SIZE - 1);
        totalSize = userArea + MP_PAGE_SIZE;
    }

    basePtr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!basePtr) {
        LeaveCriticalSection(&Engine->Lock);
        return NULL;
    }

    userPtr = basePtr;
    if (hasGuardPages) {
        DWORD oldProtect;

        /* 前守卫页 */
        (VOID)VirtualProtect(basePtr, MP_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
        /* 后守卫页（页对齐起始） */
        (VOID)VirtualProtect((PUCHAR)basePtr + userArea,
            MP_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
        /* 用户指针越过前守卫页 */
        userPtr = (PUCHAR)basePtr + MP_PAGE_SIZE;
    }

    /* 未初始化填充 */
    memset(userPtr, MP_UNINIT_MEMORY_FILL, alignedSize);

    /* 加锁（Locked/Encrypted） */
    if (Type == MpAllocLocked || Type == MpAllocEncrypted) {
        /* VirtualLock 失败不致命（对齐 SS：isLocked 记录结果） */
    }

    /* 登记 */
    Engine->SecureAllocations[slot].InUse = TRUE;
    Engine->SecureAllocations[slot].BasePtr = basePtr;
    Engine->SecureAllocations[slot].Alloc.Address = userPtr;
    Engine->SecureAllocations[slot].Alloc.Size = Size;
    Engine->SecureAllocations[slot].Alloc.AllocatedSize = totalSize;
    Engine->SecureAllocations[slot].Alloc.Type = Type;
    Engine->SecureAllocations[slot].Alloc.IsLocked = FALSE;
    Engine->SecureAllocations[slot].Alloc.IsEncrypted = FALSE;
    Engine->SecureAllocations[slot].Alloc.HasGuardPages = hasGuardPages;
    MpNow(&Engine->SecureAllocations[slot].Alloc.AllocatedAt);
    Engine->SecureAllocations[slot].Alloc.CallSite = 0;
    Engine->SecureAllocations[slot].Alloc.AllocatorThreadId = GetCurrentThreadId();

    if (Type == MpAllocLocked || Type == MpAllocEncrypted) {
        Engine->SecureAllocations[slot].Alloc.IsLocked =
            (VirtualLock(userPtr, alignedSize) != FALSE);
    }
    if (Type == MpAllocEncrypted && Engine->Config.EnableMemoryEncryption) {
        /* Encrypted 语义与 SS 一致：仅置标志（不真加密） */
        Engine->SecureAllocations[slot].Alloc.IsEncrypted = TRUE;
    }

    Engine->SecureAllocationCount++;
    InterlockedIncrement64(&Engine->Stats.TotalSecureAllocations);
    InterlockedAdd64(&Engine->Stats.TotalSecureBytes, (LONG64)Size);

    LeaveCriticalSection(&Engine->Lock);
    return userPtr;
}

/* 分配安全内存（默认类型=Secure）。 */
_Use_decl_annotations_
PVOID
MpAllocateSecure(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    )
{
    return MpAllocateSecureInternal(Engine, Size, MpAllocSecure);
}

/* 分配指定类型的安全内存。 */
_Use_decl_annotations_
PVOID
MpAllocateSecureEx(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size,
    _In_ MP_ALLOCATION_TYPE Type
    )
{
    return MpAllocateSecureInternal(Engine, Size, Type);
}

/* 释放安全内存（零化→0xDD 填充→解锁→VirtualFree）。对齐 SS FreeSecure。 */
_Use_decl_annotations_
VOID
MpFreeSecure(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    )
{
    ULONG i;
    LONG64 prev;
    LONG64 next;

    if (!Engine || !Ptr) return;

    /* Size 参数保留于签名（对齐 SS FreeSecure），
     * 实际以分配记录 entry->Alloc.Size 为准。 */
    UNREFERENCED_PARAMETER(Size);

    EnterCriticalSection(&Engine->Lock);

    for (i = 0; i < MP_MAX_SECURE_ALLOCATIONS; i++) {
        if (Engine->SecureAllocations[i].InUse &&
            Engine->SecureAllocations[i].Alloc.Address == Ptr) {
            PMP_SECURE_ALLOC_ENTRY entry = &Engine->SecureAllocations[i];

            /* 安全清零 + 释放填充 */
            MpSecureZero(Ptr, entry->Alloc.Size);
            if (entry->Alloc.Size > 0) {
                memset(Ptr, MP_FREE_MEMORY_FILL, entry->Alloc.Size);
            }

            /* 解锁 */
            if (entry->Alloc.IsLocked) {
                (VOID)VirtualUnlock(Ptr, entry->Alloc.Size);
            }

            /* 释放 */
            if (entry->BasePtr) {
                (VOID)VirtualFree(entry->BasePtr, 0, MEM_RELEASE);
            }

            /* 统计（防下溢） */
            prev = InterlockedCompareExchange64(&Engine->Stats.TotalSecureBytes, 0, 0);
            next = (prev >= (LONG64)entry->Alloc.Size) ?
                   (prev - (LONG64)entry->Alloc.Size) : 0;
            InterlockedExchange64(&Engine->Stats.TotalSecureBytes, next);

            entry->InUse = FALSE;
            if (Engine->SecureAllocationCount > 0) {
                Engine->SecureAllocationCount--;
            }
            LeaveCriticalSection(&Engine->Lock);
            return;
        }
    }

    LeaveCriticalSection(&Engine->Lock);
    /* 未追踪的指针：忽略（对齐 SS 仅记日志） */
}

/* 重分配安全内存（拷贝 min(old,new) 字节）。对齐 SS ReallocateSecure。 */
_Use_decl_annotations_
PVOID
MpReallocateSecure(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T OldSize,
    _In_ SIZE_T NewSize
    )
{
    PVOID newPtr;
    SIZE_T copySize;

    if (!Ptr) return MpAllocateSecure(Engine, NewSize);
    if (NewSize == 0) {
        MpFreeSecure(Engine, Ptr, OldSize);
        return NULL;
    }

    newPtr = MpAllocateSecure(Engine, NewSize);
    if (!newPtr) return NULL;

    copySize = (OldSize < NewSize) ? OldSize : NewSize;
    memcpy(newPtr, Ptr, copySize);

    MpFreeSecure(Engine, Ptr, OldSize);
    return newPtr;
}

/* 分配"加密"内存（对齐 SS：实际=加锁+标志）。 */
_Use_decl_annotations_
PVOID
MpAllocateEncrypted(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    )
{
    return MpAllocateSecureInternal(Engine, Size, MpAllocEncrypted);
}

_Use_decl_annotations_
VOID
MpFreeEncrypted(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    )
{
    MpFreeSecure(Engine, Ptr, Size);
}

/* 分配不可换页内存。 */
_Use_decl_annotations_
PVOID
MpAllocateLocked(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    )
{
    return MpAllocateSecureInternal(Engine, Size, MpAllocLocked);
}

_Use_decl_annotations_
VOID
MpFreeLocked(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    )
{
    MpFreeSecure(Engine, Ptr, Size);
}

/* 分配带守卫页的内存。 */
_Use_decl_annotations_
PVOID
MpAllocateGuarded(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    )
{
    return MpAllocateSecureInternal(Engine, Size, MpAllocGuarded);
}

_Use_decl_annotations_
VOID
MpFreeGuarded(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    )
{
    MpFreeSecure(Engine, Ptr, Size);
}

/* 获取安全分配信息。 */
_Use_decl_annotations_
BOOLEAN
MpGetSecureAllocationInfo(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  PVOID Ptr,
    _Out_ PMP_SECURE_ALLOCATION Info
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    if (!Engine || !Ptr || !Info) return FALSE;

    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < MP_MAX_SECURE_ALLOCATIONS; i++) {
        if (Engine->SecureAllocations[i].InUse &&
            Engine->SecureAllocations[i].Alloc.Address == Ptr) {
            *Info = Engine->SecureAllocations[i].Alloc;
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&Engine->Lock);
    return found;
}

/* 获取全部安全分配。 */
_Use_decl_annotations_
NTSTATUS
MpGetAllSecureAllocations(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_SECURE_ALLOCATION Buffer,
    _Inout_   PULONG Count
    )
{
    ULONG i;
    ULONG written = 0;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);

    if (!Buffer) {
        *Count = Engine->SecureAllocationCount;
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_SUCCESS;
    }

    for (i = 0; i < MP_MAX_SECURE_ALLOCATIONS && written < *Count; i++) {
        if (Engine->SecureAllocations[i].InUse) {
            Buffer[written++] = Engine->SecureAllocations[i].Alloc;
        }
    }

    *Count = written;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 获取当前安全内存使用量（字节）。 */
_Use_decl_annotations_
SIZE_T
MpGetSecureMemoryUsage(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    LONG64 bytes;

    if (!Engine) return 0;
    bytes = InterlockedCompareExchange64(&Engine->Stats.TotalSecureBytes, 0, 0);
    return (bytes > 0) ? (SIZE_T)bytes : 0;
}

/* ------------------------------------------------------------------ */
/* 内存区域保护（对齐 SS ProtectRegion 系列）                          */
/* ------------------------------------------------------------------ */

/* 注册保护区域内部实现：建基线哈希 + 按类型设页保护。对齐 SS ProtectRegion。
 * ProcessId：0=本进程（VirtualProtect 页保护生效）；非 0=跨进程目标
 * （OpenProcess+ReadProcessMemory 建哈希，跳过页保护——不主动改远端保护）。
 * 调用方：AcEnableMemoryIntegrityProtection（本进程薄封装）与
 * MpSyncProtectedProcessSections（受保护进程链消费, 2026-09-08）。 */
static BOOLEAN
MpRegisterRegionInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _In_ MP_REGION_TYPE Type,
    _In_ ULONG_PTR ProcessId
    )
{
    PMP_PROTECTED_REGION_ENTRY entry;
    ULONG slot;
    DWORD protection;
    DWORD oldProtect;
    ULONG i;
    ULONG_PTR effPid;

    if (!Engine || !Id || Id[0] == 0 ||
        Address == 0 || Size == 0) {
        return FALSE;
    }

    /* 本进程归一为 0（哈希/校验/页保护统一本进程语义） */
    effPid = (ProcessId == GetCurrentProcessId()) ? 0 : ProcessId;

    EnterCriticalSection(&Engine->Lock);

    /* 重复 ID 拒绝 */
    if (MpFindRegionById(Engine, Id, NULL)) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }
    if (Engine->ProtectedRegionCount >= MP_MAX_PROTECTED_REGIONS) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }

    slot = MP_MAX_PROTECTED_REGIONS;
    for (i = 0; i < MP_MAX_PROTECTED_REGIONS; i++) {
        if (!Engine->ProtectedRegions[i].InUse) {
            slot = i;
            break;
        }
    }
    if (slot == MP_MAX_PROTECTED_REGIONS) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }

    entry = &Engine->ProtectedRegions[slot];
    ZeroMemory(&entry->Region, sizeof(entry->Region));

    strncpy_s(entry->Region.Id, MP_MAX_ID_LENGTH, Id, _TRUNCATE);
    entry->Region.BaseAddress = Address;
    entry->Region.Size = Size;
    entry->Region.Type = Type;
    entry->Region.ProcessId = effPid;
    MpNow(&entry->Region.ProtectedSince);
    MpNow(&entry->Region.LastVerified);
    entry->Region.Status = MpIntegrityValid;

    /* 建基线哈希（跨进程经 ReadProcessMemory 整节载入） */
    if (!AcpCalculateMemoryRegionHash(Address, Size,
            &entry->Region.ExpectedCrc32, entry->Region.ExpectedSha256, effPid)) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }
    entry->Region.CurrentCrc32 = entry->Region.ExpectedCrc32;

    /* 按类型设页保护（对齐 SS switch；仅本进程区域执行——跨进程不主动
     * 修改远端分页保护，VirtualProtect 失败仅告警不中断） */
    protection = PAGE_READONLY;
    switch (Type) {
    case MpRegionCode:
        protection = PAGE_EXECUTE_READ;
        break;
    case MpRegionReadOnly:
        protection = PAGE_READONLY;
        break;
    case MpRegionReadWrite:
        protection = PAGE_READWRITE;
        break;
    default:
        break;
    }
    if (effPid == 0) {
        (VOID)VirtualProtect((PVOID)Address, Size, protection, &oldProtect);
    }
    entry->Region.Protection = protection;

    entry->InUse = TRUE;
    Engine->ProtectedRegionCount++;
    InterlockedIncrement64(&Engine->Stats.TotalProtectedRegions);

    LeaveCriticalSection(&Engine->Lock);
    return TRUE;
}

/* 保护内存区域（本进程语义薄封装；ProcessId=0）。对齐 SS ProtectRegion。 */
_Use_decl_annotations_
BOOLEAN
AcEnableMemoryIntegrityProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _In_ MP_REGION_TYPE Type
    )
{
    return MpRegisterRegionInternal(Engine, Id, Address, Size, Type, 0);
}

/* 解除区域保护（恢复 READWRITE + 移除基线）。SS 需令牌，Agent 免鉴权。 */
_Use_decl_annotations_
BOOLEAN
MpUnprotectRegion(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id
    )
{
    ULONG index;
    PMP_PROTECTED_REGION_ENTRY entry;
    DWORD oldProtect;

    if (!Engine || !Id) return FALSE;

    EnterCriticalSection(&Engine->Lock);

    if (!MpFindRegionById(Engine, Id, &index)) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }

    entry = &Engine->ProtectedRegions[index];

    /* 恢复为可读写（对齐 SS UnprotectRegion） */
    (VOID)VirtualProtect((PVOID)entry->Region.BaseAddress,
        entry->Region.Size, PAGE_READWRITE, &oldProtect);

    entry->InUse = FALSE;
    if (Engine->ProtectedRegionCount > 0) {
        Engine->ProtectedRegionCount--;
    }

    LeaveCriticalSection(&Engine->Lock);
    return TRUE;
}

/* 保护模块实例全部代码节（2026-09-06 策略 Y）。对齐 SS ProtectSelfCode。
 * 以 PWKD_MODULE_INSTANCE（进程内映射视图）为对象：
 *   - 节枚举优先走 WKD_MODULE::PeInfo.Sections（ImageAnalyzer 产物，
 *     零解析成本）；未就绪回退自解析镜像（含边界校验）。
 *   - 模块登记进 Engine->ModuleList（按 Module+ImageBase 判重），
 *     建链时 PsReferenceWkdModule 保活本体；Instance 指针仅登记期
 *     读取、登记后即弃用（进程退出由进程域释放，与 MP 无共享句柄）。
 *   - 区域落 AcEnableMemoryIntegrityProtection（独立 Lock 串行），
 *     判重与登记两次持 Engine->Lock，间隔二次判重防并发重复。 */
_Use_decl_annotations_
BOOLEAN
AcEnableCodeIntegrityProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PWKD_MODULE_INSTANCE Instance
    )
{
    ULONG_PTR imageBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG i;
    PLIST_ENTRY e;
    PMP_PROTECTED_MODULE node;

    if (!Engine || !Instance || !Instance->Module) return FALSE;

    imageBase = (ULONG_PTR)Instance->ImageBase;
    if (imageBase == 0) return FALSE;

    /* 重复模块判重（Module+ImageBase）：已登记直接成功 */
    EnterCriticalSection(&Engine->Lock);
    for (e = Engine->ModuleList.Flink; e != &Engine->ModuleList; e = e->Flink) {
        PMP_PROTECTED_MODULE m = CONTAINING_RECORD(e, MP_PROTECTED_MODULE, ListEntry);
        if (m->Module == Instance->Module && m->ImageBase == (PVOID)imageBase) {
            LeaveCriticalSection(&Engine->Lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&Engine->Lock);

    /* 分配保护模块节点（登记成功才占用） */
    node = (PMP_PROTECTED_MODULE)malloc(sizeof(MP_PROTECTED_MODULE));
    if (!node) return FALSE;
    RtlZeroMemory(node, sizeof(*node));

    /* 节枚举：优先 Module->PeInfo.Sections（PE_SECTION：分析与磁盘解耦，RVA 语义） */
    if (Instance->Module->PeInfo.Valid) {
        PPE_SECTION sec = Instance->Module->PeInfo.Sections;
        ULONG secCount = Instance->Module->PeInfo.NumberOfSections;
        if (secCount > PE_MAX_SECTIONS) secCount = PE_MAX_SECTIONS;
        for (i = 0; i < secCount; i++) {
            CHAR idBuf[MP_MAX_ID_LENGTH];

            if (!(sec[i].Characteristics & IMAGE_SCN_CNT_CODE)) continue;
            if (sec[i].VirtualSize == 0) continue;

            _snprintf_s(idBuf, MP_MAX_ID_LENGTH, _TRUNCATE,
                "self_%08X_%s", (ULONG)(imageBase & 0xFFFFFFFF), sec[i].Name);

            if (AcEnableMemoryIntegrityProtection(Engine, idBuf,
                    imageBase + sec[i].VirtualAddress,
                    sec[i].VirtualSize, MpRegionCode)) {
                node->RegionCount++;
            }
        }
    }

    /* 回退：PeInfo 未就绪 → 自解析模块头 */
    if (node->RegionCount == 0) {
        MEMORY_BASIC_INFORMATION mbi;

        RtlZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQuery((PVOID)imageBase, &mbi, sizeof(mbi)) != 0) {
            dosHeader = (PIMAGE_DOS_HEADER)imageBase;
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
                dosHeader->e_lfanew >= (LONG)sizeof(IMAGE_DOS_HEADER) &&
                (SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) <= mbi.RegionSize) {

                ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);
                if (ntHeaders->Signature == IMAGE_NT_SIGNATURE &&
                    ntHeaders->FileHeader.NumberOfSections > 0 &&
                    ntHeaders->FileHeader.NumberOfSections <= 96) {

                    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
                    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                        CHAR nameBuf[8 + 1];
                        CHAR idBuf[MP_MAX_ID_LENGTH];

                        if (!(sectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE)) continue;
                        if (sectionHeader[i].Misc.VirtualSize == 0) continue;

                        ZeroMemory(nameBuf, sizeof(nameBuf));
                        memcpy(nameBuf, sectionHeader[i].Name, 8);
                        nameBuf[8] = 0;

                        _snprintf_s(idBuf, MP_MAX_ID_LENGTH, _TRUNCATE,
                            "self_%08X_%s", (ULONG)(imageBase & 0xFFFFFFFF), nameBuf);

                        if (AcEnableMemoryIntegrityProtection(Engine, idBuf,
                                imageBase + sectionHeader[i].VirtualAddress,
                                sectionHeader[i].Misc.VirtualSize, MpRegionCode)) {
                            node->RegionCount++;
                        }
                    }
                }
            }
        }
    }

    /* 无任何代码节成功注册：释放节点，返回 FALSE */
    if (node->RegionCount == 0) {
        free(node);
        return FALSE;
    }

    /* 登记进模块保护链表 + 保活本体 */
    node->ListEntry.Flink = &node->ListEntry;
    node->ListEntry.Blink = &node->ListEntry;
    node->Module = Instance->Module;
    node->ImageBase = (PVOID)imageBase;
    PsReferenceWkdModule(Instance->Module);      /* 保活全局本体 */

    EnterCriticalSection(&Engine->Lock);
    /* 二次判重（首次判重与登记之间可能被并发写入；命中则回滚引用与节点） */
    for (e = Engine->ModuleList.Flink; e != &Engine->ModuleList; e = e->Flink) {
        PMP_PROTECTED_MODULE m = CONTAINING_RECORD(e, MP_PROTECTED_MODULE, ListEntry);
        if (m->Module == Instance->Module && m->ImageBase == (PVOID)imageBase) {
            LeaveCriticalSection(&Engine->Lock);
            (VOID)PsDereferenceWkdModule(Instance->Module);
            free(node);
            return TRUE;
        }
    }
    InsertTailList(&Engine->ModuleList, &node->ListEntry);
    Engine->ModuleCount++;
    LeaveCriticalSection(&Engine->Lock);

    return TRUE;
}

/* 查询地址是否落在某个受保护区域内。 */
_Use_decl_annotations_
BOOLEAN
MpIsRegionProtected(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG_PTR Address
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    if (!Engine) return FALSE;

    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < MP_MAX_PROTECTED_REGIONS; i++) {
        PMP_PROTECTED_REGION_ENTRY entry = &Engine->ProtectedRegions[i];
        if (entry->InUse &&
            Address >= entry->Region.BaseAddress &&
            Address < entry->Region.BaseAddress + entry->Region.Size) {
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&Engine->Lock);
    return found;
}

/* 获取指定 ID 的受保护区域。 */
_Use_decl_annotations_
BOOLEAN
MpGetProtectedRegion(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  PCSTR Id,
    _Out_ PMP_PROTECTED_REGION Region
    )
{
    ULONG index;
    BOOLEAN found = FALSE;

    if (!Engine || !Id || !Region) return FALSE;

    EnterCriticalSection(&Engine->Lock);
    if (MpFindRegionById(Engine, Id, &index)) {
        *Region = Engine->ProtectedRegions[index].Region;
        found = TRUE;
    }
    LeaveCriticalSection(&Engine->Lock);
    return found;
}

/* 获取全部受保护区域。 */
_Use_decl_annotations_
NTSTATUS
MpGetAllProtectedRegions(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_PROTECTED_REGION Buffer,
    _Inout_   PULONG Count
    )
{
    ULONG i;
    ULONG written = 0;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);

    if (!Buffer) {
        *Count = Engine->ProtectedRegionCount;
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_SUCCESS;
    }

    for (i = 0; i < MP_MAX_PROTECTED_REGIONS && written < *Count; i++) {
        if (Engine->ProtectedRegions[i].InUse) {
            Buffer[written++] = Engine->ProtectedRegions[i].Region;
        }
    }

    *Count = written;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 完整性校验（对齐 SS VerifyRegionIntegrity 系列）                    */
/* ------------------------------------------------------------------ */

/* 校验区域完整性：重算 CRC32+SHA-256 对比基线；不一致时做 hook 特征
 * 检测（E9/EB/FF25/68..C3/CC/x64 mov-rax jmp rax 等），置状态、记账、
 * 触发事件与回调。对齐 SS VerifyRegionIntegrity 完整语义。 */
_Use_decl_annotations_
MP_INTEGRITY_STATUS
AcpVerifyMemoryRegionIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id
    )
{
    MP_INTEGRITY_STATUS result = MpIntegrityUnknown;
    PMP_PROTECTED_REGION_ENTRY entry;
    MP_PROTECTION_EVENT event;
    MP_PROTECTED_REGION regionCopy;
    ULONG currentCrc32 = 0;
    UCHAR currentSha256[MP_SHA256_SIZE];
    ULONG index;
    UCHAR patchBuf[16];
    BOOLEAN isHook = FALSE;
    BOOLEAN hasViolation = FALSE;

    if (!Engine || !Id) return MpIntegrityUnknown;

    ZeroMemory(&event, sizeof(event));
    ZeroMemory(&regionCopy, sizeof(regionCopy));

    EnterCriticalSection(&Engine->Lock);

    if (!MpFindRegionById(Engine, Id, &index)) {
        LeaveCriticalSection(&Engine->Lock);
        return MpIntegrityUnknown;
    }
    entry = &Engine->ProtectedRegions[index];

    InterlockedIncrement64(&Engine->Stats.TotalIntegrityChecks);

    if (!AcpCalculateMemoryRegionHash(entry->Region.BaseAddress, entry->Region.Size,
            &currentCrc32, currentSha256, entry->Region.ProcessId)) {
        entry->Region.Status = MpIntegrityCorrupted;
        LeaveCriticalSection(&Engine->Lock);
        return MpIntegrityCorrupted;
    }

    entry->Region.CurrentCrc32 = currentCrc32;
    MpNow(&entry->Region.LastVerified);

    if (currentCrc32 != entry->Region.ExpectedCrc32 ||
        memcmp(currentSha256, entry->Region.ExpectedSha256, MP_SHA256_SIZE) != 0) {
        /* 修改 → 检查 hook 特征（经统一读取封装，跨进程 ReadProcessMemory） */
        entry->Region.Status = MpIntegrityModified;
        entry->Region.ViolationCount++;
        InterlockedIncrement64(&Engine->Stats.IntegrityViolations);

        if (MpReadRegionBytes(&entry->Region, patchBuf, sizeof(patchBuf))) {
            if (entry->Region.Size >= 2) {
                if (patchBuf[0] == 0xE9) {
                    isHook = TRUE;
                } else if (patchBuf[0] == 0xEB) {
                    isHook = TRUE;
                } else if (patchBuf[0] == 0xFF && patchBuf[1] == 0x25) {
                    isHook = TRUE;
                } else if (entry->Region.Size >= 6 &&
                           patchBuf[0] == 0x68 && patchBuf[5] == 0xC3) {
                    isHook = TRUE;
                } else if (patchBuf[0] == 0xCC) {
                    isHook = TRUE;
                }
#ifdef _WIN64
                else if (entry->Region.Size >= 12 &&
                         patchBuf[0] == 0x48 && patchBuf[1] == 0xB8 &&
                         patchBuf[10] == 0xFF && patchBuf[11] == 0xE0) {
                    isHook = TRUE;
                } else if (entry->Region.Size >= 13 &&
                           patchBuf[0] == 0x49 && patchBuf[1] == 0xBA &&
                           patchBuf[10] == 0x41 && patchBuf[11] == 0xFF && patchBuf[12] == 0xE2) {
                    isHook = TRUE;
                }
#endif
            }
        }

        if (isHook) {
            entry->Region.Status = MpIntegrityHooked;
            InterlockedIncrement64(&Engine->Stats.HooksDetected);
        }

        /* 构造事件（历史在锁内写入；回调在锁外） */
        hasViolation = TRUE;
        event.EventId = InterlockedIncrement64((volatile LONG64 *)&Engine->NextEventId);
        event.Type = MpEventIntegrityViolation;
        event.Address = entry->Region.BaseAddress;
        event.Size = entry->Region.Size;
        strncpy_s(event.RegionId, MP_MAX_ID_LENGTH,
            entry->Region.Id, _TRUNCATE);
        MpNow(&event.Timestamp);
        event.SourceProcessId = GetCurrentProcessId();
        event.SourceThreadId = GetCurrentThreadId();
        event.ResponseTaken = Engine->Config.DefaultResponse;
        strncpy_s(event.Description, MP_MAX_DESCRIPTION,
            "Integrity violation detected", _TRUNCATE);

        MpStoreEvent(Engine, &event);

        regionCopy = entry->Region;
        result = entry->Region.Status;
    } else {
        entry->Region.Status = MpIntegrityValid;
        result = MpIntegrityValid;
    }

    LeaveCriticalSection(&Engine->Lock);

    /* 锁外触发回调 */
    if (hasViolation) {
        MpFireEvent(Engine, &event);
        MpFireIntegrity(Engine, &regionCopy);
    }

    return result;
}

/* 校验全部受保护区域，结果写回（每项=区域快照，含 Status）。 */
_Use_decl_annotations_
NTSTATUS
AcpVerifyMemoryIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_PROTECTED_REGION Results,
    _Inout_ PULONG Count
    )
{
    PMP_PROTECTED_REGION snapshots;
    ULONG snapshotCount = 0;
    ULONG capacity;
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    /* 动态快照（MP_PROTECTED_REGION 较大，栈分配不安全） */
    capacity = Engine->ProtectedRegionCount;
    if (capacity > MP_MAX_PROTECTED_REGIONS) {
        capacity = MP_MAX_PROTECTED_REGIONS;
    }
    if (capacity == 0) {
        *Count = 0;
        return STATUS_SUCCESS;   /* 无区域，免分配 */
    }
    snapshots = (PMP_PROTECTED_REGION)malloc(capacity * sizeof(MP_PROTECTED_REGION));
    if (!snapshots) {
        *Count = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(snapshots, capacity * sizeof(MP_PROTECTED_REGION));

    /* 锁内快照区域 ID 列表（对齐 SS VerifyAllIntegrity：先复制防迭代失效） */
    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < MP_MAX_PROTECTED_REGIONS && snapshotCount < capacity; i++) {
        if (Engine->ProtectedRegions[i].InUse) {
            snapshots[snapshotCount++] = Engine->ProtectedRegions[i].Region;
        }
    }
    LeaveCriticalSection(&Engine->Lock);

    /* 锁外逐项校验 */
    for (i = 0; i < snapshotCount; i++) {
        AcpVerifyMemoryRegionIntegrity(Engine, snapshots[i].Id);
    }

    /* 返回最新状态快照 */
    if (Results) {
        ULONG written = 0;
        EnterCriticalSection(&Engine->Lock);
        for (i = 0; i < MP_MAX_PROTECTED_REGIONS && written < *Count; i++) {
            if (Engine->ProtectedRegions[i].InUse) {
                Results[written++] = Engine->ProtectedRegions[i].Region;
            }
        }
        *Count = written;
        LeaveCriticalSection(&Engine->Lock);
    } else {
        *Count = snapshotCount;
    }

    free(snapshots);
    return status;
}

/* 强制触发一次完整性校验。 */
_Use_decl_annotations_
VOID
MpForceIntegrityCheck(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    ULONG count = 0;

    if (!Engine) return;
    (VOID)AcpVerifyMemoryIntegrity(Engine, NULL, &count);
}

/* 更新区域基线（SS 需令牌，Agent 免鉴权）。 */
_Use_decl_annotations_
BOOLEAN
MpUpdateRegionBaseline(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id
    )
{
    ULONG index;
    PMP_PROTECTED_REGION_ENTRY entry;
    ULONG crc32 = 0;
    UCHAR sha256[MP_SHA256_SIZE];

    if (!Engine || !Id) return FALSE;

    EnterCriticalSection(&Engine->Lock);

    if (!MpFindRegionById(Engine, Id, &index)) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }
    entry = &Engine->ProtectedRegions[index];

    if (!AcpCalculateMemoryRegionHash(entry->Region.BaseAddress, entry->Region.Size,
            &crc32, sha256, entry->Region.ProcessId)) {
        LeaveCriticalSection(&Engine->Lock);
        return FALSE;
    }

    entry->Region.ExpectedCrc32 = crc32;
    memcpy(entry->Region.ExpectedSha256, sha256, MP_SHA256_SIZE);
    entry->Region.Status = MpIntegrityValid;
    entry->Region.CurrentCrc32 = crc32;
    MpNow(&entry->Region.LastVerified);

    LeaveCriticalSection(&Engine->Lock);
    return TRUE;
}

/* 同步受保护进程链主模块节到完整性监控（2026-09-08 链消费）。
 * 直接枚举 AcRegisterProtectedProcess 建立的受保护进程链，对每个进程
 * 主模块（PsGetMainModuleInstance）注册可执行节 + .rdata/.pdata 区域。
 * Id 形如 "p<pid>_<节名>"（如 p1234_.text）：重复 Id 由
 * MpRegisterRegionInternal 幂等拒绝。自身进程（pid==GetCurrentProcessId）
 * 归一 ProcessId=0，走本进程 VirtualProtect 页保护路径。
 * 说明：仅消费注册时刻的主模块磁盘视图（PeInfo.Valid），模块重映射/换节
 * 属越权改写，不在本函数职责。 */
static BOOLEAN
MpSyncProtectedProcessSections(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    PWKD_PROCESS* ptrs = NULL;
    ULONG needed = 0;
    ULONG count = 0;
    BOOLEAN any = FALSE;

    if (!Engine) return FALSE;

    if (AcGetAccessControlEngine() == NULL) return FALSE;

    /* 两阶段枚举（对齐 AntiDebug 链消费模式） */
    if (!NT_SUCCESS(AcEnumerateProtectedProcessPtrs(NULL, 0, &needed)) ||
        needed == 0) {
        return FALSE;
    }

    ptrs = (PWKD_PROCESS*)malloc((SIZE_T)needed * sizeof(PWKD_PROCESS));
    if (!ptrs) return FALSE;
    RtlZeroMemory(ptrs, (SIZE_T)needed * sizeof(PWKD_PROCESS));

    if (!NT_SUCCESS(AcEnumerateProtectedProcessPtrs(ptrs, needed, &count))) {
        free(ptrs);
        return FALSE;
    }

    for (ULONG i = 0; i < count && i < needed; i++) {
        PWKD_PROCESS proc = ptrs[i];
        PWKD_MODULE_INSTANCE inst = NULL;
        ULONG_PTR pid;

        if (!proc) continue;
        pid = (ULONG_PTR)proc->ProcessId;

        if (!NT_SUCCESS(PsGetMainModuleInstance(proc, &inst)) ||
            !inst || !inst->Module || !inst->ImageBase) {
            goto next;
        }

        /* 主模块节枚举（PE_SECTION：PeAnalyzer 已解析，RVA 语义） */
        if (inst->Module->PeInfo.Valid) {
            PPE_SECTION sec = inst->Module->PeInfo.Sections;
            ULONG secCount = inst->Module->PeInfo.NumberOfSections;

            if (secCount > PE_MAX_SECTIONS) secCount = PE_MAX_SECTIONS;
            for (ULONG j = 0; j < secCount; j++) {
                CHAR nameBuf[8 + 1];
                CHAR idBuf[MP_MAX_ID_LENGTH];
                MP_REGION_TYPE regType;
                BOOLEAN want;

                if (sec[j].VirtualSize == 0) continue;

                ZeroMemory(nameBuf, sizeof(nameBuf));
                memcpy(nameBuf, sec[j].Name, 8);
                nameBuf[8] = 0;

                /* 范围（用户拍板 2026-09-08）：可执行节 + .rdata/.pdata */
                want = ((sec[j].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0);
                if (!want) {
                    want = (_strnicmp(nameBuf, ".rdata", 6) == 0 ||
                            _strnicmp(nameBuf, ".pdata", 6) == 0);
                }
                if (!want) continue;

                regType = (sec[j].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                              ? MpRegionCode : MpRegionReadOnly;

                _snprintf_s(idBuf, MP_MAX_ID_LENGTH, _TRUNCATE,
                    "p%lu_%s", (ULONG)pid, nameBuf);

                if (MpRegisterRegionInternal(Engine, idBuf,
                        (ULONG_PTR)inst->ImageBase + sec[j].VirtualAddress,
                        sec[j].VirtualSize, regType,
                        (pid == GetCurrentProcessId()) ? 0 : pid)) {
                    any = TRUE;
                }
            }
        }

    next:
        PsDereferenceWkdProcess(proc);
    }

    free(ptrs);
    return any;
}

/* ------------------------------------------------------------------ */
/* 反转储保护（对齐 SS EnableAntiDump 系列）                           */
/* ------------------------------------------------------------------ */

/* 混淆自身 PE 头内部实现（假定已持锁；对齐 SS obfuscatePEHeadersInternal）。 */
static BOOLEAN
MpObfuscatePEHeadersInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    HMODULE hModule;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    SIZE_T headerSize;
    SIZE_T stubSize;
    DWORD oldProtect;
    PUCHAR saved;

    hModule = GetModuleHandleW(NULL);
    if (!hModule) return FALSE;

    dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    /* e_lfanew 越界校验 */
    if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) return FALSE;

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    if (headerSize == 0 || headerSize > 4096 * 16) return FALSE;

    /* 保存原始头 */
    saved = (PUCHAR)malloc(headerSize);
    if (!saved) return FALSE;
    memcpy(saved, hModule, headerSize);

    /* 使头可写 */
    if (!VirtualProtect(hModule, headerSize, PAGE_READWRITE, &oldProtect)) {
        free(saved);
        return FALSE;
    }

    /* 擦除 DOS stub（DOS 头与 NT 头之间） */
    stubSize = (SIZE_T)dosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    if (stubSize > 0) {
        memset((PUCHAR)hModule + sizeof(IMAGE_DOS_HEADER), 0, stubSize);
    }

    /* 清零运行时不需要的可选头字段 */
    ntHeaders->OptionalHeader.CheckSum = 0;
    memset(&ntHeaders->OptionalHeader.LoaderFlags, 0, sizeof(DWORD));

    /* 恢复保护 */
    (VOID)VirtualProtect(hModule, headerSize, oldProtect, &oldProtect);

    /* 提交备份（替换旧备份） */
    if (Engine->SavedPEHeaders) {
        free(Engine->SavedPEHeaders);
    }
    Engine->SavedPEHeaders = saved;
    Engine->SavedPEHeaderSize = headerSize;

    return TRUE;
}

/* 恢复 PE 头内部实现（假定已持锁或 Shutdown 路径）。 */
static BOOLEAN
MpRestorePEHeadersInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    HMODULE hModule;
    DWORD oldProtect;
    BOOLEAN ok = FALSE;

    if (!Engine->SavedPEHeaders || Engine->SavedPEHeaderSize == 0) return FALSE;

    hModule = GetModuleHandleW(NULL);
    if (!hModule) return FALSE;

    if (VirtualProtect(hModule, Engine->SavedPEHeaderSize, PAGE_READWRITE, &oldProtect)) {
        memcpy(hModule, Engine->SavedPEHeaders, Engine->SavedPEHeaderSize);
        (VOID)VirtualProtect(hModule, Engine->SavedPEHeaderSize, oldProtect, &oldProtect);
        ok = TRUE;
    }

    free(Engine->SavedPEHeaders);
    Engine->SavedPEHeaders = NULL;
    Engine->SavedPEHeaderSize = 0;
    return ok;
}

static BOOLEAN
MpEnableAntiDumpInternal(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (InterlockedCompareExchange(&Engine->AntiDumpEnabled, 0, 0) != 0) return TRUE;
    if (MpObfuscatePEHeadersInternal(Engine)) {
        InterlockedExchange(&Engine->AntiDumpEnabled, 1);
        return TRUE;
    }
    return FALSE;
}

/* 启用反转储（混淆自身 PE 头）。 */
_Use_decl_annotations_
BOOLEAN
MpEnableAntiDump(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    BOOLEAN ok;

    if (!Engine || !MpIsInitialized(Engine)) return FALSE;

    EnterCriticalSection(&Engine->Lock);
    ok = MpEnableAntiDumpInternal(Engine);
    LeaveCriticalSection(&Engine->Lock);
    return ok;
}

/* 禁用反转储（恢复 PE 头）。SS 需令牌，Agent 免鉴权。 */
_Use_decl_annotations_
VOID
MpDisableAntiDump(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return;

    EnterCriticalSection(&Engine->Lock);
    (VOID)MpRestorePEHeadersInternal(Engine);
    InterlockedExchange(&Engine->AntiDumpEnabled, 0);
    LeaveCriticalSection(&Engine->Lock);
}

/* 查询反转储是否启用。 */
_Use_decl_annotations_
BOOLEAN
MpIsAntiDumpEnabled(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return FALSE;
    return InterlockedCompareExchange(&Engine->AntiDumpEnabled, 0, 0) != 0;
}

/* 混淆自身 PE 头（公开入口）。 */
_Use_decl_annotations_
BOOLEAN
MpObfuscatePEHeaders(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    BOOLEAN ok;

    if (!Engine || !MpIsInitialized(Engine)) return FALSE;

    EnterCriticalSection(&Engine->Lock);
    ok = MpObfuscatePEHeadersInternal(Engine);
    LeaveCriticalSection(&Engine->Lock);
    return ok;
}

/* 恢复原始 PE 头（公开入口；SS 需令牌，Agent 免鉴权）。 */
_Use_decl_annotations_
BOOLEAN
MpRestorePEHeaders(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    BOOLEAN ok;

    if (!Engine || !MpIsInitialized(Engine)) return FALSE;

    EnterCriticalSection(&Engine->Lock);
    ok = MpRestorePEHeadersInternal(Engine);
    LeaveCriticalSection(&Engine->Lock);
    return ok;
}

/* ------------------------------------------------------------------ */
/* 堆保护（对齐 SS EnableHeapProtection 系列）                         */
/* ------------------------------------------------------------------ */

/* 启用堆保护（HeapSetInformation 终止于损坏）。 */
_Use_decl_annotations_
BOOLEAN
MpEnableHeapProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return FALSE;

    (VOID)HeapSetInformation(GetProcessHeap(), HeapEnableTerminationOnCorruption, NULL, 0);
    return TRUE;
}

/* 校验全部堆完整性（GetProcessHeaps + HeapValidate）。
 * 检测到损坏：记账 + 触发事件 + 返回 FALSE。对齐 SS ValidateHeapIntegrity。 */
_Use_decl_annotations_
BOOLEAN
MpValidateHeapIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    HANDLE heaps[MP_MAX_HEAPS];
    DWORD heapCount;
    DWORD i;
    BOOLEAN ok = TRUE;

    if (!Engine) return FALSE;

    heapCount = GetProcessHeaps(MP_MAX_HEAPS, heaps);
    if (heapCount > MP_MAX_HEAPS) {
        heapCount = MP_MAX_HEAPS;
    }
    if (heapCount == 0) return TRUE;

    for (i = 0; i < heapCount; i++) {
        if (!HeapValidate(heaps[i], 0, NULL)) {
            MP_PROTECTION_EVENT event;
            MP_HEAP_INFO heapInfo;

            InterlockedIncrement64(&Engine->Stats.HeapCorruptionsDetected);

            ZeroMemory(&event, sizeof(event));
            event.EventId = InterlockedIncrement64((volatile LONG64 *)&Engine->NextEventId);
            event.Type = MpEventHeapCorruption;
            event.Address = (ULONG_PTR)heaps[i];
            event.SourceProcessId = GetCurrentProcessId();
            event.SourceThreadId = GetCurrentThreadId();
            MpNow(&event.Timestamp);
            event.ResponseTaken = Engine->Config.DefaultResponse;
            strncpy_s(event.Description, MP_MAX_DESCRIPTION,
                "Heap corruption detected", _TRUNCATE);
            event.WasBlocked = FALSE;

            ZeroMemory(&heapInfo, sizeof(heapInfo));
            heapInfo.HeapHandle = heaps[i];
            heapInfo.IsDefaultHeap = (heaps[i] == GetProcessHeap()) ? TRUE : FALSE;

            /* 历史（锁内）+ 回调（锁外） */
            EnterCriticalSection(&Engine->Lock);
            MpStoreEvent(Engine, &event);
            LeaveCriticalSection(&Engine->Lock);

            MpFireEvent(Engine, &event);
            MpFireHeapCorruption(Engine, &heapInfo);

            ok = FALSE;
            break;
        }
    }

    return ok;
}

/* 获取全部堆信息（HeapWalk 遍历提交/块；对齐 SS GetHeapInfo）。 */
_Use_decl_annotations_
NTSTATUS
MpGetHeapInfo(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_HEAP_INFO Buffer,
    _Inout_   PULONG Count
    )
{
    HANDLE heaps[MP_MAX_HEAPS];
    DWORD heapCount;
    DWORD i;
    ULONG total = 0;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    heapCount = GetProcessHeaps(MP_MAX_HEAPS, heaps);
    if (heapCount > MP_MAX_HEAPS) {
        heapCount = MP_MAX_HEAPS;
    }

    /* 计数 */
    if (!Buffer) {
        *Count = heapCount;
        return STATUS_SUCCESS;
    }

    total = 0;
    for (i = 0; i < heapCount && total < *Count; i++) {
        PMP_HEAP_INFO info = &Buffer[total];
        PROCESS_HEAP_ENTRY entry;

        ZeroMemory(info, sizeof(*info));
        info->HeapHandle = heaps[i];
        info->IsDefaultHeap = (heaps[i] == GetProcessHeap()) ? TRUE : FALSE;

        /* HeapWalk 遍历（对齐 SS：Busy 块计入 committed/blockCount）。
         * 注意：迭代间仅重置 wFlags（MSDN 惯例），不能清零整个 entry——
         * lpData 是 HeapWalk 的游标，清零会使其从头遍历而无限循环。 */
        ZeroMemory(&entry, sizeof(entry));
        entry.lpData = NULL;
        (VOID)HeapLock(heaps[i]);
        while (HeapWalk(heaps[i], &entry)) {
            if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
                info->CommittedSize += entry.cbData;
                info->BlockCount++;
            }
            entry.wFlags = 0;
        }
        (VOID)HeapUnlock(heaps[i]);

        total++;
    }

    *Count = total;
    return STATUS_SUCCESS;
}

/* 创建安全堆（终止于损坏）。 */
_Use_decl_annotations_
PVOID
MpCreateSecureHeap(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T InitialSize
    )
{
    HANDLE heap;

    if (!Engine) return NULL;

    heap = HeapCreate(0, InitialSize, 0);
    if (heap) {
        (VOID)HeapSetInformation(heap, HeapEnableTerminationOnCorruption, NULL, 0);
    }
    return heap;
}

/* 销毁安全堆。 */
_Use_decl_annotations_
VOID
MpDestroySecureHeap(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID HeapHandle
    )
{
    if (!Engine || !HeapHandle) return;
    (VOID)HeapDestroy((HANDLE)HeapHandle);
}

/* ------------------------------------------------------------------ */
/* 内存查询（对齐 SS QueryMemoryRegion 系列）                          */
/* ------------------------------------------------------------------ */

/* 查询地址所在内存区域信息（VirtualQuery + 分类 + 模块名）。 */
_Use_decl_annotations_
BOOLEAN
MpQueryMemoryRegion(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  ULONG_PTR Address,
    _Out_ PMP_REGION_INFO Info
    )
{
    MEMORY_BASIC_INFORMATION mbi;

    if (!Engine || !Info) return FALSE;

    ZeroMemory(&mbi, sizeof(mbi));
    if (VirtualQuery((PVOID)Address, &mbi, sizeof(mbi)) == 0) return FALSE;

    ZeroMemory(Info, sizeof(*Info));
    Info->BaseAddress = (ULONG_PTR)mbi.BaseAddress;
    Info->RegionSize = mbi.RegionSize;
    Info->AllocationBase = (ULONG_PTR)mbi.AllocationBase;
    Info->AllocationSize = mbi.RegionSize;
    Info->Protection = mbi.Protect;
    Info->State = mbi.State;
    Info->Type = mbi.Type;

    /* 分类（对齐 SS，注意顺序：EXECUTE 优先、GUARD 靠后） */
    if ((mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0) {
        Info->RegionType = MpRegionCode;
    } else if ((mbi.Protect & PAGE_READONLY) != 0) {
        Info->RegionType = MpRegionReadOnly;
    } else if ((mbi.Protect & PAGE_READWRITE) != 0) {
        Info->RegionType = MpRegionReadWrite;
    } else if ((mbi.Protect & PAGE_GUARD) != 0) {
        Info->RegionType = MpRegionGuard;
    } else if (mbi.State == MEM_RESERVE) {
        Info->RegionType = MpRegionReserved;
    } else {
        Info->RegionType = MpRegionUnknown;
    }

    /* 模块名（MEM_IMAGE；GetMappedFileNameW 动态加载） */
    if (mbi.Type == MEM_IMAGE && Engine->pGetMappedFileNameW) {
        WCHAR moduleName[MAX_PATH];
        typedef DWORD (WINAPI *FN_GET_MAPPED_FILE_NAME)(
            HANDLE, LPCVOID, LPWSTR, DWORD);
        FN_GET_MAPPED_FILE_NAME fn =
            (FN_GET_MAPPED_FILE_NAME)Engine->pGetMappedFileNameW;

        if (fn(GetCurrentProcess(), mbi.BaseAddress,
               moduleName, MAX_PATH) > 0) {
            wcsncpy_s(Info->ModuleName, MP_MAX_MODULE_NAME,
                moduleName, _TRUNCATE);
        }
    }

    return TRUE;
}

/* 枚举全部内存区域（渐进式防死循环；对齐 SS EnumerateMemoryRegions）。 */
_Use_decl_annotations_
NTSTATUS
MpEnumerateMemoryRegions(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_REGION_INFO Buffer,
    _Inout_   PULONG Count
    )
{
    SYSTEM_INFO sysInfo;
    ULONG_PTR address;
    ULONG_PTR maxAddress;
    ULONG written = 0;
    MP_REGION_INFO info;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    GetSystemInfo(&sysInfo);
    address = (ULONG_PTR)sysInfo.lpMinimumApplicationAddress;
    maxAddress = (ULONG_PTR)sysInfo.lpMaximumApplicationAddress;

    while (address < maxAddress) {
        ULONG_PTR nextAddress;

        if (MpQueryMemoryRegion(Engine, address, &info)) {
            if (Buffer && written < *Count) {
                Buffer[written++] = info;
            }
            nextAddress = info.BaseAddress + info.RegionSize;
        } else {
            nextAddress = address + MP_PAGE_SIZE;
        }

        /* 保证前向推进（畸形区域描述不得造成死循环） */
        if (nextAddress <= address) {
            nextAddress = address + MP_PAGE_SIZE;
        }
        address = nextAddress;
    }

    *Count = written;
    return STATUS_SUCCESS;
}

/* 获取地址页保护。 */
_Use_decl_annotations_
ULONG
MpGetPageProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG_PTR Address
    )
{
    MP_REGION_INFO info;

    if (!Engine) return 0;
    if (MpQueryMemoryRegion(Engine, Address, &info)) return info.Protection;
    return 0;
}

/* 设置范围页保护（W^X 强制：拒绝 EXECUTE_READWRITE / EXECUTE_WRITECOPY）。 */
_Use_decl_annotations_
BOOLEAN
MpSetPageProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _In_ MP_PAGE_PROTECTION Protection
    )
{
    ULONG protVal;
    DWORD oldProtect;

    if (!Engine) return FALSE;

    protVal = (ULONG)Protection;
    if (protVal == (ULONG)PAGE_EXECUTE_READWRITE ||
        protVal == (ULONG)PAGE_EXECUTE_WRITECOPY) {
        /* W^X 违规：阻断并记账 */
        MP_PROTECTION_EVENT event;

        InterlockedIncrement64(&Engine->Stats.MemoryWritesBlocked);

        ZeroMemory(&event, sizeof(event));
        event.EventId = InterlockedIncrement64((volatile LONG64 *)&Engine->NextEventId);
        event.Type = MpEventPermissionChange;
        event.Address = Address;
        event.Size = Size;
        event.SourceProcessId = GetCurrentProcessId();
        event.SourceThreadId = GetCurrentThreadId();
        MpNow(&event.Timestamp);
        event.ResponseTaken = MpResponseBlock;
        event.WasBlocked = TRUE;
        strncpy_s(event.Description, MP_MAX_DESCRIPTION,
            "W^X violation blocked (RWX page protection denied)", _TRUNCATE);

        EnterCriticalSection(&Engine->Lock);
        MpStoreEvent(Engine, &event);
        LeaveCriticalSection(&Engine->Lock);
        MpFireEvent(Engine, &event);

        return FALSE;
    }

    if (!VirtualProtect((PVOID)Address, Size, (DWORD)Protection, &oldProtect)) return FALSE;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* 回调管理（Register/Unregister 静态回调槽）                          */
/* ------------------------------------------------------------------ */

/* 分配回调槽位（内部工具）。返回 FALSE=槽满。 */
static BOOLEAN
MpAllocCallbackSlot(
    _Inout_ PMP_CALLBACK_SLOT Slots,
    _In_ ULONG Count,
    _In_ PVOID Callback,
    _In_opt_ PVOID Context,
    _Inout_ PULONG64 NextId,
    _Out_ PULONG64 CallbackId
    )
{
    ULONG i;

    if (!Slots || !NextId) return FALSE;

    for (i = 0; i < Count; i++) {
        if (!Slots[i].InUse) {
            Slots[i].InUse = TRUE;
            Slots[i].Id = *NextId;
            Slots[i].Callback = Callback;
            Slots[i].Context = Context;
            if (CallbackId) {
                *CallbackId = *NextId;
            }
            (*NextId)++;
            return TRUE;
        }
    }
    return FALSE;
}

/* 按 ID 释放回调槽位（内部工具）。 */
static VOID
MpReleaseCallbackSlot(
    _Inout_ PMP_CALLBACK_SLOT Slots,
    _In_ ULONG Count,
    _In_ ULONG64 CallbackId
    )
{
    ULONG i;

    if (!Slots) return;

    for (i = 0; i < Count; i++) {
        if (Slots[i].InUse && Slots[i].Id == CallbackId) {
            Slots[i].InUse = FALSE;
            Slots[i].Callback = NULL;
            Slots[i].Context = NULL;
            return;
        }
    }
}

/* 注册完整性违规回调，返回回调 ID。 */
_Use_decl_annotations_
NTSTATUS
MpRegisterIntegrityCallback(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  MP_INTEGRITY_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    BOOLEAN ok;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->CallbackLock);
    ok = MpAllocCallbackSlot(Engine->IntegrityCallbacks, MP_MAX_CALLBACKS,
        (PVOID)Callback, Context, &Engine->NextCallbackId, CallbackId);
    LeaveCriticalSection(&Engine->CallbackLock);

    return ok ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

_Use_decl_annotations_
VOID
MpUnregisterIntegrityCallback(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    if (!Engine) return;

    EnterCriticalSection(&Engine->CallbackLock);
    MpReleaseCallbackSlot(Engine->IntegrityCallbacks, MP_MAX_CALLBACKS, CallbackId);
    LeaveCriticalSection(&Engine->CallbackLock);
}

/* 注册保护事件回调，返回回调 ID。 */
_Use_decl_annotations_
NTSTATUS
MpRegisterEventCallback(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  MP_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    BOOLEAN ok;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->CallbackLock);
    ok = MpAllocCallbackSlot(Engine->EventCallbacks, MP_MAX_CALLBACKS,
        (PVOID)Callback, Context, &Engine->NextCallbackId, CallbackId);
    LeaveCriticalSection(&Engine->CallbackLock);

    return ok ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

_Use_decl_annotations_
VOID
MpUnregisterEventCallback(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    if (!Engine) return;

    EnterCriticalSection(&Engine->CallbackLock);
    MpReleaseCallbackSlot(Engine->EventCallbacks, MP_MAX_CALLBACKS, CallbackId);
    LeaveCriticalSection(&Engine->CallbackLock);
}

/* 注册堆损坏回调，返回回调 ID。 */
_Use_decl_annotations_
NTSTATUS
MpRegisterHeapCorruptionCallback(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  MP_HEAP_CORRUPTION_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    BOOLEAN ok;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->CallbackLock);
    ok = MpAllocCallbackSlot(Engine->HeapCallbacks, MP_MAX_CALLBACKS,
        (PVOID)Callback, Context, &Engine->NextCallbackId, CallbackId);
    LeaveCriticalSection(&Engine->CallbackLock);

    return ok ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

_Use_decl_annotations_
VOID
MpUnregisterHeapCorruptionCallback(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    if (!Engine) return;

    EnterCriticalSection(&Engine->CallbackLock);
    MpReleaseCallbackSlot(Engine->HeapCallbacks, MP_MAX_CALLBACKS, CallbackId);
    LeaveCriticalSection(&Engine->CallbackLock);
}

/* ------------------------------------------------------------------ */
/* 统计 / 历史 / 报告（对齐 SS GetStatistics/GetEventHistory/ExportReport）*/
/* ------------------------------------------------------------------ */

/* 获取运行统计快照。 */
_Use_decl_annotations_
NTSTATUS
MpGetStatistics(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_ PMP_STATISTICS Statistics
    )
{
    if (!Engine || !Statistics) return STATUS_INVALID_PARAMETER;

    Statistics->TotalIntegrityChecks =
        InterlockedCompareExchange64(&Engine->Stats.TotalIntegrityChecks, 0, 0);
    Statistics->IntegrityViolations =
        InterlockedCompareExchange64(&Engine->Stats.IntegrityViolations, 0, 0);
    Statistics->HooksDetected =
        InterlockedCompareExchange64(&Engine->Stats.HooksDetected, 0, 0);
    Statistics->HeapCorruptionsDetected =
        InterlockedCompareExchange64(&Engine->Stats.HeapCorruptionsDetected, 0, 0);
    Statistics->MemoryWritesBlocked =
        InterlockedCompareExchange64(&Engine->Stats.MemoryWritesBlocked, 0, 0);
    Statistics->TotalSecureAllocations =
        InterlockedCompareExchange64(&Engine->Stats.TotalSecureAllocations, 0, 0);
    Statistics->TotalSecureBytes =
        InterlockedCompareExchange64(&Engine->Stats.TotalSecureBytes, 0, 0);
    Statistics->TotalProtectedRegions =
        InterlockedCompareExchange64(&Engine->Stats.TotalProtectedRegions, 0, 0);
    Statistics->DumpAttemptsBlocked =
        InterlockedCompareExchange64(&Engine->Stats.DumpAttemptsBlocked, 0, 0);
    Statistics->ScanAttemptsDetected =
        InterlockedCompareExchange64(&Engine->Stats.ScanAttemptsDetected, 0, 0);
    Statistics->StartTime = Engine->Stats.StartTime;
    Statistics->LastEventTime = Engine->Stats.LastEventTime;

    return STATUS_SUCCESS;
}

/* 重置统计（不清事件历史；对齐 SS ResetStatistics）。 */
_Use_decl_annotations_
VOID
MpResetStatistics(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return;
    InterlockedExchange64(&Engine->Stats.TotalIntegrityChecks, 0);
    InterlockedExchange64(&Engine->Stats.IntegrityViolations, 0);
    InterlockedExchange64(&Engine->Stats.HooksDetected, 0);
    InterlockedExchange64(&Engine->Stats.HeapCorruptionsDetected, 0);
    InterlockedExchange64(&Engine->Stats.MemoryWritesBlocked, 0);
    InterlockedExchange64(&Engine->Stats.TotalSecureAllocations, 0);
    InterlockedExchange64(&Engine->Stats.TotalSecureBytes, 0);
    InterlockedExchange64(&Engine->Stats.TotalProtectedRegions, 0);
    InterlockedExchange64(&Engine->Stats.DumpAttemptsBlocked, 0);
    InterlockedExchange64(&Engine->Stats.ScanAttemptsDetected, 0);
}

/* 获取事件历史（新→旧；对齐 SS GetEventHistory 语义）。
 * 最多返回 MaxEntries 条。!Buffer 时经 *Count 返回可写总数。 */
_Use_decl_annotations_
NTSTATUS
MpGetEventHistory(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_      ULONG MaxEntries,
    _Out_writes_opt_(*Count) PMP_PROTECTION_EVENT Buffer,
    _Inout_   PULONG Count
    )
{
    ULONG available;
    ULONG written = 0;
    ULONG idx;
    ULONG i;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);

    available = Engine->EventHistoryCount;
    if (available > MaxEntries) {
        available = MaxEntries;
    }

    if (!Buffer) {
        *Count = available;
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_SUCCESS;
    }

    /* 新→旧：从数组尾部开始倒序 */
    for (i = 0; i < available; i++) {
        PMP_EVENT_RECORD rec;

        idx = Engine->EventHistoryCount - 1 - i;
        rec = &Engine->EventHistory[idx];

        ZeroMemory(&Buffer[written], sizeof(MP_PROTECTION_EVENT));
        Buffer[written].EventId = rec->EventId;
        Buffer[written].Type = rec->Type;
        Buffer[written].Timestamp = rec->Timestamp;
        Buffer[written].Address = rec->Address;
        Buffer[written].Size = rec->Size;
        if (rec->RegionId[0] != 0) {
            strncpy_s(Buffer[written].RegionId, MP_MAX_ID_LENGTH,
                rec->RegionId, _TRUNCATE);
        }
        Buffer[written].SourceProcessId = rec->SourceProcessId;
        Buffer[written].SourceThreadId = rec->SourceThreadId;
        if (rec->SourceProcessName[0] != 0) {
            wcsncpy_s(Buffer[written].SourceProcessName, 64,
                rec->SourceProcessName, _TRUNCATE);
        }
        Buffer[written].ResponseTaken = rec->ResponseTaken;
        Buffer[written].WasBlocked = rec->WasBlocked;
        Buffer[written].WasRepaired = rec->WasRepaired;
        if (rec->Description[0] != 0) {
            strncpy_s(Buffer[written].Description, MP_MAX_DESCRIPTION,
                rec->Description, _TRUNCATE);
        }
        written++;
    }

    *Count = written;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

/* 清空事件历史。 */
_Use_decl_annotations_
VOID
MpClearEventHistory(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    )
{
    if (!Engine) return;

    EnterCriticalSection(&Engine->Lock);
    Engine->EventHistoryCount = 0;
    ZeroMemory(Engine->EventHistory,
        sizeof(Engine->EventHistory));
    LeaveCriticalSection(&Engine->Lock);
}

/* 导出 JSON 报告（对齐 SS exportReport 聚合内容）。
 * !Buffer 时经 *Length 返回所需字符数（含 null）。 */
_Use_decl_annotations_
NTSTATUS
MpExportReport(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Length) PWSTR Buffer,
    _Inout_   PULONG Length
    )
{
    MP_STATISTICS stats;
    ULONG needed;
    ULONG used = 0;
    ULONG i;
    PMP_PROTECTED_REGION regions;
    ULONG regionCount;
    PMP_PROTECTION_EVENT events;
    ULONG eventCount;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Engine || !Length) return STATUS_INVALID_PARAMETER;

    (VOID)MpGetStatistics(Engine, &stats);

    /* 堆分配（MP_PROTECTION_EVENT 较大，栈分配不安全） */
    regionCount = 0;
    (VOID)MpGetAllProtectedRegions(Engine, NULL, &regionCount);
    eventCount = 0;
    (VOID)MpGetEventHistory(Engine, MP_MAX_EVENT_HISTORY, NULL, &eventCount);

    regions = NULL;
    events = NULL;
    if (regionCount > 0) {
        regions = (PMP_PROTECTED_REGION)malloc(regionCount * sizeof(MP_PROTECTED_REGION));
        if (!regions) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        RtlZeroMemory(regions, regionCount * sizeof(MP_PROTECTED_REGION));
        (VOID)MpGetAllProtectedRegions(Engine, regions, &regionCount);
    }
    if (eventCount > 0) {
        events = (PMP_PROTECTION_EVENT)malloc(eventCount * sizeof(MP_PROTECTION_EVENT));
        if (!events) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        RtlZeroMemory(events, eventCount * sizeof(MP_PROTECTION_EVENT));
        (VOID)MpGetEventHistory(Engine, MP_MAX_EVENT_HISTORY, events, &eventCount);
    }

    /* 先计算所需长度（严格 JSON 格式） */
    needed = (ULONG)(wcslen(L"{"
        L"\"version\":\"3.0.0\","
        L"\"level\":{\"value\":%d,\"name\":\"%s\"},"
        L"\"hardening\":{\"antidump\":%s},"
        L"\"stats\":{"
        L"\"integrityChecks\":%lld,\"violations\":%lld,\"hooks\":%lld,"
        L"\"heapCorruptions\":%lld,\"writesBlocked\":%lld,"
        L"\"secureAllocations\":%lld,\"secureBytes\":%lld,\"protectedRegions\":%lld,"
        L"\"dumpAttemptsBlocked\":%lld,\"scanAttemptsDetected\":%lld"
        L"}")
        + 64
        + (ULONG)wcslen(MpProtectionLevelName(Engine->Level))
        + 128
        + (ULONG)(wcslen(L",\"regions\":[") + 2));

    for (i = 0; i < regionCount; i++) {
        needed += (ULONG)(wcslen(L"{\"id\":\"") + 2 + strlen(regions[i].Id)
            + wcslen(L"\",\"type\":\"") + 2 + wcslen(MpRegionTypeName(regions[i].Type))
            + wcslen(L"\",\"status\":\"") + 2 + wcslen(MpIntegrityStatusName(regions[i].Status))
            + wcslen(L"\",\"crc32\":\"%08X\",\"size\":\"%Iu\"},") + 32);
    }
    needed += (ULONG)(wcslen(L"],\"events\":[") + 2);

    for (i = 0; i < eventCount; i++) {
        needed += (ULONG)(wcslen(L"{\"id\":\"%lld\",\"type\":\"") + 2
            + wcslen(MpEventTypeName(events[i].Type))
            + wcslen(L"\",\"addr\":\"%p\",\"size\":\"%Iu\",\"desc\":\"")
            + 2 + strlen(events[i].Description)
            + wcslen(L"\"},") + 32);
    }
    needed += (ULONG)(wcslen(L"]}") + 2);

    if (!Buffer) {
        *Length = needed + 1;   /* 含 null */
        return STATUS_SUCCESS;
    }

    if (*Length < needed + 1) {
        *Length = needed + 1;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 生成 JSON */
    used = (ULONG)swprintf_s(Buffer, *Length,
        L"{"
        L"\"version\":\"3.0.0\","
        L"\"level\":{\"value\":%d,\"name\":\"%s\"},"
        L"\"hardening\":{\"antidump\":%s},"
        L"\"stats\":{"
        L"\"integrityChecks\":%lld,\"violations\":%lld,\"hooks\":%lld,"
        L"\"heapCorruptions\":%lld,\"writesBlocked\":%lld,"
        L"\"secureAllocations\":%lld,\"secureBytes\":%lld,\"protectedRegions\":%lld,"
        L"\"dumpAttemptsBlocked\":%lld,\"scanAttemptsDetected\":%lld"
        L"}",
        (INT)Engine->Level,
        MpProtectionLevelName(Engine->Level),
        MpIsAntiDumpEnabled(Engine) ? L"true" : L"false",
        stats.TotalIntegrityChecks,
        stats.IntegrityViolations,
        stats.HooksDetected,
        stats.HeapCorruptionsDetected,
        stats.MemoryWritesBlocked,
        stats.TotalSecureAllocations,
        stats.TotalSecureBytes,
        stats.TotalProtectedRegions,
        stats.DumpAttemptsBlocked,
        stats.ScanAttemptsDetected);
    if (used < 0) return STATUS_UNSUCCESSFUL;

    used += (ULONG)swprintf_s(Buffer + used, *Length - used, L",\"regions\":[");

    for (i = 0; i < regionCount; i++) {
        INT n = swprintf_s(Buffer + used, *Length - used,
            L"%s{\"id\":\"%hs\",\"type\":\"%s\",\"status\":\"%s\","
            L"\"crc32\":\"%08X\",\"size\":\"%Iu\"}",
            (i == 0) ? L"" : L",",
            regions[i].Id,
            MpRegionTypeName(regions[i].Type),
            MpIntegrityStatusName(regions[i].Status),
            regions[i].CurrentCrc32,
            regions[i].Size);
        if (n < 0) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
        used += (ULONG)n;
    }

    used += (ULONG)swprintf_s(Buffer + used, *Length - used, L"],\"events\":[");

    for (i = 0; i < eventCount; i++) {
        INT n = swprintf_s(Buffer + used, *Length - used,
            L"%s{\"id\":\"%lld\",\"type\":\"%s\",\"addr\":\"%p\","
            L"\"size\":\"%Iu\",\"desc\":\"%hs\"}",
            (i == 0) ? L"" : L",",
            events[i].EventId,
            MpEventTypeName(events[i].Type),
            (PVOID)events[i].Address,
            events[i].Size,
            events[i].Description);
        if (n < 0) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
        used += (ULONG)n;
    }

    used += (ULONG)swprintf_s(Buffer + used, *Length - used, L"]}");

    *Length = used;   /* 不含 null */

Cleanup:
    if (events) {
        free(events);
    }
    if (regions) {
        free(regions);
    }
    return status;
}

/* ------------------------------------------------------------------ */
/* 名称工具（对齐 SS 枚举→字符串映射）                                */
/* ------------------------------------------------------------------ */

/* 保护级别名称。 */
_Use_decl_annotations_
PCWSTR
MpProtectionLevelName(
    _In_ MP_PROTECTION_LEVEL Level
    )
{
    switch (Level) {
    case MpLevelDisabled:
        return L"Disabled";
    case MpLevelMinimal:
        return L"Minimal";
    case MpLevelStandard:
        return L"Standard";
    case MpLevelEnhanced:
        return L"Enhanced";
    case MpLevelMaximum:
        return L"Maximum";
    default:
        return L"Unknown";
    }
}

/* 区域类型名称。 */
_Use_decl_annotations_
PCWSTR
MpRegionTypeName(
    _In_ MP_REGION_TYPE Type
    )
{
    switch (Type) {
    case MpRegionUnknown:
        return L"Unknown";
    case MpRegionCode:
        return L"Code";
    case MpRegionReadOnly:
        return L"ReadOnly";
    case MpRegionReadWrite:
        return L"ReadWrite";
    case MpRegionStack:
        return L"Stack";
    case MpRegionHeap:
        return L"Heap";
    case MpRegionMapped:
        return L"Mapped";
    case MpRegionReserved:
        return L"Reserved";
    case MpRegionGuard:
        return L"Guard";
    default:
        return L"Unknown";
    }
}

/* 完整性状态名称。 */
_Use_decl_annotations_
PCWSTR
MpIntegrityStatusName(
    _In_ MP_INTEGRITY_STATUS Status
    )
{
    switch (Status) {
    case MpIntegrityUnknown:
        return L"Unknown";
    case MpIntegrityValid:
        return L"Valid";
    case MpIntegrityModified:
        return L"Modified";
    case MpIntegrityHooked:
        return L"Hooked";
    case MpIntegrityCorrupted:
        return L"Corrupted";
    default:
        return L"Unknown";
    }
}

/* 分配类型名称。 */
_Use_decl_annotations_
PCWSTR
MpAllocationTypeName(
    _In_ MP_ALLOCATION_TYPE Type
    )
{
    switch (Type) {
    case MpAllocStandard:
        return L"Standard";
    case MpAllocSecure:
        return L"Secure";
    case MpAllocEncrypted:
        return L"Encrypted";
    case MpAllocLocked:
        return L"Locked";
    case MpAllocGuarded:
        return L"Guarded";
    default:
        return L"Unknown";
    }
}

/* 页保护 → 字符串。 */
_Use_decl_annotations_
VOID
MpFormatPageProtection(
    _In_  ULONG Protection,
    _Out_writes_z_(Length) LPWSTR Buffer,
    _In_  ULONG Length
    )
{
    WCHAR text[64];

    text[0] = 0;

    if (Protection & PAGE_GUARD) {
        wcsncat_s(text, 64, L"GUARD|", _TRUNCATE);
    }
    if ((Protection & 0xFF) == PAGE_NOACCESS) {
        wcsncat_s(text, 64, L"NOACCESS", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_EXECUTE) {
        wcsncat_s(text, 64, L"EXECUTE", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_EXECUTE_READ) {
        wcsncat_s(text, 64, L"EXECUTE_READ", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_EXECUTE_READWRITE) {
        wcsncat_s(text, 64, L"EXECUTE_READWRITE", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_EXECUTE_WRITECOPY) {
        wcsncat_s(text, 64, L"EXECUTE_WRITECOPY", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_READONLY) {
        wcsncat_s(text, 64, L"READONLY", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_READWRITE) {
        wcsncat_s(text, 64, L"READWRITE", _TRUNCATE);
    } else if ((Protection & 0xFF) == PAGE_WRITECOPY) {
        wcsncat_s(text, 64, L"WRITECOPY", _TRUNCATE);
    } else {
        wcsncat_s(text, 64, L"UNKNOWN", _TRUNCATE);
    }
    if (Protection & PAGE_NOCACHE) {
        wcsncat_s(text, 64, L"|NOCACHE", _TRUNCATE);
    }
    if (Protection & PAGE_WRITECOMBINE) {
        wcsncat_s(text, 64, L"|WRITECOMBINE", _TRUNCATE);
    }

    if (Buffer && Length > 0) {
        wcsncpy_s(Buffer, Length, text, _TRUNCATE);
    }
}

/* 事件类型名称（对齐 SS MemoryProtectionEventType 位标志枚举）。
 * 单个事件 Type 为单一标志，直接映射。 */
_Use_decl_annotations_
PCWSTR
MpEventTypeName(
    _In_ MP_EVENT_TYPE Type
    )
{
    switch (Type) {
    case MpEventNone:
        return L"None";
    case MpEventMemoryWrite:
        return L"MemoryWrite";
    case MpEventMemoryRead:
        return L"MemoryRead";
    case MpEventPermissionChange:
        return L"PermissionChange";
    case MpEventAllocationAttempt:
        return L"AllocationAttempt";
    case MpEventFreeAttempt:
        return L"FreeAttempt";
    case MpEventIntegrityViolation:
        return L"IntegrityViolation";
    case MpEventCanaryCorruption:
        return L"CanaryCorruption";
    case MpEventHeapCorruption:
        return L"HeapCorruption";
    case MpEventHookDetected:
        return L"HookDetected";
    case MpEventDumpAttempt:
        return L"DumpAttempt";
    case MpEventScanDetected:
        return L"ScanDetected";
    default:
        return L"Unknown";
    }
}

/* ------------------------------------------------------------------ */
/* 监控线程（完整周期性完整性巡检）。对齐 SS monitorThread。 */
static DWORD WINAPI
AcpMemoryIntegrityRoutine(
    _In_ LPVOID Param
    )
{
    PAC_MEMORY_INTEGRITY_ENGINE engine = (PAC_MEMORY_INTEGRITY_ENGINE)Param;;
    ULONG intervalMs;

    if (!engine) return 1;

    /* 巡检循环：默认 500ms 轮询停止事件；启用完整性监控时以配置间隔巡检。
     * 周期内容对齐 SS startIntegrityMonitoring：
     *   先 VerifyAllIntegrity，随后若 EnableHeapProtection 则追加
     *   ValidateHeapIntegrity（与完整性校验同频 integrityCheckIntervalMs）。 */
    while (WaitForSingleObject(engine->MonitorStopEvent, 500) != WAIT_OBJECT_0) {
        if (engine->Config.EnableCodeIntegrity) {
            intervalMs = engine->Config.IntegrityCheckIntervalMs;
            if (intervalMs > 0) {
                if (WaitForSingleObject(engine->MonitorStopEvent,
                        intervalMs) == WAIT_OBJECT_0) {
                    break;
                }
            }
            /* 周期完整性校验（对齐 SS VerifyAllIntegrity）。
             * 2026-09-08 前置链同步：受保护进程链（含 EDR 自身）主模块
             * 可执行节/.rdata/.pdata 幂等注册 —— 即“链消费”，取代旧的
             * MemoryCrc32 自校验与现代码路径分离。 */
            (VOID)MpSyncProtectedProcessSections(engine);
            (VOID)AcpVerifyMemoryIntegrity(engine, NULL, NULL);

            /* 周期堆校验（对齐 SS：enableHeapProtection 时追加，与完整性同频） */
            if (engine->Config.EnableHeapProtection) {
                (VOID)MpValidateHeapIntegrity(engine);
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* 版本（对齐 SS version）                                             */
/* ------------------------------------------------------------------ */

/* 获取版本字符串（对齐 SS GetVersionString）。返回静态串。 */
_Use_decl_annotations_
PCWSTR
MpGetVersionString(
    VOID
    )
{
    return L"3.0.0 (SemanticVersion; ShadowStrike-compatible)";
}

/* ------------------------------------------------------------------ */
/* 文件尾                                                              */
/* ------------------------------------------------------------------ */
