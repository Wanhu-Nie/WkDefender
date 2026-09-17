/**************************************************/
/*  WkDefender IOA — 堆喷攻击模式检测器 (实现)      */
/*                                                  */
/*  迁移自 ShadowStrike HeapSprayDetector.cpp       */
/*  (v3.0.0, 2105 行), 功能重实现非源码复制。        */
/*                                                  */
/*  结构: 静态全局 + SRWLOCK (对齐 SPD/RPD 惯例):    */
/*    g_StateLock   保护 配置/状态                  */
/*    g_MonitorLock 保护 监控进程表                 */
/*    g_HistoryLock 保护 检测历史环形               */
/*    g_CallbackLock保护 检测回调指针               */
/*  统计 volatile 字段 + Interlocked* 更新 (无锁)。  */
/*  锁纪律: 回调调用在锁外; 不嵌套持锁。            */
/*                                                  */
/*  与 SS 的关键差异 (注释就地标注):                */
/*    - 监控线程/Start/Stop 状态机裁剪 → 检测由      */
/*      调用方驱动 (含内核告警触发)                 */
/*    - 事件序列号替代 SS RNG "HS-xxxx" 字符串      */
/*    - ScanAllHeaps 细节拼接改 char 缓冲          */
/**************************************************/

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#include <math.h>

#pragma comment(lib, "psapi.lib")

#include "../../DefendTypes.h"
#include "HeapSprayPatternDetector.h"

/**************************************************/
/*               内部结构                           */
/**************************************************/

/* 分配跟踪条目 (SS AllocationEntry).
 * 裁剪: SS 的 entropy/analyzed/suspicious 在跟踪赋值后从不被读取,
 * 此处仅保留地址/大小/时间戳。 */
typedef struct _HSD_ALLOC_ENTRY {
    UINT64          Address;            /* 分配地址            */
    SIZE_T          Size;               /* 分配大小            */
    LARGE_INTEGER   Timestamp;          /* 分配时间戳          */
} HSD_ALLOC_ENTRY;

/* 监控进程状态 (SS MonitoredProcess) */
typedef struct _HSD_MONITORED_PROCESS {
    ULONG           ProcessId;          /* 进程 ID             */
    WCHAR           ProcessName[DEF_MAX_IMAGE_NAME]; /* 进程名 */
    HSD_ALLOC_ENTRY Allocations[HSD_TRACKED_ALLOCATIONS_PER_PROCESS]; /* 分配环形 */
    UINT32          AllocationHead;     /* 环形头索引 (下一写入位) */
    UINT32          AllocationCount;    /* 环形内有效条数      */
    UINT32          SprayDetectionCount;/* SS 监测周期内累计检出 (线程裁剪, 仅保留计数) */
    LARGE_INTEGER   LastScanTime;       /* 上次扫描时间        */
    BOOLEAN         Active;             /* 活跃标志            */
} HSD_MONITORED_PROCESS;

/* shellcode 模式条目 (SS ShellcodePatternEntry).
 * 显式长度: 模式可含 0x00 有效字节 (如 JMP +0 = {EB,00}),
 * 不能按空终止符截断。 */
typedef struct _HSD_SHELLCODE_PATTERN {
    UCHAR           Bytes[8];
    UCHAR           Length;
} HSD_SHELLCODE_PATTERN;

/* 12 条 shellcode 模式表 (SS SHELLCODE_PATTERNS, 逐字节一致) */
static const HSD_SHELLCODE_PATTERN s_ShellcodePatterns[] = {
    { { 0xEB, 0x00, 0, 0, 0, 0, 0, 0 }, 2 },  /* JMP +0 (解码器常见)        */
    { { 0x90, 0x90, 0x90, 0x90, 0, 0, 0, 0 }, 4 },  /* NOP sled             */
    { { 0x31, 0xC0, 0, 0, 0, 0, 0, 0 }, 2 },  /* XOR EAX, EAX               */
    { { 0x31, 0xDB, 0, 0, 0, 0, 0, 0 }, 2 },  /* XOR EBX, EBX               */
    { { 0x31, 0xC9, 0, 0, 0, 0, 0, 0 }, 2 },  /* XOR ECX, ECX               */
    { { 0x64, 0xA1, 0, 0, 0, 0, 0, 0 }, 2 },  /* MOV EAX, FS:[...]          */
    { { 0x64, 0x8B, 0, 0, 0, 0, 0, 0 }, 2 },  /* MOV ..., FS:[...]          */
    { { 0xFF, 0xD0, 0, 0, 0, 0, 0, 0 }, 2 },  /* CALL EAX                   */
    { { 0xFF, 0xE4, 0, 0, 0, 0, 0, 0 }, 2 },  /* JMP ESP                    */
    { { 0x58, 0x58, 0x58, 0x58, 0, 0, 0, 0 }, 4 },  /* POP EAX ×4         */
    { { 0xFC, 0xE8, 0, 0, 0, 0, 0, 0 }, 2 },  /* CLD + CALL (Metasploit 前奏) */
    { { 0x60, 0xE8, 0, 0, 0, 0, 0, 0 }, 2 },  /* PUSHAD + CALL (解码桩)     */
};

/* 常见 API hash 表 (SS COMMON_API_HASHES, 逐值一致) */
static const UINT32 s_CommonApiHashes[] = {
    0x0726774C,  /* LoadLibraryA      */
    0x7C0DFCAA,  /* GetProcAddress    */
    0xE449F330,  /* VirtualAlloc      */
    0x300F2F0B,  /* VirtualProtect    */
    0x56A2B5F0,  /* ExitProcess       */
    0x8E4E0EEC,  /* CreateProcessA    */
    0xA779563A,  /* WinExec           */
    0x876F8B31,  /* URLDownloadToFileA */
};

/* 常见 NOP 字节表 (SS NOP_SLED_VALUES) */
static const UCHAR s_NopSledValues[] = {
    0x90,   /* NOP        */
    0x41,   /* INC ECX    */
    0x42,   /* INC EDX    */
    0x43,   /* INC EBX    */
    0x44,   /* INC ESP    */
    0x45,   /* INC EBP    */
    0x46,   /* INC ESI    */
    0x47,   /* INC EDI    */
    0x40,   /* INC EAX    */
};

/* 常见喷射靶址表 (SS SPRAY_TARGET_ADDRS_32, x86 经典地址) */
static const UINT32 s_SprayTargetAddrs32[] = {
    0x0C0C0C0C,
    0x0D0D0D0D,
    0x0A0A0A0A,
    0x0B0B0B0B,
    0x06060606,
    0x07070707,
    0x04040404,
    0x05050505,
};

/* 脚本引擎名表 (SS IsScriptEngine, 14 项, 小写) */
static const WCHAR* const s_ScriptEngines[] = {
    L"chrome.exe",   L"firefox.exe",  L"msedge.exe",  L"iexplore.exe",
    L"safari.exe",   L"opera.exe",    L"node.exe",    L"java.exe",
    L"javaw.exe",    L"wscript.exe",  L"cscript.exe", L"mshta.exe",
    L"powershell.exe", L"pwsh.exe",
};

/**************************************************/
/*               静态全局状态                       */
/**************************************************/

static volatile BOOLEAN  g_Initialized = FALSE;
static volatile HSD_STATUS g_Status = HsdStatus_Uninitialized;
static HSD_CONFIG        g_Config = HSD_DEFAULT_CONFIG;
static SRWLOCK           g_StateLock = SRWLOCK_INIT;

static HSD_MONITORED_PROCESS g_Monitored[HSD_MAX_MONITORED_PROCESSES];
static ULONG             g_MonitorCount = 0;
static SRWLOCK           g_MonitorLock = SRWLOCK_INIT;

static HSD_DETECTION_EVENT g_RecentEvents[HSD_MAX_RECENT_DETECTIONS];
static UINT32            g_RecentHead = 0;   /* 下一写入位  */
static UINT32            g_RecentCount = 0;  /* 有效条数     */
static SRWLOCK           g_HistoryLock = SRWLOCK_INIT;

static HSD_DETECTED_CALLBACK g_SprayCallback = NULL;
static SRWLOCK           g_CallbackLock = SRWLOCK_INIT;

/* 统计 (SS HeapSprayStatistics; volatile + Interlocked 更新) */
static volatile UINT64   g_ScansPerformed = 0;
static volatile UINT64   g_BlocksAnalyzed = 0;
static volatile UINT64   g_SpraysDetected = 0;
static volatile UINT64   g_NopSledsDetected = 0;
static volatile UINT64   g_ShellcodesDetected = 0;
static volatile UINT64   g_LowEntropyBlocks = 0;
static volatile UINT64   g_HighEntropyBlocks = 0;
static volatile UINT64   g_AttacksBlocked = 0;
static volatile UINT64   g_ByTechnique[16];
static ULONG64           g_StartTick = 0;    /* Initialize 时刻 GetTickCount64 */
static LARGE_INTEGER     g_StartTime = { 0 }; /* Initialize 时刻 FILETIME */

/* 事件序列号 (替代 SS RNG "HS-xxxx") */
static volatile ULONG    g_EventSequence = 0;

/**************************************************/
/*               内部函数                           */
/**************************************************/

/*++
HsdGetProcessName — 获取进程名 (文件名部分)。
   GetProcessName: OpenProcess(QUERY_LIMITED_INFORMATION)
   + QueryFullProcessImageNameW + 取末尾文件名字段。
   返回 FALSE 时输出缓冲置空。
--*/
static BOOLEAN
HsdpGetProcessName(
    _In_ ULONG ProcessId,
    _Out_writes_(NameSize) WCHAR* Name,
    _In_ SIZE_T NameSize)
{
    HANDLE hProcess;
    DWORD size;
    WCHAR path[DEF_MAX_PATH * 2];
    WCHAR* slash;

    if (Name == NULL || NameSize == 0 || ProcessId == 0) {
        return FALSE;
    }

    Name[0] = L'\0';

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    size = (DWORD)(DEF_MAX_PATH * 2);
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        path[DEF_MAX_PATH * 2 - 1] = L'\0';
        slash = wcsrchr(path, L'\\');
        if (slash == NULL) {
            slash = wcsrchr(path, L'/');
        }
        if (slash != NULL && slash[1] != L'\0') {
            wcsncpy_s(Name, NameSize, slash + 1, _TRUNCATE);
        } else {
            wcsncpy_s(Name, NameSize, path, _TRUNCATE);
        }
        Name[NameSize - 1] = L'\0';
    }

    CloseHandle(hProcess);
    return (Name[0] != L'\0');
}

/*++
HsdIsScriptEngine — 进程名是否命中脚本引擎表 (大小写不敏感子串匹配)。
   IsScriptEngine (14 项引擎表)。
--*/
static BOOLEAN
HsdpIsScriptEngine(
    _In_ const WCHAR* ProcessName)
{
    WCHAR lower[DEF_MAX_IMAGE_NAME];
    SIZE_T i;
    SIZE_T n;

    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return FALSE;
    }

    wcsncpy_s(lower, DEF_MAX_IMAGE_NAME, ProcessName, _TRUNCATE);
    lower[DEF_MAX_IMAGE_NAME - 1] = L'\0';
    _wcslwr_s(lower, DEF_MAX_IMAGE_NAME);

    n = sizeof(s_ScriptEngines) / sizeof(s_ScriptEngines[0]);
    for (i = 0; i < n; i++) {
        if (wcsstr(lower, s_ScriptEngines[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
HsdFindNopSledLength — 查找最长统一字节 NOP sled 长度。
   FindNopSledLength: 连续 NOP 字节, 同字节延长计数,
   不同 NOP 字节视为新 sled (sledByte 重置为当前字节, 长度 1)。
--*/
static SIZE_T
HsdpFindNopSledLength(
    _In_reads_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize)
{
    SIZE_T maxSled = 0;
    SIZE_T current = 0;
    BOOLEAN inSled = FALSE;
    UCHAR sledByte = 0;
    SIZE_T i;

    for (i = 0; i < DataSize; i++) {
        UCHAR b = Data[i];
        if (HsdIsCommonNopByte(b)) {
            if (!inSled) {
                inSled = TRUE;
                sledByte = b;
                current = 1;
            } else if (b == sledByte) {
                current++;
            } else {
                /* 不同 NOP 字节 → 新 sled (NOP sled 使用统一字节) */
                sledByte = b;
                current = 1;
            }
            if (current > maxSled) {
                maxSled = current;
            }
        } else {
            inSled = FALSE;
            current = 0;
        }
    }
    return maxSled;
}

/*++
HsdContainsApiHash — 数据中是否含常见 API hash (ContainsApiHash).
   逐 4 字节 memcpy 对齐安全扫描 8 个 hash 表。
--*/
static BOOLEAN
HsdpContainsApiHash(
    _In_reads_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize)
{
    SIZE_T i;
    SIZE_T n;
    SIZE_T j;

    if (Data == NULL || DataSize < 4) {
        return FALSE;
    }

    n = sizeof(s_CommonApiHashes) / sizeof(s_CommonApiHashes[0]);

    for (i = 0; i <= DataSize - 4; i++) {
        UINT32 dwordValue = 0;
        memcpy(&dwordValue, &Data[i], sizeof(dwordValue));
        for (j = 0; j < n; j++) {
            if (dwordValue == s_CommonApiHashes[j]) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*++
HsdExtractSprayPattern — 提取基础模式单元 (前 64B) + 重复计数 + 靶址。
   ExtractSprayPattern。
   注意: SS 主流程 (CreateSprayEvent/ScanProcessHeap) 从未调用本函数,
   sprayPattern 恒为 nullopt; 此处保留实现 (可单独调用) 不接线。
--*/
static BOOLEAN
HsdpExtractSprayPattern(
    _In_reads_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _Out_ PHSD_SPRAY_PATTERN Pattern)
{
    UINT32 repeats;
    UINT32 dwordValue;
    SIZE_T offset;

    if (Data == NULL || DataSize < HSD_MIN_SHELLCODE_SIZE || Pattern == NULL) {
        return FALSE;
    }

    memset(Pattern, 0, sizeof(*Pattern));
    Pattern->PatternId = (UINT64)InterlockedIncrement((volatile LONG*)&g_EventSequence);
    Pattern->Technique = HsdSpray_Unknown;   /* SS 实现未赋值, 恒 Unknown */

    /* 提取基础模式单元 (前 64 字节或更少) */
    Pattern->PatternLength = (UINT32)((DataSize < HSD_PATTERN_UNIT_SIZE) ?
                                      DataSize : HSD_PATTERN_UNIT_SIZE);
    memcpy(Pattern->PatternBytes, Data, Pattern->PatternLength);

    /* 统计基础模式连续重复次数 */
    repeats = 0;
    if (Pattern->PatternLength > 0 &&
        DataSize >= (SIZE_T)Pattern->PatternLength * 2) {
        for (offset = 0;
             offset + Pattern->PatternLength <= DataSize;
             offset += Pattern->PatternLength) {
            if (memcmp(Data + offset, Pattern->PatternBytes,
                       Pattern->PatternLength) == 0) {
                repeats++;
            } else {
                break;
            }
        }
        Pattern->RepeatCount = repeats;
    }

    /* 模式前 4 字节是否命中经典靶址 */
    dwordValue = 0;
    memcpy(&dwordValue, Data, sizeof(dwordValue));
    if (HsdIsCommonSprayAddress(dwordValue)) {
        Pattern->TargetAddress = dwordValue;
    }

    return TRUE;
}

/*++
HsdCalculateConfidence — 置信度分级。
   CalculateConfidence 评分表:
     NOP sled +2 / shellcode +3 / 熵<0.5 +2 / 主导字节>90% +1 /
     规模≥10MB +1 / 脚本引擎 +1
     ≥7 Confirmed / ≥5 VeryHigh / ≥3 High / ≥2 Medium / 否则 Low
--*/
static HSD_CONFIDENCE
HsdpCalculateConfidence(
    _In_ const HSD_ALLOCATION_INFO* Info,
    _In_ ULONG ProcessId,
    _In_ const HSD_CONFIG* Config)
{
    UINT32 score = 0;
    WCHAR procName[DEF_MAX_IMAGE_NAME];

    if (Info->ContainsNopSled) score += 2;
    if (Info->ContainsShellcode) score += 3;
    if (Info->Entropy < HSD_ENTROPY_THRESHOLD_VERY_LOW) score += 2;
    if (Info->DominantBytePercent > 90.0) score += 1;
    if (Info->Size >= 10 * 1024 * 1024) score += 1;

    /* 脚本引擎进程加分 (SS 无条件调用, 不检查 MonitorScriptEngines 配置) */
    if (HsdpGetProcessName(ProcessId, procName, DEF_MAX_IMAGE_NAME)) {
        if (HsdpIsScriptEngine(procName)) {
            score += 1;
        }
    }

    (VOID)Config;

    if (score >= 7) return HsdConf_Confirmed;
    if (score >= 5) return HsdConf_VeryHigh;
    if (score >= 3) return HsdConf_High;
    if (score >= 2) return HsdConf_Medium;
    return HsdConf_Low;
}

/*++
HsdCreateEvent — 构造喷射检测事件。
   CreateSprayEvent:
     technique 用首块熵做"空数据熵分类";
     进程路径/名经 QueryFullProcessImageNameW;
     sprayPattern 恒不设置 (SS 语义);
     shellcode 样本取首个含壳块的前 64 字节。
--*/
static HSD_DETECTION_EVENT
HsdpCreateEvent(
    _In_ ULONG ProcessId,
    _In_reads_(BlockCount) const HSD_ALLOCATION_INFO* Blocks,
    _In_ ULONG BlockCount,
    _In_ const HSD_CONFIG* Config)
{
    HSD_DETECTION_EVENT evt;
    ULONG i;
    ULONG stored;
    HANDLE hProcess;
    DWORD size;
    WCHAR* slash;

    memset(&evt, 0, sizeof(evt));

    evt.EventId = (ULONG)InterlockedIncrement((volatile LONG*)&g_EventSequence);
    evt.ProcessId = ProcessId;
    GetSystemTimePreciseAsFileTime((LPFILETIME)&evt.Timestamp);

    evt.BlockCount = BlockCount;
    evt.Technique = HsdSpray_Unknown;
    evt.Confidence = HsdConf_Unknown;
    evt.HasSprayPattern = FALSE;   /* SS 恒不设置喷雾模式 */

    for (i = 0; i < BlockCount; i++) {
        evt.TotalSprayedBytes += Blocks[i].Size;
        if (Blocks[i].ContainsShellcode) {
            evt.ShellcodeDetected = TRUE;
        }
    }

    /* 技术分类: 空数据 + 首块熵 (空 span 熵分类) */
    if (BlockCount > 0) {
        evt.Technique = HsdIdentifySprayTechnique(NULL, 0, Blocks[0].Entropy);
        evt.Confidence = HsdpCalculateConfidence(&Blocks[0], ProcessId, Config);
    }

    /* 内嵌可疑块 (定长上限 16) */
    stored = (BlockCount < HSD_MAX_SUSPICIOUS_BLOCKS) ?
             BlockCount : HSD_MAX_SUSPICIOUS_BLOCKS;
    evt.StoredBlockCount = stored;
    for (i = 0; i < stored; i++) {
        evt.SuspiciousBlocks[i] = Blocks[i];
    }

    /* SS 中 shellcodeSample 从未被赋值 (vector 恒空), 此处保持一致:
     * 样本读取需额外 ReadProcessMemory, 留给上层按块地址自行采集。 */

    /* 进程路径/名 */
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess != NULL) {
        size = (DWORD)(DEF_MAX_PATH * 2);
        if (QueryFullProcessImageNameW(hProcess, 0, evt.ProcessPath, &size)) {
            evt.ProcessPath[DEF_MAX_PATH * 2 - 1] = L'\0';
            slash = wcsrchr(evt.ProcessPath, L'\\');
            if (slash == NULL) {
                slash = wcsrchr(evt.ProcessPath, L'/');
            }
            if (slash != NULL && slash[1] != L'\0') {
                wcsncpy_s(evt.ProcessName, DEF_MAX_IMAGE_NAME,
                          slash + 1, _TRUNCATE);
            }
        }
        CloseHandle(hProcess);
    }

    return evt;
}

/*++
HsdNotifyDetected — 锁外回调分发 (SS NotifySprayDetected).
   在 g_CallbackLock 下仅拷贝指针, 释放后调用, 防回调死锁。
--*/
static VOID
HsdpNotifyDetected(
    _In_ const HSD_DETECTION_EVENT* Event)
{
    HSD_DETECTED_CALLBACK callback;

    AcquireSRWLockShared(&g_CallbackLock);
    callback = g_SprayCallback;
    ReleaseSRWLockShared(&g_CallbackLock);

    if (callback != NULL) {
        callback(Event);
    }
}

/*++
HsdTrackAllocation — 监控进程分配记录 (要求调用者持 g_MonitorLock).
   OnMemoryAllocation 内联跟踪逻辑: 环形写入, 满则覆盖最旧;
   Threshold > 0 时统计窗口内 ≥Threshold 的大分配计数。
   返回是否找到监控进程。
--*/
static BOOLEAN
HsdpTrackAllocation(
    _In_ ULONG ProcessId,
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _In_ SIZE_T Threshold,
    _Out_ ULONG* RecentLargeCount)
{
    HSD_MONITORED_PROCESS* mp;
    SIZE_T i;
    UINT32 j;
    UINT32 n;

    *RecentLargeCount = 0;

    for (i = 0; i < g_MonitorCount; i++) {
        if (g_Monitored[i].ProcessId == ProcessId) {
            mp = &g_Monitored[i];
            mp->Allocations[mp->AllocationHead].Address = Address;
            mp->Allocations[mp->AllocationHead].Size = Size;
            GetSystemTimePreciseAsFileTime(
                (LPFILETIME)&mp->Allocations[mp->AllocationHead].Timestamp);
            mp->AllocationHead = (mp->AllocationHead + 1) %
                                 HSD_TRACKED_ALLOCATIONS_PER_PROCESS;
            if (mp->AllocationCount < HSD_TRACKED_ALLOCATIONS_PER_PROCESS) {
                mp->AllocationCount++;
            }

            /* 统计窗口内大分配 (环形最旧优先遍历) */
            if (Threshold > 0) {
                n = mp->AllocationCount;
                for (j = 0; j < n; j++) {
                    UINT32 idx = (mp->AllocationHead +
                                  HSD_TRACKED_ALLOCATIONS_PER_PROCESS -
                                  n + j) % HSD_TRACKED_ALLOCATIONS_PER_PROCESS;
                    if (mp->Allocations[idx].Size >= Threshold) {
                        (*RecentLargeCount)++;
                    }
                }
            }
            return TRUE;
        }
    }
    return FALSE;
}

/*++
HsdIsValidConfig — 配置校验 (IsValid):
   阈值 ∈ (0, 64MB]; 熵 ∈ [0, 8]; 间隔 ∈ (0, 60000]。
--*/
static BOOLEAN
HsdpIsValidConfig(
    _In_ const HSD_CONFIG* Config)
{
    if (Config == NULL) {
        return FALSE;
    }
    if (Config->MinAllocationThreshold == 0 ||
        Config->MinAllocationThreshold > HSD_MAX_SPRAY_BLOCK_SIZE) {
        return FALSE;
    }
    if (Config->LowEntropyThreshold < 0.0 ||
        Config->LowEntropyThreshold > 8.0) {
        return FALSE;
    }
    if (Config->ScanIntervalMs == 0 || Config->ScanIntervalMs > 60000) {
        return FALSE;
    }
    return TRUE;
}

/*++
HsdGetLiveStats — 统计快照拷贝 (SS FromLive 语义)。
   统计字段均为 volatile, x64 对齐读写原子; 快照按序拷贝。
--*/
static VOID
HsdpGetLiveStats(
    _Out_ PHSD_STATS_SNAPSHOT Snapshot)
{
    ULONG i;

    if (Snapshot == NULL) {
        return;
    }

    memset(Snapshot, 0, sizeof(*Snapshot));
    Snapshot->ScansPerformed     = g_ScansPerformed;
    Snapshot->BlocksAnalyzed     = g_BlocksAnalyzed;
    Snapshot->SpraysDetected     = g_SpraysDetected;
    Snapshot->NopSledsDetected   = g_NopSledsDetected;
    Snapshot->ShellcodesDetected = g_ShellcodesDetected;
    Snapshot->LowEntropyBlocks   = g_LowEntropyBlocks;
    Snapshot->HighEntropyBlocks  = g_HighEntropyBlocks;
    Snapshot->AttacksBlocked     = g_AttacksBlocked;
    for (i = 0; i < 16; i++) {
        Snapshot->ByTechnique[i] = g_ByTechnique[i];
    }
    Snapshot->StartTime = g_StartTime;
    Snapshot->UptimeSeconds = (g_StartTick != 0) ?
        ((GetTickCount64() - g_StartTick) / 1000ULL) : 0ULL;
}

/**************************************************/
/*               生命周期/配置                      */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
HsdInitialize(
    const HSD_CONFIG* Config)
{
    NTSTATUS status = STATUS_SUCCESS;
    HSD_CONFIG localConfig = HSD_DEFAULT_CONFIG;

    if (Config != NULL) {
        localConfig = *Config;
    }

    if (!HsdpIsValidConfig(&localConfig)) {
        g_Status = HsdStatus_Error;
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockExclusive(&g_StateLock);
    if (g_Initialized) {
        ReleaseSRWLockExclusive(&g_StateLock);
        return STATUS_SUCCESS;
    }

    g_Status = HsdStatus_Initializing;
    g_Config = localConfig;

    /* 重置统计 */
    g_ScansPerformed = 0;
    g_BlocksAnalyzed = 0;
    g_SpraysDetected = 0;
    g_NopSledsDetected = 0;
    g_ShellcodesDetected = 0;
    g_LowEntropyBlocks = 0;
    g_HighEntropyBlocks = 0;
    g_AttacksBlocked = 0;
    memset((VOID*)g_ByTechnique, 0, sizeof(g_ByTechnique));
    g_StartTick = GetTickCount64();
    GetSystemTimePreciseAsFileTime((LPFILETIME)&g_StartTime);

    g_Initialized = TRUE;
    g_Status = HsdStatus_Running;
    ReleaseSRWLockExclusive(&g_StateLock);

    return status;
}

_Use_decl_annotations_
VOID
HsdShutdown(
    VOID)
{
    ULONG i;

    AcquireSRWLockExclusive(&g_StateLock);
    if (!g_Initialized) {
        ReleaseSRWLockExclusive(&g_StateLock);
        return;
    }
    g_Status = HsdStatus_Stopping;
    g_Initialized = FALSE;
    ReleaseSRWLockExclusive(&g_StateLock);

    /* 清监控表 (SS Shutdown 释放主锁后清理数据结构的顺序一致) */
    AcquireSRWLockExclusive(&g_MonitorLock);
    for (i = 0; i < g_MonitorCount; i++) {
        memset(&g_Monitored[i], 0, sizeof(g_Monitored[i]));
    }
    g_MonitorCount = 0;
    ReleaseSRWLockExclusive(&g_MonitorLock);

    /* 清历史 */
    AcquireSRWLockExclusive(&g_HistoryLock);
    g_RecentHead = 0;
    g_RecentCount = 0;
    memset(g_RecentEvents, 0, sizeof(g_RecentEvents));
    ReleaseSRWLockExclusive(&g_HistoryLock);

    /* 清回调 */
    AcquireSRWLockExclusive(&g_CallbackLock);
    g_SprayCallback = NULL;
    ReleaseSRWLockExclusive(&g_CallbackLock);

    g_Status = HsdStatus_Stopped;
}

_Use_decl_annotations_
BOOLEAN
HsdIsInitialized(
    VOID)
{
    return g_Initialized;
}

_Use_decl_annotations_
HSD_STATUS
HsdGetStatus(
    VOID)
{
    return g_Status;
}

_Use_decl_annotations_
NTSTATUS
HsdUpdateConfiguration(
    const HSD_CONFIG* Config)
{
    if (!HsdpIsValidConfig(Config)) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockExclusive(&g_StateLock);
    g_Config = *Config;
    ReleaseSRWLockExclusive(&g_StateLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HsdGetConfiguration(
    HSD_CONFIG* Config)
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockShared(&g_StateLock);
    *Config = g_Config;
    ReleaseSRWLockShared(&g_StateLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
const WCHAR*
HsdGetVersionString(
    VOID)
{
    return L"3.0.0";
}

/**************************************************/
/*               堆扫描/内存分析                    */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
HsdScanProcessHeap(
    ULONG ProcessId,
    PHSD_DETECTION_EVENT Event)
{
    HSD_CONFIG localConfig;
    HSD_ALLOCATION_INFO suspicious[HSD_MAX_SUSPICIOUS_PER_SCAN];
    ULONG suspiciousCount = 0;
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    UINT64 currentAddr = 0;
    UINT64 nextAddr;
    BOOLEAN eventProduced = FALSE;
    DOUBLE score;

    if (Event == NULL) {
        return FALSE;
    }

    if (!g_Initialized || ProcessId == 0) {
        return FALSE;
    }

    /* 配置快照 */
    AcquireSRWLockShared(&g_StateLock);
    localConfig = g_Config;
    ReleaseSRWLockShared(&g_StateLock);

    InterlockedIncrement64((volatile LONG64*)&g_ScansPerformed);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    /* VirtualQueryEx 遍历提交区 (ScanProcessHeap) */
    while (VirtualQueryEx(hProcess, (LPCVOID)currentAddr,
                          &mbi, sizeof(mbi)) == sizeof(mbi)) {
        HSD_ALLOCATION_INFO info;
        BOOLEAN isSuspicious;

        if (mbi.State == MEM_COMMIT &&
            mbi.RegionSize >= localConfig.MinAllocationThreshold &&
            mbi.RegionSize <= HSD_MAX_SPRAY_BLOCK_SIZE) {

            HsdAnalyzeMemoryRegion(ProcessId,
                                   (UINT64)(UINT_PTR)mbi.BaseAddress,
                                   mbi.RegionSize, &info);
            InterlockedIncrement64((volatile LONG64*)&g_BlocksAnalyzed);

            isSuspicious = FALSE;

            if (localConfig.EnableEntropyAnalysis) {
                if (info.Entropy < localConfig.LowEntropyThreshold) {
                    isSuspicious = TRUE;
                    InterlockedIncrement64((volatile LONG64*)&g_LowEntropyBlocks);
                } else if (info.Entropy > HSD_ENTROPY_THRESHOLD_HIGH) {
                    isSuspicious = TRUE;
                    InterlockedIncrement64((volatile LONG64*)&g_HighEntropyBlocks);
                }
            }

            if (info.ContainsNopSled) {
                isSuspicious = TRUE;
                InterlockedIncrement64((volatile LONG64*)&g_NopSledsDetected);
            }

            if (localConfig.EnableShellcodeDetection && info.ContainsShellcode) {
                isSuspicious = TRUE;
                InterlockedIncrement64((volatile LONG64*)&g_ShellcodesDetected);
            }

            if (isSuspicious) {
                suspicious[suspiciousCount++] = info;
                if (suspiciousCount >= HSD_MAX_SUSPICIOUS_PER_SCAN) {
                    /* 单扫描可疑块硬上限 (防病态地址空间耗尽 CPU, SS 同) */
                    break;
                }
            }
        }

        /* 溢出防护: 下一地址回绕则停止 */
        nextAddr = (UINT64)(UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= currentAddr) {
            break;
        }
        currentAddr = nextAddr;
    }

    CloseHandle(hProcess);

    /* ≥3 块触发事件 (ScanProcessHeap 尾部) */
    if (suspiciousCount >= HSD_SUSPICIOUS_TRIGGER_COUNT) {
        HSD_DETECTION_EVENT evt = HsdpCreateEvent(ProcessId, suspicious,
                                                  suspiciousCount,
                                                  &localConfig);

        /* 评分 = 块数×10 + 喷射 MB + 壳码(+30) + 模式(+20), 封顶 100
         * (SS 中 SprayPattern 恒无效, pattern 加分分支不生效) */
        score = 0.0;
        score += (DOUBLE)suspiciousCount * 10.0;
        score += (DOUBLE)evt.TotalSprayedBytes / (1024.0 * 1024.0);
        if (evt.ShellcodeDetected) score += 30.0;
        if (evt.HasSprayPattern) score += 20.0;
        if (score > 100.0) score = 100.0;
        evt.ConfidenceScore = score;

        InterlockedIncrement64((volatile LONG64*)&g_SpraysDetected);
        if ((ULONG)evt.Technique < 16) {
            InterlockedIncrement64((volatile LONG64*)&g_ByTechnique[evt.Technique]);
        }

        /* 历史入队 (环形, 上限 1000) */
        AcquireSRWLockExclusive(&g_HistoryLock);
        g_RecentEvents[g_RecentHead] = evt;
        g_RecentHead = (g_RecentHead + 1) % HSD_MAX_RECENT_DETECTIONS;
        if (g_RecentCount < HSD_MAX_RECENT_DETECTIONS) {
            g_RecentCount++;
        }
        ReleaseSRWLockExclusive(&g_HistoryLock);

        /* 锁外回调 */
        HsdpNotifyDetected(&evt);

        *Event = evt;
        eventProduced = TRUE;
    }

    return eventProduced;
}

_Use_decl_annotations_
BOOLEAN
HsdScanAllHeaps(
    ULONG ProcessId,
    PHSD_DETECTION_EVENT Event)
{
    BOOLEAN found = FALSE;
    HEAPLIST32 heapList;
    UINT32 heapCount = 0;
    WCHAR detail[64];
    HANDLE hSnapshot;

    if (Event == NULL || ProcessId == 0) {
        return FALSE;
    }

    /* Toolhelp32 堆枚举 */
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        /* 堆枚举不可用 → 回退单扫描 (SS 同) */
        return HsdScanProcessHeap(ProcessId, Event);
    }

    memset(&heapList, 0, sizeof(heapList));
    heapList.dwSize = sizeof(heapList);

    if (Heap32ListFirst(hSnapshot, &heapList)) {
        do {
            heapCount++;
        } while (Heap32ListNext(hSnapshot, &heapList));
    }
    CloseHandle(hSnapshot);

    if (HsdScanProcessHeap(ProcessId, Event)) {
        if (heapCount > 0) {
            wsprintfW(detail, L" Toolhelp heap count: %u.", heapCount);
            if (wcslen(Event->Details) + wcslen(detail) < HSD_DETAILS_SIZE) {
                wcscat_s(Event->Details, HSD_DETAILS_SIZE, detail);
            }
            if (heapCount >= HSD_ABNORMAL_TOOLHELP_HEAP_COUNT) {
                detail[0] = L'\0';
                wsprintfW(detail, L" Abnormally high heap count observed.");
                if (wcslen(Event->Details) + wcslen(detail) < HSD_DETAILS_SIZE) {
                    wcscat_s(Event->Details, HSD_DETAILS_SIZE, detail);
                }
                Event->ConfidenceScore += 5.0;
                if (Event->ConfidenceScore > 100.0) {
                    Event->ConfidenceScore = 100.0;
                }
            }
        }
        found = TRUE;
    }

    return found;
}

_Use_decl_annotations_
NTSTATUS
HsdAnalyzeMemoryRegion(
    ULONG ProcessId,
    UINT64 Address,
    SIZE_T Size,
    PHSD_ALLOCATION_INFO Info)
{
    HANDLE hProcess;
    SIZE_T sampleSize;
    UCHAR buffer[HSD_ENTROPY_SAMPLE_SIZE];
    SIZE_T bytesRead = 0;
    MEMORY_BASIC_INFORMATION mbi;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    memset(Info, 0, sizeof(*Info));
    Info->Address = Address;
    Info->Size = Size;

    /* 超过最大喷射块规模不再深入 (SS 同) */
    if (Size == 0 || Size > HSD_MAX_SPRAY_BLOCK_SIZE) {
        return STATUS_SUCCESS;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_SUCCESS;   /* SS: 打开失败返回默认信息 */
    }

    /* 读取样本 (上限 4096, 防过度内存) */
    sampleSize = (Size < HSD_ENTROPY_SAMPLE_SIZE) ? Size : HSD_ENTROPY_SAMPLE_SIZE;
    if (ReadProcessMemory(hProcess, (LPCVOID)Address, buffer,
                          sampleSize, &bytesRead) && bytesRead > 0) {
        HsdAnalyzeMemoryBlock(buffer, bytesRead, Address, Info);
        Info->Size = Size;   /* 恢复整区规模 */
    }

    /* 保护/区域类型 */
    if (VirtualQueryEx(hProcess, (LPCVOID)Address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        Info->Protection = mbi.Protect;
        Info->IsExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        Info->IsWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (mbi.Type == MEM_IMAGE) {
            Info->RegionType = HsdRegion_Image;
        } else if (mbi.Type == MEM_MAPPED) {
            Info->RegionType = HsdRegion_Mapped;
        } else if (mbi.Type == MEM_PRIVATE) {
            Info->RegionType = HsdRegion_Private;
        }
    }

    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HsdAnalyzeMemoryBlock(
    const UCHAR* Data,
    SIZE_T DataSize,
    UINT64 BaseAddress,
    PHSD_ALLOCATION_INFO Info)
{
    HSD_CONFIG localConfig;
    UINT32 byteFreq[256];
    UINT32 maxCount;
    SIZE_T i;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    memset(Info, 0, sizeof(*Info));
    Info->Address = BaseAddress;
    Info->Size = DataSize;

    if (Data == NULL || DataSize == 0) {
        return STATUS_SUCCESS;
    }

    /* 配置快照 */
    AcquireSRWLockShared(&g_StateLock);
    localConfig = g_Config;
    ReleaseSRWLockShared(&g_StateLock);

    /* 香农熵 + 熵标志 */
    if (localConfig.EnableEntropyAnalysis) {
        Info->Entropy = HsdCalculateEntropy(Data, DataSize);
        if (Info->Entropy < localConfig.LowEntropyThreshold) {
            Info->Flags |= HSD_ALLOC_FLAG_LOW_ENTROPY;
        } else if (Info->Entropy > HSD_ENTROPY_THRESHOLD_HIGH) {
            Info->Flags |= HSD_ALLOC_FLAG_HIGH_ENTROPY;
        }
    }

    /* 主导字节 */
    memset(byteFreq, 0, sizeof(byteFreq));
    for (i = 0; i < DataSize; i++) {
        byteFreq[Data[i]]++;
    }
    maxCount = 0;
    for (i = 0; i < 256; i++) {
        if (byteFreq[i] > maxCount) {
            maxCount = byteFreq[i];
            Info->DominantByte = (UCHAR)i;
        }
    }
    Info->DominantBytePercent = (100.0 * (DOUBLE)maxCount) /
                                (DOUBLE)DataSize;

    /* NOP sled 检测 (最小 64, SS 同) */
    if (localConfig.Enabled) {
        Info->ContainsNopSled = HsdDetectNopSled(Data, DataSize,
                                                 HSD_MIN_NOP_SLED_LENGTH);
    }

    /* shellcode 检测 */
    if (localConfig.EnableShellcodeDetection) {
        Info->ContainsShellcode = HsdDetectShellcode(Data, DataSize);
    }

    /* 多指标 → 可疑标志 (SS 同: 未开熵分析时 entropy=0 也会触发低熵判定) */
    if (Info->ContainsNopSled || Info->ContainsShellcode ||
        Info->Entropy < HSD_ENTROPY_THRESHOLD_VERY_LOW ||
        Info->DominantBytePercent > 80.0) {
        Info->Flags |= HSD_ALLOC_FLAG_SUSPICIOUS;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
DOUBLE
HsdCalculateEntropy(
    const UCHAR* Data,
    SIZE_T DataSize)
{
    UINT32 freq[256];
    DOUBLE entropy = 0.0;
    DOUBLE size;
    SIZE_T i;

    if (Data == NULL || DataSize == 0) {
        return 0.0;
    }

    memset(freq, 0, sizeof(freq));
    for (i = 0; i < DataSize; i++) {
        freq[Data[i]]++;
    }

    /* 香农熵 */
    size = (DOUBLE)DataSize;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            DOUBLE p = (DOUBLE)freq[i] / size;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

_Use_decl_annotations_
BOOLEAN
HsdDetectNopSled(
    const UCHAR* Data,
    SIZE_T DataSize,
    SIZE_T MinLength)
{
    if (Data == NULL || DataSize < MinLength) {
        return FALSE;
    }
    return (HsdpFindNopSledLength(Data, DataSize) >= MinLength);
}

_Use_decl_annotations_
BOOLEAN
HsdDetectShellcode(
    const UCHAR* Data,
    SIZE_T DataSize)
{
    UINT32 indicators = 0;
    SIZE_T patternCount;
    SIZE_T p;
    SIZE_T i;

    if (Data == NULL || DataSize < HSD_MIN_SHELLCODE_SIZE) {
        return FALSE;
    }

    /* 12 模式显式长度匹配 (每模式命中一次即计数) */
    patternCount = sizeof(s_ShellcodePatterns) / sizeof(s_ShellcodePatterns[0]);
    for (p = 0; p < patternCount; p++) {
        UCHAR len = s_ShellcodePatterns[p].Length;
        if (len == 0 || (SIZE_T)len > DataSize) {
            continue;
        }
        for (i = 0; i <= DataSize - (SIZE_T)len; i++) {
            if (memcmp(&Data[i], s_ShellcodePatterns[p].Bytes, len) == 0) {
                indicators++;
                break;
            }
        }
    }

    /* API hash (+2) */
    if (HsdpContainsApiHash(Data, DataSize)) {
        indicators += 2;
    }

    /* XOR [reg],imm 解码循环 (+1, 壳码常见) */
    if (DataSize >= 8) {
        for (i = 0; i + 1 < DataSize; i++) {
            if (Data[i] == 0x80 && (Data[i + 1] & 0xF8) == 0x30) {
                indicators++;
                break;
            }
        }
    }

    /* 3+ 指标判壳 */
    return (indicators >= 3);
}

_Use_decl_annotations_
HSD_SPRAY_TECHNIQUE
HsdIdentifySprayTechnique(
    const UCHAR* Data,
    SIZE_T DataSize,
    DOUBLE Entropy)
{
    UINT32 dwordValue = 0;

    /* 空数据 → 纯熵分类 (对齐 SS) */
    if (Data == NULL || DataSize == 0) {
        if (Entropy < HSD_ENTROPY_THRESHOLD_VERY_LOW) {
            return HsdSpray_ClassicNopSled;
        }
        if (Entropy > HSD_ENTROPY_THRESHOLD_HIGH) {
            return HsdSpray_ArrayBuffer;
        }
        if (Entropy > 3.0 && Entropy < 5.0) {
            return HsdSpray_StringSpray;
        }
        return HsdSpray_Unknown;
    }

    /* 低熵 + NOP sled(32) → 经典 NOP sled 喷 */
    if (Entropy < HSD_ENTROPY_THRESHOLD_VERY_LOW &&
        HsdDetectNopSled(Data, DataSize, HSD_NOP_SLED_CLASSIFY_MIN)) {
        return HsdSpray_ClassicNopSled;
    }

    /* 前 4 字节命中经典靶址 (memcpy 对齐安全读) */
    if (DataSize >= 4) {
        memcpy(&dwordValue, Data, sizeof(dwordValue));
        if (HsdIsCommonSprayAddress(dwordValue)) {
            return HsdSpray_ClassicNopSled;
        }
    }

    if (Entropy > 3.0 && Entropy < 5.0) {
        return HsdSpray_StringSpray;
    }

    if (Entropy > HSD_ENTROPY_THRESHOLD_HIGH) {
        return HsdSpray_ArrayBuffer;
    }

    return HsdSpray_Unknown;
}

/**************************************************/
/*               进程堆状态                         */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
HsdGetProcessHeapState(
    ULONG ProcessId,
    PHSD_HEAP_STATE State)
{
    HSD_CONFIG localConfig;
    HANDLE hProcess;
    PROCESS_MEMORY_COUNTERS_EX pmc;
    MEMORY_BASIC_INFORMATION mbi;
    UINT64 currentAddr = 0;
    UINT64 nextAddr;
    UINT32 heapCount = 0;
    UINT32 largeAllocs = 0;

    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    memset(State, 0, sizeof(*State));
    State->ProcessId = ProcessId;
    GetSystemTimePreciseAsFileTime((LPFILETIME)&State->SnapshotTime);

    if (ProcessId == 0) {
        return STATUS_SUCCESS;
    }

    AcquireSRWLockShared(&g_StateLock);
    localConfig = g_Config;
    ReleaseSRWLockShared(&g_StateLock);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_SUCCESS;
    }

    /* 工作集/私有字节 */
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProcess,
                             (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        State->WorkingSetSize = pmc.WorkingSetSize;
        State->PrivateBytes = pmc.PrivateUsage;
    }

    /* VirtualQueryEx 遍历提交/保留区 */
    while (VirtualQueryEx(hProcess, (LPCVOID)currentAddr,
                          &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            State->TotalCommitted += mbi.RegionSize;

            if (mbi.RegionSize >= localConfig.MinAllocationThreshold) {
                largeAllocs++;
            }

            /* SS: heapCount 为 MEM_PRIVATE 提交区计数 (非真实堆数) */
            if (mbi.Type == MEM_PRIVATE) {
                heapCount++;
            }
        }

        if (mbi.State == MEM_RESERVE) {
            State->TotalReserved += mbi.RegionSize;
        }

        nextAddr = (UINT64)(UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= currentAddr) {
            break;
        }
        currentAddr = nextAddr;
    }

    CloseHandle(hProcess);

    State->HeapCount = heapCount;
    State->LargeAllocationCount = largeAllocs;
    State->IsUnderPressure =
        (State->TotalCommitted > localConfig.MemoryPressureThreshold);
    State->SpraySuspected =
        (largeAllocs > 10 ||
         State->TotalCommitted > localConfig.MemoryPressureThreshold);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
HsdHasSprayIndicators(
    ULONG ProcessId)
{
    HSD_HEAP_STATE state;

    memset(&state, 0, sizeof(state));
    HsdGetProcessHeapState(ProcessId, &state);
    return (state.SpraySuspected || state.LargeAllocationCount > 5);
}

/**************************************************/
/*               进程监控                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
HsdMonitorProcess(
    ULONG ProcessId)
{
    SIZE_T i;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockExclusive(&g_MonitorLock);

    /* 已监控 → 成功 (SS 同) */
    for (i = 0; i < g_MonitorCount; i++) {
        if (g_Monitored[i].ProcessId == ProcessId) {
            ReleaseSRWLockExclusive(&g_MonitorLock);
            return STATUS_SUCCESS;
        }
    }

    /* 表满 (SS: unordered_map 受 MAX_TRACKED_ALLOCATIONS 保护,
     * C 静态化收敛 HSD_MAX_MONITORED_PROCESSES) */
    if (g_MonitorCount >= HSD_MAX_MONITORED_PROCESSES) {
        ReleaseSRWLockExclusive(&g_MonitorLock);
        return STATUS_TOO_MANY_OPENED;
    }

    memset(&g_Monitored[g_MonitorCount], 0, sizeof(g_Monitored[g_MonitorCount]));
    g_Monitored[g_MonitorCount].ProcessId = ProcessId;
    g_Monitored[g_MonitorCount].Active = TRUE;
    GetSystemTimePreciseAsFileTime(
        (LPFILETIME)&g_Monitored[g_MonitorCount].LastScanTime);
    HsdpGetProcessName(ProcessId, g_Monitored[g_MonitorCount].ProcessName,
                       DEF_MAX_IMAGE_NAME);
    g_MonitorCount++;

    ReleaseSRWLockExclusive(&g_MonitorLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HsdStopMonitoring(
    ULONG ProcessId)
{
    SIZE_T i;

    AcquireSRWLockExclusive(&g_MonitorLock);

    for (i = 0; i < g_MonitorCount; i++) {
        if (g_Monitored[i].ProcessId == ProcessId) {
            /* 末位补位删除 */
            if (i + 1 < g_MonitorCount) {
                g_Monitored[i] = g_Monitored[g_MonitorCount - 1];
            }
            memset(&g_Monitored[g_MonitorCount - 1], 0,
                   sizeof(g_Monitored[g_MonitorCount - 1]));
            g_MonitorCount--;
            ReleaseSRWLockExclusive(&g_MonitorLock);
            return STATUS_SUCCESS;
        }
    }

    ReleaseSRWLockExclusive(&g_MonitorLock);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
BOOLEAN
HsdIsMonitoring(
    ULONG ProcessId)
{
    SIZE_T i;
    BOOLEAN found = FALSE;

    AcquireSRWLockShared(&g_MonitorLock);
    for (i = 0; i < g_MonitorCount; i++) {
        if (g_Monitored[i].ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_MonitorLock);
    return found;
}

_Use_decl_annotations_
NTSTATUS
HsdGetMonitoredProcesses(
    ULONG* ProcessIds,
    ULONG MaxProcesses,
    ULONG* ProcessCount)
{
    SIZE_T i;
    ULONG count;

    if (ProcessCount == NULL || (ProcessIds == NULL && MaxProcesses > 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockShared(&g_MonitorLock);
    count = (g_MonitorCount < MaxProcesses) ? g_MonitorCount : MaxProcesses;
    for (i = 0; i < count; i++) {
        ProcessIds[i] = g_Monitored[i].ProcessId;
    }
    *ProcessCount = count;
    ReleaseSRWLockShared(&g_MonitorLock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               内核内存告警接入                   */
/**************************************************/

_Use_decl_annotations_
VOID
HsdOnMemoryAllocation(
    ULONG ProcessId,
    UINT64 Address,
    SIZE_T Size,
    ULONG Protection)
{
    HSD_CONFIG localConfig;
    BOOLEAN shouldScan = FALSE;
    ULONG recentLarge = 0;
    BOOLEAN isExecutable;
    BOOLEAN isWritable;

    if (!g_Initialized || ProcessId == 0 || Size == 0) {
        return;
    }

    /* 配置快照 */
    AcquireSRWLockShared(&g_StateLock);
    localConfig = g_Config;
    ReleaseSRWLockShared(&g_StateLock);

    if (!localConfig.Enabled) {
        return;
    }

    /* 记录分配 + 大分配计数合一临界区 (防 TOCTOU, 注释) */
    AcquireSRWLockExclusive(&g_MonitorLock);
    HsdpTrackAllocation(ProcessId, Address, Size,
                        localConfig.MinAllocationThreshold, &recentLarge);
    shouldScan = (recentLarge >= HSD_SUSPICIOUS_TRIGGER_COUNT);
    ReleaseSRWLockExclusive(&g_MonitorLock);

    /* 快路径: 低于阈值的分配不深入 (SS 同) */
    if (Size < localConfig.MinAllocationThreshold) {
        return;
    }

    /* RWX 事件高优先级 (W→X 由 OnProtectionChange 负责, 此处仅识别) */
    isExecutable = (Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    isWritable = (Protection & (PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    if (isExecutable && isWritable) {
        /* RWX 分配: 高优先可疑 (SS 仅记录日志, 检测由扫描决策) */
    }

    if (shouldScan) {
        HSD_DETECTION_EVENT evt;
        memset(&evt, 0, sizeof(evt));
        HsdScanProcessHeap(ProcessId, &evt);
    }
}

_Use_decl_annotations_
VOID
HsdOnProtectionChange(
    ULONG ProcessId,
    UINT64 Address,
    SIZE_T Size,
    ULONG OldProtection,
    ULONG NewProtection)
{
    HSD_CONFIG localConfig;
    BOOLEAN wasWritable;
    BOOLEAN nowExecutable;
    BOOLEAN wasNotExecutable;

    if (!g_Initialized || ProcessId == 0) {
        return;
    }

    /* W→X 转换: 原可写且不可执行, 现可执行 (壳码执行模式) */
    wasWritable = (OldProtection & (PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    wasNotExecutable = (OldProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0;
    nowExecutable = (NewProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    if (!(wasWritable && wasNotExecutable && nowExecutable)) {
        return;
    }

    AcquireSRWLockShared(&g_StateLock);
    localConfig = g_Config;
    ReleaseSRWLockShared(&g_StateLock);

    /* 大区域 W→X 翻转是强信号 → 触发扫描 */
    if (Size >= localConfig.MinAllocationThreshold) {
        HSD_DETECTION_EVENT evt;
        memset(&evt, 0, sizeof(evt));
        HsdScanProcessHeap(ProcessId, &evt);
    }
}

_Use_decl_annotations_
VOID
HsdProcessKernelMemoryAlert(
    ULONG ProcessId,
    UINT64 Address,
    SIZE_T Size,
    ULONG Protection)
{
    /* 统一内核告警入口 → 委托分配处理器 (ProcessKernelMemoryAlert) */
    HsdOnMemoryAllocation(ProcessId, Address, Size, Protection);
}

/**************************************************/
/*               回调/统计/历史                     */
/**************************************************/

_Use_decl_annotations_
VOID
HsdRegisterCallback(
    HSD_DETECTED_CALLBACK Callback)
{
    AcquireSRWLockExclusive(&g_CallbackLock);
    g_SprayCallback = Callback;
    ReleaseSRWLockExclusive(&g_CallbackLock);
}

_Use_decl_annotations_
BOOLEAN
HsdGetStatistics(
    PHSD_STATS_SNAPSHOT Snapshot)
{
    if (Snapshot == NULL) {
        return FALSE;
    }
    HsdpGetLiveStats(Snapshot);
    return TRUE;
}

_Use_decl_annotations_
VOID
HsdResetStatistics(
    VOID)
{
    g_ScansPerformed = 0;
    g_BlocksAnalyzed = 0;
    g_SpraysDetected = 0;
    g_NopSledsDetected = 0;
    g_ShellcodesDetected = 0;
    g_LowEntropyBlocks = 0;
    g_HighEntropyBlocks = 0;
    g_AttacksBlocked = 0;
    memset((VOID*)g_ByTechnique, 0, sizeof(g_ByTechnique));
    g_StartTick = GetTickCount64();
    GetSystemTimePreciseAsFileTime((LPFILETIME)&g_StartTime);
}

_Use_decl_annotations_
NTSTATUS
HsdGetRecentDetections(
    PHSD_DETECTION_EVENT Events,
    ULONG MaxCount,
    ULONG* EventCount)
{
    ULONG count;
    ULONG i;
    ULONG idx;

    if (EventCount == NULL || (Events == NULL && MaxCount > 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockExclusive(&g_HistoryLock);

    count = (g_RecentCount < MaxCount) ? g_RecentCount : MaxCount;
    *EventCount = count;

    /* 最新在前 (rbegin 逆序返回) */
    for (i = 0; i < count; i++) {
        idx = (g_RecentHead + HSD_MAX_RECENT_DETECTIONS - 1 - i) %
              HSD_MAX_RECENT_DETECTIONS;
        Events[i] = g_RecentEvents[idx];
    }

    ReleaseSRWLockExclusive(&g_HistoryLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
HsdSelfTest(
    VOID)
{
    HSD_ALLOCATION_INFO info;

    /* 测试 1: 熵计算 (1024×0x90 均匀块, 熵应 ≤ 0.5) */
    {
        UCHAR uniform[1024];
        memset(uniform, 0x90, sizeof(uniform));
        if (HsdCalculateEntropy(uniform, sizeof(uniform)) > 0.5) {
            return FALSE;
        }
    }

    /* 测试 2: NOP sled 检测 (128×0x90, 最小 64) */
    {
        UCHAR nops[128];
        memset(nops, 0x90, sizeof(nops));
        if (!HsdDetectNopSled(nops, sizeof(nops), 64)) {
            return FALSE;
        }
    }

    /* 测试 3: shellcode 模式检测 (SS 中失败仅为警告, 此处不判 FAIL) */
    {
        UCHAR shellcode[256];
        memset(shellcode, 0x90, sizeof(shellcode));
        shellcode[0] = 0xEB; shellcode[1] = 0x00;   /* JMP +0  */
        shellcode[2] = 0x31; shellcode[3] = 0xC0;   /* XOR EAX */
        shellcode[4] = 0xFF; shellcode[5] = 0xD0;   /* CALL EAX */
        if (!HsdDetectShellcode(shellcode, sizeof(shellcode))) {
            /* 与 SS 一致: 仅警告, 不判失败 */
        }
    }

    /* 测试 4: 块分析 (4096×0x0C, 熵应 < 1.0) */
    {
        UCHAR testData[4096];
        memset(testData, 0x0C, sizeof(testData));
        memset(&info, 0, sizeof(info));
        HsdAnalyzeMemoryBlock(testData, sizeof(testData), 0x0C0C0C0C, &info);
        if (info.Entropy >= 1.0) {
            return FALSE;
        }
    }

    return TRUE;
}

/**************************************************/
/*               工具函数                           */
/**************************************************/

_Use_decl_annotations_
const WCHAR*
HsdGetSprayTechniqueName(
    HSD_SPRAY_TECHNIQUE Technique)
{
    switch (Technique) {
    case HsdSpray_ClassicNopSled:  return L"ClassicNopSled";
    case HsdSpray_JitSpray:        return L"JitSpray";
    case HsdSpray_ArrayBuffer:     return L"ArrayBuffer";
    case HsdSpray_TypedArray:      return L"TypedArray";
    case HsdSpray_Bstr:            return L"BSTR";
    case HsdSpray_Variant:         return L"Variant";
    case HsdSpray_DomElement:      return L"DomElement";
    case HsdSpray_StringSpray:     return L"StringSpray";
    case HsdSpray_FengShui:        return L"FengShui";
    case HsdSpray_Plunger:         return L"Plunger";
    case HsdSpray_LookAsideList:   return L"LookAsideList";
    case HsdSpray_SegmentHeap:     return L"SegmentHeap";
    case HsdSpray_LfhBucket:       return L"LFHBucket";
    default:                       return L"Unknown";
    }
}

_Use_decl_annotations_
const WCHAR*
HsdGetMemoryRegionTypeName(
    HSD_MEMORY_REGION_TYPE RegionType)
{
    switch (RegionType) {
    case HsdRegion_Heap:          return L"Heap";
    case HsdRegion_Stack:         return L"Stack";
    case HsdRegion_Image:         return L"Image";
    case HsdRegion_Mapped:        return L"Mapped";
    case HsdRegion_Private:       return L"Private";
    case HsdRegion_JitCode:       return L"JitCode";
    case HsdRegion_SharedMemory:  return L"SharedMemory";
    default:                      return L"Unknown";
    }
}

_Use_decl_annotations_
const WCHAR*
HsdGetConfidenceLevelName(
    HSD_CONFIDENCE Level)
{
    switch (Level) {
    case HsdConf_Low:       return L"Low";
    case HsdConf_Medium:    return L"Medium";
    case HsdConf_High:      return L"High";
    case HsdConf_VeryHigh:  return L"VeryHigh";
    case HsdConf_Confirmed: return L"Confirmed";
    default:                return L"Unknown";
    }
}

_Use_decl_annotations_
BOOLEAN
HsdIsCommonNopByte(
    UCHAR Byte)
{
    SIZE_T i;

    for (i = 0; i < sizeof(s_NopSledValues); i++) {
        if (Byte == s_NopSledValues[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
HsdIsCommonSprayAddress(
    ULONG Address)
{
    SIZE_T i;

    for (i = 0; i < sizeof(s_SprayTargetAddrs32) / sizeof(UINT32); i++) {
        if (Address == s_SprayTargetAddrs32[i]) {
            return TRUE;
        }
    }
    return FALSE;
}