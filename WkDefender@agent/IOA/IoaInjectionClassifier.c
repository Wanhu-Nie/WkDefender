/**************************************************/
/*  WkDefender IOA — 注入类型分类器实现              */
/**************************************************/

#include "IoaInjectionClassifier.h"
#include "../WkDefenderHeader.h"   /* WKD_SEC_SUSPICION_TRANSACTED 等统一协议头 */
#include "../Common/Exempts/Exempts.h"   /* 统一豁免门面 (Exempts 重构 #67, 注入豁免原 IocInjectionWhitelist) */
#include "../IOC/IocProcessEnrich.h"   /* IpeDetectProcessHollowing */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"
#include "../Common/FileUtils.h"
#include "../IOC/IocScanner.h"         /* IocScanner_ComputeBufferSha256 (死代码 payload 哈希) */
#include "../Memory/MemoryScan.h"      /* MsGetRegionInfo / MsScanRegionAt (定向确认) */
#include "../ProcessThreads.h"         /* WptValidateThread / WptIsThreadStartUnbacked (线程上下文验证) */
#include "Tier1/T1ShellcodeDetect.h"   /* IocDetectShellcode (壳码字节模式) */
#include "IoaProcessPair.h"            /* IoaPairResolveNodeIds (pair 键 PID 化反查) */

/* 前向声明: static 统计变量定义于本文件后半部 (L1878 附近),
 * 此处先声明供前部函数使用 (C89 要求先声明后使用)。 */
static volatile LONG64 g_IoaInjStatsTotalCalls;
static volatile LONG64 g_IoaInjStatsDetected;

/**************************************************/
/*               常量                               */
/**************************************************/

/* 线程起始地址属性 (对齐 PS TnpAnalyzeThreadCreation 内核判定) */
#define WKD_MSG_INJECT_REMOTE_THREAD     0x00000001
#define WKD_MSG_INJECT_SUSPENDED_START   0x00000002
#define WKD_MSG_INJECT_UNBACKED_START    0x00000004
#define WKD_MSG_INJECT_RWX_START         0x00000008
#define WKD_MSG_INJECT_CROSS_SESSION     0x00000010
#define WKD_MSG_INJECT_SYSTEM_TARGET     0x00000020
#define WKD_MSG_INJECT_ELEVATED_SOURCE   0x00000040
#define WKD_MSG_INJECT_SHELLCODE_PATTERN 0x00000080
#define WKD_MSG_INJECT_PROTECTED_TARGET  0x00000100  /* 受保护进程目标 (PS: TN_SCORE_PROTECTED_TARGET 200) */
#define WKD_MSG_INJECT_UNUSUAL_ENTRY     0x00000200  /* 入口点不在已加载模块 (PS: TN_SCORE_UNUSUAL_ENTRY 75) */
#define WKD_MSG_INJECT_RAPID_CREATION    0x00000400  /* 远程线程快速创建 (PS: TN_SCORE_RAPID_CREATION 100) */

#define WKD_INJECT_CONF_CAP              100
#define WKD_INJECT_RISK_CAP              100

/**************************************************/
/*           原子炸弹分析 (T1055.009)               */
/*  移植自 ShadowStrike AtomBombingDetector        */
/*  AnalyzeAtomImpl + CalculateAtomSuspicion +     */
/*  TargetsAtomRetrievalImpl                       */
/**************************************************/

#define IOA_ATOM_MIN_GLOBAL             0xC000      /* 全局原子表起始 */
#define IOA_ATOM_MAX_GLOBAL             0xFFFF      /* 全局原子表结束 */
#define IOA_ATOM_NAME_MAX               256         /* 原子内容最大 wchar 数 (255 + null) */
#define IOA_ATOM_ENTROPY_THRESHOLD      6500       /* CoEntropyBinary bits*1000 (6.5 bits, 替换 SS 香农熵 6.5) */
#define IOA_ATOM_SIZE_THRESHOLD         64          /* 尺寸可疑阈值 (对齐 SS suspiciousAtomSizeThreshold) */
#define IOA_ATOM_CORRELATION_WINDOW_MS  5000        /* 关联时间窗 (死代码周期路径用, 对齐 SS 5000ms) */

/* 可疑 API 名字符串 (对齐 ShadowStrike CheckSuspiciousStrings 8 token) */
static const PCWSTR g_IoaAtomSuspiciousTokens[] = {
    L"VirtualAlloc", L"VirtualProtect", L"LoadLibrary",
    L"GetProcAddress", L"NtProtect", L"WriteProcessMemory",
    L"CreateRemoteThread", L"NtQueueApcThread"
};
#define IOA_ATOM_SUSPICIOUS_TOKEN_COUNT  (sizeof(g_IoaAtomSuspiciousTokens) / sizeof(g_IoaAtomSuspiciousTokens[0]))

/* 原子内容分级 (对齐 ShadowStrike AtomSuspicion) */
typedef enum _IOA_ATOM_SUSPICION {
    IoaAtom_Normal = 0,
    IoaAtom_LowRisk = 1,
    IoaAtom_MediumRisk = 2,
    IoaAtom_HighRisk = 3,
    IoaAtom_Critical = 4,
} IOA_ATOM_SUSPICION, *PIOA_ATOM_SUSPICION;

/* 单原子分析结果 */
typedef struct _IOA_ATOM_RESULT {
    ULONG_PTR         AtomValue;          /* 原子值 (0 = 无效) */
    WCHAR             Name[IOA_ATOM_NAME_MAX];
    ULONG             ContentLength;      /* wchar 数 */
    BOOLEAN           HasHighEntropy;
    BOOLEAN           HasShellcodePatterns;
    BOOLEAN           HasSuspiciousStrings;
    BOOLEAN           HasNullBytes;
    IOA_ATOM_SUSPICION Suspicion;
    ULONG             Score;              /* 加权分 */
} IOA_ATOM_RESULT, *PIOA_ATOM_RESULT;

/* 原子检索 API 地址缓存。
 * kernel32/KernelBase/ntdll 每启动 ASLR 同地址 (非每进程), 本进程解析即可跨进程比对。
 * 移植自 SS TargetsAtomRetrievalImpl 的 6 地址, 补充 NtQueryInformationAtom。 */
#define IOA_ATOM_API_COUNT              7
typedef struct _IOA_ATOM_API_ADDRS {
    BOOLEAN   Resolved;
    ULONG_PTR Addr[IOA_ATOM_API_COUNT];
} IOA_ATOM_API_ADDRS;
static IOA_ATOM_API_ADDRS g_IoaAtomApiAddrs;

/* 已知安全原子 (系统窗口类, 对齐 SS InitializeKnownSafeAtoms 14 项)。
 * RegisterClass 产生的窗口类原子是正常系统状态, 不应判可疑, 扫描时跳过。 */
static const PCWSTR g_IoaAtomSafeNames[] = {
    L"Button", L"ComboBox", L"Edit", L"ListBox",
    L"MDIClient", L"ScrollBar", L"Static",
    L"ComboLBox", L"DDEMLEvent", L"DDEMLMom",
    L"DDEMLAnsiClient", L"DDEMLUnicodeClient",
    L"IME", L"MSCTFIME UI"
};
#define IOA_ATOM_SAFE_NAME_COUNT  (sizeof(g_IoaAtomSafeNames) / sizeof(g_IoaAtomSafeNames[0]))

/* 安全原子值集合 (惰性经 GlobalFindAtomW 解析, 未注册=0) */
static USHORT g_IoaAtomSafeValues[IOA_ATOM_SAFE_NAME_COUNT];
static BOOLEAN g_IoaAtomSafeResolved = FALSE;

/**************************************************/
/*             静态辅助函数                         */
/**************************************************/

/*
 * IoaAtomResolveApiAddresses — 惰性解析原子检索 API 地址 (一次性)。
 * 对齐 SS ResolveApiAddresses (cpp L439-458)。
 */
static
VOID
IoaAtomResolveApiAddresses(
    VOID
    )
{
    HMODULE hMod;

    if (g_IoaAtomApiAddrs.Resolved) return;

    if ((hMod = GetModuleHandleW(L"kernel32.dll")) != NULL) {
        g_IoaAtomApiAddrs.Addr[0] = (ULONG_PTR)GetProcAddress(hMod, "GlobalGetAtomNameA");
        g_IoaAtomApiAddrs.Addr[1] = (ULONG_PTR)GetProcAddress(hMod, "GlobalGetAtomNameW");
    }
    if ((hMod = GetModuleHandleW(L"KernelBase.dll")) != NULL) {
        g_IoaAtomApiAddrs.Addr[2] = (ULONG_PTR)GetProcAddress(hMod, "GlobalGetAtomNameA");
        g_IoaAtomApiAddrs.Addr[3] = (ULONG_PTR)GetProcAddress(hMod, "GlobalGetAtomNameW");
    }
    if ((hMod = GetModuleHandleW(L"ntdll.dll")) != NULL) {
        g_IoaAtomApiAddrs.Addr[4] = (ULONG_PTR)GetProcAddress(hMod, "NtAddAtom");
        g_IoaAtomApiAddrs.Addr[5] = (ULONG_PTR)GetProcAddress(hMod, "NtFindAtom");
        g_IoaAtomApiAddrs.Addr[6] = (ULONG_PTR)GetProcAddress(hMod, "NtQueryInformationAtom");
    }

    g_IoaAtomApiAddrs.Resolved = TRUE;
}

/*
 * IoaAtomResolveSafeAtoms — 解析已知安全原子值 (惰性, 一次性)。
 * 对齐 SS InitializeKnownSafeAtoms (cpp L623-647): 用 GlobalFindAtomW 解析
 * 系统窗口类名字对应的原子值; 未注册时为 0 (窗口类可能随窗口站延迟注册)。
 */
static
VOID
IoaAtomResolveSafeAtoms(
    VOID
    )
{
    ULONG i;

    if (g_IoaAtomSafeResolved) return;
    for (i = 0; i < IOA_ATOM_SAFE_NAME_COUNT; i++) {
        ATOM a = GlobalFindAtomW(g_IoaAtomSafeNames[i]);
        g_IoaAtomSafeValues[i] = (USHORT)((a != 0 && (ULONG)a >= IOA_ATOM_MIN_GLOBAL) ? a : 0);
    }
    g_IoaAtomSafeResolved = TRUE;
}

/* 判断原子值是否命中已知安全集合 */
static
BOOLEAN
IoaAtomIsSafeValue(
    _In_ ULONG AtomValue
    )
{
    ULONG i;

    for (i = 0; i < IOA_ATOM_SAFE_NAME_COUNT; i++) {
        if ((ULONG)g_IoaAtomSafeValues[i] == AtomValue) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * IoaAtomTargetsRetrieval — 判断 APC 例程是否指向原子检索 API。
 * 移植自 ShadowStrike TargetsAtomRetrievalImpl (cpp L1030-1040);
 * SS 仅比 6 地址 (缺 NtQueryInformationAtom, 全库未用), 此处补全。
 * 返回 TRUE = ApcRoutine 是 GlobalGetAtomNameA/W / NtAddAtom /
 *   NtFindAtom / NtQueryInformationAtom 之一 (AtomBombing 精准信号)。
 */
static
BOOLEAN
IoaAtomTargetsRetrieval(
    _In_ ULONG_PTR ApcRoutine
    )
{
    ULONG i;

    if (ApcRoutine == 0) return FALSE;
    IoaAtomResolveApiAddresses();

    for (i = 0; i < IOA_ATOM_API_COUNT; i++) {
        if (g_IoaAtomApiAddrs.Addr[i] != 0 &&
            g_IoaAtomApiAddrs.Addr[i] == ApcRoutine) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * IoaAtomCheckSuspiciousStrings — 原子内容含可疑 API 名字符串检测。
 * 移植自 ShadowStrike CheckSuspiciousStrings (cpp L864-879)。
 */
static
BOOLEAN
IoaAtomCheckSuspiciousStrings(
    _In_ PCWSTR Name
    )
{
    ULONG i;

    if (!Name) return FALSE;
    for (i = 0; i < IOA_ATOM_SUSPICIOUS_TOKEN_COUNT; i++) {
        if (wcsstr(Name, g_IoaAtomSuspiciousTokens[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * IoaAtomAnalyzeContent — 原子内容分级 (熵/壳码/可疑串/尺寸/null 加权)。
 * 移植自 ShadowStrike AnalyzeAtomImpl + CalculateAtomSuspicion (cpp L881-898);
 * 熵/壳码判定替换为 WkD 现有工具 (CoEntropyBinary / IocDetectShellcode),
 * 重功能实现而非源码复制。
 *
 * 加权 (对齐 SS): 高熵+25 / 壳码+40 / 可疑串+20 / 尺寸≥64 +15 / null(>16)+10
 *   分级: ≥60 Critical / ≥40 High / ≥20 Medium / >0 Low / 0 Normal
 */
static
VOID
IoaAtomAnalyzeContent(
    _In_ PCWSTR Name,
    _In_ ULONG ContentChars,
    _Out_ PIOA_ATOM_RESULT Out
    )
{
    ULONG entropy = 0;
    ULONG scFlags;
    ULONG64 scFamily;
    ULONG score = 0;
    ULONG byteLen;
    ULONG i;
    BOOLEAN hasNull = FALSE;

    RtlZeroMemory(Out, sizeof(*Out));
    if (!Name || ContentChars == 0) return;

    byteLen = ContentChars * sizeof(WCHAR);
    Out->ContentLength = ContentChars;
    wcsncpy_s(Out->Name, IOA_ATOM_NAME_MAX, Name, _TRUNCATE);

    /* 熵 (CoEntropyBinary bits*1000, 阈值 6500; 替换 SS 香农熵 6.5) */
    entropy = (ULONG)(CoEntropyBinary((PVOID)Name, byteLen, 0) * 1000.0);
    if (entropy >= IOA_ATOM_ENTROPY_THRESHOLD) {
        Out->HasHighEntropy = TRUE;
        score += 25;
    }

    /* 壳码字节模式 (WkD IocDetectShellcode 6 类, 替换 SS 16 条字节签名;
     * 判定: 非 X64 家族 ≥2 或含 APIHASH/SYSCALL/ROP_CHAIN, 对齐 SS "≥2 家族") */
    scFlags = IocDetectShellcode((const UCHAR*)Name, byteLen, FALSE);
    scFamily = (ULONG64)scFlags & ~(ULONG64)T1_SC_X64;
    if ((ULONG)__popcnt64(scFamily) >= 2 ||
        (scFlags & (T1_SC_APIHASH | T1_SC_SYSCALL | T1_SC_ROP_CHAIN))) {
        Out->HasShellcodePatterns = TRUE;
        score += 40;
    }

    /* 可疑 API 名字符串 */
    if (IoaAtomCheckSuspiciousStrings(Name)) {
        Out->HasSuspiciousStrings = TRUE;
        score += 20;
    }

    /* 尺寸阈值 */
    if (ContentChars >= IOA_ATOM_SIZE_THRESHOLD) {
        score += 15;
    }

    /* null 字节 (数据含 0x00; 仅 >16 wchar 时计分, 对齐 SS) */
    if (ContentChars > 16) {
        for (i = 0; i < byteLen; i++) {
            if (((PUCHAR)Name)[i] == 0) {
                hasNull = TRUE;
                break;
            }
        }
    }
    if (hasNull) {
        Out->HasNullBytes = TRUE;
        score += 10;
    }

    Out->Score = score;
    if (score >= 60)      Out->Suspicion = IoaAtom_Critical;
    else if (score >= 40) Out->Suspicion = IoaAtom_HighRisk;
    else if (score >= 20) Out->Suspicion = IoaAtom_MediumRisk;
    else if (score > 0)   Out->Suspicion = IoaAtom_LowRisk;
    else                  Out->Suspicion = IoaAtom_Normal;
}

/**************************************************/
/*           全局可疑原子缓存                       */
/*  事件驱动按需枚举 (活) + 周期全表扫描 (死代码)     */
/*  结构仿 IOA_MOD_CACHE (SRWLOCK + 桶 + 上限)     */
/**************************************************/

#define IOA_ATOM_CACHE_BUCKETS      64
#define IOA_ATOM_CACHE_MAX          256
#define IOA_ATOM_SCAN_THROTTLE_MS   1000    /* 按需枚举节流 (距上次全扫) */

typedef struct _IOA_ATOM_CACHE_ENTRY {
    LIST_ENTRY      ListEntry;
    IOA_ATOM_RESULT Result;
    LARGE_INTEGER   LastScanTime;
} IOA_ATOM_CACHE_ENTRY, *PIOA_ATOM_CACHE_ENTRY;

typedef struct _IOA_ATOM_CACHE {
    SRWLOCK         Lock;
    LIST_ENTRY      Buckets[IOA_ATOM_CACHE_BUCKETS];
    ULONG           Count;
    LARGE_INTEGER   LastFullScan;
} IOA_ATOM_CACHE;

static IOA_ATOM_CACHE g_IoaAtomCache;
static BOOLEAN g_IoaAtomCacheInit = FALSE;

/* 惰性初始化缓存桶 */
static
VOID
IoaAtomCacheEnsureInit(
    VOID
    )
{
    ULONG i;

    if (!g_IoaAtomCacheInit) {
        InitializeSRWLock(&g_IoaAtomCache.Lock);
        for (i = 0; i < IOA_ATOM_CACHE_BUCKETS; i++) {
            InitializeListHead(&g_IoaAtomCache.Buckets[i]);
        }
        g_IoaAtomCache.Count = 0;
        g_IoaAtomCache.LastFullScan.QuadPart = 0;
        g_IoaAtomCacheInit = TRUE;
    }
}

/* 写缓存 (调用方持写锁; 存在则更新, 新条目插入, 超上限淘汰最老) */
static
VOID
IoaAtomCacheUpsertLocked(
    _In_ PIOA_ATOM_RESULT Res
    )
{
    PIOA_ATOM_CACHE_ENTRY rec = NULL;
    PLIST_ENTRY e;
    ULONG bucket = (ULONG)(Res->AtomValue % IOA_ATOM_CACHE_BUCKETS);

    for (e = g_IoaAtomCache.Buckets[bucket].Flink;
         e != &g_IoaAtomCache.Buckets[bucket];
         e = e->Flink) {
        PIOA_ATOM_CACHE_ENTRY cur =
            CONTAINING_RECORD(e, IOA_ATOM_CACHE_ENTRY, ListEntry);
        if (cur->Result.AtomValue == Res->AtomValue) {
            rec = cur;
            break;
        }
    }

    if (rec) {
        rec->Result = *Res;
        GetSystemTimeAsFileTime((PFILETIME)&rec->LastScanTime);
        return;
    }

    rec = (PIOA_ATOM_CACHE_ENTRY)HeapAlloc(GetProcessHeap(), 0, sizeof(*rec));
    if (!rec) return;
    RtlZeroMemory(rec, sizeof(*rec));
    rec->Result = *Res;
    GetSystemTimeAsFileTime((PFILETIME)&rec->LastScanTime);
    InsertHeadList(&g_IoaAtomCache.Buckets[bucket], &rec->ListEntry);
    g_IoaAtomCache.Count++;

    if (g_IoaAtomCache.Count > IOA_ATOM_CACHE_MAX) {
        ULONG k;
        for (k = 0; k < IOA_ATOM_CACHE_BUCKETS; k++) {
            if (!IsListEmpty(&g_IoaAtomCache.Buckets[k])) {
                PLIST_ENTRY tail = g_IoaAtomCache.Buckets[k].Blink;
                PIOA_ATOM_CACHE_ENTRY oldest =
                    CONTAINING_RECORD(tail, IOA_ATOM_CACHE_ENTRY, ListEntry);
                RemoveEntryList(tail);
                g_IoaAtomCache.Count--;
                HeapFree(GetProcessHeap(), 0, oldest);
                break;
            }
        }
    }
}

/* 全表枚举 + 写缓存 + 更新节流时间 (调用方持写锁) */
static
VOID
IoaAtomCacheFullScanLocked(
    _In_ LARGE_INTEGER Now
    )
{
    ULONG atomVal;

    IoaAtomResolveSafeAtoms();

    for (atomVal = IOA_ATOM_MIN_GLOBAL;
         atomVal <= IOA_ATOM_MAX_GLOBAL;
         atomVal++) {
        WCHAR name[IOA_ATOM_NAME_MAX];
        UINT len;
        IOA_ATOM_RESULT res;

        /* 跳过已知安全原子 (系统窗口类), 防误报 */
        if (IoaAtomIsSafeValue(atomVal)) continue;

        len = GlobalGetAtomNameW((ATOM)atomVal, name, IOA_ATOM_NAME_MAX);
        if (len == 0) continue;

        IoaAtomAnalyzeContent(name, len, &res);
        res.AtomValue = atomVal;
        IoaAtomCacheUpsertLocked(&res);
    }

    g_IoaAtomCache.LastFullScan = Now;
}

/* 从缓存收集最佳可疑原子 (调用方持锁) */
static
BOOLEAN
IoaAtomCacheCollectBestLocked(
    _Out_opt_ PIOA_ATOM_RESULT Best
    )
{
    ULONG bestScore = 0;
    IOA_ATOM_RESULT bestAtom;
    BOOLEAN found = FALSE;
    ULONG b;
    PLIST_ENTRY e;

    for (b = 0; b < IOA_ATOM_CACHE_BUCKETS; b++) {
        for (e = g_IoaAtomCache.Buckets[b].Flink;
             e != &g_IoaAtomCache.Buckets[b];
             e = e->Flink) {
            PIOA_ATOM_CACHE_ENTRY cur =
                CONTAINING_RECORD(e, IOA_ATOM_CACHE_ENTRY, ListEntry);
            if (cur->Result.Suspicion >= IoaAtom_MediumRisk &&
                cur->Result.Score > bestScore) {
                bestScore = cur->Result.Score;
                bestAtom = cur->Result;
                found = TRUE;
            }
        }
    }

    if (found && Best) *Best = bestAtom;
    return found;
}

/*
 * IoaAtomCache_ScanGlobalTable — 事件驱动按需枚举全局原子表。
 * 返回全局原子表中 Suspicion >= MediumRisk 的最佳可疑原子。
 * 节流: 距上次全扫 <1000ms 直接查缓存 (APC 执行时原子必在场);
 *   缓存无结果时强制全扫兜底, 防节流窗口内漏检最新创建的可疑原子。
 *   优于 ShadowStrike 固定 5s 周期扫描。
 */
static
BOOLEAN
IoaAtomCache_ScanGlobalTable(
    _Out_opt_ PIOA_ATOM_RESULT Best
    )
{
    LARGE_INTEGER now;
    BOOLEAN found;
    ULONG64 elapsedMs;

    if (Best) RtlZeroMemory(Best, sizeof(*Best));
    IoaAtomCacheEnsureInit();

    GetSystemTimeAsFileTime((PFILETIME)&now);

    AcquireSRWLockExclusive(&g_IoaAtomCache.Lock);
    elapsedMs = (now.QuadPart - g_IoaAtomCache.LastFullScan.QuadPart) / 10000;

    if (elapsedMs > IOA_ATOM_SCAN_THROTTLE_MS) {
        IoaAtomCacheFullScanLocked(now);
    }

    found = IoaAtomCacheCollectBestLocked(Best);

    /* 兜底: 缓存无结果时强制全扫 (APC 确认时刻, 防漏检原子创建后即 QueueApc) */
    if (!found) {
        IoaAtomCacheFullScanLocked(now);
        found = IoaAtomCacheCollectBestLocked(Best);
    }

    ReleaseSRWLockExclusive(&g_IoaAtomCache.Lock);
    return found;
}

/*
 * 从进程节点取文件名 (ImageFileName 优先, 否则取 ImagePath 末段)。
 */
static
PCWSTR
IoaGetProcessName(
    _In_opt_ PWKD_PROCESS Node,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
/*++
Routine Description:
    提取进程可执行文件名 (不含路径)。
    优先使用 ImageFileName, 否则从 ImagePath 末段截取。

Arguments:
    Node    - 进程节点 (可为 NULL)。
    Out     - 输出缓冲区。
    MaxLen  - 缓冲区大小。

Return Value:
    返回 Out 指针。
--*/
{
    PCWSTR src = NULL;

    if (!Node) {
        if (MaxLen > 0) Out[0] = L'\0';
        return Out;
    }

    if (Node->ImageFileName && Node->ImageFileName->Buffer) {
        src = Node->ImageFileName->Buffer;
    } else if (Node->ImagePath && Node->ImagePath->Buffer) {
        src = Node->ImagePath->Buffer;
    }

    if (!src) {
        if (MaxLen > 0) Out[0] = L'\0';
        return Out;
    }

    /* 从末段 '\\' 或 '/' 后取文件名 */
    {
        PCWSTR last = src;
        for (PCWSTR p = src; *p; p++) {
            if (*p == L'\\' || *p == L'/') last = p + 1;
        }
        _snwprintf_s(Out, MaxLen, _TRUNCATE, L"%ls", last);
    }

    return Out;
}

/*
 * 判断目标进程是否为敏感进程 (lsass/winlogon/csrss)。
 * 移植自 ShadowStrike CalculateRiskScore 的目标加分逻辑。
 */
static
BOOLEAN
IoaIsSensitiveTarget(
    _In_ PCWSTR ProcessName
    )
{
    if (!ProcessName || !ProcessName[0]) return FALSE;

    if (_wcsicmp(ProcessName, L"lsass.exe") == 0 ||
        _wcsicmp(ProcessName, L"winlogon.exe") == 0 ||
        _wcsicmp(ProcessName, L"csrss.exe") == 0) {
        return TRUE;
    }

    return FALSE;
}

/**************************************************/
/*             注入置信度计算                        */
/*  移植自 ShadowStrike CalculateConfidence         */
/**************************************************/

static
ULONG
IoaComputeInjectionConfidence(
    _In_ WKD_INJECTION_TYPE Type,
    _In_ ULONG64 DataDword,
    _In_ BOOLEAN UnbackedStart,
    _In_ BOOLEAN HasExecProtect,
    _In_ BOOLEAN HasWrite,
    _In_ ULONG64 TotalSize,
    _In_ PCWSTR SourceName,
    _In_ PCWSTR TargetName
    )
/*++
Routine Description:
    计算注入置信度 [0,100]。
    基础分按技术 + 事件数 boost + 起始地址 boost + 注入原语维度 + 白名单减分。

Arguments:
    Type         - 注入类型。
    DataDword    - 数据层位图 (用于事件数统计)。
    UnbackedStart- 起始地址无文件支撑。
    HasExecProtect - 目标内存 EXECUTE 保护 (对齐 SS INJ_CHAIN_FLAG_HAS_EXECUTE)。
    HasWrite     - 进程对含写边 (对齐 SS INJ_CHAIN_FLAG_HAS_WRITE)。
    TotalSize    - 当前事件操作大小 (SS Chain->TotalSize 的当前事件近似)。
    SourceName   - 源进程名 (白名单减分)。
    TargetName   - 目标进程名。

Return Value:
    置信度 [0,100]。
--*/
{
    ULONG confidence = 0;
    ULONG edgePop;

    /* 基础分 (对齐 ShadowStrike, 仅保留有检测路径的类型) */
    switch (Type) {
    case WkdInjection_ProcessHollowing:   confidence = 95; break;
    case WkdInjection_ProcessDoppelganging:confidence = 90; break;  /* TxF 变体, 对齐 SS T1055.013 */
    case WkdInjection_ReflectiveDLL:      confidence = 90; break;
    case WkdInjection_ThreadHijacking:    confidence = 85; break;
    case WkdInjection_APC:                confidence = 80; break;
    case WkdInjection_EarlyBird:          confidence = 80; break;
    case WkdInjection_AtomBombing:        confidence = 80; break;  /* 对齐 SS CalculateConfidence AtomBombing 基准 */
    case WkdInjection_SectionMapping:     confidence = 80; break;
    case WkdInjection_DLLInjection:       confidence = 75; break;
    case WkdInjection_RemoteThread:       confidence = 70; break;
    case WkdInjection_DirectSyscallThread:confidence = 70; break;
    case WkdInjection_PeInjection:        confidence = 70; break;  /* 对齐 SS InjTechPeInjection=70 (InjectionDetector.c:2397-2400) */
    case WkdInjection_ShellcodeInjection: confidence = 65; break;
    default:                              confidence = 60; break;
    }

    /* 事件数 boost: 相关边 >=5 +10, >=3 +5 */
    edgePop = (ULONG)__popcnt64(DataDword);
    if (edgePop >= 5)      confidence += 10;
    else if (edgePop >= 3) confidence += 5;

    /* 起始地址不在模块 boost */
    if (UnbackedStart) {
        confidence += 10;
    }

    /* 注入原语维度 (对齐 SS InjpCalculateSuspicionScore 调整段,
     * InjectionDetector.c:2415-2429, 0-100 尺度):
     *   INJ_CHAIN_FLAG_HAS_EXECUTE +5 / HAS_WRITE +3 / TotalSize>64KB +3 */
    if (HasExecProtect)      confidence += 5;
    if (HasWrite)            confidence += 3;
    if (TotalSize > 0x10000) confidence += 3;

    /* 白名单进程对减分 (常见合法组合降低置信度) */
    if (ExemptsInjectionIsPairWhitelisted(SourceName, TargetName)) {
        confidence = (confidence > 30) ? (confidence - 30) : 0;
    }

    return min(confidence, WKD_INJECT_CONF_CAP);
}

/**************************************************/
/*             注入风险分计算                        */
/*  移植自 ShadowStrike CalculateRiskScore         */
/**************************************************/

static
ULONG
IoaComputeInjectionRisk(
    _In_ WKD_INJECTION_TYPE Type,
    _In_ PCWSTR TargetName
    )
/*++
Routine Description:
    计算注入风险分 [0,100]。
    基础分按技术 + 目标敏感进程加分。

Arguments:
    Type       - 注入类型。
    TargetName - 目标进程名 (敏感进程 lsass/winlogon/csrss 加分)。

Return Value:
    风险分 [0,100]。
--*/
{
    ULONG risk;

    switch (Type) {
    case WkdInjection_ProcessHollowing:   risk = 95; break;
    case WkdInjection_ProcessDoppelganging:risk = 90; break;  /* 对齐 SS 镂空家族 */
    case WkdInjection_ReflectiveDLL:      risk = 90; break;
    case WkdInjection_ThreadHijacking:    risk = 80; break;
    case WkdInjection_APC:                risk = 75; break;
    case WkdInjection_EarlyBird:          risk = 75; break;
    case WkdInjection_AtomBombing:        risk = 85; break;  /* 对齐 SS ATOM_BOMBING_SCORE=85 */
    case WkdInjection_RemoteThread:       risk = 70; break;
    case WkdInjection_DirectSyscallThread:risk = 70; break;
    case WkdInjection_SectionMapping:     risk = 65; break;
    case WkdInjection_PeInjection:        risk = 70; break;  /* 对齐 SS InjTechPeInjection=70 */
    case WkdInjection_ShellcodeInjection: risk = 65; break;
    default:                              risk = 60; break;
    }

    /* 目标敏感进程加分 */
    if (IoaIsSensitiveTarget(TargetName)) {
        risk = min(risk + 15, WKD_INJECT_RISK_CAP);
    }

    return min(risk, WKD_INJECT_RISK_CAP);
}

/**************************************************/
/*             注入类型判定                          */
/*  移植自 ShadowStrike ClassifyFromEvents          */
/*  集合存在性匹配 (乱序), 顺序: 镂空→反射→DLL→APC→   */
/*  劫持→区段→远程线程→壳码                          */
/**************************************************/

static
WKD_INJECTION_TYPE
IoaClassifyFromEdges(
    _In_ ULONG64 DataDword,
    _In_ ULONG BehaviorFlags,
    _In_ BOOLEAN HasUnbackedStart,
    _In_ BOOLEAN HasSuspendedStart,
    _In_ BOOLEAN HasRemoteThreadEvent,
    _In_ BOOLEAN HasAtomBombing,
    _In_ BOOLEAN HasHijackConfirmed,
    _In_ BOOLEAN HasExecProtect,
    _In_ BOOLEAN HasTxF
    )
/*++
Routine Description:
    基于边集合 + 事件标志判定注入类型。

Arguments:
    DataDword          - 数据层位图 (边类型集合)。
    BehaviorFlags      - 当前事件行为标志 (驱动采集)。
    HasUnbackedStart   - 线程起始地址无文件支撑。
    HasSuspendedStart  - 线程挂起启动 (CREATE_SUSPENDED)。
    HasRemoteThreadEvent - 当前/历史存在远程线程创建。
    HasAtomBombing     - QueueApc 命中原子检索 API 且全局表存在可疑原子 (T1055.009)。
    HasHijackConfirmed - 线程劫持时序 (Suspend→SetContext→Resume) 已闭合。
    HasExecProtect     - 目标内存 EXECUTE 保护 (MemoryProtection / MemoryProtect
                         NewProtection / MemoryAllocate PageProtection, 对齐 SS
                         INJ_PATTERN_PROTECT_EXECUTE + HAS_EXECUTE)。
    HasTxF             - 事务化进程创建 (NtCreateProcessEx + TxF 句柄, T1055.013)。

Return Value:
    注入类型枚举。
--*/
{
    BOOLEAN hasAlloc, hasWrite, hasInjects;
    BOOLEAN hasHollows, hasAssociated;

#define EDGE_HAS(d, e)  (((d) & (1ULL << (ULONG)(e))) != 0)

    hasAlloc      = EDGE_HAS(DataDword, DefEdge_Allocates);
    hasWrite      = EDGE_HAS(DataDword, DefEdge_WritesTo);
    hasInjects    = EDGE_HAS(DataDword, DefEdge_InjectsInto);
    hasHollows    = EDGE_HAS(DataDword, DefEdge_Hollows);
    hasAssociated = EDGE_HAS(DataDword, DefEdge_AssociatedWith);

    /*
     * 0. 原子炸弹 (置顶: QueueApc + ApcRoutine 命中原子检索 API + 可疑原子,
     *    特异性最高)。移植自 ShadowStrike AtomBombingDetector, T1055.009。
     *    ※ 数据源缺失: 依赖驱动补 NtQueueApcThread case + ApcRoutine 参数解析;
     *       当前 HasAtomBombing 由 IoaClassifyInjection 现场判定, 恒 FALSE 时
     *       自然降级到下方 APC 通用分支。
     */
    if (HasAtomBombing) {
        return WkdInjection_AtomBombing;
    }

    /*
     * 1. 进程镂空: Hollows + Alloc + Write + SetContext
     *    ShadowStrike: Unmap + Allocate + Write + SetContext
     *    WkDefender: Hollows 边替代 Unmap; SET_CONTEXT 标志替代 SetContext 事件。
     *    ※ 死代码: 当前驱动不产生 Hollows 边/SetContext 事件, 待波次0补源。
     */
    if (hasHollows && hasAlloc && hasWrite &&
        (BehaviorFlags & DEF_BEHAVIOR_FLAG_SET_CONTEXT)) {
        return WkdInjection_ProcessHollowing;
    }

    /*
     * 1.5 进程 Doppelganging: TxF 事务化进程创建 (T1055.013)
     *    ShadowStrike: NtCreateTransaction->CreateFileTransacted->
     *    NtCreateSection->NtCreateProcessEx->NtRollbackTransaction
     *    ※ 死代码: HasTxF 依赖 DEF_BEHAVIOR_FLAG_TXF_CREATE。驱动已补
     *       NtCreateSection TxF/DeletePending 检测（SectionTracker 迁移 #58，
     *       0x1011 → WkdEvent_SectionCreate），Transacted/Deleted 信号经
     *       IoaSectionTrackCreate 聚合（g_IoaSectionSharingEnabled 门控）;
     *       待接入 IoaObserve 阶段4.12 将 SuspicionFlags 的 TRANSACTED/
     *       DELETED 位回填为 DEF_BEHAVIOR_FLAG_TXF_CREATE 后本分支可达。
     */
    if (HasTxF && hasWrite) {
        return WkdInjection_ProcessDoppelganging;
    }

    /*
     * 2. 反射 DLL: Write + 远程线程 + 起始地址非模块
     *    ※ 部分死代码: 精确确认依赖内存扫描 (ReflectiveDLLDetector),
     *       此处以 UNBACKED_START 作为起始地址非模块的近似判定。
     */
    if (hasWrite && hasInjects && HasUnbackedStart) {
        return WkdInjection_ReflectiveDLL;
    }

    /*
     * 3. 经典 DLL 注入: Write + 远程线程 + 起始地址在合法模块
     *    LoadLibrary 入口落在 kernel32/kernelbase (文件支撑, 非 UNBACKED)。
     */
    if (hasWrite && hasInjects && !HasUnbackedStart) {
        return WkdInjection_DLLInjection;
    }

    /*
     * 4. APC 注入 / Early Bird: QueueAPC (挂起线程 = Early Bird)
     *    ※ 死代码: 当前驱动不拦 NtQueueApcThread, APC_INJECTION 标志
     *       仅能由 syscall 聚合事件携带 (未实现 case)。
     */
    if (BehaviorFlags & DEF_BEHAVIOR_FLAG_APC_INJECTION) {
        return HasSuspendedStart ? WkdInjection_EarlyBird : WkdInjection_APC;
    }

    /*
     * 5. 线程劫持: Suspend→SetContext→Resume 时序闭合 (T1055.003)
     *    优先消费 PairCtx->ThreadHijack.Confirmed (阶段4.5b 时序确认);
     *    无时序数据时降级用 SET_CONTEXT 标志 + 边集合近似。
     *    ※ 激活依赖驱动补 Suspend/SetContext/Resume case。
     */
    if (HasHijackConfirmed ||
        ((BehaviorFlags & DEF_BEHAVIOR_FLAG_SET_CONTEXT) &&
         (hasAssociated || hasAlloc))) {
        return WkdInjection_ThreadHijacking;
    }

    /*
     * 6. 区段映射: Map + Write
     *    ※ PreAcquireSection 迁移 2026-08: 文件轨 AcquireSection 已激活
     *       （Filter.c FspPreAcquireSection → 0x1308 → 0x6005），syscall 轨
     *       NtMapViewOfSection case 已落位（SyscallHijack.c），触发依赖
     *       SmInitialize() 启用。
     *    ※ 上游标志缺口（SectionTracker 迁移 #58 记录）: SECTION_MAP_REMOTE
     *       位唯一赋值在分类器自身回填（见下），解析器/引擎不预置 → 首次事件
     *       不命中。接入方案: IoaSectionTrackMap 聚合跨进程映射后由阶段4.12
     *       置该位，或改按 WkdEvent_MapViewOfSection Origin=1 判定。
     */
    if (BehaviorFlags & DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE) {
        return WkdInjection_SectionMapping;
    }

    /*
     * 7. 远程线程注入 (兜底): 有远程线程创建
     */
    if (hasInjects || HasRemoteThreadEvent) {
        return WkdInjection_RemoteThread;
    }

    /*
     * 7.5 PE 注入: Alloc + Write + 目标内存 EXECUTE 保护 (T1055.002)
     *    ShadowStrike: ALLOCATE_WRITE + HAS_EXECUTE (InjectionDetector.c:2293-2296,
     *    InjTechPeInjection)。HAS_EXECUTE 信号 = MemoryProtection 可执行 (活, 线程
     *    事件已上送 EventTypes.h:275) / MemoryProtect NewProtection / MemoryAllocate
     *    PageProtection (内存事件轨, 数据源门控)。顺序: Reflective/DLL 分支在前已
     *    捕获有远程线程场景 (LoadLibrary 落在 kernel32 可执行但不被误抢);
     *    PEInjection 是"无远程线程的 Write+Alloc+Exec" 兜底特化 (Shellcode 的可执行
     *    细分), 对齐 SS InjpMatchPatternToTechnique 的通用 PE 注入兜底。
     */
    if (hasAlloc && hasWrite && HasExecProtect) {
        return WkdInjection_PeInjection;
    }

    /*
     * 8. 壳码注入 (兜底): 跨进程内存写且无远程线程。
     *    要求写+分配 (内存操作特征) 组合, 避免普通文件写
     *    (FileWrite 也映射 DefEdge_WritesTo) 被误判为注入。
     */
    if (hasWrite && hasAlloc) {
        return WkdInjection_ShellcodeInjection;
    }

    return WkdInjection_Unknown;

#undef EDGE_HAS
}

/**************************************************/
/*       DLL 注入模块窗口确认 (对齐 ShadowStrike     */
/*       DetectRemoteThreadInjectionImpl)           */
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

/**************************************************/
/*    反射 DLL 精确确认 (SS AnalyzeCandidate 迁移)  */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
IoaConfirmReflectiveLoading(
    ULONG TargetProcessId,
    ULONG_PTR StartRoutine
    )
/*++
Routine Description:
    反射 DLL 精确确认 — 事件驱动定向验证。
    分类器以 UNBACKED_START 近似判定 ReflectiveDLL; 本函数用线程入口地址定向确认:
      MsGetRegionInfo 定位入口区域 → 私有可执行 → MsScanRegionAt 定向扫描 →
      确认隐藏无背衬 PE (WkdMemThreat_PEInjection 且 !PeInPeb)。
    对齐 SS AnalyzeCandidate 的内存扫描确认阶段 (ReflectiveDLLDetector.cpp L2403-2418,
      hasThreadStartingHere → Confirmed)。

Arguments:
    TargetProcessId    - 目标进程 PID。
    StartRoutine - 远程线程入口地址 (ThreadCreate 载荷 StartRoutine)。

Return Value:
    TRUE = 确认隐藏无背衬 PE (反射加载); FALSE = 不可验证/未确认。
    不可验证时返回 FALSE, 不改变原近似判定, 不引入误报。
--*/
{
    WKD_MEMORY_REGION region;
    PWKD_MEM_SCAN_RESULT scan;
    ULONG i;
    BOOLEAN confirmed = FALSE;

    if (TargetProcessId <= 4 || StartRoutine == 0) return FALSE;

    /* 入口所在区域: 私有可执行 → 候选无背衬加载 (对齐 SS FindUnbackedExecutable) */
    if (!MsGetRegionInfo(TargetProcessId, StartRoutine, &region)) return FALSE;
    if (region.Type != WkdMemType_Private || !region.IsExecutable) return FALSE;

    /* 定向扫描入口所在区域 (对齐 SS DispatchAsyncScan 的定向版本, MsScanRegionAt) */
    scan = (PWKD_MEM_SCAN_RESULT)malloc(sizeof(WKD_MEM_SCAN_RESULT));
    if (scan == NULL) return FALSE;

    if (NT_SUCCESS(MsScanRegionAt(TargetProcessId, region.BaseAddress,
                                  region.RegionSize, scan))) {
        for (i = 0; i < scan->ThreatsFound; i++) {
            if (scan->Threats[i].Type == WkdMemThreat_PEInjection &&
                !scan->Threats[i].PeInPeb) {
                /* 深度 PE 验证 (对齐 SS ValidatePEImpl, WpeAnalyzePEDeep):
                   节表/数据目录/熵/SHA256 分级, 确认有效隐藏 PE (反射加载);
                   深度验证不可用时保留 MsScanRegionAt 的区域级确认。 */
                confirmed = TRUE;
                {
                    WKD_PE_DEEP_INFO deep;
                    HANDLE hProc = OpenProcess(
                        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        FALSE, TargetProcessId);
                    if (hProc != NULL) {
                        if (SUCCEEDED(WpeAnalyzePEDeep(hProc,
                                scan->Threats[i].PeImageBase, &deep))) {
                            confirmed = deep.IsValidPE;
                        }
                        CloseHandle(hProc);
                    }
                }
                break;
            }
        }
    }

    free(scan);
    return confirmed;
}

/**************************************************/
/*    线程劫持定向确认 (SS ValidateThread 迁移)     */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
IoaConfirmThreadHijacking(
    ULONG   TargetProcessId,
    ULONG   TargetTid,
    BOOLEAN CrossProcess
    )
/*++
Routine Description:
    线程劫持定向确认 — 事件驱动定向验证 (对齐 SS ValidateThreadInternal,
    ThreadHijackDetector.cpp L889-1081 + CalculateRiskScore L531-551)。
    分类器/时序确认 (阶段4.5b) 判出劫持候选后, 用本函数读取目标线程上下文
    定向验证: RIP 无背衬 / 栈翻转 / 段异常 / 调试寄存器 / RWX, 输出
    IsCompromised。复用 ProcessThreads 的 WptValidateThread (含 WoW64 /
    TEB 栈边界), 壳码复用 IocDetectShellcode。

    对齐 IoaConfirmReflectiveLoading 的"不可验证回退"模式: 无法读取上下文
    时返回 FALSE, 不改变原判定, 不引入误报。

    ※ 死代码: 供阶段4.5b 闭合深化与 IoaAnalyzeProcessInjection Step2
      (ScanProcess) 接线, 当前无调用者。激活需确认数据源 (驱动补
      Suspend/SetContext/Resume case) 后接入。

Arguments:
    TargetProcessId    - 目标进程 PID (线程所属)。
    TargetTid    - 目标线程 TID (被劫持线程)。
    CrossProcess - 跨进程操作 (调用者进程 != 目标进程)。

Return Value:
    TRUE = 线程上下文异常 (劫持确认); FALSE = 不可验证/未确认。
--*/
{
    WKD_THREAD_VALIDATION val;

    if (TargetProcessId <= 4 || TargetTid == 0) return FALSE;
    if (!NT_SUCCESS(WptValidateThread(TargetTid, CrossProcess, FALSE, &val))) {
        return FALSE;
    }
    return val.IsCompromised;
}

/**************************************************/
/*               公开 API                           */
/**************************************************/

NTSTATUS
IoaClassifyInjection(
    _In_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_EVENT_HEADER Event,
    _In_opt_ PWKD_PROCESS SrcNode,
    _In_opt_ PWKD_PROCESS TgtNode,
    _Out_opt_ PWKD_INJECTION_TYPE InjectedType,
    _Out_opt_ PULONG Confidence,
    _Out_opt_ PULONG RiskScore
    )
/*++
Routine Description:
    基于进程对状态 + 事件参数判定注入类型并计算置信度/风险分。
    副作用: 设置注入语义位 (补充 T1 未覆盖的精确判定) 并回填事件标志。

Arguments:
    PairCtx     - 进程对上下文 (必填)。
    Event       - 当前事件 (可为 NULL)。
    SrcNode     - 源进程节点 (可为 NULL)。
    TgtNode     - 目标进程节点 (可为 NULL)。
    InjectedType - [可选] 输出注入类型。
    Confidence  - [可选] 输出置信度。
    RiskScore   - [可选] 输出风险分。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
--*/
{
    ULONG64 dataDword;
    WKD_INJECTION_TYPE type;
    BOOLEAN hasUnbacked, hasSuspended, hasRemoteThreadEvent;
    BOOLEAN hasExecProtect;
    ULONG64 memSize;          /* 当前事件操作大小 (MemoryProtect/MemoryAllocate), 供 TotalSize>64KB 评分 */
    BOOLEAN hasAtomBombing;
    BOOLEAN hasHijackConfirmed;
    IOA_ATOM_SUSPICION atomSuspicion;
    WCHAR srcName[64], tgtName[64];
    ULONG conf, risk;

    if (!PairCtx) {
        return STATUS_INVALID_PARAMETER;
    }

    dataDword = BM_DATA_U64(&PairCtx->InteractionBitmap);

    /* 统计 (供 IoaGetInjectionStatistics, 对齐 SS InjGetStatistics) */
    InterlockedIncrement64(&g_IoaInjStatsTotalCalls);

    /* 事件参数提取 (线程创建类事件含注入分析载荷; 内存事件携带保护/大小) */
    hasUnbacked = FALSE;
    hasSuspended = FALSE;
    hasRemoteThreadEvent = FALSE;
    hasExecProtect = FALSE;
    memSize = 0;

    if (Event &&
        (Event->Type == WkdEvent_RemoteThreadCreate ||
         Event->Type == WkdEvent_ThreadCreate)) {

        PEVENT_PAYLOAD_THREAD_CREATE payload =
            (PEVENT_PAYLOAD_THREAD_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

        if (payload->InjectIndicators & WKD_MSG_INJECT_UNBACKED_START) {
            hasUnbacked = TRUE;
        }
        if (payload->InjectIndicators & WKD_MSG_INJECT_SUSPENDED_START) {
            hasSuspended = TRUE;
        }
        /* MemoryProtection 已上送未消费 (对齐 SS InjTechPeInjection: Alloc+Write+EXECUTE,
         * InjectionDetector.c:2293-2296): 线程入口点可执行保护 → PE 注入判定信号,
         * 激活 IoaIsExecutableProtection (原死代码)。 */
        if (IoaIsExecutableProtection(payload->MemoryProtection) ||
            (payload->InjectIndicators & WKD_MSG_INJECT_RWX_START)) {
            hasExecProtect = TRUE;
        }
        hasRemoteThreadEvent = TRUE;
    }
    else if (Event &&
             (Event->Type == WkdEvent_MemoryProtect ||
              Event->Type == WkdEvent_MemoryAllocate)) {
        /* 内存事件轨 (数据源门控: 驱动当前不发内存事件, IoaHandleRealTimeMemoryEvent
         * 实际不可达): MemoryProtect NewProtection / MemoryAllocate PageProtection →
         * EXECUTE 信号; memSize 供 TotalSize>64KB 评分 (SS 链累积 TotalSize 的
         * 当前事件近似, 对齐 InjectionDetector.c:2074 Chain->TotalSize += Op->Size)。
         * 参数布局对齐 IoaEngine.c:701-703 (ParameterBase[1]=地址 [3]=大小)。 */
        PEVENT_PAYLOAD_SYSCALL payload =
            (PEVENT_PAYLOAD_SYSCALL)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        ULONG protect = (Event->Type == WkdEvent_MemoryProtect)
            ? (ULONG)(ULONG_PTR)payload->ParameterBase[3]   /* NewProtection */
            : (ULONG)(ULONG_PTR)payload->ParameterBase[5];  /* PageProtection */
        memSize = (Event->Type == WkdEvent_MemoryProtect)
            ? (ULONG64)(ULONG_PTR)payload->ParameterBase[2]  /* 大小 */
            : (ULONG64)(ULONG_PTR)payload->ParameterBase[3]; /* 大小 */
        if (IoaIsExecutableProtection(protect)) {
            hasExecProtect = TRUE;
        }
    }

    /* 原子炸弹判定 (T1055.009): QueueApc 且 ApcRoutine 命中原子检索 API,
     * 且全局原子表存在可疑原子 (事件驱动按需枚举, 节流 1000ms)。
     * 移植自 SS TargetsAtomRetrievalImpl + CorrelateEventsImpl 的精准路径;
     * ApcRoutine==0 (驱动参数未解析) 时恒 FALSE, 自然降级到 APC 通用分支。 */
    hasAtomBombing = FALSE;
    atomSuspicion = IoaAtom_Normal;

    if (Event && Event->Type == WkdEvent_QueueApc) {
        PEVENT_PAYLOAD_QUEUE_APC payload =
            (PEVENT_PAYLOAD_QUEUE_APC)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        IOA_ATOM_RESULT best;

        /* 跨进程要求 (对齐 SS isCrossProcess): 同进程自 APC 不构成原子炸弹 */
        if ((ULONG)(ULONG_PTR)payload->SourceProcessId !=
            (ULONG)(ULONG_PTR)payload->TargetProcessId &&
            payload->ApcRoutine != 0 &&
            IoaAtomTargetsRetrieval(payload->ApcRoutine) &&
            IoaAtomCache_ScanGlobalTable(&best)) {
            hasAtomBombing = TRUE;
            atomSuspicion = best.Suspicion;
        }
    }

    /* 线程劫持时序确认 (阶段4.5b Suspend→SetContext→Resume 闭合) */
    hasHijackConfirmed = PairCtx->ThreadHijack.Confirmed;

    /* 分类 */
    type = IoaClassifyFromEdges(
        dataDword,
        Event ? Event->BehaviorFlags : 0,
        hasUnbacked,
        hasSuspended,
        hasRemoteThreadEvent,
        hasAtomBombing,
        hasHijackConfirmed,
        hasExecProtect,   /* 新增: 目标内存 EXECUTE 保护 (PE 注入信号, SS HAS_EXECUTE) */
        Event ? (BOOLEAN)((Event->BehaviorFlags & DEF_BEHAVIOR_FLAG_TXF_CREATE) != 0)
              : FALSE);

    /* 统计: 检出计数 (供 IoaGetInjectionStatistics) */
    if (type != WkdInjection_Unknown) {
        InterlockedIncrement64(&g_IoaInjStatsDetected);
    }

    /* 进程名 (白名单/敏感进程) */
    IoaGetProcessName(SrcNode, srcName, ARRAYSIZE(srcName));
    IoaGetProcessName(TgtNode, tgtName, ARRAYSIZE(tgtName));

    /* 置信度/风险分 */
    conf = IoaComputeInjectionConfidence(type, dataDword, hasUnbacked,
                                         hasExecProtect,
                                         (dataDword & (1ULL << (ULONG)DefEdge_WritesTo)) != 0,
                                         memSize,
                                         srcName, tgtName);
    risk = IoaComputeInjectionRisk(type, tgtName);

    /* 孤儿注入器修正（对齐 SS PrpCalculateRelationshipScore
     * PR_SCORE_ORPHANED_INJECTOR=200）: 源进程父节点缺失（父已退出/
     * 不在谱系, T1_GFLAG_ORPHAN 语义）且非系统进程 → 注入风险分提升。
     * SS 0-1000 尺度 +200 → wkd 0-100 约 +20。 */
    if (SrcNode != NULL &&
        SrcNode->Parent == NULL &&
        !SrcNode->IsSystemProcess) {
        risk = min(risk + 20, WKD_INJECT_RISK_CAP);
    }

    /* 多目标注入器修正（对齐 SS PR_SCORE_MULTIPLE_TARGETS=120）:
     * 源进程操作不同目标数 >5 → 注入风险分提升。SS +120 → wkd 约 +10。 */
    if (SrcNode != NULL && SrcNode->OutPairCount > 5) {
        risk = min(risk + 10, WKD_INJECT_RISK_CAP);
    }

    /* DLL 注入模块窗口确认 (对齐 ShadowStrike DetectRemoteThreadInjectionImpl):
     * 目标进程在窗口内加载未信任模块 → 置信度提升至确认级。
     * 模块缓存空 (ImageLoad 未接入) 时自然降级, 不改变判定。 */
    if (type == WkdInjection_DLLInjection && TgtNode) {
        (VOID)IoaConfirmDllInjectionByModule(
            (ULONG)(ULONG_PTR)TgtNode->ProcessId,
            &conf, &risk);
    }

    /* 反射 DLL 精确确认 (事件驱动定向验证, 对齐 SS AnalyzeCandidate L2403-2418):
     * 分类器以 UNBACKED_START 近似判定 ReflectiveDLL; 定向验证线程入口区域
     * 是否为隐藏无背衬 PE (MsGetRegionInfo + MsScanRegionAt + 模块对照)。
     * 确认成功 → 置信度提升至确认级; 不可验证 → 保留近似判定, 不引入误报。 */
    if (type == WkdInjection_ReflectiveDLL && TgtNode) {
        ULONG_PTR startRoutine = 0;
        if (Event &&
            (Event->Type == WkdEvent_RemoteThreadCreate ||
             Event->Type == WkdEvent_ThreadCreate)) {
            PEVENT_PAYLOAD_THREAD_CREATE payload =
                (PEVENT_PAYLOAD_THREAD_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
            startRoutine = (ULONG_PTR)payload->StartRoutine;
        }
        if (IoaConfirmReflectiveLoading(
                (ULONG)(ULONG_PTR)TgtNode->ProcessId,
                startRoutine)) {
            conf = 95;   /* 对齐 SS DetectionConfidence::Confirmed */
            if (risk < 90) risk = 90;
        }
    }

    /* 原子炸弹 Critical 提升: 全局表存在 Critical 级可疑原子 (壳码+高熵等强特征)
     * 时置信度提升至确认级 (对齐 SS BuildAttackFromCorrelation 高置信度路径)。 */
    if (type == WkdInjection_AtomBombing &&
        atomSuspicion == IoaAtom_Critical) {
        conf = 90;   /* 对齐 SS DetectionConfidence::Confirmed */
        if (risk < 85) risk = 85;
    }

    /* 副作用: 补充设置注入语义位 (不覆盖 T1 已推导结果) */
    if (type != WkdInjection_Unknown) {
        PINTERACTION_BITMAP bm = &PairCtx->InteractionBitmap;

        switch (type) {
        case WkdInjection_ProcessHollowing:
            if (!BM_SEM_TEST(bm, BM_SEM_PROCESS_HOLLOWING)) {
                BM_SEM_SET(bm, BM_SEM_PROCESS_HOLLOWING);
            }
            break;
        case WkdInjection_ProcessDoppelganging:
            /* Doppelgang 属镂空家族, 复用 HOLLOWING 语义位 (T1055.013) */
            if (!BM_SEM_TEST(bm, BM_SEM_PROCESS_HOLLOWING)) {
                BM_SEM_SET(bm, BM_SEM_PROCESS_HOLLOWING);
            }
            break;
        case WkdInjection_ReflectiveDLL:
            if (!BM_SEM_TEST(bm, BM_SEM_REFLECTIVE_LOAD)) {
                BM_SEM_SET(bm, BM_SEM_REFLECTIVE_LOAD);
            }
            break;
        case WkdInjection_DLLInjection:
            if (!BM_SEM_TEST(bm, BM_SEM_DLL_INJECTION)) {
                BM_SEM_SET(bm, BM_SEM_DLL_INJECTION);
            }
            break;
        case WkdInjection_APC:
        case WkdInjection_EarlyBird:
            if (!BM_SEM_TEST(bm, BM_SEM_APC_INJECTION)) {
                BM_SEM_SET(bm, BM_SEM_APC_INJECTION);
            }
            break;
        case WkdInjection_AtomBombing:
            /* 原子炸弹同时具备 APC 注入原语语义 */
            if (!BM_SEM_TEST(bm, BM_SEM_APC_INJECTION)) {
                BM_SEM_SET(bm, BM_SEM_APC_INJECTION);
            }
            if (!BM_SEM_TEST(bm, BM_SEM_ATOM_BOMBING)) {
                BM_SEM_SET(bm, BM_SEM_ATOM_BOMBING);
            }
            break;
        case WkdInjection_ThreadHijacking:
            if (!BM_SEM_TEST(bm, BM_SEM_THREAD_HIJACK)) {
                BM_SEM_SET(bm, BM_SEM_THREAD_HIJACK);
            }
            break;
        case WkdInjection_SectionMapping:
            if (!BM_SEM_TEST(bm, BM_SEM_SECTION_MAP_REMOTE)) {
                BM_SEM_SET(bm, BM_SEM_SECTION_MAP_REMOTE);
            }
            break;
        default:
            break;
        }

        /* 回填事件注入标志 */
        if (Event) {
            switch (type) {
            case WkdInjection_ProcessHollowing:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_HOLLOWING;
                break;
            case WkdInjection_ProcessDoppelganging:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_HOLLOWING;
                break;
            case WkdInjection_ReflectiveDLL:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD;
                break;
            case WkdInjection_DLLInjection:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_INJECTION |
                                        DEF_BEHAVIOR_FLAG_REMOTE_THREAD;
                break;
            case WkdInjection_APC:
            case WkdInjection_EarlyBird:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_APC_INJECTION;
                break;
            case WkdInjection_AtomBombing:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_APC_INJECTION;
                break;
            case WkdInjection_ThreadHijacking:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_SET_CONTEXT;
                break;
            case WkdInjection_SectionMapping:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE;
                break;
            default:
                Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_INJECTION;
                break;
            }
        }
    }

    if (InjectedType) *InjectedType = type;
    if (Confidence) *Confidence = conf;
    if (RiskScore) *RiskScore = risk;

    return STATUS_SUCCESS;
}

/**************************************************/
/*             MITRE / 名称映射                     */
/**************************************************/

PCWSTR
IoaInjectionTypeToMitre(
    _In_ WKD_INJECTION_TYPE Type
    )
/*++
Routine Description:
    注入类型 → MITRE ATT&CK 子技术。

Return Value:
    静态字符串指针。
--*/
{
    switch (Type) {
    case WkdInjection_DLLInjection:
    case WkdInjection_ReflectiveDLL:
        return L"T1055.001";
    case WkdInjection_ShellcodeInjection:
        return L"T1055.002";
    case WkdInjection_PeInjection:
        /* 对齐 SS InjTechPeInjection (InjectionDetector.c:2313-2316): PE 注入 */
        return L"T1055.002";
    case WkdInjection_ThreadHijacking:
        return L"T1055.003";
    case WkdInjection_APC:
    case WkdInjection_EarlyBird:
        return L"T1055.004";
    case WkdInjection_TlsCallback:
        /* 对齐 SS InjTechTlsCallback (InjectionDetector.c:2328-2331) */
        return L"T1055.005";
    case WkdInjection_AtomBombing:
        return L"T1055.009";
    case WkdInjection_ExtraWindowMemory:
        /* 对齐 SS InjTechExtraWindowMemory (InjectionDetector.c:2333-2336) */
        return L"T1055.011";
    case WkdInjection_ProcessHollowing:
        return L"T1055.012";
    case WkdInjection_ProcessDoppelganging:
        /* 修复: 原落默认 T1055, 注释已言明应映射 T1055.013 (对齐 SS 链模式) */
        return L"T1055.013";
    case WkdInjection_VdsoHijacking:
        return L"T1055.014";
    case WkdInjection_Listplanting:
        return L"T1055.015";
    case WkdInjection_SectionMapping:
        /* 对齐 SS InjTechMapViewOfSection (InjectionDetector.c:2358-2361): 归 T1055,
         * 避免与 PeInjection 的 T1055.002 撞号 */
        return L"T1055";
    case WkdInjection_CallbackInjection:
        /* 对齐 SS InjTechCallbackInjection: MITRE 无独立子技术, 归 T1055 */
        return L"T1055";
    default:
        return L"T1055";
    }
}

PCWSTR
IoaInjectionTypeToString(
    _In_ WKD_INJECTION_TYPE Type
    )
/*++
Routine Description:
    注入类型 → 可读名称。

Return Value:
    静态字符串指针。
--*/
{
    switch (Type) {
    case WkdInjection_RemoteThread:        return L"CreateRemoteThread";
    case WkdInjection_DirectSyscallThread: return L"Direct Syscall Thread";
    case WkdInjection_APC:                 return L"QueueUserAPC";
    case WkdInjection_EarlyBird:           return L"Early Bird APC";
    case WkdInjection_AtomBombing:         return L"Atom Bombing";
    case WkdInjection_ProcessHollowing:    return L"Process Hollowing";
    case WkdInjection_ProcessDoppelganging:return L"Process Doppelganging";
    case WkdInjection_PeInjection:         return L"PE Injection";
    case WkdInjection_TlsCallback:         return L"TLS Callback Injection";
    case WkdInjection_ExtraWindowMemory:   return L"Extra Window Memory Injection";
    case WkdInjection_CallbackInjection:   return L"Callback Injection";
    case WkdInjection_VdsoHijacking:       return L"VDSO Hijacking";
    case WkdInjection_Listplanting:        return L"Listplanting";
    case WkdInjection_DLLInjection:        return L"DLL Injection (LoadLibrary)";
    case WkdInjection_ReflectiveDLL:       return L"Reflective DLL Injection";
    case WkdInjection_ThreadHijacking:     return L"Thread Execution Hijacking";
    case WkdInjection_SectionMapping:      return L"NtMapViewOfSection Injection";
    case WkdInjection_ShellcodeInjection:  return L"Shellcode Injection";
    default:                               return L"Unknown";
    }
}

/**************************************************/
/*           遗漏项补充 (移植 ShadowStrike)          */
/**************************************************/

/*
 * 注入语义位掩码: 判断某进程对的 InteractionBitmap 是否含注入语义。
 */
static
BOOLEAN
IoaInjSemHasAny(
    _In_ PINTERACTION_BITMAP bm
    )
{
    const ULONG64 injSem =
        (1ULL << BM_SEM_DLL_INJECTION)     |
        (1ULL << BM_SEM_APC_INJECTION)     |
        (1ULL << BM_SEM_PROCESS_HOLLOWING) |
        (1ULL << BM_SEM_THREAD_HIJACK)     |
        (1ULL << BM_SEM_REFLECTIVE_LOAD)   |
        (1ULL << BM_SEM_SECTION_MAP_REMOTE) |
        (1ULL << BM_SEM_ATOM_BOMBING);

    if (!bm) return FALSE;
    return (BM_SEM_U64(bm) & injSem) != 0;
}

BOOLEAN
IoaIsExecutableProtection(
    _In_ ULONG Protection
    )
/*++
Routine Description:
    判断内存保护属性是否可执行 (PAGE_EXECUTE* 家族)。
    移植自 ShadowStrike IsExecutableProtection。

    ※ 死代码: 分类器当前用 InjectIndicators 的 RWX_START 标志近似,
      本函数供 MemoryProtection 字段 (已解析未消费) 直接判定时使用。

Arguments:
    Protection - 内存保护属性 (PAGE_*)。

Return Value:
    TRUE=可执行。
--*/
{
    const ULONG kPageExecute          = 0x10;
    const ULONG kPageExecuteRead      = 0x20;
    const ULONG kPageExecuteReadWrite = 0x40;
    const ULONG kPageExecuteWriteCopy = 0x80;

    return (Protection & (kPageExecute | kPageExecuteRead |
                          kPageExecuteReadWrite | kPageExecuteWriteCopy)) != 0;
}

BOOLEAN
IoaIsSuspiciousHandleAccess(
    _In_ ULONG AccessRights
    )
/*++
Routine Description:
    判断句柄访问权限组合是否可疑 (Write+Operation 或 Write+CreateThread)。
    移植自 ShadowStrike IsSuspiciousHandleAccess。

    ※ 死代码: 当前 ProcessOpen 事件不携带 DesiredAccess 详情,
      驱动侧 ObCallback 句柄告警未启用。

Arguments:
    AccessRights - 进程句柄访问权限。

Return Value:
    TRUE=可疑 (注入能力组合)。
--*/
{
    const ULONG kProcessVmWrite      = 0x20;   /* PROCESS_VM_WRITE */
    const ULONG kProcessVmOperation  = 0x08;   /* PROCESS_VM_OPERATION */
    const ULONG kProcessCreateThread = 0x02;   /* PROCESS_CREATE_THREAD */

    BOOLEAN hasWrite      = (AccessRights & kProcessVmWrite) != 0;
    BOOLEAN hasOperation  = (AccessRights & kProcessVmOperation) != 0;
    BOOLEAN hasCreateThread = (AccessRights & kProcessCreateThread) != 0;

    return (hasWrite && hasOperation) || (hasWrite && hasCreateThread);
}

WKD_INJECTOR_TYPE
IoaClassifyInjector(
    _In_ ULONG Confidence
    )
/*++
Routine Description:
    注入器分级。移植自 ShadowStrike CreateAlert:
      confidence >= 90 → Malware, >= 70 → Exploit, 否则 Unknown。

    ※ 死代码: 供告警生成补充注入器分类字段, 当前告警出口未使用。

Arguments:
    Confidence - 注入置信度 [0,100]。

Return Value:
    注入器分类枚举。
--*/
{
    if (Confidence >= 90) return WkdInjector_Malware;
    if (Confidence >= 70) return WkdInjector_Exploit;
    return WkdInjector_Unknown;
}

NTSTATUS
IoaQueryProcessInjectionState(
    _In_ PWKD_PROCESS Node,
    _Out_ PWKD_INJECTION_PROCESS_STATE Out
    )
/*++
Routine Description:
    进程注入状态查询。移植自 ShadowStrike
    IsProcessInjected/IsProcessInjecting + ProcessInjectionState。

    遍历进程节点双向 PairContext 链:
      - OutPairListHead: 该进程作为源 (注入者) 的进程对
      - InPairListHead:  该进程作为目标 (被注入) 的进程对
    聚合注入语义位得出注入状态。

    ※ 死代码: 供 UI/主动查询, 当前无调用者。

Arguments:
    Node - 进程节点。
    Out  - 输出注入状态。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
--*/
{
    PLIST_ENTRY entry;

    if (!Node || !Out) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Out, sizeof(*Out));

    /* 链头锁原则 (2026-08-25): Out/InPairListHead 遍历持节点
     * PairLinksLock 共享 (与挂链/摘除同锁域)。 */
    AcquireSRWLockShared(&Node->PairLinksLock);

    /* 作为注入者: 遍历出向进程对 */
    for (entry = Node->OutPairListHead.Flink;
         entry != &Node->OutPairListHead;
         entry = entry->Flink) {
        PAE_PROCESS_PAIR pair =
            CONTAINING_RECORD(entry, AE_PROCESS_PAIR, SourceProcessLinks);
        if (IoaInjSemHasAny(&pair->InteractionBitmap)) {
            Out->IsInjecting = TRUE;
            Out->TotalInjectionsAsSource++;
        }
    }

    /* 作为被注入: 遍历入向进程对 */
    for (entry = Node->InPairListHead.Flink;
         entry != &Node->InPairListHead;
         entry = entry->Flink) {
        PAE_PROCESS_PAIR pair =
            CONTAINING_RECORD(entry, AE_PROCESS_PAIR, TargetProcessLinks);
        if (IoaInjSemHasAny(&pair->InteractionBitmap)) {
            Out->IsBeingInjected = TRUE;
            Out->HasBeenInjected = TRUE;
            Out->TotalInjectionsAsTarget++;
        }
    }

    ReleaseSRWLockShared(&Node->PairLinksLock);

    return STATUS_SUCCESS;
}

NTSTATUS
IoaAnalyzeProcessInjection(
    _In_ PWKD_PROCESS Node,
    _Out_opt_ PULONG Verdict
    )
/*++
Routine Description:
    进程注入主动分析。移植自 ShadowStrike AnalyzeProcess:
      Step1 查进程注入状态 (hasBeenInjected→Detected, isBeingInjected→Suspicious)
      Step2 主动扫描兄弟检测器确认 (Hollowing→Confirmed/Reflective→Confirmed/
            ThreadHijack→Detected)

    ※ 死代码: Step1 已实现; Step2 依赖波次1/2 的 MemoryScanner/
      ProcessHollowingDetector/ThreadHijackDetector (未迁移), 待接入。

Arguments:
    Node    - 进程节点。
    Verdict - [可选] 输出判定: 0=Clean, 1=Suspicious, 2=Detected, 3=Confirmed。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
--*/
{
    WKD_INJECTION_PROCESS_STATE state;

    if (!Node) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Step1: 状态查询级判定 */
    RtlZeroMemory(&state, sizeof(state));
    IoaQueryProcessInjectionState(Node, &state);

    if (Verdict) {
        if (state.HasBeenInjected) {
            *Verdict = 2;   /* Detected */
        } else if (state.IsBeingInjected) {
            *Verdict = 1;   /* Suspicious */
        } else {
            *Verdict = 0;   /* Clean */
        }
    }

    /*
     * Step2: 主动扫描 (ProcessHollowing 已接入 IpeDetectProcessHollowing)
     *   - ProcessHollowingDetector::IsHollowed → Confirmed [已接入]
     *   - ReflectiveDLLDetector::HasReflectiveLoading → Confirmed [未迁移, 死代码]
     *   - ThreadHijackDetector::ScanProcess     → Detected [未迁移, 死代码]
     *   - MemoryScanner::ScanProcessMemory      → Detected [已由 MsScanProcessMemoryFull 覆盖]
     */
    {
        WKD_HOLLOWING_RESULT hollow = { 0 };
        if (IpeDetectProcessHollowing((ULONG)(ULONG_PTR)Node->ProcessId,
                                      WkdMemScan_Normal, &hollow) &&
            hollow.IsHollowed) {
            if (Verdict && *Verdict < 3) {
                *Verdict = 3;   /* Confirmed */
            }
            InterlockedOr(&Node->BehaviorFlags, DEF_BEHAVIOR_FLAG_HOLLOWING);
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*   SS InjectionDetector.c 迁移补充 (2026-08)      */
/*                                                  */
/*  以下能力为活编译无调用者死代码, 对齐 SS 内核版      */
/*  InjectionDetector.c 功能面 (操作追踪+链关联+       */
/*  技术判定+统计查询)。数据源缺失标注见各函数注释,     */
/*  激活条件满足后接线, 不改变现有判定。               */
/**************************************************/

/* 注入检测统计 (供 IoaGetInjectionStatistics, 由 IoaClassifyInjection 实时累计) */
static volatile LONG64 g_IoaInjStatsTotalCalls = 0;
static volatile LONG64 g_IoaInjStatsDetected   = 0;

/*
 * IoaCalcOperationSuspicion — 单操作即时嫌疑分。
 * 对齐 SS InjRecordOperation (InjectionDetector.c:918-938) +
 * InjpIsSuspiciousProtection (L3010-3030):
 *   跨进程 +20 / 可疑保护 (RWX 或 ExecuteWriteCopy) +30 /
 *   远程 CreateThread +40 / 远程 QueueApc +35, cap 100。
 *
 * ※ 死代码: 当前驱动不逐操作上送内存/APC syscall 参数解析 (SyscallHijack.c
 *   default 分支仅跨进程异步上送, 不解析 Protection), 无调用者。
 *   与驱动指示器体系 (InjectIndicators→InjectionScore 0-1000 加权) 的关系:
 *   SS 单操作即时分用于逐操作阻断决策 (InjpShouldBlockInjection 前置), 是
 *   补充尺子而非替代; 激活后供驱动告警回调对齐校验与阻断接线。
 *
 * Arguments:
 *   IsRemote    - SourceProcessId != TargetProcessId。
 *   Protection  - 内存保护属性 (PAGE_*), 0=未知。
 *   OpType      - 操作类型。
 *
 * Return Value:
 *   嫌疑分 [0,100]。
 */
ULONG
IoaCalcOperationSuspicion(
    _In_ BOOLEAN IsRemote,
    _In_ ULONG Protection,
    _In_ IOA_INJ_OP OpType
    )
{
    ULONG score = 0;

    if (IsRemote) {
        score += 20;
    }

    /* 可疑保护: 基础值 (低 8 位, 忽略修饰标志) 为 RWX (0x40) 或
     * ExecuteWriteCopy (0x80)。对齐 SS M-6 FIX: PAGE_* 基础值是互斥值
     * 非位掩码, 须等值比较 (InjectionDetector.c:3019-3030)。 */
    {
        ULONG base = Protection & 0xFF;
        if (base == 0x40 /* PAGE_EXECUTE_READWRITE */ ||
            base == 0x80 /* PAGE_EXECUTE_WRITECOPY */) {
            score += 30;
        }
    }

    if (OpType == IoaInjOp_CreateThread && IsRemote) {
        score += 40;
    }
    if (OpType == IoaInjOp_QueueApc && IsRemote) {
        score += 35;
    }

    return min(score, 100);
}

/*
 * IoaClassifySecondaryInjection — 次级注入技术判定 (SS 纸面技术补齐)。
 *
 * SS InjectionDetector.c 在 INJ_TECHNIQUE 枚举声明了 TLS Callback /
 * ExtraWindowMemory / CallbackInjection 等, 但 InjpMatchPatternToTechnique
 * 从未实现对应判定 (纸面枚举, 见 InjectionDetector.h:100-139 与
 * InjectionDetector.c:2227-2299)。本函数保留各技术判定信号与数据源标注,
 * 供驱动补 syscall case 后接线 (从 IoaClassifyFromEdges 返回前调用, 命中
 * 即覆盖主链兜底类型)。
 *
 * ※ 死代码: 各技术数据源当前均缺失, 恒返回 Unknown, 不改变主链判定。
 *
 * Arguments:
 *   DataDword       - 数据层位图 (边类型集合)。
 *   BehaviorFlags   - 事件行为标志。
 *   MemoryProtection - 线程入口点内存保护 (PAGE_*)。
 *
 * Return Value:
 *   注入类型枚举 (当前恒 Unknown)。
 */
WKD_INJECTION_TYPE
IoaClassifySecondaryInjection(
    _In_ ULONG64 DataDword,
    _In_ ULONG BehaviorFlags,
    _In_ ULONG MemoryProtection
    )
{
    /*
     * TLS Callback 注入 (T1055.005, SS InjTechTlsCallback, T1055.005):
     *   进程创建时入口 PE 的 TLS 目录含回调地址 → 回调在线程入口前执行。
     *   判定信号: 线程入口区 PE 头 TLS 目录存在回调 (WpeParseTls / PeLazy)。
     *   ※ 数据源缺失: 需驱动 ProcessCreate 时提取入口 PE TLS 目录, 或 Agent
     *      线程创建确认时 MsScanRegionAt + PE TLS 解析, 当前无。
     */
    /* TLS 回调判定骨架 — 激活后取消注释并接入真实参数
    if (BehaviorFlags & DEF_BEHAVIOR_FLAG_TLS_CALLBACK) {
        return WkdInjection_TlsCallback;
    }
    */

    /*
     * Extra Window Memory 注入 (T1055.011, SS InjTechExtraWindowMemory):
     *   跨进程 SetWindowLongPtr + 偏移超出窗口类保留区 + 写入值指向私有可执行内存。
     *   判定信号: win32k SetWindowLong 事件 + 窗口句柄跨进程。
     *   ※ 数据源缺失: 需驱动补 win32k NtUserSetWindowLong syscall case, 当前无。
     */
    /* EWM 判定骨架 — 激活后取消注释
    if (BehaviorFlags & DEF_BEHAVIOR_FLAG_EXTRA_WINDOW_MEMORY) {
        return WkdInjection_ExtraWindowMemory;
    }
    */

    /*
     * Callback 注入 (T1055, SS InjTechCallbackInjection):
     *   回调句柄 (SetWindowsHookEx/CreateTimerQueueTimer/EnumWindows) + 回调地址
     *   落在跨进程写入的私有可执行区。
     *   判定信号: win32k 回调类事件 + 回调地址内存保护。
     *   ※ 数据源缺失: 需驱动补 win32k 回调类 syscall case 或 ETW, 依赖同
     *      IoaDllInj_EnumerateHooks (#if 0 块)。
     */
    /* Callback 判定骨架 — 激活后取消注释
    if (BehaviorFlags & DEF_BEHAVIOR_FLAG_CALLBACK_INJECTION) {
        return WkdInjection_CallbackInjection;
    }
    */

    /*
     * VDSO Hijacking (T1055.014) / Listplanting (T1055.015):
     *   均为 Linux 专有技术 (vDSO 页覆写 / eventfd·SO_REUSEPORT 列表投毒),
     *   Windows 端保留枚举与 MITRE 映射 (IoaMitreMapper.h 已有条目),
     *   判定恒不触发。
     */
    UNREFERENCED_PARAMETER(DataDword);
    UNREFERENCED_PARAMETER(BehaviorFlags);
    UNREFERENCED_PARAMETER(MemoryProtection);

    return WkdInjection_Unknown;
}

/*
 * IoaGetInjectionStatistics — 注入检测统计。
 * 对齐 SS InjGetStatistics (InjectionDetector.c:1467-1540, 8 计数)。
 *
 * wkd 无操作哈希表/链/阻断通道, 5 个计数无对应物置 0 留位:
 *   BlockedInjections / DroppedOperations / ChainsCreated / ActiveOperations
 *   (wkd 无操作表与链), ActiveInjectionPairs (需 PairManager 全量遍历 API)。
 * TotalInjectionCalls / DetectedInjections 由 IoaClassifyInjection 实时累计。
 *
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaGetInjectionStatistics(
    _Out_ PWKD_INJECTION_STATISTICS Stats
    )
{
    if (!Stats) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));
    Stats->TotalInjectionCalls = (ULONG64)InterlockedCompareExchange64(
        &g_IoaInjStatsTotalCalls, 0, 0);
    Stats->DetectedInjections  = (ULONG64)InterlockedCompareExchange64(
        &g_IoaInjStatsDetected, 0, 0);
    Stats->UptimeSeconds = (ULONG)(GetTickCount64() / 1000);  /* 近似: 系统运行时长 */
    return STATUS_SUCCESS;
}

/*
 * IoaQueryInjectionChain — 进程对注入链查询。
 * 对齐 SS InjGetChainInfo (InjectionDetector.c:1226-1292)。
 *
 * SS 链键为 (SrcPid,TgtPid), wkd 进程对键亦为 (SourceProcessId,TargetProcessId) PID
 * (2026-08-23 pair 键 PID 化): 调用方先用 AeLookupProcessPair(SrcPid, TgtPid)
 * 获取 PairCtx 后查询; NodeId 经 IoaPairResolveNodeIds 反查 (占位节点输出零 GUID)。
 * SS 链 5s 滑窗/32 操作上限由 wkd 进程对 60s TTL +
 * 边衰减承担, 此处输出当前进程对的数据层/语义层位图与重算判定。
 *
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaQueryInjectionChain(
    _In_ PAE_PROCESS_PAIR PairCtx,
    _Out_ PWKD_INJECTION_CHAIN_INFO Info
    )
{
    WKD_INJECTION_TYPE type = WkdInjection_Unknown;
    ULONG conf = 0, risk = 0;

    if (!PairCtx || !Info) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(*Info));
    IoaPairResolveNodeIds(PairCtx, &Info->SourceNodeId, &Info->TargetNodeId);
    Info->DataBitmap64    = BM_DATA_U64(&PairCtx->InteractionBitmap);
    Info->SemBitmap64     = BM_SEM_U64(&PairCtx->InteractionBitmap);
    Info->TotalEvents = PairCtx->TotalEdges;

    /* 复用分类器重算当前判定 (对齐 InjGetChainInfo 输出 DetectedTechnique/Confidence) */
    if (NT_SUCCESS(IoaClassifyInjection(PairCtx, NULL, NULL, NULL,
                                        &type, &conf, &risk))) {
        Info->DetectedTechnique = type;
        Info->ConfidenceScore = conf;
        Info->RiskScore = risk;
    }

    return STATUS_SUCCESS;
}

/*
 * IoaDetectInjectionAtRegion — 地址区域定向注入检测。
 * 对齐 SS InjDetectInjection (InjectionDetector.c:1099-1224):
 *   SS 在 (SrcPid,TgtPid) 链的操作里匹配 TargetAddress∈[addr, addr+Size),
 *   对命中链做链分析取最佳技术。wkd 无地址级操作记录, 退化实现:
 *     Step1 进程注入状态查询 (该进程作为目标的所有注入对);
 *     Step2 MsScanRegionAt 定向扫描区域, 按威胁类型映射注入判定
 *           (反射 PE/无背衬 → ReflectiveDLL, 有背衬 → PEInjection,
 *           壳码 → Shellcode, 高熵 → Suspicious);
 *     Step3 区域无命中但进程已处于被注入状态 → RemoteThread 近似。
 *
 * ※ 死代码: 无调用者 (主动扫描场景接线, 对齐 IoaAnalyzeProcessInjection)。
 */
NTSTATUS
IoaDetectInjectionAtRegion(
    _In_ PWKD_PROCESS Node,
    _In_ ULONG_PTR TargetAddress,
    _In_ SIZE_T Size,
    _Out_opt_ PWKD_INJECTION_TYPE Type,
    _Out_opt_ PULONG Confidence
    )
{
    WKD_INJECTION_PROCESS_STATE state;
    WKD_MEM_SCAN_RESULT scan;
    WKD_INJECTION_TYPE type = WkdInjection_Unknown;
    ULONG confidence = 0;
    ULONG i;

    if (!Node) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Step1: 进程注入状态 */
    RtlZeroMemory(&state, sizeof(state));
    IoaQueryProcessInjectionState(Node, &state);

    /* Step2: 区域定向扫描 */
    if (TargetAddress != 0 && Size != 0) {
        RtlZeroMemory(&scan, sizeof(scan));
        if (NT_SUCCESS(MsScanRegionAt(
                (DWORD)(ULONG_PTR)Node->ProcessId,
                TargetAddress, Size, &scan))) {
            for (i = 0; i < scan.ThreatsFound && i < WKD_MEM_MAX_THREATS; i++) {
                PWKD_MEM_THREAT t = &scan.Threats[i];
                if (t->Type == WkdMemThreat_PEInjection && !t->PeInPeb) {
                    /* 隐藏无背衬 PE → 反射加载 (对齐 IoaConfirmReflectiveLoading) */
                    type = WkdInjection_ReflectiveDLL;
                    if (confidence < 90) confidence = 90;
                } else if (t->Type == WkdMemThreat_PEInjection) {
                    /* 有背衬/模块表内 PE → PE 注入 */
                    type = WkdInjection_PeInjection;
                    if (confidence < 70) confidence = 70;
                } else if (t->Type == WkdMemThreat_Shellcode) {
                    type = WkdInjection_ShellcodeInjection;
                    if (confidence < 65) confidence = 65;
                } else if (t->Type == WkdMemThreat_EncryptedPayload) {
                    if (type == WkdInjection_Unknown) {
                        type = WkdInjection_ShellcodeInjection;
                    }
                    if (confidence < 55) confidence = 55;
                }
            }
        }
    }

    /* Step3: 区域无命中但进程已处于被注入状态 */
    if (type == WkdInjection_Unknown && state.HasBeenInjected) {
        type = WkdInjection_RemoteThread;
        confidence = 70;
    }

    if (Type)       *Type = type;
    if (Confidence) *Confidence = confidence;
    return STATUS_SUCCESS;
}

/*
 * IoaClearInjectionChain — 清进程对注入语义位。
 * 对齐 SS InjClearChain (InjectionDetector.c:1542-1595) 删除指定进程对链。
 * wkd 进程对无链结构, 仅清 InteractionBitmap 语义层的注入位 (对齐
 * IoaInjSemHasAny 掩码, 保留非注入语义)。
 * InjClearAllChains (清全部) 需 PairManager 全量遍历 API, wkd 无, 不提供。
 *
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaClearInjectionChain(
    _In_ PAE_PROCESS_PAIR PairCtx
    )
{
    PINTERACTION_BITMAP bm;
    ULONG64 injSem;

    if (!PairCtx) {
        return STATUS_INVALID_PARAMETER;
    }

    bm = &PairCtx->InteractionBitmap;
    injSem =
        (1ULL << BM_SEM_DLL_INJECTION)     |
        (1ULL << BM_SEM_APC_INJECTION)     |
        (1ULL << BM_SEM_PROCESS_HOLLOWING) |
        (1ULL << BM_SEM_THREAD_HIJACK)     |
        (1ULL << BM_SEM_REFLECTIVE_LOAD)   |
        (1ULL << BM_SEM_SECTION_MAP_REMOTE)|
        (1ULL << BM_SEM_ATOM_BOMBING);

    *(ULONG64*)&bm->Bits[BM_SEM_OFFSET] &= ~injSem;
    return STATUS_SUCCESS;
}

/*
 * IoaClassifyBySsOperationPattern — SS 操作模式位→技术判定。
 * 完整保留 SS InjpCalculateOperationPatterns (InjectionDetector.c:2148-2225,
 * 累积模式位, I-6 非严格相邻) + InjpMatchPatternToTechnique (L2227-2299,
 * 8 种技术匹配) 的判定逻辑, 输入为 SS 风格操作模式位。
 *
 * 与 wkd 主分类器 (IoaClassifyFromEdges, 基于边集合+事件标志) 的信号集不同:
 *   SS 基于"操作类型+保护属性+链标志", wkd 基于"边类型集合+行为标志"。本函数
 *   保留 SS 维度作为独立信号源, 供未来驱动补操作类型级事件 (携带 Protection/
 *   跨进程标志) 后接线; 当前无调用者, 恒不改变主链判定。
 *
 * ※ 死代码: 无调用者。
 */
WKD_INJECTION_TYPE
IoaClassifyBySsOperationPattern(
    _In_ const IOA_SS_OP_PATTERN* Pat
    )
{
    ULONG patterns = 0;
    ULONG flags = 0;

    if (!Pat) {
        return WkdInjection_Unknown;
    }

    /* 累积模式位 (对齐 SS InjpCalculateOperationPatterns) */
    if (Pat->HasAllocate && Pat->HasWrite)      patterns |= 0x0001;  /* ALLOCATE_WRITE */
    if (Pat->HasWrite && Pat->HasProtect)       patterns |= 0x0002;  /* WRITE_PROTECT */
    if (Pat->HasProtect && Pat->HasExecProtect) patterns |= 0x0004;  /* PROTECT_EXECUTE */
    if (Pat->HasCreateThread)                   patterns |= 0x0008;  /* CREATE_THREAD */
    if (Pat->HasQueueApc)                       patterns |= 0x0010;  /* QUEUE_APC */
    if (Pat->HasMapSection)                     patterns |= 0x0020;  /* MAP_SECTION */
    if (Pat->HasSetContext)                     patterns |= 0x0040;  /* SET_CONTEXT */
    if (Pat->HasSuspendResume)                  patterns |= 0x0080;  /* SUSPEND_RESUME */
    if (Pat->HasExecProtect)                    flags |= 0x0001;     /* INJ_CHAIN_FLAG_HAS_EXECUTE */
    if (Pat->HasTransacted)                     flags |= 0x0010;     /* INJ_CHAIN_FLAG_TRANSACTED */

    /* 技术匹配 (对齐 SS InjpMatchPatternToTechnique, 判定顺序一致) */
    if ((patterns & 0x0080) && (patterns & 0x0040) && (patterns & 0x0001)) {
        return WkdInjection_ProcessHollowing;    /* Suspend+SetCtx+AllocWrite */
    }
    if ((patterns & 0x0020) && (flags & 0x0010)) {
        return WkdInjection_ProcessDoppelganging; /* MapSection+Transacted */
    }
    if ((patterns & 0x0001) && (patterns & 0x0010)) {
        return WkdInjection_APC;                  /* AllocWrite+QueueApc */
    }
    if ((patterns & 0x0001) && (patterns & 0x0008)) {
        return WkdInjection_DLLInjection;         /* AllocWrite+CreateThread (SS ClassicDLL) */
    }
    if ((patterns & 0x0001) && (patterns & 0x0004)) {
        return WkdInjection_ReflectiveDLL;        /* AllocWrite+ProtectExec (SS Reflective) */
    }
    if ((patterns & 0x0080) && (patterns & 0x0040)) {
        return WkdInjection_ThreadHijacking;      /* Suspend+SetCtx */
    }
    if ((patterns & 0x0020) && (flags & 0x0001)) {
        return WkdInjection_SectionMapping;       /* MapSection+Exec (SS MapView) */
    }
    if ((patterns & 0x0001) && (flags & 0x0001)) {
        return WkdInjection_PeInjection;          /* AllocWrite+Exec (SS PEInjection) */
    }

    return WkdInjection_Unknown;
}

/**************************************************/
/*      死代码迁移 (对齐 ShadowStrike)               */
/*                                                  */
/*  以下能力依赖的数据源当前未就绪, 以 #if 0 形式     */
/*  全量迁移并保留实现。激活条件见各块注释。           */
/**************************************************/

#if 0

/* ============================================================================
 * ① APC 注入关联 (对齐 ShadowStrike DetectAPCInjectionImpl / OnAPCQueue)
 *
 * 数据源依赖: 驱动需补 NtQueueApcThread syscall case (主计划波次0),
 *   使 APC 队列事件 (APC_ROUTINE / 跨进程标志) 上送 Agent。
 *   激活后取消 #if 0, 由 IoaObserve 的 APC 事件分支调用, 将 APC 队列 +
 *   窗口内未信任模块关联为 WkdInjection_APC (T1055.004)。
 *
 * 实现复用模块加载缓存 (IoaRecordModuleLoad / IOA_MOD_WINDOW_MS),
 *   判定目标进程窗口内加载未信任模块, 输出确认结果。
 * ========================================================================== */

typedef struct _IOA_APC_QUEUE_EVENT {
    ULONG          TargetProcessId;
    ULONG          TargetTid;
    ULONG          QueuedByPid;    /* 跨进程: QueuedByPid != TargetProcessId */
    ULONG_PTR      ApcRoutine;
    LARGE_INTEGER  Timestamp;
} IOA_APC_QUEUE_EVENT, *PIOA_APC_QUEUE_EVENT;

/* 单条 APC 队列记录入环 (对齐 InjectionCorrelator.RecordAPCQueue,
 * 60s 窗口 / 4096 上限)。由驱动 NtQueueApcThread case 上送的事件填充。 */
static
NTSTATUS
IoaDllInj_RecordApcQueue(
    _In_ PIOA_APC_QUEUE_EVENT Apc
    )
{
    /* 预留: APC 事件环形记录 */
    UNREFERENCED_PARAMETER(Apc);
    return STATUS_NOT_IMPLEMENTED;
}

/* APC 模块窗口确认: 跨进程 APC 队列 + 窗口内未信任模块 → APC 注入 */
static
NTSTATUS
IoaDllInj_ConfirmApcInjection(
    _In_ ULONG TargetProcessId,
    _In_ ULONG QueuedByPid,
    _Inout_ PULONG Confidence,
    _Inout_ PULONG RiskScore
    )
{
    if (QueuedByPid == TargetProcessId) {
        return STATUS_NOT_FOUND;    /* 自 APC 不构成注入 */
    }
    /* 与 DLL 注入相同的模块窗口确认逻辑 */
    return IoaConfirmDllInjectionByModule(TargetProcessId, Confidence, RiskScore);
}

/* ============================================================================
 * ② Hook 注入检测 (对齐 ShadowStrike EnumerateHooks / GetProcessHooks /
 *    DetectHookInjectionImpl / OnHookInstall)
 *
 * 数据源依赖: Windows 无公开用户态 API 枚举全局钩子, 需 ETW
 *   (Microsoft-Windows-Win32k) 或驱动拦截 NtUserSetWindowsHookEx。
 *   当前无事件源, 全量迁移保留实现。
 * ========================================================================== */

typedef enum _IOA_HOOK_TYPE {
    IoaHook_Unknown = 0,
    IoaHook_Keyboard = 1,
    IoaHook_KeyboardLowLevel = 2,
    IoaHook_Mouse = 3,
    IoaHook_MouseLowLevel = 4,
    IoaHook_CBT = 5,
    IoaHook_GetMessage = 6,
    IoaHook_CallWndProc = 7,
    IoaHook_CallWndProcRet = 8,
    IoaHook_Shell = 9,
} IOA_HOOK_TYPE, *PIOA_HOOK_TYPE;

/* WH_* 常量 → Hook 类型 (对齐 ShadowStrike ConvertHookType) */
static
IOA_HOOK_TYPE
IoaDllInj_ConvertHookType(
    _In_ int HookTypeValue
    )
{
    switch (HookTypeValue) {
    case 2:  return IoaHook_Keyboard;
    case 13: return IoaHook_KeyboardLowLevel;
    case 7:  return IoaHook_Mouse;
    case 14: return IoaHook_MouseLowLevel;
    case 5:  return IoaHook_CBT;
    case 3:  return IoaHook_GetMessage;
    case 4:  return IoaHook_CallWndProc;
    case 8:  return IoaHook_CallWndProcRet;
    case 10: return IoaHook_Shell;
    default: return IoaHook_Unknown;
    }
}

/* 全局钩子怀疑启发式 (对齐 ShadowStrike OnHookInstall):
 * 全局低级别键盘钩子 (WH_KEYBOARD_LL=13, threadId=0) 即可疑 */
static
BOOLEAN
IoaDllInj_IsSuspiciousHook(
    _In_ int HookTypeValue,
    _In_ ULONG ThreadId
    )
{
    if (ThreadId == 0 && HookTypeValue == 13) {
        return TRUE;    /* 全局低级别键盘钩子 */
    }
    return FALSE;
}

/* 枚举全系统钩子 (预留; 当前无公开 API 可用) */
static
VOID
IoaDllInj_EnumerateHooks(
    VOID
    )
{
    /* 需 ETW Microsoft-Windows-Win32k 或驱动 NtUserSetWindowsHookEx 拦截。
     * 当前返回空集, 与 ShadowStrike EnumerateHooks 一致。 */
}

/* 钩子信息 (对齐 ShadowStrike HookInfo) */
typedef struct _IOA_HOOK_INFO {
    IOA_HOOK_TYPE  Type;
    int            HookTypeValue;
    ULONG_PTR      HookProc;
    ULONG          ThreadId;       /* 0 = 全局钩子 */
    ULONG          InstallerPid;
    WCHAR          InstallerName[64];
    WCHAR          ModulePath[260];
    BOOLEAN        IsGlobal;
    BOOLEAN        IsSuspicious;
} IOA_HOOK_INFO, *PIOA_HOOK_INFO;

/* Hook 安装事件处理 (对齐 ShadowStrike OnHookInstall):
 * 组装 HookInfo, 应用全局钩子怀疑启发式。
 * 数据源: 需驱动拦截 NtUserSetWindowsHookEx 上送事件。 */
static
VOID
IoaDllInj_OnHookInstall(
    _In_ int HookTypeValue,
    _In_ ULONG ThreadId,
    _In_ ULONG_PTR HookProc,
    _In_ ULONG InstallerPid,
    _In_opt_ PCWSTR InstallerName,
    _In_opt_ PCWSTR ModulePath
    )
{
    IOA_HOOK_INFO info;

    RtlZeroMemory(&info, sizeof(info));
    info.Type = IoaDllInj_ConvertHookType(HookTypeValue);
    info.HookTypeValue = HookTypeValue;
    info.HookProc = HookProc;
    info.ThreadId = ThreadId;
    info.InstallerPid = InstallerPid;
    info.IsGlobal = (ThreadId == 0);
    if (InstallerName) {
        wcsncpy_s(info.InstallerName, ARRAYSIZE(info.InstallerName),
                  InstallerName, _TRUNCATE);
    }
    if (ModulePath) {
        wcsncpy_s(info.ModulePath, ARRAYSIZE(info.ModulePath), ModulePath, _TRUNCATE);
    }
    info.IsSuspicious = IoaDllInj_IsSuspiciousHook(HookTypeValue, ThreadId);

    if (info.IsSuspicious) {
        /* 告警/提升: 预留, 由注入分类/策略层消费 */
    }
}

/* Hook 注入判定 (对齐 ShadowStrike DetectHookInjectionImpl):
 * 对进程安装的可疑钩子组装 SetWindowsHookEx 注入事件 (T1055)。 */
static
VOID
IoaDllInj_DetectHookInjection(
    _In_ ULONG TargetProcessId,
    _In_ const IOA_HOOK_INFO* Hooks,
    _In_ ULONG HookCount
    )
{
    ULONG i;

    if (!Hooks) {
        return;
    }
    for (i = 0; i < HookCount; i++) {
        if (Hooks[i].IsSuspicious && Hooks[i].InstallerPid != TargetProcessId) {
            /* 跨进程可疑钩子 → SetWindowsHookEx 注入事件 (T1055):
             * 预留, 组装注入事件由策略层决定告警/阻断。 */
        }
    }
}

/* DLL 加载阻断判定 (对齐 ShadowStrike ShouldBlock):
 * 按监控模式 + 置信度 + 恶意 + 未签名配置决定是否阻断加载。
 * 数据源: 需 ImageLoad 同步路径 (驱动在加载前同步查询 Agent),
 *   当前 ImageLoad 异步上送, 无阻断通道。 */

typedef enum _IOA_DLL_MONITOR_MODE {
    IoaDllMode_Disabled = 0,
    IoaDllMode_PassiveOnly = 1,
    IoaDllMode_ActiveBlock = 2,
    IoaDllMode_Aggressive = 3,
} IOA_DLL_MONITOR_MODE, *PIOA_DLL_MONITOR_MODE;

static
BOOLEAN
IoaDllInj_ShouldBlock(
    _In_ IOA_DLL_MONITOR_MODE Mode,
    _In_ ULONG TrustLevel,      /* WKD_DLL_TRUST_LEVEL */
    _In_ ULONG Confidence,      /* 0-100 */
    _In_ BOOLEAN IsSigned,
    _In_ BOOLEAN BlockUnsigned
    )
{
    if (Mode == IoaDllMode_Aggressive) {
        return (TrustLevel != WkdDllTrust_System &&
                TrustLevel != WkdDllTrust_Whitelisted);
    }
    if (Mode == IoaDllMode_ActiveBlock && Confidence >= 60) {
        return TRUE;
    }
    if (TrustLevel == WkdDllTrust_Malicious) {
        return TRUE;
    }
    if (BlockUnsigned && !IsSigned) {
        return TRUE;
    }
    return FALSE;
}

#endif /* 死代码: APC/Hook 注入检测 + 模块阻断判定 */

/**************************************************/
/*      原子炸弹主动查询 (活编译, 无调用者)           */
/*  移植自 ShadowStrike CheckAtomBombing           */
/**************************************************/

BOOLEAN
IoaCheckAtomBombing(
    _In_ ULONG_PTR ApcRoutine
    )
/*++
Routine Description:
    主动查询: 判断一次 APC 队列是否构成 AtomBombing (T1055.009)。
    对齐 ShadowStrike ProcessInjectionDetector::CheckAtomBombing
      (cpp L3110-3153) 的原子判定路径:
      1. ApcRoutine 命中原子检索 API (GlobalGetAtomNameA/W 等)
      2. 全局原子表存在可疑原子 (Suspicion >= MediumRisk)

    ※ 活编译无调用者: 供 UI/主动查询/紧急分析 (T3HandleBlockingQuery) 接线,
      复用分类器内部同一判定逻辑, 不引入第二套实现。

Arguments:
    ApcRoutine - APC 例程地址 (来自 NtQueueApcThread 载荷)。

Return Value:
    TRUE = 构成 AtomBombing; FALSE = 非原子炸弹。
--*/
{
    IOA_ATOM_RESULT best;

    if (ApcRoutine == 0) return FALSE;
    if (!IoaAtomTargetsRetrieval(ApcRoutine)) return FALSE;
    return IoaAtomCache_ScanGlobalTable(&best);
}

/**************************************************/
/*      原子炸弹搁置能力 (对齐 ShadowStrike)          */
/*                                                  */
/*  数据源依赖未就绪, 以 #if 0 形式全量迁移保留。      */
/**************************************************/

#if 0

/* ⑥ IoaAtomModuleOfRoutine 依赖 psapi (EnumProcessModules/GetModuleFileNameExW);
 *   激活本区时 include 与链接随之生效, 不激活则完全无副作用。 */
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

/* ============================================================================
 * ③ 原子炸弹周期全表扫描 (对齐 ShadowStrike MonitoringThread, cpp L1301-1329)
 *
 * 数据源依赖: Agent 周期任务框架 (Orchestrator 维护线程或新建专用线程)。
 *   检测主路径不依赖本函数 — 事件驱动按需枚举 (IoaAtomCache_ScanGlobalTable)
 *   已在活代码路径覆盖。本函数为周期兜底: 即使无 QueueApc 事件也定期发现
 *   可疑原子, 激活后补充与近期 QueueApc 事件的关联输出。
 * ========================================================================== */
static
VOID
IoaAtom_ScanPeriodic(
    VOID
    )
{
    IOA_ATOM_RESULT best;

    IoaAtomCache_ScanGlobalTable(&best);
    /* 周期性存在可疑原子: 记录/告警出口 (预留) */
}

/* ============================================================================
 * ④ NtQueueApcThread 驱动参数捕获
 *
 * 激活依赖: SyscallHijack.c ShpEtwCallback 过滤 switch 补
 *   case WkdSyscall_NtQueueApcThread (枚举已定义 0x45),
 *   ShpExtractSyscallParameters 补 NtQueueApcThread 参数解析。
 * ParameterBase 布局约定 (Agent 侧 NtfpParseQueueApc 已实现):
 *   [0]=ThreadHandle, [1]=ApcRoutine, [2..4]=ApcArgument1/2/3
 * ========================================================================== */

/* ============================================================================
 * ⑤ NtAddAtom / NtQueryInformationAtom 驱动 case (可选)
 *
 * 原子写入事件上送: 成本高 (原子创建高频) 且 Agent 轮询 (GlobalGetAtomNameW)
 *   已覆盖原子内容获取, 收益不确定。激活后可改为事件驱动维护原子表,
 *   消除全表枚举开销。当前搁置, 用 Agent 轮询替代。
 * ========================================================================== */

/* ============================================================================
 * ⑥ APC 例程模块名解析 (对齐 SS GetModuleNameFromAddress, cpp L217-241)
 *
 * 降级判定: 当 ApcRoutine 非精确 API 地址时, 用所在模块名 (kernel32/
 *   kernelbase/ntdll) 作弱信号。SS 在 AnalyzeAPCImpl (ntdll.dll +10 分)
 *   与 CheckAtomBombing (模块名含 kernel32/kernelbase, cpp L3140-3150) 使用。
 *   WkD 主路径用 IoaAtomTargetsRetrieval 地址比对 (更精确), 本函数为
 *   死代码降级路径, 激活需链接 psapi.lib。
 * ========================================================================== */
static
VOID
IoaAtomModuleOfRoutine(
    _In_ ULONG TargetProcessId,
    _In_ ULONG_PTR ApcRoutine,
    _Out_writes_(NameLen) WCHAR* ModuleName,
    _In_ ULONG NameLen,
    _Out_opt_ PBOOLEAN IsBacked
    )
{
    const ULONG kMaxModules = 512;
    HMODULE* hMods;
    DWORD cbNeeded = 0;
    DWORD moduleCount;
    DWORD limit;
    DWORD i;
    HANDLE hProcess;

    if (!ModuleName || NameLen == 0) return;
    ModuleName[0] = L'\0';
    if (IsBacked) *IsBacked = FALSE;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, TargetProcessId);
    if (!hProcess) return;

    hMods = (HMODULE*)HeapAlloc(GetProcessHeap(), 0,
                                kMaxModules * sizeof(HMODULE));
    if (!hMods) { CloseHandle(hProcess); return; }

    if (EnumProcessModules(hProcess, hMods,
                           kMaxModules * sizeof(HMODULE), &cbNeeded)) {
        moduleCount = cbNeeded / sizeof(HMODULE);
        limit = min(moduleCount, kMaxModules);
        for (i = 0; i < limit; i++) {
            MODULEINFO modInfo = { 0 };
            if (GetModuleInformation(hProcess, hMods[i],
                                     &modInfo, sizeof(modInfo))) {
                ULONG_PTR base = (ULONG_PTR)modInfo.lpBaseOfDll;
                if (ApcRoutine >= base &&
                    ApcRoutine < base + modInfo.SizeOfImage) {
                    WCHAR modPath[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i],
                                             modPath, MAX_PATH)) {
                        PCWSTR name = wcsrchr(modPath, L'\\');
                        wcsncpy_s(ModuleName, NameLen,
                                  name ? name + 1 : modPath, _TRUNCATE);
                    } else {
                        wcsncpy_s(ModuleName, NameLen, L"Unknown", _TRUNCATE);
                    }
                    if (IsBacked) *IsBacked = TRUE;
                    break;
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, hMods);
    CloseHandle(hProcess);
}

/* ============================================================================
 * ⑦ 可疑原子 payload 提取 + SHA256 (对齐 SS BuildAttackFromCorrelation,
 *    cpp L1231-1247)
 *
 * 将可疑原子内容作为 payload 提取并计算 SHA256, 反哺 IOC (哈希查询/
 *   威胁情报关联)。WkD 复用 IocScanner_ComputeBufferSha256。
 *   激活后可在 AtomBombing 确认时调用, 输出哈希交 IocScanner_QueryHash。
 * ========================================================================== */
static
BOOLEAN
IoaAtomExtractPayloadHash(
    _In_ PCWSTR Name,
    _In_ ULONG ContentChars,
    _Out_ PDEF_SHA256_HASH Hash
    )
{
    if (!Name || !Hash || ContentChars == 0) return FALSE;
    return IocScanner_ComputeBufferSha256(
        (const BYTE*)Name, ContentChars * sizeof(WCHAR), Hash);
}

/* ============================================================================
 * ⑧ 单原子查询工具 (对齐 SS GetAtomName / ContainsShellcode / GetAtomEntropy,
 *    cpp L1684-1700 / L2099-2112)
 *
 * 供 UI/主动查询: 对指定原子值做一次完整分析 (内容/熵/壳码/分级)。
 * ========================================================================== */
static
BOOLEAN
IoaAtomQueryAtom(
    _In_ ULONG AtomValue,
    _Out_ PIOA_ATOM_RESULT Out
    )
{
    WCHAR name[IOA_ATOM_NAME_MAX];
    UINT len;

    if (!Out) return FALSE;
    len = GlobalGetAtomNameW((ATOM)AtomValue, name, IOA_ATOM_NAME_MAX);
    if (len == 0) return FALSE;

    IoaAtomAnalyzeContent(name, len, Out);
    Out->AtomValue = AtomValue;
    return TRUE;
}

/* ============================================================================
 * ⑨ 原子创建/删除事件入口 (对齐 SS OnAtomCreateImpl / OnAtomDeleteImpl,
 *    cpp L1335-1377 / L1379-1387)
 *
 * 激活依赖: 驱动补 NtAddAtom/NtDeleteAtom syscall case 上送事件。
 *   WkD 当前以 Agent 轮询 (GlobalGetAtomNameW 全表枚举) 覆盖原子内容获取,
 *   事件入口激活后可改为事件驱动增量维护原子缓存, 消除全表枚举开销。
 *   事件解析需在 EventParser 注册 (对齐 NtfpParseQueueApc)。
 * ========================================================================== */
static
VOID
IoaAtomOnCreate(
    _In_ ULONG AtomValue,
    _In_ ULONG CreatorPid,
    _In_ PCWSTR AtomName
    )
{
    IOA_ATOM_RESULT res;

    UNREFERENCED_PARAMETER(CreatorPid);
    if (!AtomName) return;

    IoaAtomAnalyzeContent(AtomName, (ULONG)wcslen(AtomName), &res);
    res.AtomValue = AtomValue;
    IoaAtomCacheEnsureInit();
    AcquireSRWLockExclusive(&g_IoaAtomCache.Lock);
    IoaAtomCacheUpsertLocked(&res);
    ReleaseSRWLockExclusive(&g_IoaAtomCache.Lock);
}

static
VOID
IoaAtomOnDelete(
    _In_ ULONG AtomValue
    )
{
    PLIST_ENTRY e;
    ULONG bucket;

    IoaAtomCacheEnsureInit();
    bucket = AtomValue % IOA_ATOM_CACHE_BUCKETS;
    AcquireSRWLockExclusive(&g_IoaAtomCache.Lock);
    for (e = g_IoaAtomCache.Buckets[bucket].Flink;
         e != &g_IoaAtomCache.Buckets[bucket];
         e = e->Flink) {
        PIOA_ATOM_CACHE_ENTRY cur =
            CONTAINING_RECORD(e, IOA_ATOM_CACHE_ENTRY, ListEntry);
        if (cur->Result.AtomValue == AtomValue) {
            RemoveEntryList(e);
            g_IoaAtomCache.Count--;
            HeapFree(GetProcessHeap(), 0, cur);
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_IoaAtomCache.Lock);
}

#endif /* 死代码: 原子炸弹周期扫描 + 驱动参数捕获 */

/* ============================================================================
 * ⑩ Section 共享映射聚合表（SectionTracker 迁移 2026-08，死代码）
 *
 * SS SectionTracker.c 对象级追踪表功能面落 agent（用户确认决策：agent 侧
 * 死代码表 + 融合本分类器）。以 SectionObject（内核对象指针）为键聚合
 * 「创建 → 跨进程映射」生命周期，CrossProcessMapCount / RemoteMap 三方判定
 * + 查询 API（对齐 SecGetCrossProcessMaps / SecIsCrossProcessMapped /
 * SecGetSectionInfo / SecGetSectionById）。
 *
 * 数据源（驱动 SmInitialize 启用后上送）:
 *   - WkdEvent_SectionCreate (0x6007)  → IoaSectionTrackCreate
 *   - WkdEvent_MapViewOfSection(0x6005) → IoaSectionTrackMap (仅 syscall 轨
 *     Origin=1，文件轨同进程 DLL 加载不聚合——无跨进程语义)
 *   - WkdEvent_UnmapViewOfSection      → IoaSectionTrackUnmap
 * 接线点: IoaObserve 阶段4.12（g_IoaSectionSharingEnabled 门控，当前死代码）。
 *
 * 生命周期: 容量 8192（SEC_MAX_TRACKED_SECTIONS）/ 每 Section 256 映射
 *   （SEC_MAX_MAPS_PER_SECTION）/ 5min 无活跃映射过期清理
 *   （SEC_STALE_THRESHOLD_100NS）。
 * ========================================================================== */

typedef struct _IOA_SECTION_TABLE {
    CRITICAL_SECTION    Lock;
    LIST_ENTRY          Buckets[IOA_SECTION_HASH_BUCKETS];
    LONG                Count;
    BOOLEAN             Initialized;
    LONG                NextSectionId;      /* 自增 SectionId（对齐 SS NextSectionId） */
    LARGE_INTEGER       StartTime;
    /* 统计（对齐 SS SEC_TRACKER.Stats） */
    ULONG64             TotalCreated;
    ULONG64             TotalMapped;
    ULONG64             TotalUnmapped;
    ULONG64             SuspiciousDetections;
    ULONG64             CrossProcessMaps;
    ULONG64             TransactedDetections;
} IOA_SECTION_TABLE;

static IOA_SECTION_TABLE g_IoaSectionTable;

/* 惰性初始化（对齐 IoaAtomCacheEnsureInit 模式） */
static
VOID
IoaSectionEnsureInit(
    VOID
    )
{
    ULONG i;

    if (g_IoaSectionTable.Initialized) return;
    InitializeCriticalSection(&g_IoaSectionTable.Lock);
    for (i = 0; i < IOA_SECTION_HASH_BUCKETS; i++) {
        InitializeListHead(&g_IoaSectionTable.Buckets[i]);
    }
    g_IoaSectionTable.Count = 0;
    g_IoaSectionTable.NextSectionId = 1;
    GetSystemTimeAsFileTime((PFILETIME)&g_IoaSectionTable.StartTime);
    g_IoaSectionTable.Initialized = TRUE;
}

/* 64 位斐波那契哈希（对齐 SS SecpHashSectionObject c:1931） */
static
ULONG
IoaSectionHashObject(
    _In_ ULONG64 SectionObject
    )
{
    ULONG64 hash64;

    hash64 = (ULONG64)SectionObject * 0x9E3779B97F4A7C15ULL;
    hash64 ^= hash64 >> 32;
    hash64 *= 0xBF58476D1CE4E5B9ULL;
    hash64 ^= hash64 >> 32;

    return (ULONG)(hash64 % IOA_SECTION_HASH_BUCKETS);
}

/* 查找（锁内调用） */
static
PIOA_SECTION_ENTRY
IoaSectionFindLocked(
    _In_ ULONG64 SectionObject
    )
{
    ULONG bucket;
    PLIST_ENTRY e;

    bucket = IoaSectionHashObject(SectionObject);
    for (e = g_IoaSectionTable.Buckets[bucket].Flink;
         e != &g_IoaSectionTable.Buckets[bucket];
         e = e->Flink) {
        PIOA_SECTION_ENTRY cur = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
        if (cur->SectionObject == SectionObject) {
            return cur;
        }
    }
    return NULL;
}

/* 释放条目（锁外调用，条目已摘链） */
static
VOID
IoaSectionFreeEntry(
    _In_ PIOA_SECTION_ENTRY Entry
    )
{
    PLIST_ENTRY e;

    while (!IsListEmpty(&Entry->MapList)) {
        PIOA_SECTION_MAP_RECORD rec;
        e = RemoveHeadList(&Entry->MapList);
        rec = CONTAINING_RECORD(e, IOA_SECTION_MAP_RECORD, ListEntry);
        HeapFree(GetProcessHeap(), 0, rec);
    }
    HeapFree(GetProcessHeap(), 0, Entry);
}

/* 填 Section 快照（锁内调用，调用者保证 Entry 有效） */
static
VOID
IoaSectionFillInfo(
    _In_ PIOA_SECTION_ENTRY Entry,
    _Out_ PIOA_SECTION_INFO Info
    )
{
    RtlZeroMemory(Info, sizeof(IOA_SECTION_INFO));
    Info->SectionObject = Entry->SectionObject;
    Info->SectionId = Entry->SectionId;
    Info->CreatorProcessId = Entry->CreatorProcessId;
    Info->MaximumSize = Entry->MaximumSize;
    Info->SectionType = Entry->SectionType;
    Info->IsAnonymous = Entry->IsAnonymous;
    Info->SuspicionFlags = Entry->SuspicionFlags;
    Info->SuspicionScore = Entry->SuspicionScore;
    Info->MapCount = Entry->TotalMapCount;
    Info->CrossProcessMapCount = Entry->CrossProcessMapCount;
    Info->CreateTime = Entry->CreateTime;
    Info->LastMapTime = Entry->LastMapTime;
}

/*
 * IoaSectionTrackCreate — 记录 Section 创建（对齐 SS SecTrackSectionCreate c:566）。
 * SectionObject==0（创建失败）时忽略；已存在条目返回 STATUS_OBJECT_NAME_EXISTS
 * （对齐 CRITICAL-2 原子 check-and-insert）。
 */
NTSTATUS
IoaSectionTrackCreate(
    _In_ PEVENT_PAYLOAD_SECTION_CREATE Payload
    )
{
    PIOA_SECTION_ENTRY entry;
    ULONG bucket;

    if (Payload == NULL || Payload->SectionObject == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);

    if (IoaSectionFindLocked(Payload->SectionObject) != NULL) {
        LeaveCriticalSection(&g_IoaSectionTable.Lock);
        return STATUS_OBJECT_NAME_EXISTS;
    }

    if (g_IoaSectionTable.Count >= IOA_SECTION_MAX_TRACKED) {
        LeaveCriticalSection(&g_IoaSectionTable.Lock);
        return STATUS_QUOTA_EXCEEDED;
    }

    entry = (PIOA_SECTION_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          sizeof(IOA_SECTION_ENTRY));
    if (entry == NULL) {
        LeaveCriticalSection(&g_IoaSectionTable.Lock);
        return STATUS_NO_MEMORY;
    }

    entry->SectionObject = Payload->SectionObject;
    entry->SectionId = g_IoaSectionTable.NextSectionId++;  /* 自增 ID（对齐 SS） */
    entry->CreatorProcessId = Payload->SourceProcessId;
    entry->MaximumSize = Payload->MaximumSize;
    entry->SectionType = Payload->SectionType;
    entry->IsAnonymous = Payload->IsAnonymous;
    entry->SuspicionFlags = Payload->SuspicionFlags;
    entry->SuspicionScore = Payload->SuspicionScore;
    entry->CreateTime = Payload->Timestamp;
    InitializeListHead(&entry->MapList);

    bucket = IoaSectionHashObject(entry->SectionObject);
    InsertTailList(&g_IoaSectionTable.Buckets[bucket], &entry->HashEntry);
    g_IoaSectionTable.Count++;
    g_IoaSectionTable.TotalCreated++;

    if (entry->SuspicionFlags != 0) {
        g_IoaSectionTable.SuspiciousDetections++;
    }
    if (entry->SuspicionFlags & WKD_SEC_SUSPICION_TRANSACTED) {
        g_IoaSectionTable.TransactedDetections++;
    }

    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return STATUS_SUCCESS;
}

/*
 * IoaSectionTrackMap — 记录一次映射（对齐 SS SecTrackSectionMap c:790）。
 * 跨进程（Source≠Target）→ CrossProcessMapCount++；映射进程≠Creator 的
 * RemoteMap 由 IoaSectionIsRemoteMapped 即时判定（不在此置位）。
 */
NTSTATUS
IoaSectionTrackMap(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG64 SectionObject,
    _In_ ULONG64 BaseAddress,
    _In_ ULONG64 RegionSize,
    _In_ ULONG Protection
    )
{
    PIOA_SECTION_ENTRY entry;
    PIOA_SECTION_MAP_RECORD rec;

    /* SourceProcessId 保留签名语义（跨进程判定以 Target vs Creator 为准，
     * 对齐 SS；调用方仍传 Source 供未来诊断/事件关联使用） */
    UNREFERENCED_PARAMETER(SourceProcessId);

    if (SectionObject == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);

    entry = IoaSectionFindLocked(SectionObject);
    if (entry == NULL) {
        LeaveCriticalSection(&g_IoaSectionTable.Lock);
        return STATUS_NOT_FOUND;
    }

    /* 映射记录容量（对齐 SEC_MAX_MAPS_PER_SECTION=256） */
    if (entry->ActiveMapCount >= IOA_SECTION_MAX_MAPS_PER_SEC) {
        LeaveCriticalSection(&g_IoaSectionTable.Lock);
        return STATUS_QUOTA_EXCEEDED;
    }

    rec = (PIOA_SECTION_MAP_RECORD)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             sizeof(IOA_SECTION_MAP_RECORD));
    if (rec == NULL) {
        LeaveCriticalSection(&g_IoaSectionTable.Lock);
        return STATUS_NO_MEMORY;
    }

    rec->ProcessId = TargetProcessId;           /* 被映射进程 */
    rec->ViewBase = BaseAddress;
    rec->ViewSize = RegionSize;
    rec->Protection = Protection;
    GetSystemTimeAsFileTime((PFILETIME)&rec->MapTime);

    InsertTailList(&entry->MapList, &rec->ListEntry);
    entry->ActiveMapCount++;
    entry->TotalMapCount++;             /* 历史累计（对齐 SS MapCount） */
    g_IoaSectionTable.TotalMapped++;

    /* 跨进程判定（对齐 SS SecTrackSectionMap c:858：mapEntry->ProcessId !=
     * CreatorProcessId，即被映射进程 ≠ Section 创建者） */
    if (TargetProcessId != entry->CreatorProcessId) {
        entry->CrossProcessMapCount++;
        g_IoaSectionTable.CrossProcessMaps++;
    }
    entry->LastMapTime = rec->MapTime;

    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return STATUS_SUCCESS;
}

/*
 * IoaSectionTrackUnmap — 记录解除映射（对齐 SS SecTrackSectionUnmap c:901）。
 * 按 (ProcessId, ViewBase) 匹配活跃记录并移除（活跃映射数递减）。
 */
NTSTATUS
IoaSectionTrackUnmap(
    _In_ HANDLE ProcessId,
    _In_ ULONG64 ViewBase
    )
{
    PLIST_ENTRY e;
    ULONG i;
    BOOLEAN found = FALSE;

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);

    for (i = 0; i < IOA_SECTION_HASH_BUCKETS && !found; i++) {
        for (e = g_IoaSectionTable.Buckets[i].Flink;
             e != &g_IoaSectionTable.Buckets[i];
             e = e->Flink) {
            PIOA_SECTION_ENTRY entry = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
            PLIST_ENTRY me;

            for (me = entry->MapList.Flink;
                 me != &entry->MapList;
                 me = me->Flink) {
                PIOA_SECTION_MAP_RECORD rec =
                    CONTAINING_RECORD(me, IOA_SECTION_MAP_RECORD, ListEntry);
                if (rec->ProcessId == ProcessId && rec->ViewBase == ViewBase) {
                    RemoveEntryList(me);
                    HeapFree(GetProcessHeap(), 0, rec);
                    entry->ActiveMapCount--;
                    g_IoaSectionTable.TotalUnmapped++;
                    found = TRUE;
                    break;
                }
            }
        }
    }

    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * IoaGetCrossProcessSections — 查询某 Section 的跨进程映射（对齐 SS
 * SecGetCrossProcessMaps c:1358）。返回映射快照数组（排除 Creator 自身）。
 */
NTSTATUS
IoaGetCrossProcessSections(
    _In_ ULONG64 SectionObject,
    _Out_writes_to_(MaxMaps, *MapCount) PIOA_SECTION_MAP_INFO Maps,
    _In_ ULONG MaxMaps,
    _Out_ PULONG MapCount
    )
{
    PIOA_SECTION_ENTRY entry;
    PLIST_ENTRY e;
    ULONG count = 0;

    if (Maps == NULL || MapCount == NULL || MaxMaps == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *MapCount = 0;
    RtlZeroMemory(Maps, MaxMaps * sizeof(IOA_SECTION_MAP_INFO));

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);

    entry = IoaSectionFindLocked(SectionObject);
    if (entry != NULL) {
        for (e = entry->MapList.Flink;
             e != &entry->MapList && count < MaxMaps;
             e = e->Flink) {
            PIOA_SECTION_MAP_RECORD rec =
                CONTAINING_RECORD(e, IOA_SECTION_MAP_RECORD, ListEntry);
            if (rec->ProcessId != entry->CreatorProcessId) {
                Maps[count].ProcessId = rec->ProcessId;
                Maps[count].ViewBase = rec->ViewBase;
                Maps[count].ViewSize = rec->ViewSize;
                Maps[count].Protection = rec->Protection;
                Maps[count].MapTime = rec->MapTime;
                count++;
            }
        }
    }

    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    *MapCount = count;
    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * IoaIsSectionCrossProcessMapped — 某 Section 是否被跨进程映射（对齐 SS
 * SecIsCrossProcessMapped c:1434）。
 */
BOOLEAN
IoaIsSectionCrossProcessMapped(
    _In_ ULONG64 SectionObject,
    _Out_opt_ PULONG ProcessCount
    )
{
    PIOA_SECTION_ENTRY entry;
    BOOLEAN result = FALSE;

    if (ProcessCount != NULL) *ProcessCount = 0;

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    entry = IoaSectionFindLocked(SectionObject);
    if (entry != NULL && entry->CrossProcessMapCount > 0) {
        result = TRUE;
        if (ProcessCount != NULL) *ProcessCount = (ULONG)entry->CrossProcessMapCount;
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return result;
}

/*
 * IoaSectionIsRemoteMapped — RemoteMap 三方判定（对齐 SS SecSuspicion_RemoteMap
 * 120 分语义：映射进程 ≠ Creator 且 ≠ 当前进程）。在共享 Section 的跨进程映射
 * 中查找"第三方"（既非创建者也非当前检查者）进程。
 */
BOOLEAN
IoaSectionIsRemoteMapped(
    _In_ ULONG64 SectionObject,
    _In_ HANDLE CurrentProcessId,
    _Out_opt_ PHANDLE RemoteProcessId
    )
{
    PIOA_SECTION_ENTRY entry;
    PLIST_ENTRY e;
    BOOLEAN result = FALSE;

    if (RemoteProcessId != NULL) *RemoteProcessId = NULL;

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    entry = IoaSectionFindLocked(SectionObject);
    if (entry != NULL) {
        for (e = entry->MapList.Flink;
             e != &entry->MapList;
             e = e->Flink) {
            PIOA_SECTION_MAP_RECORD rec =
                CONTAINING_RECORD(e, IOA_SECTION_MAP_RECORD, ListEntry);
            if (rec->ProcessId != entry->CreatorProcessId &&
                rec->ProcessId != CurrentProcessId) {
                if (RemoteProcessId != NULL) *RemoteProcessId = rec->ProcessId;
                result = TRUE;
                break;
            }
        }
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return result;
}

/*
 * IoaGetSectionInfo — 查询 Section 快照（对齐 SS SecGetSectionInfo c:1040）。
 */
NTSTATUS
IoaGetSectionInfo(
    _In_ ULONG64 SectionObject,
    _Out_ PIOA_SECTION_INFO Info
    )
{
    PIOA_SECTION_ENTRY entry;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(IOA_SECTION_INFO));

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    entry = IoaSectionFindLocked(SectionObject);
    if (entry != NULL) {
        IoaSectionFillInfo(entry, Info);
        status = STATUS_SUCCESS;
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return status;
}

/*
 * IoaSectionCleanupExpired — 清理过期条目（对齐 SS SecpCleanupTimerCallback c:1773）。
 * 移除 ActiveMapCount==0 且超过 5min 的条目。由外部周期调用（死代码，接入后挂
 * agent 维护线程；对齐 SS 60s 周期）。
 */
VOID
IoaSectionCleanupExpired(
    VOID
    )
{
    LARGE_INTEGER now;
    LIST_ENTRY staleList;
    ULONG i;

    IoaSectionEnsureInit();
    GetSystemTimeAsFileTime((PFILETIME)&now);
    InitializeListHead(&staleList);

    EnterCriticalSection(&g_IoaSectionTable.Lock);
    for (i = 0; i < IOA_SECTION_HASH_BUCKETS; i++) {
        PLIST_ENTRY e = g_IoaSectionTable.Buckets[i].Flink;
        while (e != &g_IoaSectionTable.Buckets[i]) {
            PLIST_ENTRY next = e->Flink;
            PIOA_SECTION_ENTRY entry = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
            if (entry->ActiveMapCount == 0 &&
                (now.QuadPart - entry->CreateTime.QuadPart) > IOA_SECTION_STALE_100NS) {
                RemoveEntryList(e);
                InsertTailList(&staleList, e);
                g_IoaSectionTable.Count--;
            }
            e = next;
        }
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);

    while (!IsListEmpty(&staleList)) {
        PLIST_ENTRY e = RemoveHeadList(&staleList);
        PIOA_SECTION_ENTRY entry = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
        IoaSectionFreeEntry(entry);
    }
}

/*
 * IoaGetSectionById — 按 SectionId 查询（对齐 SS SecGetSectionById c:1081）。
 * ※ 死代码: SectionId 为聚合表自增 ID（SectionObject 指针的代理），供 UI/日志引用。
 */
NTSTATUS
IoaGetSectionById(
    _In_ ULONG SectionId,
    _Out_ PIOA_SECTION_INFO Info
    )
{
    PIOA_SECTION_ENTRY entry;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG i;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(IOA_SECTION_INFO));

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    for (i = 0; i < IOA_SECTION_HASH_BUCKETS && status != STATUS_SUCCESS; i++) {
        PLIST_ENTRY e;
        for (e = g_IoaSectionTable.Buckets[i].Flink;
             e != &g_IoaSectionTable.Buckets[i];
             e = e->Flink) {
            entry = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
            if (entry->SectionId == SectionId) {
                IoaSectionFillInfo(entry, Info);
                status = STATUS_SUCCESS;
                break;
            }
        }
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return status;
}

/*
 * IoaFindSectionByFile — 按后备文件名查询（对齐 SS SecFindSectionByFile c:1130）。
 * ※ 死代码: 数据源缺失——IOA_SECTION_ENTRY.FileName 恒空（驱动 Section Create
 *   不上送 FilePath），恒 STATUS_NOT_FOUND。接入前提: 驱动 Section Create body
 *   补 FilePath 上送 + IoaSectionTrackCreate 填充 FileName。
 */
NTSTATUS
IoaFindSectionByFile(
    _In_ PCWSTR FileName,
    _Out_ PIOA_SECTION_INFO Info
    )
{
    PIOA_SECTION_ENTRY entry;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG i;

    if (FileName == NULL || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(IOA_SECTION_INFO));

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    for (i = 0; i < IOA_SECTION_HASH_BUCKETS && status != STATUS_SUCCESS; i++) {
        PLIST_ENTRY e;
        for (e = g_IoaSectionTable.Buckets[i].Flink;
             e != &g_IoaSectionTable.Buckets[i];
             e = e->Flink) {
            entry = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
            if (entry->FileName[0] != L'\0' &&
                _wcsicmp(entry->FileName, FileName) == 0) {
                IoaSectionFillInfo(entry, Info);
                status = STATUS_SUCCESS;
                break;
            }
        }
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return status;
}

/*
 * IoaGetSuspiciousSections — 按 MinScore 过滤返回可疑 Section 列表（对齐 SS
 * SecGetSuspiciousSections c:1301）。遍历全表，SuspicionScore>=MinScore 填快照。
 * ※ 死代码: 供 UI/主动查询。
 */
NTSTATUS
IoaGetSuspiciousSections(
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxEntries, *EntryCount) PIOA_SECTION_INFO Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount
    )
{
    ULONG count = 0;
    ULONG i;

    if (Entries == NULL || EntryCount == NULL || MaxEntries == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *EntryCount = 0;
    RtlZeroMemory(Entries, MaxEntries * sizeof(IOA_SECTION_INFO));

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    for (i = 0; i < IOA_SECTION_HASH_BUCKETS && count < MaxEntries; i++) {
        PLIST_ENTRY e;
        for (e = g_IoaSectionTable.Buckets[i].Flink;
             e != &g_IoaSectionTable.Buckets[i] && count < MaxEntries;
             e = e->Flink) {
            PIOA_SECTION_ENTRY entry = CONTAINING_RECORD(e, IOA_SECTION_ENTRY, HashEntry);
            if (entry->SuspicionScore >= MinScore) {
                IoaSectionFillInfo(entry, &Entries[count]);
                count++;
            }
        }
    }
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    *EntryCount = count;
    return STATUS_SUCCESS;
}

/*
 * IoaSectionGetStatistics — 聚合表统计（对齐 SS SecGetStatistics c:1657）。
 * ※ 死代码: 无调用者。
 */
NTSTATUS
IoaSectionGetStatistics(
    _Out_ PIOA_SECTION_STATISTICS Stats
    )
{
    LARGE_INTEGER now;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Stats, sizeof(IOA_SECTION_STATISTICS));

    IoaSectionEnsureInit();
    EnterCriticalSection(&g_IoaSectionTable.Lock);
    Stats->ActiveSections = (ULONG)g_IoaSectionTable.Count;
    Stats->TotalCreated = g_IoaSectionTable.TotalCreated;
    Stats->TotalMapped = g_IoaSectionTable.TotalMapped;
    Stats->TotalUnmapped = g_IoaSectionTable.TotalUnmapped;
    Stats->SuspiciousDetections = g_IoaSectionTable.SuspiciousDetections;
    Stats->CrossProcessMaps = g_IoaSectionTable.CrossProcessMaps;
    Stats->TransactedDetections = g_IoaSectionTable.TransactedDetections;
    GetSystemTimeAsFileTime((PFILETIME)&now);
    Stats->UpTime.QuadPart = now.QuadPart - g_IoaSectionTable.StartTime.QuadPart;
    LeaveCriticalSection(&g_IoaSectionTable.Lock);
    return STATUS_SUCCESS;
}
