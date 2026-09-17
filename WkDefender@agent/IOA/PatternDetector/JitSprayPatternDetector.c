/**************************************************/
/*  WkDefender IOA — JIT 喷射攻击防护检测器 (实现) */
/*                                                  */
/*  迁移自 ShadowStrike JITSprayDetector.cpp       */
/*  (v3.0.0, 2036 行), 功能重实现非源码复制。       */
/*                                                  */
/*  IRQL: 全部 PASSIVE_LEVEL。                      */
/*  同步: SRWLOCK (配置/监控集合/回调/事件环/缓存), */
/*        统计计数 volatile + Interlocked。         */
/*                                                  */
/*  与 SS 的关键实现差异 (就地标注):                */
/*    - 页引擎识别按进程一次探测复用 (SS 各页独立)  */
/*    - 读取缓冲上限 JSP_MAX_SCAN_SIZE (1MB)/页     */
/*    - 近期检测环形缓冲代替 deque                  */
/*    - 缓存条目定长 + malloc 页数组 (SS vector)    */
/*    - 事件 details 文案同步为中文                 */
/**************************************************/

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#include "../../DefendTypes.h"
#include "JitSprayPatternDetector.h"

/**************************************************/
/*  静态常量表                                    */
/**************************************************/

/* JIT 引擎模块表 (SS JIT_ENGINE_MODULES, 20 项, 子串匹配用,
 * 含带路径形式 server\jvm.dll 保留) */
static const WCHAR JsppJitEngineModules[][JSP_ENGINE_NAME_LEN] = {
    L"v8.dll",        L"chrome.dll",    L"node.dll",      L"mozjs.dll",
    L"xul.dll",       L"chakra.dll",    L"chakracore.dll", L"javascriptcore.dll",
    L"clrjit.dll",    L"ryujit.dll",    L"mscorjit.dll",  L"jvm.dll",
    L"server\\jvm.dll", L"client\\jvm.dll", L"j9vm29.dll", L"luajit.dll",
    L"libluajit.dll", L"wasmtime.dll",  L"flash.ocx",     L"pypy.dll"
};

/* NOP sled 模式 (SS NOP_PATTERNS, 4 种 8 字节) */
static const UINT8 JsppNopPatterns[][8] = {
    { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
    { 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C },
    { 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D },
    { 0x1F, 0x44, 0x00, 0x00, 0x1F, 0x44, 0x00, 0x00 }
};

/* Metasploit 风格 shellcode 头模式 (SS SHELLCODE_PATTERNS, 4 种 4 字节) */
static const UINT8 JsppShellcodePatterns[][4] = {
    { 0xFC, 0xE8, 0x82, 0x00 },   /* cld; call ... */
    { 0xEB, 0x03, 0x59, 0xEB },   /* jmp; pop ecx; jmp */
    { 0x60, 0xE8, 0x00, 0x00 },   /* pushad; call */
    { 0x55, 0x8B, 0xEC, 0x83 }    /* push ebp; mov ebp,esp; add/sub */
};

/* XOR 喷射常量表 (SS XOR_SPRAY_VALUES, 4 项 x86 小端) */
static const UINT32 JsppXorSprayValues[] = {
    0x3C909090, 0x3C0D0D0D, 0x3C0C0C0C, 0x35909090
};

/* 字节码字面量标记: "\x90\x90" 与 "\xcc\xcc" (SS BYTECODE_NOP_MARKER/
 * BYTECODE_INT3_MARKER, 文本形态出现于 JIT 数据页) */
static const UINT8 JsppBytecodeNopMarker[8]  = { 0x5C, 0x78, 0x39, 0x30, 0x5C, 0x78, 0x39, 0x30 };
static const UINT8 JsppBytecodeInt3Marker[8] = { 0x5C, 0x78, 0x63, 0x63, 0x5C, 0x78, 0x63, 0x63 };

/**************************************************/
/*  内部类型                                      */
/**************************************************/

/* 重复模式匹配结果 (SS RepeatedPatternMatch) */
typedef struct _JSPP_REPEATED_MATCH {
    UINT32 offset;
    UINT32 patternSize;
    UINT32 repeatCount;
} JSPP_REPEATED_MATCH;

/* JIT 页缓存条目 (SS m_jitPageCache 单 map 裁剪为定长条目池) */
typedef struct _JSPP_CACHE_ENTRY {
    UINT32             pid;
    UINT32             count;
    UINT32             capacity;
    ULONGLONG          lastTick;       /* GetTickCount64, 满池淘汰最旧 */
    JSP_JIT_PAGE_INFO* pages;          /* malloc, 60s 全清时释放 */
} JSPP_CACHE_ENTRY;

/**************************************************/
/*  全局状态                                      */
/**************************************************/

static JSP_CONFIG               g_config;            /* 受 g_stateLock 保护 */
static SRWLOCK                  g_stateLock;
static volatile JSP_MODULE_STATUS g_status;
static volatile BOOLEAN         g_initialized;

static JSP_DETECTED_CALLBACK    g_detectionCallback; /* 受 g_callbackLock 保护 */
static SRWLOCK                  g_callbackLock;

static UINT32                   g_monitoredProcesses[JSP_MAX_MONITORED_PROCESSES];
static UINT32                   g_monitoredCount;
static SRWLOCK                  g_monitorLock;

static JSP_JIT_SPRAY_EVENT      g_recentDetections[JSP_MAX_RECENT_DETECTIONS];
static UINT32                   g_eventsHead;        /* 最新写入槽 (环形) */
static UINT32                   g_eventsCount;
static UINT64                   g_eventSequence;
static SRWLOCK                  g_eventsLock;

static JSPP_CACHE_ENTRY         g_pageCache[JSP_MAX_CACHED_PROCESSES];
static SRWLOCK                  g_cacheLock;
static ULONGLONG                g_cacheLastClearTick;

/* 统计计数 (SS JITSprayStatistics, volatile + Interlocked) */
static volatile UINT64          g_pagesScanned;
static volatile UINT64          g_constantsAnalyzed;
static volatile UINT64          g_spraysDetected;
static volatile UINT64          g_wxViolationsDetected;
static volatile UINT64          g_shellcodesDetected;
static volatile UINT64          g_attacksBlocked;
static volatile UINT64          g_byEngine[JSP_BY_ENGINE_COUNT];
static volatile UINT64          g_byTechnique[JSP_BY_TECHNIQUE_COUNT];
static volatile ULONGLONG       g_startTick;

/**************************************************/
/*  内部工具: 配置快照/状态                       */
/**************************************************/

static VOID JsppSnapshotConfig(JSP_CONFIG* out) {
    _Acq_srw_lock_shared_(&g_stateLock);
    *out = g_config;
    _Release_srw_lock_shared_(&g_stateLock);
}

static BOOLEAN JsppIsActive(void) {
    return (g_initialized != FALSE && g_status == JspStatus_Running) ? TRUE : FALSE;
}

/**************************************************/
/*  内部工具: 统计分析                            */
/**************************************************/

static VOID JsppStatsInc(volatile UINT64* counter) {
    InterlockedIncrement64((volatile LONGLONG*)counter);
}

static VOID JsppStatsAdd(volatile UINT64* counter, UINT64 delta) {
    InterlockedExchangeAdd64((volatile LONGLONG*)counter, (LONGLONG)delta);
}

static VOID JsppStatsResetAll(void) {
    UINT32 i;
    InterlockedExchange64((volatile LONGLONG*)&g_pagesScanned, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_constantsAnalyzed, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_spraysDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_wxViolationsDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_shellcodesDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_attacksBlocked, 0);
    for (i = 0; i < JSP_BY_ENGINE_COUNT; i++) {
        InterlockedExchange64((volatile LONGLONG*)&g_byEngine[i], 0);
    }
    for (i = 0; i < JSP_BY_TECHNIQUE_COUNT; i++) {
        InterlockedExchange64((volatile LONGLONG*)&g_byTechnique[i], 0);
    }
    g_startTick = GetTickCount64();
}

/**************************************************/
/*  内部工具: 字节分析                            */
/**************************************************/

/* 香农熵 (SS CalculateEntropy) */
static double JsppCalculateEntropy(const UINT8* data, UINT32 size) {
    UINT32 freq[256] = { 0 };
    UINT32 i;
    double entropy = 0.0, p;
    if (data == NULL || size == 0) {
        return 0.0;
    }
    for (i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    for (i = 0; i < 256; i++) {
        if (freq[i] == 0) {
            continue;
        }
        p = (double)freq[i] / (double)size;
        entropy -= p * (log(p) / log(2.0));
    }
    return entropy;
}

/* 重复模式搜索 (SS FindRepeatedPattern):
 * patternSize 从 4 到 min(size/8,16), 逐偏移比较连续重复,
 * 重复次数 ≥ JSP_MIN_CONSTANT_REPEAT 即返回首个命中 */
static BOOLEAN JsppFindRepeatedPattern(const UINT8* data, UINT32 size,
                                       JSPP_REPEATED_MATCH* match) {
    UINT32 maxPatternSize;
    UINT32 patternSize;
    UINT32 offset;
    UINT32 consecutive;
    UINT32 i;

    if (data == NULL || size < JSP_MIN_CONSTANT_REPEAT * sizeof(UINT64)) {
        return FALSE;
    }

    maxPatternSize = size / 8;
    if (maxPatternSize > 16) {
        maxPatternSize = 16;
    }

    for (patternSize = 4; patternSize <= maxPatternSize; patternSize++) {
        if (size < JSP_MIN_CONSTANT_REPEAT * patternSize) {
            break;
        }
        for (offset = 0; offset < size - patternSize; offset++) {
            consecutive = 1;
            for (i = offset + patternSize; i + patternSize <= size; i += patternSize) {
                if (memcmp(data + i, data + offset, patternSize) == 0) {
                    consecutive++;
                    if (consecutive >= JSP_MIN_CONSTANT_REPEAT) {
                        if (match != NULL) {
                            match->offset = offset;
                            match->patternSize = patternSize;
                            match->repeatCount = consecutive;
                        }
                        return TRUE;
                    }
                } else {
                    break;
                }
            }
        }
    }
    return FALSE;
}

/* NOP sled 判定 (SS IsNopSled):
 * 长度 ≥ JSP_NOP_SLED_MIN 且任一种 8 字节模式覆盖 >75% 字节 */
static BOOLEAN JsppIsNopSled(const UINT8* data, UINT32 size) {
    UINT32 patternIdx;
    UINT32 matches;
    UINT32 i;

    if (data == NULL || size < JSP_NOP_SLED_MIN) {
        return FALSE;
    }

    for (patternIdx = 0; patternIdx < (sizeof(JsppNopPatterns) / sizeof(JsppNopPatterns[0])); patternIdx++) {
        matches = 0;
        for (i = 0; i + 8 <= size; i += 8) {
            if (memcmp(data + i, JsppNopPatterns[patternIdx], 8) == 0) {
                matches++;
            }
        }
        if (matches * 8 > size * 3 / 4) {
            return TRUE;
        }
    }
    return FALSE;
}

/* shellcode 头模式判定 (SS ContainsShellcodePattern), 4 字节滑动匹配 */
static BOOLEAN JsppContainsShellcodePattern(const UINT8* data, UINT32 size) {
    UINT32 patternIdx;
    UINT32 i;

    if (data == NULL || size < 4) {
        return FALSE;
    }

    for (patternIdx = 0; patternIdx < (sizeof(JsppShellcodePatterns) / sizeof(JsppShellcodePatterns[0])); patternIdx++) {
        for (i = 0; i + 4 <= size; i++) {
            if (memcmp(data + i, JsppShellcodePatterns[patternIdx], 4) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* XOR 喷射常量判定 */
static BOOLEAN JsppIsXorSprayConstant(UINT32 value) {
    UINT32 i;
    for (i = 0; i < (sizeof(JsppXorSprayValues) / sizeof(JsppXorSprayValues[0])); i++) {
        if (value == JsppXorSprayValues[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 4 字节步进扫描 XOR 喷射常量 (SS ScanJitPages/AnalyzeJitPage) */
static BOOLEAN JsppScanXorSpray(const UINT8* data, UINT32 size, PUINT32 count) {
    UINT32 i;
    UINT32 value;
    UINT32 hits = 0;

    for (i = 0; i + 4 <= size; i += 4) {
        memcpy(&value, data + i, 4);
        if (JsppIsXorSprayConstant(value)) {
            hits++;
        }
    }
    if (count != NULL) {
        *count = hits;
    }
    return (hits > 0) ? TRUE : FALSE;
}

/* 字节码文本标记判定 ("\x90\x90"/"\xcc\xcc", SS BYTECODE_* 扫描) */
static BOOLEAN JsppContainsBytecodeMarker(const UINT8* data, UINT32 size) {
    UINT32 i;
    if (data == NULL || size < 8) {
        return FALSE;
    }
    for (i = 0; i + 8 <= size; i++) {
        if (memcmp(data + i, JsppBytecodeNopMarker, 8) == 0 ||
            memcmp(data + i, JsppBytecodeInt3Marker, 8) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*  内部工具: 保护位判定                          */
/**************************************************/

static BOOLEAN JsppIsExecutableProtection(UINT32 protect) {
    UINT32 type = protect & 0xFF;
    return (type == PAGE_EXECUTE || type == PAGE_EXECUTE_READ ||
            type == PAGE_EXECUTE_READWRITE || type == PAGE_EXECUTE_WRITECOPY)
           ? TRUE : FALSE;
}

static BOOLEAN JsppIsWritableProtection(UINT32 protect) {
    UINT32 type = protect & 0xFF;
    return (type == PAGE_READWRITE || type == PAGE_EXECUTE_READWRITE ||
            type == PAGE_WRITECOPY || type == PAGE_EXECUTE_WRITECOPY)
           ? TRUE : FALSE;
}

static JSP_WX_VIOLATION_TYPE JsppClassifyWxViolation(UINT32 protect) {
    BOOLEAN exec = JsppIsExecutableProtection(protect);
    BOOLEAN write = JsppIsWritableProtection(protect);
    if (exec && write) {
        return JspWx_SimultaneousRWX;
    }
    /* WriteToExecutable/ExecuteWritable 需要写监控数据, 运行时仅探测 RWX */
    return JspWx_None;
}

/**************************************************/
/*  内部工具: 进程基础信息                        */
/**************************************************/

static BOOLEAN JsppGetProcessName(HANDLE process, WCHAR* buffer, UINT32 bufferLen) {
    if (process == NULL || buffer == NULL || bufferLen == 0) {
        return FALSE;
    }
    buffer[0] = L'\0';
    if (GetModuleBaseNameW(process, NULL, buffer, bufferLen) == 0) {
        return FALSE;
    }
    buffer[bufferLen - 1] = L'\0';
    return TRUE;
}

/* 模块名小写化 (写入调用方缓冲, 上限 JSP_ENGINE_NAME_LEN-1) */
static VOID JsppLowerModuleName(const WCHAR* src, WCHAR* dest, UINT32 destLen) {
    UINT32 i = 0;
    if (src == NULL) {
        dest[0] = L'\0';
        return;
    }
    while (i + 1 < destLen && src[i] != L'\0') {
        dest[i] = (WCHAR)towlower((wint_t)src[i]);
        i++;
    }
    dest[i] = L'\0';
}

/**************************************************/
/*  内部工具: JIT 引擎识别                        */
/**************************************************/

/* 模块名(已小写) → 引擎映射 (SS DetectJitEngineFromModule 规则表) */
static JSP_JIT_ENGINE JsppDetectJitEngineLower(const WCHAR* lowerName) {
    if (lowerName == NULL) {
        return JspEngine_Unknown;
    }
    if (wcsstr(lowerName, L"v8.dll") != NULL ||
        wcsstr(lowerName, L"chrome.dll") != NULL ||
        wcsstr(lowerName, L"node.dll") != NULL) {
        return JspEngine_V8;
    }
    if (wcsstr(lowerName, L"mozjs") != NULL ||
        wcsstr(lowerName, L"xul.dll") != NULL) {
        return JspEngine_SpiderMonkey;
    }
    if (wcsstr(lowerName, L"chakra") != NULL) {
        return JspEngine_Chakra;
    }
    if (wcsstr(lowerName, L"javascriptcore") != NULL) {
        return JspEngine_JavaScriptCore;
    }
    if (wcsstr(lowerName, L"clrjit") != NULL ||
        wcsstr(lowerName, L"ryujit") != NULL ||
        wcsstr(lowerName, L"mscorjit") != NULL) {
        return JspEngine_DotNetJIT;
    }
    if (wcsstr(lowerName, L"jvm.dll") != NULL) {
        return JspEngine_JavaHotSpot;
    }
    if (wcsstr(lowerName, L"j9vm") != NULL) {
        return JspEngine_OpenJ9;
    }
    if (wcsstr(lowerName, L"luajit") != NULL) {
        return JspEngine_LuaJIT;
    }
    if (wcsstr(lowerName, L"wasm") != NULL) {
        return JspEngine_WASM;
    }
    if (wcsstr(lowerName, L"flash") != NULL) {
        return JspEngine_ActionScript;
    }
    if (wcsstr(lowerName, L"pypy") != NULL) {
        return JspEngine_PyPy;
    }
    return JspEngine_Unknown;
}

/* 枚举进程加载模块并识别 JIT 引擎:
 * firstOnly=TRUE  返回首个命中引擎;
 * firstOnly=FALSE 收集全部去重引擎 (SS GetAllJitEngines);
 * 失败返回 FALSE (进程不可打开/无模块) */
static BOOLEAN JsppEnumerateEngines(UINT32 processId,
                                    JSP_JIT_ENGINE* engines, UINT32 maxCount,
                                    PUINT32 outCount, BOOLEAN firstOnly) {
    HANDLE process = NULL;
    HMODULE modules[JSP_MAX_MODULES];
    DWORD needed = 0;
    DWORD moduleCount = 0;
    DWORD m;
    WCHAR moduleName[JSP_ENGINE_NAME_LEN];
    WCHAR lowerName[JSP_ENGINE_NAME_LEN];
    JSP_JIT_ENGINE engine;
    UINT32 collected = 0;
    UINT32 e;
    BOOLEAN ok = FALSE;

    if (outCount != NULL) {
        *outCount = 0;
    }

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == NULL) {
        return FALSE;
    }

    if (!EnumProcessModules(process, modules, sizeof(modules), &needed)) {
        CloseHandle(process);
        return FALSE;
    }

    moduleCount = needed / sizeof(HMODULE);
    if (moduleCount > JSP_MAX_MODULES) {
        moduleCount = JSP_MAX_MODULES;
    }

    for (m = 0; m < moduleCount; m++) {
        moduleName[0] = L'\0';
        if (GetModuleBaseNameW(process, modules[m], moduleName, JSP_ENGINE_NAME_LEN) == 0) {
            continue;
        }
        JsppLowerModuleName(moduleName, lowerName, JSP_ENGINE_NAME_LEN);
        engine = JsppDetectJitEngineLower(lowerName);
        if (engine == JspEngine_Unknown) {
            continue;
        }
        if (firstOnly) {
            if (engines != NULL && maxCount > 0) {
                engines[0] = engine;
            }
            if (outCount != NULL) {
                *outCount = 1;
            }
            ok = TRUE;
            break;
        }
        /* 去重收集 */
        for (e = 0; e < collected; e++) {
            if (engines[e] == engine) {
                break;
            }
        }
        if (e == collected) {
            if (collected < maxCount && engines != NULL) {
                engines[collected] = engine;
            }
            collected++;
            ok = TRUE;
        }
    }

    if (outCount != NULL) {
        *outCount = collected;
    }
    CloseHandle(process);
    return ok;
}

/**************************************************/
/*  内部工具: JIT 页缓存                          */
/**************************************************/

/* 60s 全清缓存并释放页数组 (SS ClearExpiredCache 周期全清) */
static VOID JsppClearExpiredCache(void) {
    ULONGLONG now = GetTickCount64();
    UINT32 i;

    AcquireSRWLockExclusive(&g_cacheLock);
    if (now - g_cacheLastClearTick >= JSP_CACHE_LIFETIME_MS) {
        for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
            if (g_pageCache[i].pages != NULL) {
                free(g_pageCache[i].pages);
                g_pageCache[i].pages = NULL;
            }
            g_pageCache[i].pid = 0;
            g_pageCache[i].count = 0;
            g_pageCache[i].capacity = 0;
        }
        g_cacheLastClearTick = now;
    }
    ReleaseSRWLockExclusive(&g_cacheLock);
}

/* 缓存页列表 (拷贝到调用者缓冲) */
static BOOLEAN JsppCacheLookup(UINT32 processId,
                               JSP_JIT_PAGE_INFO* pages, UINT32 bufferLen,
                               PUINT32 outCount) {
    UINT32 i;
    UINT32 copyCount;
    BOOLEAN found = FALSE;

    if (outCount != NULL) {
        *outCount = 0;
    }

    AcquireSRWLockShared(&g_cacheLock);
    for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
        if (g_pageCache[i].pid == processId && g_pageCache[i].pages != NULL) {
            g_pageCache[i].lastTick = GetTickCount64();
            copyCount = g_pageCache[i].count;
            if (pages != NULL && bufferLen > 0) {
                if (copyCount > bufferLen) {
                    copyCount = bufferLen;
                }
                memcpy(pages, g_pageCache[i].pages, copyCount * sizeof(JSP_JIT_PAGE_INFO));
            }
            if (outCount != NULL) {
                *outCount = copyCount;
            }
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_cacheLock);
    return found;
}

/* 入缓存: 同 pid 覆盖或空槽, 满池淘汰最旧访问条目 (SS map 按需增长) */
static VOID JsppCacheStore(UINT32 processId,
                           const JSP_JIT_PAGE_INFO* pages, UINT32 count) {
    ULONGLONG now = GetTickCount64();
    UINT32 slot = JSP_MAX_CACHED_PROCESSES;
    UINT32 oldest = JSP_MAX_CACHED_PROCESSES;
    ULONGLONG oldestTick = 0xFFFFFFFFFFFFFFFFULL;
    UINT32 i;
    JSP_JIT_PAGE_INFO* newPages = NULL;

    if (count == 0) {
        return;
    }

    newPages = (JSP_JIT_PAGE_INFO*)malloc(count * sizeof(JSP_JIT_PAGE_INFO));
    if (newPages == NULL) {
        return;
    }
    memcpy(newPages, pages, count * sizeof(JSP_JIT_PAGE_INFO));

    AcquireSRWLockExclusive(&g_cacheLock);

    /* 同 pid 覆盖 */
    for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
        if (g_pageCache[i].pid == processId) {
            slot = i;
            break;
        }
    }

    /* 首个空槽 */
    if (slot == JSP_MAX_CACHED_PROCESSES) {
        for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
            if (g_pageCache[i].pages == NULL) {
                slot = i;
                break;
            }
        }
    }

    /* 满池: 淘汰最旧访问条目 */
    if (slot == JSP_MAX_CACHED_PROCESSES) {
        for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
            if (g_pageCache[i].lastTick < oldestTick) {
                oldestTick = g_pageCache[i].lastTick;
                oldest = i;
            }
        }
        slot = oldest;
    }

    if (g_pageCache[slot].pages != NULL) {
        free(g_pageCache[slot].pages);
    }
    g_pageCache[slot].pid = processId;
    g_pageCache[slot].count = count;
    g_pageCache[slot].capacity = count;
    g_pageCache[slot].pages = newPages;
    g_pageCache[slot].lastTick = now;

    ReleaseSRWLockExclusive(&g_cacheLock);
}

/**************************************************/
/*  内部工具: 事件序列号/回调/环形缓冲            */
/**************************************************/

static UINT64 JsppNextEventSequence(void) {
    return (UINT64)InterlockedIncrement64((volatile LONGLONG*)&g_eventSequence);
}

/* 回调在锁外触发 (防止回调锁内重入死锁) */
static VOID JsppFireDetectionCallback(const JSP_JIT_SPRAY_EVENT* event) {
    JSP_DETECTED_CALLBACK callback;

    AcquireSRWLockShared(&g_callbackLock);
    callback = g_detectionCallback;
    ReleaseSRWLockShared(&g_callbackLock);

    if (callback != NULL) {
        callback(event);
    }
}

/* 近期检测环形写入 (最新在前, 复用 SS deque push_front 语义) */
static VOID JsppAddRecentDetection(const JSP_JIT_SPRAY_EVENT* event) {
    AcquireSRWLockExclusive(&g_eventsLock);
    g_recentDetections[g_eventsHead] = *event;
    g_eventsHead = (g_eventsHead + 1) % JSP_MAX_RECENT_DETECTIONS;
    if (g_eventsCount < JSP_MAX_RECENT_DETECTIONS) {
        g_eventsCount++;
    }
    ReleaseSRWLockExclusive(&g_eventsLock);
}

/**************************************************/
/*  内部工具: JIT 页枚举 (GetJitPages 核心)       */
/**************************************************/

/* VirtualQueryEx 遍历进程地址空间, 收集可执行 MEM_COMMIT 区域:
 * MEM_PRIVATE → CodePage, 可写可执行同时成立 → SimultaneousRWX 违规,
 * 上限 JSP_MAX_JIT_PAGES; 结果并入缓存后拷贝到调用者缓冲 */
static UINT32 JsppGetJitPagesInternal(UINT32 processId,
                                      JSP_JIT_PAGE_INFO* pages, UINT32 bufferLen) {
    HANDLE process = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    UINT8* base = NULL;
    SIZE_T querySize;
    BOOLEAN isExec;
    BOOLEAN isWrite;
    JSP_JIT_PAGE_INFO page;
    UINT32 total = 0;
    UINT32 copyCount = 0;

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == NULL) {
        return 0;
    }

    for (base = NULL; ; ) {
        querySize = VirtualQueryEx(process, (LPCVOID)base, &mbi, sizeof(mbi));
        if (querySize == 0) {
            break;
        }
        if (mbi.State == MEM_COMMIT && JsppIsExecutableProtection(mbi.Protect)) {
            isExec = JsppIsExecutableProtection(mbi.Protect);
            isWrite = JsppIsWritableProtection(mbi.Protect);
            memset(&page, 0, sizeof(page));
            page.baseAddress = (UINT64)base;
            page.size = (UINT64)mbi.RegionSize;
            page.engine = JspEngine_Unknown;   /* 引擎识别在扫描侧按进程一次完成 */
            page.pageType = (mbi.Type == MEM_PRIVATE) ? JspPageType_Code : JspPageType_Stub;
            page.protection = mbi.Protect;
            page.isExecutable = isExec ? 1 : 0;
            page.isWritable = isWrite ? 1 : 0;
            page.wxViolation = JsppClassifyWxViolation(mbi.Protect);
            page.allocationBase = (UINT64)mbi.AllocationBase;
            page.moduleName[0] = L'\0';        /* SS 亦未填充 */
            GetSystemTimeAsFileTime(&page.lastScanned);

            if (total == 0) {
                /* 首页记录 firstSeen */
                page.firstSeen = page.lastScanned;
            } else if (pages != NULL && (total - 1) < bufferLen) {
                /* 沿用上一拷贝项的时间戳语义由调用侧管理, 此处仅维持枚举 */
            }

            /* 数出来再拷贝, 保证 pages==NULL 时返回总数 */
            total++;
            if (pages != NULL && total <= bufferLen) {
                pages[total - 1] = page;
            }
            if (total >= JSP_MAX_JIT_PAGES) {
                break;
            }
        }
        base = (UINT8*)mbi.BaseAddress + mbi.RegionSize;
        if ((UINT64)base < (UINT64)mbi.BaseAddress) {
            break;   /* 地址回绕防御 */
        }
    }

    CloseHandle(process);

    copyCount = (pages != NULL) ? ((total < bufferLen) ? total : bufferLen) : total;

    /* 入缓存仅当进程存在且枚举到页 (SS 同条件) */
    if (total > 0) {
        JsppCacheStore(processId, pages, copyCount);
    }

    return copyCount;
}

/**************************************************/
/*  公共 API: 生命周期                            */
/**************************************************/

/* 默认配置 (SS GetDefaultConfiguration 语义裁剪) */
static VOID JsppSetDefaultConfig(JSP_CONFIG* config) {
    ZeroMemory(config, sizeof(*config));
    config->enabled = TRUE;
    config->enforceWX = FALSE;       /* SS 未消费该字段 */
    config->scanJitPages = TRUE;
    config->maxScanBytes = JSP_MAX_SCAN_SIZE;
    config->enableConstantAnalysis = TRUE;
    config->blockOnWXViolation = FALSE;
    config->blockOnSprayDetection = FALSE;
    config->monitoredEngineCount = 0;   /* SS 未消费该字段 */
    config->scanIntervalMs = 1000;      /* SS 默认 1000, 无线程消费 */
    config->verboseLogging = FALSE;
}

_Use_decl_annotations_
BOOLEAN JspInitialize(const JSP_CONFIG* config) {
    JSP_CONFIG newConfig;
    UINT32 i;

    if (config != NULL && !JspConfigIsValid(config)) {
        return FALSE;
    }

    if (config != NULL) {
        newConfig = *config;
    } else {
        JsppSetDefaultConfig(&newConfig);
    }

    /* 可重入初始化: Stopped 后可再次 Initialize (BOF 同款) */
    AcquireSRWLockExclusive(&g_stateLock);
    if (g_initialized && g_status != JspStatus_Stopped) {
        ReleaseSRWLockExclusive(&g_stateLock);
        return FALSE;
    }
    g_status = JspStatus_Initializing;
    g_config = newConfig;
    ReleaseSRWLockExclusive(&g_stateLock);

    /* 统计 / 监控集合 / 近期检测 / 缓存重置 */
    JsppStatsResetAll();

    AcquireSRWLockExclusive(&g_monitorLock);
    g_monitoredCount = 0;
    ReleaseSRWLockExclusive(&g_monitorLock);

    AcquireSRWLockExclusive(&g_eventsLock);
    g_eventsHead = 0;
    g_eventsCount = 0;
    ReleaseSRWLockExclusive(&g_eventsLock);

    InterlockedExchange64((volatile LONGLONG*)&g_eventSequence, 0);

    AcquireSRWLockExclusive(&g_cacheLock);
    for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
        if (g_pageCache[i].pages != NULL) {
            free(g_pageCache[i].pages);
            g_pageCache[i].pages = NULL;
        }
        g_pageCache[i].pid = 0;
        g_pageCache[i].count = 0;
        g_pageCache[i].capacity = 0;
        g_pageCache[i].lastTick = 0;
    }
    g_cacheLastClearTick = GetTickCount64();
    ReleaseSRWLockExclusive(&g_cacheLock);

    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = NULL;
    ReleaseSRWLockExclusive(&g_callbackLock);

    _InterlockedExchange8((volatile CHAR*)&g_initialized, (CHAR)1);
    InterlockedExchange((volatile LONG*)&g_status, (LONG)JspStatus_Running);

    return TRUE;
}

_Use_decl_annotations_
VOID JspShutdown(VOID) {
    UINT32 i;

    /* 先置失效: 扫描入口立即放行返回 */
    _InterlockedExchange8((volatile CHAR*)&g_initialized, (CHAR)0);
    InterlockedExchange((volatile LONG*)&g_status, (LONG)JspStatus_Stopped);

    AcquireSRWLockExclusive(&g_monitorLock);
    g_monitoredCount = 0;
    ReleaseSRWLockExclusive(&g_monitorLock);

    AcquireSRWLockExclusive(&g_eventsLock);
    g_eventsHead = 0;
    g_eventsCount = 0;
    ReleaseSRWLockExclusive(&g_eventsLock);

    AcquireSRWLockExclusive(&g_cacheLock);
    for (i = 0; i < JSP_MAX_CACHED_PROCESSES; i++) {
        if (g_pageCache[i].pages != NULL) {
            free(g_pageCache[i].pages);
            g_pageCache[i].pages = NULL;
        }
        g_pageCache[i].pid = 0;
        g_pageCache[i].count = 0;
        g_pageCache[i].capacity = 0;
    }
    ReleaseSRWLockExclusive(&g_cacheLock);

    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = NULL;
    ReleaseSRWLockExclusive(&g_callbackLock);
}

_Use_decl_annotations_
BOOLEAN JspIsInitialized(VOID) {
    return (g_initialized != FALSE) ? TRUE : FALSE;
}

_Use_decl_annotations_
JSP_MODULE_STATUS JspGetStatus(VOID) {
    return g_status;
}

_Use_decl_annotations_
BOOLEAN JspUpdateConfiguration(const JSP_CONFIG* config) {
    if (config == NULL || !JspConfigIsValid(config)) {
        return FALSE;
    }
    if (!JsppIsActive()) {
        return FALSE;
    }
    AcquireSRWLockExclusive(&g_stateLock);
    g_config = *config;
    ReleaseSRWLockExclusive(&g_stateLock);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN JspGetConfiguration(JSP_CONFIG* config) {
    if (config == NULL) {
        return FALSE;
    }
    if (!g_initialized) {
        return FALSE;
    }
    JsppSnapshotConfig(config);
    return TRUE;
}

/* ++
 * JspScanJitPages
 *
 * 扫描指定进程全部 JIT 可执行页:
 *   - W^X 违规页 (blockOnWXViolation 开) → 立即返回 High 事件
 *   - 可疑页 (XOR/重复常量/熵低/NOP/shellcode) → 返回置信度事件
 *
 * 页级统计: pagesScanned 按页累加 (SS 注释: 原实现按进程累加已修正);
 * 引擎识别按进程一次 (SS 各页独立探测, 开销等价更低).
 *
 * 返回值: 找到命中事件 TRUE, 此时 event 被填充;
 *         event 可为 NULL (仅统计, 不返回内容).
 * -- */
_Use_decl_annotations_
BOOLEAN JspScanJitPages(UINT32 processId, JSP_JIT_SPRAY_EVENT* event) {
    JSP_CONFIG config;
    JSP_JIT_SPRAY_EVENT localEvent;
    JSP_JIT_PAGE_INFO* jitPages = NULL;
    UINT8* readData = NULL;
    UINT32 pageCount = 0;
    UINT32 readCap;
    UINT32 j;
    HANDLE process = NULL;
    WCHAR processName[JSP_ENGINE_NAME_LEN];
    JSP_JIT_ENGINE procEngine;
    SIZE_T bytesRead = 0;
    UINT32 readSize;
    double entropy;
    JSPP_REPEATED_MATCH match;
    BOOLEAN hasRepeated;
    UINT32 xorCount = 0;
    BOOLEAN xorSpray;
    BOOLEAN shellcode;
    BOOLEAN nop;
    BOOLEAN bytecodeMarker;
    BOOLEAN isSuspicious;
    JSP_SPRAY_TECHNIQUE technique;
    double score;
    UINT32 engineIdx;
    UINT32 techniqueIdx;
    BOOLEAN found = FALSE;
    JSP_JIT_SPRAY_EVENT* outEvent;
    UINT32 i;
    UINT32 copySize;

    if (event != NULL) {
        ZeroMemory(event, sizeof(*event));
    }

    if (!JsppIsActive()) {
        return FALSE;
    }

    JsppSnapshotConfig(&config);
    if (!config.scanJitPages) {
        return FALSE;
    }

    JsppClearExpiredCache();

    jitPages = (JSP_JIT_PAGE_INFO*)malloc(JSP_MAX_JIT_PAGES * sizeof(JSP_JIT_PAGE_INFO));
    if (jitPages == NULL) {
        return FALSE;
    }
    ZeroMemory(jitPages, JSP_MAX_JIT_PAGES * sizeof(JSP_JIT_PAGE_INFO));

    /* 读取缓冲上限 1MB/页 (SS vector 动态, C 定长裁剪) */
    readCap = (UINT32)config.maxScanBytes;
    if (readCap > JSP_MAX_SCAN_SIZE) {
        readCap = JSP_MAX_SCAN_SIZE;
    }
    readData = (UINT8*)malloc(readCap);
    if (readData == NULL) {
        free(jitPages);
        return FALSE;
    }

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == NULL) {
        free(jitPages);
        free(readData);
        return FALSE;
    }
    processName[0] = L'\0';
    JsppGetProcessName(process, processName, JSP_ENGINE_NAME_LEN);

    pageCount = JsppGetJitPagesInternal(processId, jitPages, JSP_MAX_JIT_PAGES);
    if (pageCount == 0) {
        CloseHandle(process);
        free(jitPages);
        free(readData);
        return FALSE;
    }

    JsppStatsAdd(&g_pagesScanned, pageCount);

    /* 引擎按进程一次探测复用 */
    procEngine = JspDetectJitEngine(processId);

    for (j = 0; j < pageCount && j < JSP_MAX_JIT_PAGES; j++) {
        JSP_JIT_PAGE_INFO* page = &jitPages[j];
        page->engine = procEngine;

        /* W^X 违规处理 (SS: 命中违规页且配置阻止 → 立即返回) */
        if (page->wxViolation != JspWx_None) {
            JsppStatsInc(&g_wxViolationsDetected);
            if (config.blockOnWXViolation) {
                ZeroMemory(&localEvent, sizeof(localEvent));
                localEvent.eventSequence = JsppNextEventSequence();
                localEvent.processId = processId;
                wcsncpy(localEvent.processName, processName, JSP_ENGINE_NAME_LEN - 1);
                localEvent.engine = page->engine;
                localEvent.technique = JspTechnique_Unknown;
                localEvent.suspiciousPage = *page;
                localEvent.address = page->baseAddress;
                localEvent.wxViolation = page->wxViolation;
                localEvent.confidence = JspConfidence_High;
                localEvent.confidenceScore = 85.0;
                localEvent.wasBlocked = TRUE;
                wcsncpy(localEvent.details, L"W^X 违规: 页面同时可写可执行", JSP_MAX_DETAILS - 1);
                GetSystemTimeAsFileTime(&localEvent.timestamp);

                JsppStatsInc(&g_attacksBlocked);
                JsppAddRecentDetection(&localEvent);
                JsppFireDetectionCallback(&localEvent);

                if (event != NULL) {
                    *event = localEvent;
                }
                found = TRUE;
                break;
            }
            /* 不阻止: 继续该页喷洒特征分析 */
        }

        readSize = (UINT32)page->size;
        if (readSize > readCap) {
            readSize = readCap;
        }
        if (readSize < JSP_MIN_JIT_PAGE_SIZE) {
            continue;   /* 小页跳过 (SS 同) */
        }

        bytesRead = 0;
        if (!ReadProcessMemory(process, (LPCVOID)(UINT_PTR)page->baseAddress,
                               readData, readSize, &bytesRead)) {
            continue;
        }
        if (bytesRead == 0) {
            continue;
        }

        entropy = JsppCalculateEntropy(readData, (UINT32)bytesRead);

        memset(&match, 0, sizeof(match));
        hasRepeated = JsppFindRepeatedPattern(readData, (UINT32)bytesRead, &match);
        JsppStatsInc(&g_constantsAnalyzed);

        xorSpray = JsppScanXorSpray(readData, (UINT32)bytesRead, &xorCount);
        if (xorSpray && !config.enableConstantAnalysis && !hasRepeated) {
            /* enableConstantAnalysis=关 时跳过常量特征 (SS 语义: 仅影响事件判定,
             * 统计仍计) */
        }
        shellcode = JsppContainsShellcodePattern(readData, (UINT32)bytesRead);
        nop = JsppIsNopSled(readData, (UINT32)bytesRead);
        bytecodeMarker = JsppContainsBytecodeMarker(readData, (UINT32)bytesRead);

        isSuspicious = FALSE;
        if (xorSpray || shellcode || nop || bytecodeMarker) {
            isSuspicious = TRUE;
        } else if (hasRepeated && match.repeatCount >= JSP_MIN_CONSTANT_REPEAT) {
            isSuspicious = TRUE;
        } else if (entropy < JSP_ENTROPY_SPRAY_MAX && bytesRead >= 256) {
            isSuspicious = TRUE;
        }

        if (!isSuspicious) {
            continue;
        }

        /* 技术类型/评分 (SS 评分体系) */
        technique = JspTechnique_Unknown;
        score = 0.0;
        if (xorSpray) {
            technique = JspTechnique_XorConstant;
            score = 80.0;
        } else if (hasRepeated) {
            technique = (match.patternSize == 8)
                        ? JspTechnique_FloatConstant
                        : JspTechnique_IntegerConstant;
            score = 65.0;
        } else if (nop) {
            technique = JspTechnique_ImmediateValue;
            score = 75.0;
        } else if (bytecodeMarker) {
            technique = JspTechnique_StringConstant;
            score = 70.0;
        }

        if (shellcode) {
            score += 15.0;
            JsppStatsInc(&g_shellcodesDetected);
        } else if (xorSpray && xorCount >= (UINT32)bytesRead / 8) {
            score += 5.0;   /* 全页 XOR 密度加成 (SS 同) */
        }

        /* 事件组装 */
        ZeroMemory(&localEvent, sizeof(localEvent));
        localEvent.eventSequence = JsppNextEventSequence();
        localEvent.processId = processId;
        wcsncpy(localEvent.processName, processName, JSP_ENGINE_NAME_LEN - 1);
        localEvent.engine = page->engine;
        localEvent.technique = technique;
        localEvent.suspiciousPage = *page;
        localEvent.address = page->baseAddress;
        localEvent.hasConstantInfo = hasRepeated ? TRUE : FALSE;
        if (hasRepeated) {
            localEvent.constantInfo.offset = match.offset;
            localEvent.constantInfo.repeatCount = match.repeatCount;
            localEvent.constantInfo.totalLength = (UINT64)bytesRead;
            localEvent.constantInfo.technique = technique;
            localEvent.constantInfo.isValidShellcode = shellcode ? TRUE : FALSE;
            copySize = match.patternSize;
            if (copySize > JSP_MAX_CONSTANT_VALUE) {
                copySize = JSP_MAX_CONSTANT_VALUE;
            }
            memcpy(localEvent.constantInfo.constantValue,
                   readData + match.offset, copySize);
            localEvent.constantInfo.constantValueSize = match.patternSize;
        }
        if (bytecodeMarker) {
            copySize = (UINT32)bytesRead;
            if (copySize > JSP_MAX_BYTECODE) {
                copySize = JSP_MAX_BYTECODE;
            }
            memcpy(localEvent.suspiciousBytecode, readData, copySize);
            localEvent.suspiciousBytecodeSize = copySize;
        }
        localEvent.shellcodeDetected = shellcode ? TRUE : FALSE;
        localEvent.wxViolation = page->wxViolation;
        localEvent.confidence = (score >= 80.0) ? JspConfidence_High
                              : (score >= 60.0) ? JspConfidence_Medium
                              : JspConfidence_Low;
        localEvent.confidenceScore = score;
        localEvent.wasBlocked = config.blockOnSprayDetection ? TRUE : FALSE;
        swprintf(localEvent.details, JSP_MAX_DETAILS,
                 L"JIT 喷洒: %s (熵 %.2f)", 
                 JspGetJitSprayTechniqueName(technique), entropy);
        GetSystemTimeAsFileTime(&localEvent.timestamp);

        JsppStatsInc(&g_spraysDetected);
        if (localEvent.wasBlocked) {
            JsppStatsInc(&g_attacksBlocked);
        }
        engineIdx = (UINT32)page->engine;
        if (engineIdx < JSP_BY_ENGINE_COUNT) {
            JsppStatsInc(&g_byEngine[engineIdx]);
        }
        techniqueIdx = (UINT32)technique;
        if (techniqueIdx < JSP_BY_TECHNIQUE_COUNT) {
            JsppStatsInc(&g_byTechnique[techniqueIdx]);
        }

        JsppAddRecentDetection(&localEvent);
        JsppFireDetectionCallback(&localEvent);

        if (event != NULL) {
            *event = localEvent;
        }
        found = TRUE;
        break;
    }

    CloseHandle(process);
    free(jitPages);
    free(readData);
    return found;
}

_Use_decl_annotations_
UINT32 JspScanAllProcesses(JSP_JIT_SPRAY_EVENT* events, UINT32 maxCount) {
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe;
    UINT32 collected = 0;
    JSP_JIT_SPRAY_EVENT evt;
    BOOLEAN any = FALSE;

    if (!JsppIsActive()) {
        return 0;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snapshot, &pe)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (pe.th32ProcessID == 0) {
            continue;   /* 跳过 System Idle */
        }
        /* 跨模块关联 SS 侧已裁剪 (CorrelateWithHeapSpray 不迁移) */
        if (JspScanJitPages(pe.th32ProcessID, &evt)) {
            any = TRUE;
            if (events != NULL && collected < maxCount) {
                events[collected] = evt;
                collected++;
            } else if (events == NULL) {
                collected++;
            }
            if (events != NULL && collected >= maxCount) {
                break;
            }
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return collected;
}

_Use_decl_annotations_
BOOLEAN JspAnalyzeJitPage(UINT32 processId, UINT64 address, UINT64 size,
                          JSP_JIT_PAGE_INFO* pageInfo) {
    JSP_CONFIG config;
    HANDLE process = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T querySize;
    UINT32 readCap;
    UINT8* readData = NULL;
    SIZE_T bytesRead = 0;
    UINT32 readSize;
    double entropy;
    JSPP_REPEATED_MATCH match = { 0, 0, 0 };
    BOOLEAN hasRepeated = FALSE;
    UINT32 xorCount = 0;
    BOOLEAN xorSpray = FALSE;
    BOOLEAN shellcode = FALSE;
    BOOLEAN nop = FALSE;
    BOOLEAN ok = FALSE;
    JSP_JIT_PAGE_INFO result;

    if (pageInfo == NULL) {
        return FALSE;
    }
    ZeroMemory(pageInfo, sizeof(*pageInfo));

    if (!JsppIsActive()) {
        return FALSE;
    }
    JsppSnapshotConfig(&config);

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == NULL) {
        return FALSE;
    }

    querySize = VirtualQueryEx(process, (LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi));
    if (querySize == 0 || mbi.State != MEM_COMMIT ||
        !JsppIsExecutableProtection(mbi.Protect)) {
        CloseHandle(process);
        return FALSE;
    }

    readCap = (UINT32)config.maxScanBytes;
    if (readCap > JSP_MAX_SCAN_SIZE) {
        readCap = JSP_MAX_SCAN_SIZE;
    }
    readSize = (UINT32)size;
    if (readSize > (UINT32)mbi.RegionSize) {
        readSize = (UINT32)mbi.RegionSize;
    }
    if (readSize > readCap) {
        readSize = readCap;
    }
    if (readSize == 0) {
        CloseHandle(process);
        return FALSE;
    }

    readData = (UINT8*)malloc(readCap);
    if (readData == NULL) {
        CloseHandle(process);
        return FALSE;
    }

    if (!ReadProcessMemory(process, (LPCVOID)(UINT_PTR)address,
                           readData, readSize, &bytesRead) || bytesRead == 0) {
        free(readData);
        CloseHandle(process);
        return FALSE;
    }

    entropy = JsppCalculateEntropy(readData, (UINT32)bytesRead);
    hasRepeated = JsppFindRepeatedPattern(readData, (UINT32)bytesRead, &match);
    JsppStatsInc(&g_constantsAnalyzed);
    xorSpray = JsppScanXorSpray(readData, (UINT32)bytesRead, &xorCount);
    shellcode = JsppContainsShellcodePattern(readData, (UINT32)bytesRead);
    nop = JsppIsNopSled(readData, (UINT32)bytesRead);

    ZeroMemory(&result, sizeof(result));
    result.baseAddress = address;
    result.size = (UINT64)bytesRead;
    result.engine = JspDetectJitEngine(processId);
    result.pageType = (mbi.Type == MEM_PRIVATE) ? JspPageType_Code : JspPageType_Stub;
    result.protection = mbi.Protect;
    result.isExecutable = JsppIsExecutableProtection(mbi.Protect) ? 1 : 0;
    result.isWritable = JsppIsWritableProtection(mbi.Protect) ? 1 : 0;
    result.wxViolation = JsppClassifyWxViolation(mbi.Protect);
    result.allocationBase = (UINT64)mbi.AllocationBase;
    result.moduleName[0] = L'\0';
    result.entropy = entropy;
    result.suspiciousConstants = (hasRepeated ||
                                  xorSpray ||
                                  shellcode ||
                                  nop) ? 1 : 0;
    result.constantRepeatCount = hasRepeated ? match.repeatCount : 0;
    GetSystemTimeAsFileTime(&result.firstSeen);
    GetSystemTimeAsFileTime(&result.lastScanned);

    *pageInfo = result;
    ok = TRUE;

    free(readData);
    CloseHandle(process);
    return ok;
}

_Use_decl_annotations_
BOOLEAN JspDetectConstantEmbedding(const UINT8* data, UINT64 dataSize,
                                   UINT64 baseAddress,
                                   JSP_CONSTANT_EMBEDDING* embedding) {
    JSPP_REPEATED_MATCH match;
    BOOLEAN found;
    UINT32 copySize;
    UINT32 value;
    UINT32 i;
    JSP_CONSTANT_EMBEDDING result;
    BOOLEAN shellcode = FALSE;

    if (data == NULL || dataSize == 0 || dataSize > 0xFFFFFFFFULL ||
        embedding == NULL) {
        return FALSE;
    }
    ZeroMemory(embedding, sizeof(*embedding));

    if (!JsppIsActive()) {
        return FALSE;
    }
    JsppStatsInc(&g_constantsAnalyzed);

    memset(&match, 0, sizeof(match));
    found = JsppFindRepeatedPattern(data, (UINT32)dataSize, &match);
    if (!found) {
        return FALSE;
    }

    ZeroMemory(&result, sizeof(result));
    result.offset = match.offset;
    copySize = match.patternSize;
    if (copySize > JSP_MAX_CONSTANT_VALUE) {
        copySize = JSP_MAX_CONSTANT_VALUE;
    }
    memcpy(result.constantValue, data + match.offset, copySize);
    result.constantValueSize = match.patternSize;
    result.repeatCount = match.repeatCount;
    result.totalLength = dataSize;
    (VOID)baseAddress;   /* SS 基址参与解码, 本项目不复制解码链 */

    /* 技术类型: 4 字节 XOR 常量 > 整数常量; 8 字节 → 浮点常量 */
    result.technique = JspTechnique_Unknown;
    if (match.patternSize == 4) {
        memcpy(&value, data + match.offset, 4);
        for (i = 0; i < (sizeof(JsppXorSprayValues) / sizeof(JsppXorSprayValues[0])); i++) {
            if (value == JsppXorSprayValues[i]) {
                result.technique = JspTechnique_XorConstant;
                break;
            }
        }
        if (result.technique == JspTechnique_Unknown) {
            result.technique = JspTechnique_IntegerConstant;
        }
    } else if (match.patternSize == 8) {
        result.technique = JspTechnique_FloatConstant;
    }

    /* 常量即 shellcode 头模式 → 判定有效载荷 */
    shellcode = JsppContainsShellcodePattern(data, (UINT32)dataSize) ||
                JsppIsNopSled(data, (UINT32)dataSize);
    result.isValidShellcode = shellcode ? TRUE : FALSE;

    *embedding = result;
    return TRUE;
}

/**************************************************/
/*  公共 API: W^X 合规 (本模块独有能力)           */
/**************************************************/

_Use_decl_annotations_
BOOLEAN JspCheckWXCompliance(UINT32 processId, JSP_WX_COMPLIANCE_REPORT* report) {
    HANDLE process = NULL;
    JSP_JIT_PAGE_INFO* jitPages = NULL;
    UINT32 pageCount = 0;
    UINT32 j;
    JSP_WX_COMPLIANCE_REPORT result;
    UINT32 typeIdx;

    if (report == NULL) {
        return FALSE;
    }
    ZeroMemory(report, sizeof(*report));

    if (!JsppIsActive()) {
        return FALSE;
    }

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == NULL) {
        return FALSE;
    }

    jitPages = (JSP_JIT_PAGE_INFO*)malloc(JSP_MAX_JIT_PAGES * sizeof(JSP_JIT_PAGE_INFO));
    if (jitPages == NULL) {
        CloseHandle(process);
        return FALSE;
    }
    ZeroMemory(jitPages, JSP_MAX_JIT_PAGES * sizeof(JSP_JIT_PAGE_INFO));

    pageCount = JsppGetJitPagesInternal(processId, jitPages, JSP_MAX_JIT_PAGES);

    ZeroMemory(&result, sizeof(result));
    result.processId = processId;
    JsppGetProcessName(process, result.processName, JSP_ENGINE_NAME_LEN);
    result.totalJitPages = pageCount;

    for (j = 0; j < pageCount; j++) {
        if (jitPages[j].wxViolation != JspWx_None) {
            result.violationCount++;
            typeIdx = (UINT32)jitPages[j].wxViolation;
            if (typeIdx < 5) {
                result.violationsByType[typeIdx]++;
            }
            if (result.nonCompliantCount < JSP_MAX_NONCOMPLIANT_PAGES) {
                result.nonCompliantPages[result.nonCompliantCount] = jitPages[j];
                result.nonCompliantCount++;
            }
        } else {
            result.compliantPages++;
        }
    }

    result.isFullyCompliant = (result.violationCount == 0) ? TRUE : FALSE;
    result.complianceScore = (pageCount > 0)
                             ? ((double)result.compliantPages * 100.0 / (double)pageCount)
                             : 100.0;
    GetSystemTimeAsFileTime(&result.timestamp);

    *report = result;

    free(jitPages);
    CloseHandle(process);
    return TRUE;
}

_Use_decl_annotations_
JSP_WX_VIOLATION_TYPE JspCheckPageWXViolation(UINT32 processId, UINT64 address) {
    HANDLE process = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T querySize;
    JSP_WX_VIOLATION_TYPE result = JspWx_None;

    if (!JsppIsActive()) {
        return JspWx_None;
    }

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == NULL) {
        return JspWx_None;
    }

    querySize = VirtualQueryEx(process, (LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi));
    if (querySize != 0 && mbi.State == MEM_COMMIT) {
        result = JsppClassifyWxViolation(mbi.Protect);
    }

    CloseHandle(process);
    return result;
}

_Use_decl_annotations_
UINT32 JspGetWXViolatingPages(UINT32 processId,
                              JSP_JIT_PAGE_INFO* pages, UINT32 maxCount) {
    JSP_JIT_PAGE_INFO* jitPages = NULL;
    UINT32 pageCount = 0;
    UINT32 j;
    UINT32 collected = 0;

    if (!JsppIsActive()) {
        return 0;
    }

    jitPages = (JSP_JIT_PAGE_INFO*)malloc(JSP_MAX_JIT_PAGES * sizeof(JSP_JIT_PAGE_INFO));
    if (jitPages == NULL) {
        return 0;
    }
    ZeroMemory(jitPages, JSP_MAX_JIT_PAGES * sizeof(JSP_JIT_PAGE_INFO));

    pageCount = JsppGetJitPagesInternal(processId, jitPages, JSP_MAX_JIT_PAGES);

    for (j = 0; j < pageCount; j++) {
        if (jitPages[j].wxViolation != JspWx_None) {
            if (pages != NULL && collected < maxCount) {
                pages[collected] = jitPages[j];
            }
            collected++;
        }
    }

    free(jitPages);
    return collected;
}

/**************************************************/
/*  公共 API: JIT 引擎                            */
/**************************************************/

_Use_decl_annotations_
JSP_JIT_ENGINE JspDetectJitEngine(UINT32 processId) {
    JSP_JIT_ENGINE engines[1] = { JspEngine_Unknown };
    UINT32 count = 0;
    JSP_JIT_ENGINE engine = JspEngine_Unknown;
    UINT32 engineIdx;

    if (!JsppIsActive()) {
        return JspEngine_Unknown;
    }

    JsppClearExpiredCache();

    if (JsppEnumerateEngines(processId, engines, 1, &count, TRUE) && count > 0) {
        engine = engines[0];
    }

    /* SS: DetectJitEngine 命中也累加 byEngine */
    if (engine != JspEngine_Unknown) {
        engineIdx = (UINT32)engine;
        if (engineIdx < JSP_BY_ENGINE_COUNT) {
            JsppStatsInc(&g_byEngine[engineIdx]);
        }
    }
    return engine;
}

_Use_decl_annotations_
UINT32 JspGetAllJitEngines(UINT32 processId,
                           JSP_JIT_ENGINE* engines, UINT32 maxCount) {
    UINT32 count = 0;

    if (!JsppIsActive()) {
        return 0;
    }

    if (JsppEnumerateEngines(processId, engines, maxCount, &count, FALSE)) {
        return count;
    }
    return 0;
}

_Use_decl_annotations_
UINT32 JspGetJitPages(UINT32 processId,
                      JSP_JIT_PAGE_INFO* pages, UINT32 maxCount) {
    if (!JsppIsActive()) {
        return 0;
    }

    JsppClearExpiredCache();

    /* 缓存命中时直接拷贝 (SS 语义) */
    {
        UINT32 cached = 0;
        UINT32 copyCount;
        if (JsppCacheLookup(processId, pages, maxCount, &cached)) {
            copyCount = (pages != NULL) ? ((cached < maxCount) ? cached : maxCount) : cached;
            return copyCount;
        }
    }

    return JsppGetJitPagesInternal(processId, pages, maxCount);
}

/**************************************************/
/*  公共 API: 监控                                */
/**************************************************/

_Use_decl_annotations_
BOOLEAN JspMonitorProcess(UINT32 processId) {
    UINT32 i;
    BOOLEAN added = FALSE;

    if (!JsppIsActive() || processId == 0) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_monitorLock);
    for (i = 0; i < g_monitoredCount; i++) {
        if (g_monitoredProcesses[i] == processId) {
            added = TRUE;   /* 已存在 */
            break;
        }
    }
    if (!added && g_monitoredCount < JSP_MAX_MONITORED_PROCESSES) {
        g_monitoredProcesses[g_monitoredCount++] = processId;
        added = TRUE;
    }
    ReleaseSRWLockExclusive(&g_monitorLock);
    return added;
}

_Use_decl_annotations_
BOOLEAN JspStopMonitoring(UINT32 processId) {
    UINT32 i;
    BOOLEAN removed = FALSE;

    AcquireSRWLockExclusive(&g_monitorLock);
    for (i = 0; i < g_monitoredCount; i++) {
        if (g_monitoredProcesses[i] == processId) {
            g_monitoredProcesses[i] = g_monitoredProcesses[g_monitoredCount - 1];
            g_monitoredCount--;
            removed = TRUE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_monitorLock);
    return removed;
}

_Use_decl_annotations_
BOOLEAN JspIsMonitoring(UINT32 processId) {
    UINT32 i;
    BOOLEAN found = FALSE;

    AcquireSRWLockShared(&g_monitorLock);
    for (i = 0; i < g_monitoredCount; i++) {
        if (g_monitoredProcesses[i] == processId) {
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_monitorLock);
    return found;
}

/**************************************************/
/*  公共 API: 内核内存告警接入                    */
/*                                                */
/*  汇入点: ioctl HK_IOCTL_OBJ_ALLOC_DIVERT (SS   */
/*  ProcessKernelMemoryAlert 同签名, 由调用方分发) */
/**************************************************/

_Use_decl_annotations_
VOID JspProcessKernelMemoryAlert(UINT32 processId, UINT64 address,
                                 UINT64 size, UINT32 protection) {
    JSP_CONFIG config;
    HANDLE process = NULL;
    UINT8* readData = NULL;
    UINT32 readCap;
    UINT32 readSize;
    SIZE_T bytesRead = 0;
    double entropy;
    JSPP_REPEATED_MATCH match = { 0, 0, 0 };
    BOOLEAN hasRepeated = FALSE;
    UINT32 xorCount = 0;
    BOOLEAN xorSpray = FALSE;
    BOOLEAN shellcode = FALSE;
    BOOLEAN suspicious;
    JSP_JIT_SPRAY_EVENT evt;
    UINT32 engineIdx;
    UINT32 techniqueIdx;
    JSP_JIT_ENGINE engine;

    if (!JsppIsActive()) {
        return;
    }
    JsppSnapshotConfig(&config);
    if (!config.enabled) {
        return;
    }

    /* 非可执行分配直接忽略 (SS 同) */
    if (!JsppIsExecutableProtection(protection)) {
        return;
    }

    /* 内核告警使 JIT 页缓存失效 (SS 同) */
    JsppClearExpiredCache();

    readCap = (UINT32)config.maxScanBytes;
    if (readCap > JSP_MAX_SCAN_SIZE) {
        readCap = JSP_MAX_SCAN_SIZE;
    }
    readSize = (UINT32)size;
    if (readSize > readCap) {
        readSize = readCap;
    }
    if (readSize == 0) {
        return;
    }

    /* 页面当前保护状态: RWX 违规时优先触发 W^X 路径 */
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T querySize;
        process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (process == NULL) {
            return;
        }
        querySize = VirtualQueryEx(process, (LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi));
        if (querySize != 0 &&
            mbi.State == MEM_COMMIT &&
            JsppClassifyWxViolation(mbi.Protect) != JspWx_None) {
            JsppStatsInc(&g_wxViolationsDetected);
            if (config.blockOnWXViolation) {
                ZeroMemory(&evt, sizeof(evt));
                evt.eventSequence = JsppNextEventSequence();
                evt.processId = processId;
                JsppGetProcessName(process, evt.processName, JSP_ENGINE_NAME_LEN);
                evt.engine = JspDetectJitEngine(processId);
                evt.technique = JspTechnique_Unknown;
                evt.address = address;
                evt.wxViolation = JsppClassifyWxViolation(mbi.Protect);
                evt.confidence = JspConfidence_High;
                evt.confidenceScore = 85.0;
                evt.wasBlocked = TRUE;
                wcsncpy(evt.details, L"W^X 违规 (内核告警): 可执行分配同时可写", JSP_MAX_DETAILS - 1);
                GetSystemTimeAsFileTime(&evt.timestamp);

                JsppStatsInc(&g_attacksBlocked);
                JsppAddRecentDetection(&evt);
                JsppFireDetectionCallback(&evt);
                CloseHandle(process);
                return;
            }
        }
    }

    readData = (UINT8*)malloc(readCap);
    if (readData == NULL) {
        CloseHandle(process);
        return;
    }

    bytesRead = 0;
    if (!ReadProcessMemory(process, (LPCVOID)(UINT_PTR)address,
                           readData, readSize, &bytesRead) || bytesRead == 0) {
        free(readData);
        CloseHandle(process);
        return;
    }

    entropy = JsppCalculateEntropy(readData, (UINT32)bytesRead);
    hasRepeated = JsppFindRepeatedPattern(readData, (UINT32)bytesRead, &match);
    JsppStatsInc(&g_constantsAnalyzed);
    xorSpray = JsppScanXorSpray(readData, (UINT32)bytesRead, &xorCount);
    shellcode = JsppContainsShellcodePattern(readData, (UINT32)bytesRead);
    /* 与 SS 一致: 告警路径不做 NOP sled 判定 */

    suspicious = (hasRepeated && match.repeatCount >= JSP_MIN_CONSTANT_REPEAT) ||
                 (entropy < JSP_ENTROPY_SPRAY_MAX && bytesRead >= 256) ||
                 xorSpray || shellcode;
    if (!suspicious) {
        free(readData);
        CloseHandle(process);
        return;
    }

    /* 引擎一次探测 (SS 各页独立, 此处进程级等价) */
    engine = JspDetectJitEngine(processId);

    ZeroMemory(&evt, sizeof(evt));
    evt.eventSequence = JsppNextEventSequence();
    evt.processId = processId;
    JsppGetProcessName(process, evt.processName, JSP_ENGINE_NAME_LEN);
    evt.engine = engine;
    evt.technique = xorSpray ? JspTechnique_XorConstant
                 : hasRepeated ? JspTechnique_IntegerConstant
                 : JspTechnique_ImmediateValue;
    evt.address = address;
    evt.hasConstantInfo = hasRepeated ? TRUE : FALSE;
    evt.shellcodeDetected = shellcode ? TRUE : FALSE;
    evt.confidence = JspConfidence_High;
    evt.confidenceScore = 80.0;
    evt.wasBlocked = config.blockOnSprayDetection ? TRUE : FALSE;

    {
        UINT32 copySize = (UINT32)bytesRead;
        if (copySize > JSP_MAX_BYTECODE) {
            copySize = JSP_MAX_BYTECODE;
        }
        memcpy(evt.suspiciousBytecode, readData, copySize);
        evt.suspiciousBytecodeSize = copySize;
    }
    swprintf(evt.details, JSP_MAX_DETAILS,
             L"JIT 喷洒嫌疑 (内核告警): 熵 %.2f", entropy);
    GetSystemTimeAsFileTime(&evt.timestamp);

    JsppStatsInc(&g_spraysDetected);
    if (evt.wasBlocked) {
        JsppStatsInc(&g_attacksBlocked);
    }
    engineIdx = (UINT32)engine;
    if (engineIdx < JSP_BY_ENGINE_COUNT) {
        JsppStatsInc(&g_byEngine[engineIdx]);
    }
    techniqueIdx = (UINT32)evt.technique;
    if (techniqueIdx < JSP_BY_TECHNIQUE_COUNT) {
        JsppStatsInc(&g_byTechnique[techniqueIdx]);
    }

    JsppAddRecentDetection(&evt);
    JsppFireDetectionCallback(&evt);

    free(readData);
    CloseHandle(process);
}

/**************************************************/
/*  公共 API: 回调                                */
/**************************************************/

_Use_decl_annotations_
VOID JspRegisterDetectionCallback(JSP_DETECTED_CALLBACK callback) {
    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = callback;
    ReleaseSRWLockExclusive(&g_callbackLock);
}

_Use_decl_annotations_
VOID JspUnregisterCallbacks(VOID) {
    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = NULL;
    ReleaseSRWLockExclusive(&g_callbackLock);
}

/**************************************************/
/*  公共 API: 统计与诊断                          */
/**************************************************/

_Use_decl_annotations_
BOOLEAN JspGetStatistics(JSP_STATS_SNAPSHOT* snapshot) {
    UINT32 i;
    ULONGLONG now;

    if (snapshot == NULL) {
        return FALSE;
    }
    if (!g_initialized) {
        return FALSE;
    }

    ZeroMemory(snapshot, sizeof(*snapshot));
    snapshot->pagesScanned = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_pagesScanned, 0);
    snapshot->constantsAnalyzed = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_constantsAnalyzed, 0);
    snapshot->spraysDetected = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_spraysDetected, 0);
    snapshot->wxViolationsDetected = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_wxViolationsDetected, 0);
    snapshot->shellcodesDetected = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_shellcodesDetected, 0);
    snapshot->attacksBlocked = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_attacksBlocked, 0);
    for (i = 0; i < JSP_BY_ENGINE_COUNT; i++) {
        snapshot->byEngine[i] = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_byEngine[i], 0);
    }
    for (i = 0; i < JSP_BY_TECHNIQUE_COUNT; i++) {
        snapshot->byTechnique[i] = (UINT64)InterlockedExchangeAdd64((volatile LONGLONG*)&g_byTechnique[i], 0);
    }
    now = GetTickCount64();
    snapshot->uptimeSeconds = (g_startTick != 0 && now >= g_startTick)
                              ? (now - g_startTick) / 1000 : 0;
    {
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &snapshot->startTime);
    }
    return TRUE;
}

_Use_decl_annotations_
VOID JspResetStatistics(VOID) {
    JsppStatsResetAll();
}

_Use_decl_annotations_
UINT32 JspGetRecentDetections(JSP_JIT_SPRAY_EVENT* events, UINT32 maxCount) {
    UINT32 n;
    UINT32 i;
    UINT32 idx;
    UINT32 collected = 0;

    if (!g_initialized) {
        return 0;
    }

    AcquireSRWLockShared(&g_eventsLock);
    n = g_eventsCount;
    if (events != NULL && n > maxCount) {
        n = maxCount;
    }
    /* 最新在前: 从 head-1 递减 */
    for (i = 0; i < n; i++) {
        idx = (g_eventsHead + JSP_MAX_RECENT_DETECTIONS - 1 - i) % JSP_MAX_RECENT_DETECTIONS;
        if (events != NULL) {
            events[collected] = g_recentDetections[idx];
        }
        collected++;
    }
    ReleaseSRWLockShared(&g_eventsLock);
    return collected;
}

_Use_decl_annotations_
BOOLEAN JspSelfTest(VOID) {
    UINT8 uniform[256];
    UINT8 repeated[400];
    UINT8 nopSled[256];
    UINT8 xorBytes[4];
    JSPP_REPEATED_MATCH match;
    BOOLEAN ok = TRUE;
    JSP_CONFIG cfg;
    double entropy;
    UINT32 value;
    UINT32 i;

    /* 1) 熵判定: 全 0x90 页熵约 0 ≤ 2.0 */
    memset(uniform, 0x90, sizeof(uniform));
    entropy = JsppCalculateEntropy(uniform, sizeof(uniform));
    if (!(entropy <= JSP_ENTROPY_SPRAY_MAX)) {
        ok = FALSE;
    }

    /* 2) 重复模式: 0x0C×400 → 4 字节模式重复 100 次 */
    memset(repeated, 0x0C, sizeof(repeated));
    memset(&match, 0, sizeof(match));
    if (!JsppFindRepeatedPattern(repeated, sizeof(repeated), &match)) {
        ok = FALSE;
    } else if (match.patternSize != 4 || match.repeatCount != 100) {
        ok = FALSE;
    }

    /* 3) NOP sled: 0x90×256 */
    memset(nopSled, 0x90, sizeof(nopSled));
    if (!JsppIsNopSled(nopSled, sizeof(nopSled))) {
        ok = FALSE;
    }

    /* 4) XOR 常量: {90 90 90 3C} 小端 = 0x3C909090 */
    xorBytes[0] = 0x90; xorBytes[1] = 0x90;
    xorBytes[2] = 0x90; xorBytes[3] = 0x3C;
    memcpy(&value, xorBytes, 4);
    if (!JsppIsXorSprayConstant(value)) {
        ok = FALSE;
    }

    /* 5) 配置校验: maxScanBytes=1MB, scanIntervalMs=1000 */
    JsppSetDefaultConfig(&cfg);
    if (!JspConfigIsValid(&cfg)) {
        ok = FALSE;
    }

    return ok;
}

_Use_decl_annotations_
PCWSTR JspGetVersionString(VOID) {
    return L"3.0.0";
}

/**************************************************/
/*  公共 API: 名称工具函数                        */
/**************************************************/

_Use_decl_annotations_
PCWSTR JspGetJitEngineName(JSP_JIT_ENGINE engine) {
    switch (engine) {
        case JspEngine_V8:             return L"V8";
        case JspEngine_SpiderMonkey:   return L"SpiderMonkey";
        case JspEngine_Chakra:         return L"Chakra";
        case JspEngine_JavaScriptCore: return L"JavaScriptCore";
        case JspEngine_DotNetJIT:      return L".NET JIT";
        case JspEngine_DotNetNGen:     return L".NET NGen";
        case JspEngine_JavaHotSpot:    return L"Java HotSpot";
        case JspEngine_OpenJ9:         return L"OpenJ9";
        case JspEngine_LuaJIT:         return L"LuaJIT";
        case JspEngine_WASM:           return L"WebAssembly";
        case JspEngine_ActionScript:   return L"ActionScript";
        case JspEngine_PyPy:           return L"PyPy";
        default:                       return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR JspGetJitPageTypeName(JSP_JIT_PAGE_TYPE type) {
    switch (type) {
        case JspPageType_Code:         return L"Code";
        case JspPageType_Stub:         return L"Stub";
        case JspPageType_ConstantPool: return L"ConstantPool";
        case JspPageType_Data:         return L"Data";
        case JspPageType_Trampoline:   return L"Trampoline";
        default:                       return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR JspGetJitSprayTechniqueName(JSP_SPRAY_TECHNIQUE technique) {
    switch (technique) {
        case JspTechnique_XorConstant:     return L"XOR Constant";
        case JspTechnique_FloatConstant:   return L"Float Constant";
        case JspTechnique_IntegerConstant: return L"Integer Constant";
        case JspTechnique_StringConstant:  return L"String Constant";
        case JspTechnique_ArrayConstant:   return L"Array Constant";
        case JspTechnique_ImmediateValue:  return L"Immediate Value";
        case JspTechnique_AddressLeak:     return L"Address Leak";
        default:                           return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR JspGetWXViolationTypeName(JSP_WX_VIOLATION_TYPE type) {
    switch (type) {
        case JspWx_SimultaneousRWX:     return L"Simultaneous RWX";
        case JspWx_WriteToExecutable:   return L"Write to Executable";
        case JspWx_ExecuteWritable:     return L"Execute Writable";
        case JspWx_TransitionViolation: return L"Transition Violation";
        case JspWx_None:                return L"None";
        default:                        return L"Unknown";
    }
}

_Use_decl_annotations_
BOOLEAN JspIsJitEngineModule(const WCHAR* moduleName) {
    WCHAR lowerName[JSP_ENGINE_NAME_LEN];
    UINT32 i;

    if (moduleName == NULL || moduleName[0] == L'\0') {
        return FALSE;
    }
    if (wcslen(moduleName) >= JSP_ENGINE_NAME_LEN) {
        return FALSE;
    }

    JsppLowerModuleName(moduleName, lowerName, JSP_ENGINE_NAME_LEN);
    for (i = 0; i < (sizeof(JsppJitEngineModules) / sizeof(JsppJitEngineModules[0])); i++) {
        if (wcsstr(lowerName, JsppJitEngineModules[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

_Use_decl_annotations_
JSP_JIT_ENGINE JspDetectJitEngineFromModule(const WCHAR* moduleName) {
    WCHAR lowerName[JSP_ENGINE_NAME_LEN];

    if (moduleName == NULL || moduleName[0] == L'\0') {
        return JspEngine_Unknown;
    }
    if (wcslen(moduleName) >= JSP_ENGINE_NAME_LEN) {
        return JspEngine_Unknown;
    }

    JsppLowerModuleName(moduleName, lowerName, JSP_ENGINE_NAME_LEN);
    return JsppDetectJitEngineLower(lowerName);
}

/**************************************************/
/*  公共 API: 配置有效性                          */
/**************************************************/

_Use_decl_annotations_
BOOLEAN JspConfigIsValid(const JSP_CONFIG* config) {
    if (config == NULL) {
        return FALSE;
    }
    if (config->maxScanBytes == 0 || config->maxScanBytes > JSP_MAX_SCAN_BYTES_LIMIT) {
        return FALSE;
    }
    if (config->scanIntervalMs < JSP_SCAN_INTERVAL_MIN_MS ||
        config->scanIntervalMs > JSP_SCAN_INTERVAL_MAX_MS) {
        return FALSE;
    }
    return TRUE;
}