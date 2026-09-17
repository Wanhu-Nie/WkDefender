/**************************************************/
/*  WkDefender IOA — 缓冲区溢出攻击防护检测器 (实现) */
/*                                                  */
/*  迁移自 ShadowStrike BufferOverflowProtection.cpp*/
/*  (v3.0.0, 2625 行), 功能重实现非源码复制。        */
/*                                                  */
/*  结构: 静态全局 + SRWLOCK (对齐 SPD/RPD/HSD 惯例): */
/*    g_stateLock   保护 配置/状态                  */
/*    g_monitorLock 保护 监控进程集合               */
/*    g_eventsLock  保护 检测事件环形               */
/*    g_callbackLock保护 检测回调指针               */
/*  统计 volatile 字段 + Interlocked* 更新 (无锁)。  */
/*  锁纪律: 回调调用在锁外; 不嵌套持锁。            */
/*  周期扫描线程随 Start/Stop 状态机一并裁剪,       */
/*  检测由调用方驱动 (HardenProcess / Analyze* /    */
/*  BofProcessKernelMemoryAlert 内核告警触发)。     */
/*  事件序列号替代 SS RNG "BOF-xxxx" 字符串        */
/*  (对齐 HSD 先例, InterlockedIncrement64)。      */
/**************************************************/

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <intrin.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#include "../../DefendTypes.h"
#include "BufferOverflowPatternDetector.h"

/**************************************************/
/*  旧 SDK 兼容: CET 影子栈策略结构               */
/*  (SS 同名单并定义, Win10 2004+ 才可用)         */
/**************************************************/
typedef struct _SS_USER_SHADOW_STACK_POLICY {
    union {
        DWORD Flags;
        struct {
            DWORD EnableUserShadowStack : 1;
            DWORD AuditUserShadowStack : 1;
            DWORD SetContextIpValidation : 1;
            DWORD AuditSetContextIpValidation : 1;
            DWORD EnableUserShadowStackStrictMode : 1;
            DWORD BlockNonCetBinaries : 1;
            DWORD BlockNonCetBinariesNonEhcont : 1;
            DWORD AuditBlockNonCetBinaries : 1;
            DWORD CetDynamicApisOutOfProcOnly : 1;
            DWORD SetContextIpValidationRelaxedMode : 1;
            DWORD ReservedFlags : 22;
        };
    };
} SS_USER_SHADOW_STACK_POLICY;

#ifndef ProcessUserShadowStackPolicy
#define ProcessUserShadowStackPolicy ((PROCESS_MITIGATION_POLICY)13)
#endif

/**************************************************/
/*  静态全局                                      */
/**************************************************/
static BOF_CONFIG         g_config;
static BOOLEAN volatile   g_initialized = FALSE;
static BOF_MODULE_STATUS volatile g_status = BofStatus_Uninitialized;
static SRWLOCK            g_stateLock;
static SRWLOCK            g_monitorLock;
static SRWLOCK            g_eventsLock;
static SRWLOCK            g_callbackLock;

/* 12 个统计计数器 (SS BufferOverflowStatistics) */
static UINT64 volatile g_processesMonitored;
static UINT64 volatile g_processesHardened;
static UINT64 volatile g_exceptionsHandled;
static UINT64 volatile g_stackOverflowsDetected;
static UINT64 volatile g_heapCorruptionsDetected;
static UINT64 volatile g_formatStringsDetected;
static UINT64 volatile g_integerOverflowsDetected;
static UINT64 volatile g_useAfterFreeDetected;
static UINT64 volatile g_exploitsBlocked;
static UINT64 volatile g_processesTerminated;
static UINT64 volatile g_canaryChecks;
static UINT64 volatile g_canaryFailures;

/* 监控进程集合 (SS unordered_set, 上限裁剪为 BOF_MAX_MONITORED_PROCESSES) */
static UINT32 g_monitoredProcesses[BOF_MAX_MONITORED_PROCESSES];
static UINT32 g_monitoredCount;

/* 近期事件环形 (SS deque 上限 1000) */
static BOF_EVENT g_recentEvents[BOF_MAX_RECENT_EVENTS];
static UINT32 g_eventsHead;   /* 下一个写入槽 */
static UINT32 g_eventsCount;

/* 事件序列号 (替代 SS "BOF-{ts}-{cnt}" 字符串) */
static UINT64 volatile g_eventSequence;

/* 单检测回调 (SS 4 类 vector 合 1) */
static BOF_DETECTED_CALLBACK g_detectionCallback;

/* 硬件能力缓存 (SS DetectHardwareCapabilities) */
static BOF_CPU_VENDOR g_cpuVendor = BofCpu_Unknown;
static BOOLEAN        g_cetAvailable = FALSE;
static BOOLEAN        g_shadowStackAvailable = FALSE;
static UINT64         g_hardwareFeatures = 0;

/* 启动时刻 (统计快照用) */
static FILETIME g_startTime;
static ULONG64  g_startTick;

/**************************************************/
/*  内部函数 (Bofp* 前缀, 静态, 假定被正确调用)    */
/**************************************************/

/* 判断地址是否落在可执行内存区 */
static BOOLEAN
BofpIsExecutableAddress(HANDLE hProcess, ULONG_PTR address)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T len;

    len = VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi));
    if (len == 0) {
        return FALSE;
    }
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

/* 获取地址所在模块基址 (AllocationBase) */
static ULONG_PTR
BofpGetModuleBase(HANDLE hProcess, ULONG_PTR address)
{
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) != 0) {
        return (ULONG_PTR)mbi.AllocationBase;
    }
    return 0;
}

/* 获取地址所在模块名 (仅文件名, 不带路径) */
static void
BofpGetModuleName(HANDLE hProcess, ULONG_PTR address,
                  WCHAR* name, UINT32 nameLen)
{
    HMODULE hModule;
    WCHAR   fullPath[DEF_MAX_PATH];
    DWORD   len;
    WCHAR*  slash;

    name[0] = L'\0';
    hModule = (HMODULE)BofpGetModuleBase(hProcess, address);
    if (hModule == NULL) {
        return;
    }
    len = GetModuleFileNameExW(hProcess, hModule, fullPath, DEF_MAX_PATH);
    if (len == 0) {
        wcscpy_s(name, nameLen, L"<unknown>");
        return;
    }
    slash = wcsrchr(fullPath, L'\\');
    if (slash == NULL) {
        slash = wcsrchr(fullPath, L'/');
    }
    if (slash != NULL && slash[1] != L'\0') {
        wcsncpy_s(name, nameLen, slash + 1, _TRUNCATE);
    } else {
        wcsncpy_s(name, nameLen, fullPath, _TRUNCATE);
    }
}

/* CPUID 检测厂商 (GenuineIntel / AuthenticAMD) */
static BOF_CPU_VENDOR
BofpDetectCpuVendor(void)
{
    int    cpuInfo[4];
    char   vendor[13];

    __cpuid(cpuInfo, 0);
    /* CPUID 厂商串返回在 EBX/EDX/ECX (依序) */
    memcpy(vendor + 0, &cpuInfo[1], sizeof(int));
    memcpy(vendor + 4, &cpuInfo[3], sizeof(int));
    memcpy(vendor + 8, &cpuInfo[2], sizeof(int));
    vendor[12] = '\0';

    if (memcmp(vendor, "GenuineIntel", 12) == 0) {
        return BofCpu_Intel;
    }
    if (memcmp(vendor, "AuthenticAMD", 12) == 0) {
        return BofCpu_AMD;
    }
    return BofCpu_Unknown;
}

/* CPUID leaf 7: ECX[7]=CET_SS(影子栈) / EDX[20]=CET_IBT */
static BOOLEAN
BofpIsCETSupported(void)
{
    int cpuInfo[4];

    __cpuidex(cpuInfo, 7, 0);
    if ((cpuInfo[2] & (1 << 7)) != 0) {   /* ECX bit 7: Shadow Stack */
        return TRUE;
    }
    if ((cpuInfo[3] & (1 << 20)) != 0) {  /* EDX bit 20: IBT */
        return TRUE;
    }
    return FALSE;
}

/* 构造时填充硬件能力缓存 (SS DetectHardwareCapabilities) */
static void
BofpDetectHardwareCapabilities(void)
{
    g_cpuVendor = BofpDetectCpuVendor();
    g_cetAvailable = BofpIsCETSupported();
    g_shadowStackAvailable = g_cetAvailable;

    g_hardwareFeatures = 0;
    if (g_cetAvailable) {
        g_hardwareFeatures |= BOF_PROTECT_HARDWARE_CET;
        g_hardwareFeatures |= BOF_PROTECT_SHADOW_STACK;
    }
}

/* 加固评分: DEP/ASLR/CFG +15, 永久/高熵/严格 +10,
 * CET/影子栈 +20, 其余 +5, 封顶 100 (SS CalculateHardeningScore) */
static double
BofpCalculateHardeningScore(const UINT64* policies, UINT32 count)
{
    double score;
    UINT32 i;
    UINT64 p;

    if (count == 0) {
        return 0.0;
    }
    score = 0.0;
    for (i = 0; i < count; i++) {
        p = policies[i];
        if (p == BOF_PROTECT_DEP || p == BOF_PROTECT_ASLR || p == BOF_PROTECT_CFG) {
            score += 15.0;
        } else if (p == BOF_PROTECT_PERMANENT_DEP ||
                   p == BOF_PROTECT_HIGH_ENTROPY_ASLR ||
                   p == BOF_PROTECT_STRICT_CFG) {
            score += 10.0;
        } else if (p == BOF_PROTECT_HARDWARE_CET || p == BOF_PROTECT_SHADOW_STACK) {
            score += 20.0;
        } else {
            score += 5.0;
        }
    }
    if (score > 100.0) {
        score = 100.0;
    }
    return score;
}

/* 加固建议 (SS GenerateRecommendations, 输出以 '\n' 分隔) */
static void
BofpGenerateRecommendations(BOF_POLICY policyMask,
                            const UINT64* appliedPolicies, UINT32 appliedCount,
                            WCHAR* buffer, UINT32 bufferLen)
{
    WCHAR* p;
    UINT32 remaining;
    UINT32 len;

    UNREFERENCED_PARAMETER(appliedPolicies);
    UNREFERENCED_PARAMETER(appliedCount);

    if (buffer == NULL || bufferLen == 0) {
        return;
    }
    p = buffer;
    remaining = bufferLen;

#define BOF_APPEND_REC(rec)                                                  \
    do {                                                                     \
        len = (UINT32)_snwprintf(p, remaining, L"%s\n", rec);                \
        if (len == (UINT32)-1 || len >= remaining) {                         \
            goto bof_rec_done;                                               \
        }                                                                    \
        p += len;                                                            \
        remaining -= len;                                                    \
    } while (0)

    if ((policyMask & BOF_PROTECT_PERMANENT_DEP) == 0) {
        BOF_APPEND_REC(L"Enable permanent DEP to prevent runtime disabling");
    }
    if ((policyMask & BOF_PROTECT_HIGH_ENTROPY_ASLR) == 0) {
        BOF_APPEND_REC(L"Enable high-entropy ASLR for 64-bit processes");
    }
    if ((policyMask & BOF_PROTECT_STRICT_CFG) == 0) {
        BOF_APPEND_REC(L"Enable strict CFG mode for enhanced protection");
    }
    if ((policyMask & BOF_PROTECT_DISABLE_DYN_CODE) == 0) {
        BOF_APPEND_REC(L"Consider disabling dynamic code generation");
    }
    if ((policyMask & BOF_PROTECT_BLOCK_REMOTE_IMG) == 0) {
        BOF_APPEND_REC(L"Block remote DLL loading to prevent DLL injection");
    }
    if (g_cetAvailable && (policyMask & BOF_PROTECT_HARDWARE_CET) == 0) {
        BOF_APPEND_REC(L"Enable hardware CET for hardware-backed protection");
    }
    if (p == buffer) {
        BOF_APPEND_REC(L"Process is well-protected with current settings");
    }

bof_rec_done:
    *p = L'\0';
#undef BOF_APPEND_REC
}

/* 读取进程现网缓解策略 → BOF_POLICY 掩码
 * (SS GetProcessPolicyInternal, 往返位集合 20 位) */
static BOF_POLICY
BofpGetProcessPolicyInternal(UINT32 processId)
{
    BOF_POLICY mask;
    HANDLE hProcess;
    PROCESS_MITIGATION_DEP_POLICY depPolicy;
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicPolicy;
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy;
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imagePolicy;
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy;
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPolicy;
    SS_USER_SHADOW_STACK_POLICY cetPolicy;

    mask = 0;
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return 0;
    }

    /* DEP */
    if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy,
                                   &depPolicy, sizeof(depPolicy))) {
        if (depPolicy.Enable != 0) {
            mask |= BOF_PROTECT_DEP;
        }
        if (depPolicy.Permanent != 0) {
            mask |= BOF_PROTECT_PERMANENT_DEP;
        }
    }

    /* ASLR (SS 中 Enable 无字段, 查询成功即视为启用) */
    if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy,
                                   &aslrPolicy, sizeof(aslrPolicy))) {
        mask |= BOF_PROTECT_ASLR;
        if (aslrPolicy.EnableHighEntropy != 0) {
            mask |= BOF_PROTECT_HIGH_ENTROPY_ASLR;
        }
        if (aslrPolicy.EnableBottomUpRandomization != 0) {
            mask |= BOF_PROTECT_BOTTOM_UP_ASLR;
        }
        if (aslrPolicy.EnableForceRelocateImages != 0) {
            mask |= BOF_PROTECT_FORCE_RELOCATE;
        }
    }

    /* CFG */
    if (GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy,
                                   &cfgPolicy, sizeof(cfgPolicy))) {
        if (cfgPolicy.EnableControlFlowGuard != 0) {
            mask |= BOF_PROTECT_CFG;
        }
        if (cfgPolicy.StrictMode != 0) {
            mask |= BOF_PROTECT_STRICT_CFG;
        }
    }

    /* 动态代码 */
    if (GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy,
                                   &dynamicPolicy, sizeof(dynamicPolicy))) {
        if (dynamicPolicy.ProhibitDynamicCode != 0) {
            mask |= BOF_PROTECT_DISABLE_DYN_CODE;
        }
        if (dynamicPolicy.AllowThreadOptOut != 0) {
            mask |= BOF_PROTECT_ALLOW_THREAD_OPTOUT;
        }
    }

    /* 严格句柄 */
    if (GetProcessMitigationPolicy(hProcess, ProcessStrictHandleCheckPolicy,
                                   &handlePolicy, sizeof(handlePolicy))) {
        if (handlePolicy.RaiseExceptionOnInvalidHandleReference != 0) {
            mask |= BOF_PROTECT_STRICT_HANDLE;
        }
    }

    /* 镜像加载 */
    if (GetProcessMitigationPolicy(hProcess, ProcessImageLoadPolicy,
                                   &imagePolicy, sizeof(imagePolicy))) {
        if (imagePolicy.NoRemoteImages != 0) {
            mask |= BOF_PROTECT_BLOCK_REMOTE_IMG;
        }
        if (imagePolicy.NoLowMandatoryLabelImages != 0) {
            mask |= BOF_PROTECT_BLOCK_LOW_LABEL;
        }
        if (imagePolicy.PreferSystem32Images != 0) {
            mask |= BOF_PROTECT_PREFER_SYSTEM32;
        }
    }

    /* 系统调用禁用 */
    if (GetProcessMitigationPolicy(hProcess, ProcessSystemCallDisablePolicy,
                                   &syscallPolicy, sizeof(syscallPolicy))) {
        if (syscallPolicy.DisallowWin32kSystemCalls != 0) {
            mask |= BOF_PROTECT_DISALLOW_WIN32K;
        }
    }

    /* 扩展点禁用 */
    if (GetProcessMitigationPolicy(hProcess, ProcessExtensionPointDisablePolicy,
                                   &extPolicy, sizeof(extPolicy))) {
        if (extPolicy.DisableExtensionPoints != 0) {
            mask |= BOF_PROTECT_DISABLE_EXT_PTS;
        }
    }

    /* CET 影子栈 (Win10 2004+, 旧系统查询失败静默跳过) */
    if (GetProcessMitigationPolicy(hProcess, ProcessUserShadowStackPolicy,
                                   &cetPolicy, sizeof(cetPolicy))) {
        if (cetPolicy.EnableUserShadowStack != 0) {
            mask |= BOF_PROTECT_HARDWARE_CET;
        }
    }

    CloseHandle(hProcess);
    return mask;
}

/* 事件入环形缓冲 (SS m_recentEvents deque, 上限 1000) */
static void
BofpCacheEvent(const BOF_EVENT* event)
{
    AcquireSRWLockExclusive(&g_eventsLock);
    g_recentEvents[g_eventsHead] = *event;
    g_eventsHead = (g_eventsHead + 1) % BOF_MAX_RECENT_EVENTS;
    if (g_eventsCount < BOF_MAX_RECENT_EVENTS) {
        g_eventsCount++;
    }
    ReleaseSRWLockExclusive(&g_eventsLock);
}

/* 锁外调用检测回调 (SS InvokeExploitCallbacks: 锁内拷贝, 锁外调用) */
static void
BofpInvokeDetectionCallbacks(const BOF_EVENT* event)
{
    BOF_DETECTED_CALLBACK cb;

    AcquireSRWLockShared(&g_callbackLock);
    cb = g_detectionCallback;
    ReleaseSRWLockShared(&g_callbackLock);

    if (cb != NULL) {
        cb(event);
    }
}

/* 取下一事件序列号 (替代 SS GenerateEventId 字符串) */
static UINT64
BofpNextEventSequence(void)
{
    return InterlockedIncrement64((volatile LONGLONG*)&g_eventSequence);
}

/* 异常分类 + 事件组装 (SS AnalyzeExceptionInternal)
 * 分类完毕入环形、触发回调; 统计副产品就地累计 */
static void
BofpAnalyzeExceptionInternal(UINT32 processId,
                             const BOF_EXCEPTION_CONTEXT* context,
                             BOF_EVENT* event)
{
    HANDLE hProcess;
    WCHAR  processNameBuf[DEF_MAX_PATH];
    DWORD  procNameLen;

    InterlockedIncrement64((volatile LONGLONG*)&g_exceptionsHandled);

    /* 组装事件基础字段 */
    memset(event, 0, sizeof(*event));
    event->eventSequence = BofpNextEventSequence();
    event->processId = processId;
    event->instructionPointer = context->exceptionAddress;
    event->stackPointer = context->registers.rsp;
    event->hasExceptionContext = TRUE;
    event->exceptionContext = *context;
    event->status = BofExploit_Suspicious;
    event->severity = BofSeverity_Medium;
    event->detectionMethod = BofDetect_ExceptionHandler;
    GetSystemTimeAsFileTime(&event->timestamp);

    /* 进程名/路径与故障模块信息 */
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, processId);
    if (hProcess != NULL) {
        procNameLen = GetModuleFileNameExW(hProcess, NULL,
                                           processNameBuf, DEF_MAX_PATH);
        if (procNameLen != 0) {
            wcsncpy_s(event->processPath, DEF_MAX_PATH,
                      processNameBuf, _TRUNCATE);
            {
                WCHAR* slash = wcsrchr(processNameBuf, L'\\');
                if (slash == NULL) {
                    slash = wcsrchr(processNameBuf, L'/');
                }
                wcsncpy_s(event->processName, DEF_MAX_IMAGE_NAME,
                          (slash != NULL) ? slash + 1 : processNameBuf,
                          _TRUNCATE);
            }
        }
        BofpGetModuleName(hProcess, (ULONG_PTR)context->exceptionAddress,
                          event->moduleName, DEF_MAX_IMAGE_NAME);
        event->moduleBase =
            (UINT64)BofpGetModuleBase(hProcess, (ULONG_PTR)context->exceptionAddress);
        CloseHandle(hProcess);
    }

    /* 按异常码分类 (SS 同表) */
    switch (context->exceptionCode) {
        case 0xC0000005:  /* EXCEPTION_ACCESS_VIOLATION */
            if (context->numParameters >= 2) {
                BOOLEAN isWrite = (context->parameters[0] == 1);
                UINT64 faultAddr = context->parameters[1];
                if (faultAddr == 0 || faultAddr < BOF_SUSPECT_ADDR_MIN) {
                    event->type = BofOverflow_NullPointerDeref;
                    event->severity = BofSeverity_Low;
                } else if (isWrite) {
                    event->type = BofOverflow_OutOfBoundsWrite;
                    event->severity = BofSeverity_High;
                } else {
                    event->type = BofOverflow_OutOfBoundsRead;
                    event->severity = BofSeverity_Medium;
                }
                event->targetAddress = faultAddr;
            }
            break;

        case 0xC00000FD:  /* EXCEPTION_STACK_OVERFLOW */
            event->type = BofOverflow_StackSmashing;
            event->severity = BofSeverity_Critical;
            InterlockedIncrement64((volatile LONGLONG*)&g_stackOverflowsDetected);
            break;

        case 0xC0000409:  /* STATUS_STACK_BUFFER_OVERRUN (GS cookie) */
            event->type = BofOverflow_StackCanaryCorrupt;
            event->severity = BofSeverity_Critical;
            event->status = BofExploit_ConfirmedExploit;
            event->detectionMethod = BofDetect_CanaryCheck;
            InterlockedIncrement64((volatile LONGLONG*)&g_canaryFailures);
            break;

        case 0xC000001D:  /* EXCEPTION_ILLEGAL_INSTRUCTION */
            event->type = BofOverflow_Unknown;
            event->severity = BofSeverity_High;
            break;

        default:
            event->type = BofOverflow_Unknown;
            break;
    }

    /* 详情 (SS: format "Exception ... type: ...") */
    _snwprintf_s(event->details, BOF_MAX_DETAILS, _TRUNCATE,
                 L"Exception 0x%08X at 0x%llX, type: %s",
                 context->exceptionCode, context->exceptionAddress,
                 BofGetOverflowTypeName(event->type));

    /* 入环形 + 触发回调 */
    BofpCacheEvent(event);
    BofpInvokeDetectionCallbacks(event);

    if (event->severity >= BofSeverity_High) {
        InterlockedIncrement64((volatile LONGLONG*)&g_exploitsBlocked);
    }
}

/* 堆完整性校验 (SS ValidateHeapInternal) */
static void
BofpValidateHeapInternal(UINT32 processId, UINT64 heapHandle,
                         BOF_HEAP_ANALYSIS_RESULT* result)
{
    memset(result, 0, sizeof(*result));
    result->heapHandle = heapHandle;

    if (processId == GetCurrentProcessId()) {
        /* 本进程: HeapValidate 直接校验 */
        HANDLE heap = (HANDLE)heapHandle;
        if (heap == NULL) {
            result->isCorrupted = TRUE;
            wcscpy_s(result->corruptionType, BOF_MAX_CORRUPTION_TYPE,
                     L"Null heap handle");
            return;
        }

        if (!HeapValidate(heap, 0, NULL)) {
            BOF_EVENT event;
            result->isCorrupted = TRUE;
            wcscpy_s(result->corruptionType, BOF_MAX_CORRUPTION_TYPE,
                     L"HeapValidate failed - heap metadata corruption detected");
            result->corruptionAddress = heapHandle;
            InterlockedIncrement64((volatile LONGLONG*)&g_heapCorruptionsDetected);

            memset(&event, 0, sizeof(event));
            event.eventSequence = BofpNextEventSequence();
            event.type = BofOverflow_HeapMetaCorrupt;
            event.severity = BofSeverity_Critical;
            event.status = BofExploit_ConfirmedExploit;
            event.detectionMethod = BofDetect_HeapValidation;
            event.processId = processId;
            event.targetAddress = heapHandle;
            GetSystemTimeAsFileTime(&event->timestamp);
            _snwprintf_s(event.details, BOF_MAX_DETAILS, _TRUNCATE,
                         L"Heap corruption detected at handle 0x%llX", heapHandle);
            BofpCacheEvent(&event);
            BofpInvokeDetectionCallbacks(&event);
            return;
        }

        /* HeapWalk 统计 */
        if (HeapLock(heap)) {
            PROCESS_HEAP_ENTRY heapEntry;
            memset(&heapEntry, 0, sizeof(heapEntry));
            while (HeapWalk(heap, &heapEntry)) {
                if (heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
                    result->allocationCount++;
                    result->committedSize += heapEntry.cbData;
                } else {
                    result->freeSize += heapEntry.cbData;
                }
                result->totalSize += heapEntry.cbData + heapEntry.cbOverhead;
            }
            HeapUnlock(heap);
        }
        result->isCorrupted = FALSE;
    } else {
        /* 远程进程: 仅读堆头 8 字节做可读性完整性判断
         * (SS 同策略; BOF_HEAP_HEADER_MAGIC 定义但 SS 未比对魔数) */
        HANDLE hProcess;
        UINT64 headerMagic;
        SIZE_T bytesRead;

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, processId);
        if (hProcess == NULL) {
            return;
        }
        headerMagic = 0;
        bytesRead = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)heapHandle,
                              &headerMagic, sizeof(headerMagic), &bytesRead)) {
            if (bytesRead == 0) {
                result->isCorrupted = TRUE;
                wcscpy_s(result->corruptionType, BOF_MAX_CORRUPTION_TYPE,
                         L"Heap handle points to unreadable memory");
            }
        } else {
            result->isCorrupted = TRUE;
            wcscpy_s(result->corruptionType, BOF_MAX_CORRUPTION_TYPE,
                     L"Cannot read heap memory from remote process");
        }
        CloseHandle(hProcess);
    }
}

/* 枚举进程全部堆并校验 (SS ValidateAllHeapsInternal) */
static UINT32
BofpValidateAllHeapsInternal(UINT32 processId,
                             BOF_HEAP_ANALYSIS_RESULT* results,
                             UINT32 maxResults)
{
    UINT32 count;
    HANDLE hProcess;

    count = 0;
    if (results == NULL || maxResults == 0) {
        return 0;
    }

    if (processId == GetCurrentProcessId()) {
        DWORD numHeaps;
        DWORD actualCount;
        HANDLE* heaps;
        DWORD i;

        numHeaps = GetProcessHeaps(0, NULL);
        if (numHeaps == 0) {
            return 0;
        }
        heaps = (HANDLE*)malloc(numHeaps * sizeof(HANDLE));
        if (heaps == NULL) {
            return 0;
        }
        actualCount = GetProcessHeaps(numHeaps, heaps);
        if (actualCount == 0) {
            free(heaps);
            return 0;
        }
        for (i = 0; i < actualCount && count < maxResults; i++) {
            BofpValidateHeapInternal(processId, (UINT64)(ULONG_PTR)heaps[i],
                                     &results[count]);
            if (results[count].isCorrupted) {
                InterlockedIncrement64((volatile LONGLONG*)&g_heapCorruptionsDetected);
            }
            count++;
        }
        free(heaps);
    } else {
        /* 远程: NtQueryInformationProcess 取 PEB → 读 ProcessHeap
         * (WoW64 偏移 0x18 / x64 偏移 0x30); 函数经 GetProcAddress
         * 动态解析 (对齐 SS, 避免链接 ntdll.lib 依赖);
         * 进程基本信息为查询类 0, 就地定义结构避免依赖 winternl.h */
        typedef struct _BOF_PROCESS_BASIC_INFORMATION {
            NTSTATUS   ExitStatus;
            PVOID      PebBaseAddress;
            ULONG_PTR  AffinityMask;
            LONG       BasePriority;
            ULONG_PTR  UniqueProcessId;
            ULONG_PTR  InheritedFromUniqueProcessId;
        } BOF_PROCESS_BASIC_INFORMATION;
        typedef NTSTATUS (NTAPI* FN_NtQueryInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);
        static FN_NtQueryInformationProcess fnNtQuery = NULL;
        NTSTATUS status;
        BOF_PROCESS_BASIC_INFORMATION pbi;

        if (fnNtQuery == NULL) {
            fnNtQuery = (FN_NtQueryInformationProcess)
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                               "NtQueryInformationProcess");
        }

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, processId);
        if (hProcess == NULL) {
            return 0;
        }

        status = (fnNtQuery != NULL)
            ? fnNtQuery(hProcess, 0 /* ProcessBasicInformation */,
                        &pbi, sizeof(pbi), NULL)
            : STATUS_UNSUCCESSFUL;
        if (status == 0 && pbi.PebBaseAddress != NULL) {
            BOOL isWow64 = FALSE;
            SIZE_T heapFieldOffset = 0x30;
            SIZE_T ptrSize = sizeof(UINT64);
            UINT64 processHeap = 0;
            SIZE_T bytesRead = 0;

            IsWow64Process(hProcess, &isWow64);
            if (isWow64) {
                heapFieldOffset = 0x18;
                ptrSize = sizeof(UINT32);
            }

            if (ReadProcessMemory(hProcess,
                                  (LPCBYTE)pbi.PebBaseAddress + heapFieldOffset,
                                  &processHeap, ptrSize, &bytesRead) &&
                bytesRead == ptrSize && processHeap != 0) {
                BofpValidateHeapInternal(processId, processHeap,
                                         &results[count]);
                if (results[count].isCorrupted) {
                    InterlockedIncrement64((volatile LONGLONG*)&g_heapCorruptionsDetected);
                }
                count++;
            }
        }
        CloseHandle(hProcess);
        UNREFERENCED_PARAMETER(hThread);
    }

    return count;
}

/* 栈 canary 校验 (SS ValidateStackCanaryInternal)
 * 挂起线程从 RSP 起最多检查 8 个槽位的返回地址是否指向可执行内存,
 * 持挂起态读栈避免 TOCTOU; 任一槽位指向非可执行内存 → 判定被破坏 */
static BOOLEAN
BofpValidateStackCanaryInternal(UINT32 processId, UINT32 threadId)
{
    HANDLE hThread;
    DWORD prevSuspendCount;
    CONTEXT ctx;
    HANDLE hProcess;
    UINT64 stackRetAddr;
    SIZE_T bytesRead;
    BOOLEAN corrupted;
    BOOLEAN result;
    UINT32 slot;

    InterlockedIncrement64((volatile LONGLONG*)&g_canaryChecks);

    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
                         THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        return FALSE;
    }

    prevSuspendCount = SuspendThread(hThread);
    if (prevSuspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        return FALSE;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    /* 先读栈后恢复: RSP 内容易变, 恢复后再读存在 TOCTOU 竞态 */
    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    /* 检查返回地址槽位 (SS 上限 8 槽) */
    corrupted = FALSE;
    for (slot = 0; slot < 8; slot++) {
        stackRetAddr = 0;
        bytesRead = 0;
        if (!ReadProcessMemory(hProcess,
                               (LPCVOID)(ctx.Rsp + (UINT64)slot * sizeof(UINT64)),
                               &stackRetAddr, sizeof(stackRetAddr), &bytesRead) ||
            bytesRead != sizeof(stackRetAddr)) {
            break;   /* 越界或不可读, 停止扫描 */
        }
        if (stackRetAddr == 0) {
            break;   /* 栈底 */
        }
        if (!BofpIsExecutableAddress(hProcess, (ULONG_PTR)stackRetAddr)) {
            corrupted = TRUE;
            break;
        }
    }

    /* 恢复线程: 上下文与栈在挂起期间一致性快照已取 */
    ResumeThread(hThread);
    CloseHandle(hThread);

    result = TRUE;
    if (corrupted) {
        BOF_EVENT event;

        InterlockedIncrement64((volatile LONGLONG*)&g_canaryFailures);

        memset(&event, 0, sizeof(event));
        event.eventSequence = BofpNextEventSequence();
        event.type = BofOverflow_StackSmashing;
        event.severity = BofSeverity_Critical;
        event.status = BofExploit_ConfirmedExploit;
        event.detectionMethod = BofDetect_CanaryCheck;
        event.processId = processId;
        event.threadId = threadId;
        event.instructionPointer = ctx.Rip;
        event.stackPointer = ctx.Rsp;
        event.targetAddress = stackRetAddr;
        GetSystemTimeAsFileTime(&event.timestamp);
        _snwprintf_s(event.details, BOF_MAX_DETAILS, _TRUNCATE,
                     L"Return address 0x%llX at RSP+0x%X points to non-executable memory",
                     stackRetAddr, slot * (UINT32)sizeof(UINT64));
        BofpCacheEvent(&event);
        BofpInvokeDetectionCallbacks(&event);
        result = FALSE;
    }

    CloseHandle(hProcess);
    return result;
}

/* 调用栈回溯 (SS GetCallStackInternal)
 * DbgHelp 非线程安全, 模块级静态锁串行化; 挂起线程保证帧一致性 */
static UINT32
BofpGetCallStackInternal(UINT32 processId, UINT32 threadId,
                         UINT32 maxFrames, BOF_STACK_FRAME_INFO* frames)
{
    static SRWLOCK s_symApiLock;   /* 模块级 DbgHelp 串行化 */
    UINT32 clamped;
    UINT32 count;
    HANDLE hProcess;
    HANDLE hThread;
    BOOL symInit;
    DWORD prevCount;
    CONTEXT ctx;
    STACKFRAME64 stackFrame;
    UINT32 i;

    clamped = maxFrames;
    if (clamped > BOF_MAX_STACK_FRAMES) {
        clamped = BOF_MAX_STACK_FRAMES;
    }
    count = 0;
    if (frames == NULL || clamped == 0) {
        return 0;
    }

    AcquireSRWLockExclusive(&s_symApiLock);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, processId);
    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
                         THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hProcess == NULL || hThread == NULL) {
        if (hProcess != NULL) CloseHandle(hProcess);
        if (hThread != NULL) CloseHandle(hThread);
        ReleaseSRWLockExclusive(&s_symApiLock);
        return 0;
    }

    symInit = SymInitialize(hProcess, NULL, TRUE);

    prevCount = SuspendThread(hThread);
    if (prevCount == (DWORD)-1) {
        if (symInit) {
            SymCleanup(hProcess);
        }
        CloseHandle(hThread);
        CloseHandle(hProcess);
        ReleaseSRWLockExclusive(&s_symApiLock);
        return 0;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        if (symInit) {
            SymCleanup(hProcess);
        }
        CloseHandle(hThread);
        CloseHandle(hProcess);
        ReleaseSRWLockExclusive(&s_symApiLock);
        return 0;
    }

    memset(&stackFrame, 0, sizeof(stackFrame));
    stackFrame.AddrPC.Offset = ctx.Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = ctx.Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = ctx.Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;

    /* 仅支持 x64 (SS 硬编码 IMAGE_FILE_MACHINE_AMD64) */
    for (i = 0; i < clamped; i++) {
        BOF_STACK_FRAME_INFO* frame;

        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
                         &stackFrame, &ctx, NULL,
                         SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
        if (stackFrame.AddrPC.Offset == 0) {
            break;
        }

        frame = &frames[count];
        memset(frame, 0, sizeof(*frame));
        frame->frameIndex = count;
        frame->returnAddress = stackFrame.AddrReturn.Offset;
        frame->stackPointer = stackFrame.AddrStack.Offset;
        frame->basePointer = stackFrame.AddrFrame.Offset;
        frame->isValid = TRUE;

        BofpGetModuleName(hProcess, (ULONG_PTR)stackFrame.AddrPC.Offset,
                          frame->moduleName, DEF_MAX_IMAGE_NAME);
        frame->moduleBase =
            (UINT64)BofpGetModuleBase(hProcess, (ULONG_PTR)stackFrame.AddrPC.Offset);
        if (frame->moduleBase != 0) {
            frame->moduleOffset = stackFrame.AddrPC.Offset - frame->moduleBase;
        }
        frame->returnInExecutable =
            (frame->returnAddress == 0) ||
            BofpIsExecutableAddress(hProcess, (ULONG_PTR)frame->returnAddress);

        if (symInit) {
            __declspec(align(8)) char symbolBuf[sizeof(SYMBOL_INFO) +
                                                MAX_SYM_NAME * sizeof(TCHAR)];
            SYMBOL_INFO* symbol;
            DWORD64 displacement;

            symbol = (SYMBOL_INFO*)symbolBuf;
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = MAX_SYM_NAME;
            displacement = 0;
            if (SymFromAddr(hProcess, stackFrame.AddrPC.Offset,
                            &displacement, symbol)) {
                /* SYMBOL_INFO.Name 为 ANSI 缓冲, 需转宽字符 (SS 经
                 * std::string→std::wstring 隐式转换, C 版显式转换) */
                MultiByteToWideChar(CP_ACP, 0, symbol->Name, -1,
                                    frame->functionName, BOF_MAX_FUNCTION_NAME);
                frame->functionOffset = (UINT32)displacement;
            }
        }
        count++;
    }

    if (symInit) {
        SymCleanup(hProcess);
    }
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    ReleaseSRWLockExclusive(&s_symApiLock);

    return count;
}

/* 监控进程登记 (SS MonitorProcessInternal)
 * shared 预检 + unique 插入双锁关闭 TOCTOU; 排除列表经状态锁读取 */
static BOOLEAN
BofpMonitorProcessInternal(UINT32 processId)
{
    UINT32 i;

    if (processId == 0) {
        return FALSE;
    }

    /* 上限/重复预检 */
    AcquireSRWLockShared(&g_monitorLock);
    if (g_monitoredCount >= BOF_MAX_MONITORED_PROCESSES) {
        ReleaseSRWLockShared(&g_monitorLock);
        return FALSE;
    }
    for (i = 0; i < g_monitoredCount; i++) {
        if (g_monitoredProcesses[i] == processId) {
            ReleaseSRWLockShared(&g_monitorLock);
            return TRUE;
        }
    }
    ReleaseSRWLockShared(&g_monitorLock);

    /* 排除列表检查 */
    {
        HANDLE hProcess;
        WCHAR  procName[DEF_MAX_PATH];
        DWORD  nameLen;
        WCHAR  filename[DEF_MAX_IMAGE_NAME];
        WCHAR* slash;
        UINT32 j;

        AcquireSRWLockShared(&g_stateLock);
        if (g_config.excludedProcessCount > 0) {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (hProcess != NULL) {
                nameLen = GetModuleFileNameExW(hProcess, NULL, procName, DEF_MAX_PATH);
                CloseHandle(hProcess);
                if (nameLen != 0) {
                    slash = wcsrchr(procName, L'\\');
                    if (slash == NULL) {
                        slash = wcsrchr(procName, L'/');
                    }
                    wcsncpy_s(filename, DEF_MAX_IMAGE_NAME,
                              (slash != NULL) ? slash + 1 : procName, _TRUNCATE);
                    for (j = 0; j < g_config.excludedProcessCount; j++) {
                        if (_wcsicmp(filename, g_config.excludedProcesses[j]) == 0) {
                            ReleaseSRWLockShared(&g_stateLock);
                            return FALSE;
                        }
                    }
                }
            }
        }
        ReleaseSRWLockShared(&g_stateLock);
    }

    /* 进程存在性验证 */
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, processId);
        if (hProcess == NULL) {
            return FALSE;
        }
        CloseHandle(hProcess);
    }

    /* unique 锁下重查并插入 (关闭预检与插入间 TOCTOU 窗口) */
    AcquireSRWLockExclusive(&g_monitorLock);
    if (g_monitoredCount >= BOF_MAX_MONITORED_PROCESSES) {
        ReleaseSRWLockExclusive(&g_monitorLock);
        return FALSE;
    }
    for (i = 0; i < g_monitoredCount; i++) {
        if (g_monitoredProcesses[i] == processId) {
            ReleaseSRWLockExclusive(&g_monitorLock);
            return TRUE;   /* 并发下其他线程已插入 */
        }
    }
    g_monitoredProcesses[g_monitoredCount++] = processId;
    ReleaseSRWLockExclusive(&g_monitorLock);

    InterlockedIncrement64((volatile LONGLONG*)&g_processesMonitored);
    return TRUE;
}

/* 停止监控 (SS StopMonitoringInternal) */
static BOOLEAN
BofpStopMonitoringInternal(UINT32 processId)
{
    UINT32 i;
    BOOLEAN removed;

    removed = FALSE;
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

/* 是否在监控中 (SS IsMonitoringInternal) */
static BOOLEAN
BofpIsMonitoringInternal(UINT32 processId)
{
    UINT32 i;
    BOOLEAN found;

    found = FALSE;
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

/* 导出监控列表 (SS GetMonitoredProcessesInternal)
 * buffer==NULL: 返回实际数量 (供调用方预分配);
 * buffer!=NULL: 拷贝 min(数量, bufferLen) 项并返回拷贝项数 */
static UINT32
BofpGetMonitoredProcessesInternal(UINT32* buffer, UINT32 bufferLen)
{
    UINT32 i;
    UINT32 n;

    AcquireSRWLockShared(&g_monitorLock);
    if (buffer == NULL) {
        n = g_monitoredCount;
        ReleaseSRWLockShared(&g_monitorLock);
        return n;
    }
    n = g_monitoredCount;
    if (n > bufferLen) {
        n = bufferLen;
    }
    for (i = 0; i < n; i++) {
        buffer[i] = g_monitoredProcesses[i];
    }
    ReleaseSRWLockShared(&g_monitorLock);
    return n;
}

/* 进程加固内部实现 (SS HardenProcessInternal)
 * 逐组应用 SetProcessMitigationPolicy 并记录成功/失败策略 */
static BOOLEAN
BofpHardenProcessInternal(UINT32 processId, BOF_POLICY policyMask,
                          BOF_HARDENING_REPORT* report)
{
    HANDLE hProcess;
    DWORD  procNameLen;
    WCHAR  processNameBuf[DEF_MAX_PATH];

    if (report == NULL) {
        return FALSE;
    }
    memset(report, 0, sizeof(*report));
    report->processId = processId;
    GetSystemTimeAsFileTime(&report->timestamp);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
                           PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return FALSE;
    }

    procNameLen = GetModuleFileNameExW(hProcess, NULL, processNameBuf, DEF_MAX_PATH);
    if (procNameLen != 0) {
        WCHAR* slash = wcsrchr(processNameBuf, L'\\');
        if (slash == NULL) {
            slash = wcsrchr(processNameBuf, L'/');
        }
        wcsncpy_s(report->processName, DEF_MAX_IMAGE_NAME,
                  (slash != NULL) ? slash + 1 : processNameBuf, _TRUNCATE);
    }

    report->currentPolicy = BofpGetProcessPolicyInternal(processId);
    report->appliedPolicy = policyMask;

#define BOF_RECORD_SUCCESS(tech)                                               \
    do {                                                                       \
        if (report->successCount < BOF_MAX_SUCCESSFUL_POLICIES) {              \
            report->successfulPolicies[report->successCount++] = (UINT64)(tech); \
        }                                                                      \
    } while (0)

#define BOF_RECORD_FAILURE(tech, fmt)                                          \
    do {                                                                       \
        if (report->failureCount < BOF_MAX_FAILED_POLICIES) {                  \
            BOF_HARDENING_FAILED_ENTRY* fe =                                  \
                &report->failedPolicies[report->failureCount];                 \
            fe->technique = (UINT64)(tech);                                    \
            _snwprintf_s(fe->message, BOF_MAX_FAILED_MSG_LEN, _TRUNCATE,        \
                         L"SetProcessMitigationPolicy failed: 0x%08X", fmt);    \
            report->failureCount++;                                            \
        }                                                                      \
    } while (0)

    /* DEP */
    if (policyMask & BOF_PROTECT_DEP) {
        PROCESS_MITIGATION_DEP_POLICY depPolicy;
        memset(&depPolicy, 0, sizeof(depPolicy));
        depPolicy.Enable = 1;
        depPolicy.DisableAtlThunkEmulation = 1;
        depPolicy.Permanent = (policyMask & BOF_PROTECT_PERMANENT_DEP) ? 1 : 0;

        if (SetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_DEP);
            if (depPolicy.Permanent) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_PERMANENT_DEP);
            }
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_DEP, GetLastError());
        }
    }

    /* ASLR */
    if (policyMask & BOF_PROTECT_ASLR) {
        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy;
        memset(&aslrPolicy, 0, sizeof(aslrPolicy));
        aslrPolicy.EnableBottomUpRandomization =
            (policyMask & BOF_PROTECT_BOTTOM_UP_ASLR) ? 1 : 0;
        aslrPolicy.EnableForceRelocateImages =
            (policyMask & BOF_PROTECT_FORCE_RELOCATE) ? 1 : 0;
        aslrPolicy.EnableHighEntropy =
            (policyMask & BOF_PROTECT_HIGH_ENTROPY_ASLR) ? 1 : 0;

        if (SetProcessMitigationPolicy(ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_ASLR);
            if (aslrPolicy.EnableHighEntropy) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_HIGH_ENTROPY_ASLR);
            }
            if (aslrPolicy.EnableBottomUpRandomization) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_BOTTOM_UP_ASLR);
            }
            if (aslrPolicy.EnableForceRelocateImages) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_FORCE_RELOCATE);
            }
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_ASLR, GetLastError());
        }
    }

    /* CFG */
    if (policyMask & BOF_PROTECT_CFG) {
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy;
        memset(&cfgPolicy, 0, sizeof(cfgPolicy));
        cfgPolicy.EnableControlFlowGuard = 1;
        cfgPolicy.StrictMode = (policyMask & BOF_PROTECT_STRICT_CFG) ? 1 : 0;

        if (SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy,
                                       &cfgPolicy, sizeof(cfgPolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_CFG);
            if (cfgPolicy.StrictMode) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_STRICT_CFG);
            }
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_CFG, GetLastError());
        }
    }

    /* 动态代码禁用 */
    if (policyMask & BOF_PROTECT_DISABLE_DYN_CODE) {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicPolicy;
        memset(&dynamicPolicy, 0, sizeof(dynamicPolicy));
        dynamicPolicy.ProhibitDynamicCode = 1;
        dynamicPolicy.AllowThreadOptOut =
            (policyMask & BOF_PROTECT_ALLOW_THREAD_OPTOUT) ? 1 : 0;

        if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy,
                                       &dynamicPolicy, sizeof(dynamicPolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_DISABLE_DYN_CODE);
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_DISABLE_DYN_CODE, GetLastError());
        }
    }

    /* 严格句柄检查 */
    if (policyMask & BOF_PROTECT_STRICT_HANDLE) {
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy;
        memset(&handlePolicy, 0, sizeof(handlePolicy));
        handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handlePolicy.HandleExceptionsPermanentlyEnabled = 1;

        if (SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy,
                                       &handlePolicy, sizeof(handlePolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_STRICT_HANDLE);
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_STRICT_HANDLE, GetLastError());
        }
    }

    /* 镜像加载 */
    if ((policyMask & BOF_PROTECT_BLOCK_REMOTE_IMG) ||
        (policyMask & BOF_PROTECT_BLOCK_LOW_LABEL) ||
        (policyMask & BOF_PROTECT_PREFER_SYSTEM32)) {
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY imagePolicy;
        memset(&imagePolicy, 0, sizeof(imagePolicy));
        imagePolicy.NoRemoteImages =
            (policyMask & BOF_PROTECT_BLOCK_REMOTE_IMG) ? 1 : 0;
        imagePolicy.NoLowMandatoryLabelImages =
            (policyMask & BOF_PROTECT_BLOCK_LOW_LABEL) ? 1 : 0;
        imagePolicy.PreferSystem32Images =
            (policyMask & BOF_PROTECT_PREFER_SYSTEM32) ? 1 : 0;

        if (SetProcessMitigationPolicy(ProcessImageLoadPolicy,
                                       &imagePolicy, sizeof(imagePolicy))) {
            if (imagePolicy.NoRemoteImages) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_BLOCK_REMOTE_IMG);
            }
            if (imagePolicy.NoLowMandatoryLabelImages) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_BLOCK_LOW_LABEL);
            }
            if (imagePolicy.PreferSystem32Images) {
                BOF_RECORD_SUCCESS(BOF_PROTECT_PREFER_SYSTEM32);
            }
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_BLOCK_REMOTE_IMG, GetLastError());
        }
    }

    /* 扩展点禁用 */
    if (policyMask & BOF_PROTECT_DISABLE_EXT_PTS) {
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPolicy;
        memset(&extPolicy, 0, sizeof(extPolicy));
        extPolicy.DisableExtensionPoints = 1;

        if (SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy,
                                       &extPolicy, sizeof(extPolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_DISABLE_EXT_PTS);
        } else {
            BOF_RECORD_FAILURE(BOF_PROTECT_DISABLE_EXT_PTS, GetLastError());
        }
    }

    /* 硬件 CET 影子栈 (Win10 2004+ 且 CPU 支持; ERROR_NOT_SUPPORTED 静默) */
    if ((policyMask & BOF_PROTECT_HARDWARE_CET) && g_cetAvailable) {
        SS_USER_SHADOW_STACK_POLICY cetPolicy;
        memset(&cetPolicy, 0, sizeof(cetPolicy));
        cetPolicy.EnableUserShadowStack = 1;

        if (SetProcessMitigationPolicy(ProcessUserShadowStackPolicy,
                                       &cetPolicy, sizeof(cetPolicy))) {
            BOF_RECORD_SUCCESS(BOF_PROTECT_HARDWARE_CET);
            BOF_RECORD_SUCCESS(BOF_PROTECT_SHADOW_STACK);
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_NOT_SUPPORTED) {
                BOF_RECORD_FAILURE(BOF_PROTECT_HARDWARE_CET, err);
            }
        }
    }

#undef BOF_RECORD_SUCCESS
#undef BOF_RECORD_FAILURE

    /* 评分与建议 */
    report->hardeningScore =
        BofpCalculateHardeningScore(report->successfulPolicies,
                                    report->successCount);

    CloseHandle(hProcess);

    InterlockedIncrement64((volatile LONGLONG*)&g_processesHardened);
    return TRUE;
}

/**************************************************/
/*  公共 API                                      */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
BofInitialize(const BOF_CONFIG* config)
{
    BOOLEAN wasInitialized;

    wasInitialized = (BOOLEAN)_InterlockedExchange8(
        (volatile char*)&g_initialized, (char)TRUE);
    if (wasInitialized) {
        return TRUE;
    }

    g_status = BofStatus_Initializing;

    /* 配置校验 (SS: interval==0 → 无效; defaultPolicy.IsValid 恒真) */
    if (config != NULL && !BofConfigIsValid(config)) {
        g_status = BofStatus_Error;
        _InterlockedExchange8((volatile char*)&g_initialized, (char)FALSE);
        return FALSE;
    }

    memset(&g_config, 0, sizeof(g_config));
    if (config != NULL) {
        g_config = *config;
    } else {
        g_config.enabled = TRUE;
        g_config.defaultPolicy = BOF_POLICY_SECURE_DEFAULT;
        g_config.enableExceptionMonitoring = TRUE;
        g_config.enableHeapValidation = TRUE;
        g_config.enableCanaryChecks = TRUE;
        g_config.canaryCheckIntervalMs = BOF_CANARY_CHECK_INTERVAL_MS;
        g_config.terminateOnExploit = TRUE;
        g_config.autoHardenProcesses = TRUE;
        g_config.enableShadowStack = FALSE;
        g_config.enableFormatStringProtection = TRUE;
        g_config.enableIntegerOverflowDetection = TRUE;
    }

    /* 硬件能力检测 (SS 构造时 DetectHardwareCapabilities) */
    BofpDetectHardwareCapabilities();

    /* 启动时刻 (统计快照用) */
    GetSystemTimeAsFileTime(&g_startTime);
    g_startTick = GetTickCount64();

    g_status = BofStatus_Running;
    return TRUE;
}

_Use_decl_annotations_
VOID
BofShutdown(VOID)
{
    if (!_InterlockedExchange8((volatile char*)&g_initialized, (char)FALSE)) {
        return;
    }

    g_status = BofStatus_Stopped;

    /* 清空监控集合 */
    AcquireSRWLockExclusive(&g_monitorLock);
    g_monitoredCount = 0;
    ReleaseSRWLockExclusive(&g_monitorLock);

    /* 清空事件环形 */
    AcquireSRWLockExclusive(&g_eventsLock);
    g_eventsHead = 0;
    g_eventsCount = 0;
    ReleaseSRWLockExclusive(&g_eventsLock);

    /* 清空回调 */
    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = NULL;
    ReleaseSRWLockExclusive(&g_callbackLock);
}

_Use_decl_annotations_
BOOLEAN
BofIsInitialized(VOID)
{
    return g_initialized;
}

_Use_decl_annotations_
BOF_MODULE_STATUS
BofGetStatus(VOID)
{
    return g_status;
}

_Use_decl_annotations_
BOOLEAN
BofUpdateConfiguration(const BOF_CONFIG* config)
{
    if (config == NULL || !BofConfigIsValid(config)) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_stateLock);
    g_config = *config;
    ReleaseSRWLockExclusive(&g_stateLock);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
BofGetConfiguration(BOF_CONFIG* config)
{
    if (config == NULL) {
        return FALSE;
    }
    if (!g_initialized) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_stateLock);
    *config = g_config;
    ReleaseSRWLockShared(&g_stateLock);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
BofHardenProcess(UINT32 processId, BOF_POLICY policyMask,
                 BOF_HARDENING_REPORT* report)
{
    BOF_HARDENING_REPORT localReport;
    BOF_POLICY effective;

    effective = (policyMask != 0) ? policyMask : BOF_POLICY_SECURE_DEFAULT;

    if (!BofpHardenProcessInternal(processId, effective, &localReport)) {
        return FALSE;
    }

    /* 建议列表生成在加固成功后执行 (依赖 g_cetAvailable 已就绪) */
    BofpGenerateRecommendations(effective, NULL, 0,
                                &localReport.recommendations[0][0],
                                BOF_MAX_RECOMMENDATIONS * BOF_MAX_RECOMMENDATION_LEN);
    {
        UINT32 i;
        UINT32 c = 0;
        const WCHAR* p = &localReport.recommendations[0][0];
        /* 按 '\n' 分行计数 (生成函数以 '\n' 结尾) */
        for (i = 0; p[i] != L'\0'; i++) {
            if (p[i] == L'\n') {
                c++;
            }
        }
        localReport.recommendationCount = c;
    }

    if (report != NULL) {
        *report = localReport;
    }
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
BofGetProcessPolicy(UINT32 processId, BOF_POLICY* policyMask)
{
    BOF_POLICY mask;

    if (policyMask == NULL) {
        return FALSE;
    }
    mask = BofpGetProcessPolicyInternal(processId);
    *policyMask = mask;
    return (mask != 0);
}

_Use_decl_annotations_
BOOLEAN
BofHasProtection(UINT32 processId, UINT64 technique)
{
    BOF_POLICY mask;

    mask = BofpGetProcessPolicyInternal(processId);
    return (mask & technique) != 0;
}

_Use_decl_annotations_
BOOLEAN
BofGetHardeningScore(UINT32 processId, double* score)
{
    BOF_POLICY mask;
    UINT64 policies[3];
    UINT32 count;

    if (score == NULL) {
        return FALSE;
    }
    mask = BofpGetProcessPolicyInternal(processId);
    if (mask == 0) {
        return FALSE;
    }

    /* SS GetHardeningScore 仅按 DEP/ASLR/CFG 三项计分 */
    count = 0;
    if (mask & BOF_PROTECT_DEP) {
        policies[count++] = BOF_PROTECT_DEP;
    }
    if (mask & BOF_PROTECT_ASLR) {
        policies[count++] = BOF_PROTECT_ASLR;
    }
    if (mask & BOF_PROTECT_CFG) {
        policies[count++] = BOF_PROTECT_CFG;
    }
    *score = BofpCalculateHardeningScore(policies, count);
    return TRUE;
}

_Use_decl_annotations_
UINT32
BofGetRecommendations(UINT32 processId, WCHAR* buffer, UINT32 bufferLen)
{
    BOF_POLICY mask;
    UINT32 i;
    UINT32 c;

    if (buffer == NULL || bufferLen == 0) {
        return 0;
    }
    mask = BofpGetProcessPolicyInternal(processId);
    if (mask == 0) {
        buffer[0] = L'\0';
        return 0;
    }

    BofpGenerateRecommendations(mask, NULL, 0, buffer, bufferLen);
    c = 0;
    for (i = 0; buffer[i] != L'\0'; i++) {
        if (buffer[i] == L'\n') {
            c++;
        }
    }
    return c;
}

_Use_decl_annotations_
BOOLEAN
BofMonitorProcess(UINT32 processId)
{
    return BofpMonitorProcessInternal(processId);
}

_Use_decl_annotations_
BOOLEAN
BofStopMonitoring(UINT32 processId)
{
    return BofpStopMonitoringInternal(processId);
}

_Use_decl_annotations_
BOOLEAN
BofIsMonitoring(UINT32 processId)
{
    return BofpIsMonitoringInternal(processId);
}

_Use_decl_annotations_
UINT32
BofGetMonitoredProcesses(UINT32* buffer, UINT32 bufferLen)
{
    return BofpGetMonitoredProcessesInternal(buffer, bufferLen);
}

_Use_decl_annotations_
BOOLEAN
BofAnalyzeException(UINT32 processId, const BOF_EXCEPTION_CONTEXT* context,
                    BOF_EVENT* event)
{
    if (context == NULL || event == NULL) {
        return FALSE;
    }
    BofpAnalyzeExceptionInternal(processId, context, event);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
BofAnalyzeCrashDump(const WCHAR* dumpPath, BOF_EVENT* event)
{
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID baseAddr;
    MINIDUMP_HEADER* header;
    MINIDUMP_DIRECTORY* dir;
    VOID* streamData;
    ULONG streamSize;

    if (dumpPath == NULL || event == NULL) {
        return FALSE;
    }
    memset(event, 0, sizeof(*event));
    event->eventSequence = BofpNextEventSequence();
    GetSystemTimeAsFileTime(&event->timestamp);
    event->detectionMethod = BofDetect_HardwareTrap;
    event->status = BofExploit_Suspicious;

    if (GetFileAttributesW(dumpPath) == INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(event->details, BOF_MAX_DETAILS, L"Crash dump file not found");
        return FALSE;
    }

    hFile = CreateFileW(dumpPath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _snwprintf_s(event->details, BOF_MAX_DETAILS, _TRUNCATE,
                     L"Failed to open crash dump: error 0x%08X", GetLastError());
        return FALSE;
    }

    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        CloseHandle(hFile);
        wcscpy_s(event->details, BOF_MAX_DETAILS, L"Failed to map crash dump file");
        return FALSE;
    }

    baseAddr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (baseAddr == NULL) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        wcscpy_s(event->details, BOF_MAX_DETAILS, L"Failed to map view of crash dump");
        return FALSE;
    }

    header = (MINIDUMP_HEADER*)baseAddr;
    if (header->Signature != MINIDUMP_SIGNATURE) {
        UnmapViewOfFile(baseAddr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        wcscpy_s(event->details, BOF_MAX_DETAILS, L"Invalid minidump signature");
        return FALSE;
    }

    /* 解析异常流 (SS 同路径) */
    dir = NULL;
    streamData = NULL;
    streamSize = 0;
    if (MiniDumpReadDumpStream(baseAddr, ExceptionStream,
                               &dir, &streamData, &streamSize) && streamData != NULL) {
        MINIDUMP_EXCEPTION_STREAM* excStream =
            (MINIDUMP_EXCEPTION_STREAM*)streamData;
        MINIDUMP_EXCEPTION_RECORD* excRecord;
        BOF_EXCEPTION_CONTEXT ctx;
        UINT32 i;

        excRecord = &excStream->ExceptionRecord;
        event->threadId = excStream->ThreadId;
        event->instructionPointer = excRecord->ExceptionAddress;

        memset(&ctx, 0, sizeof(ctx));
        ctx.exceptionCode = excRecord->ExceptionCode;
        ctx.exceptionAddress = excRecord->ExceptionAddress;
        ctx.exceptionFlags = excRecord->ExceptionFlags;
        ctx.numParameters = excRecord->NumberParameters;
        if (ctx.numParameters > 15) {
            ctx.numParameters = 15;
        }
        for (i = 0; i < ctx.numParameters; i++) {
            ctx.parameters[i] = excRecord->ExceptionInformation[i];
        }
        ctx.isContinuable = (excRecord->ExceptionFlags == 0);
        ctx.isFirstChance = TRUE;
        event->hasExceptionContext = TRUE;
        event->exceptionContext = ctx;

        switch (excRecord->ExceptionCode) {
            case 0xC0000005:
                event->type = BofOverflow_OutOfBoundsWrite;
                event->severity = BofSeverity_High;
                break;
            case 0xC00000FD:
                event->type = BofOverflow_StackSmashing;
                event->severity = BofSeverity_Critical;
                break;
            case 0xC0000409:
                event->type = BofOverflow_StackCanaryCorrupt;
                event->severity = BofSeverity_Critical;
                event->status = BofExploit_ConfirmedExploit;
                break;
            default:
                event->type = BofOverflow_Unknown;
                event->severity = BofSeverity_Medium;
                break;
        }

        _snwprintf_s(event->details, BOF_MAX_DETAILS, _TRUNCATE,
                     L"Crash dump analysis: exception 0x%08X at 0x%llX (%s)",
                     excRecord->ExceptionCode, excRecord->ExceptionAddress,
                     BofGetExceptionCodeName(excRecord->ExceptionCode,
                                             NULL, 0));
    } else {
        wcscpy_s(event->details, BOF_MAX_DETAILS,
                 L"Crash dump contains no exception stream");
        UnmapViewOfFile(baseAddr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return TRUE;   /* 已读取但无异常流: 返回 TRUE, 事件含 details */
    }

    UnmapViewOfFile(baseAddr);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    BofpCacheEvent(event);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
BofAnalyzeMemoryRegion(UINT32 processId, UINT64 address, SIZE_T size,
                       BOF_EVENT* event)
{
    SIZE_T scanSize;
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    UINT8* buffer;
    SIZE_T bytesRead;
    BOOLEAN suspicious;
    BOF_SEVERITY curSeverity;
    BOF_OVERFLOW_TYPE curType;
    WCHAR detailBuf[256];
    SIZE_T i;

    if (processId == 0 || address == 0 || size == 0 || event == NULL) {
        return FALSE;
    }

    /* 读取上限 64KB 防资源耗尽 (SS MAX_SCAN_SIZE) */
    scanSize = size;
    if (scanSize > BOF_MAX_SCAN_SIZE) {
        scanSize = BOF_MAX_SCAN_SIZE;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, processId);
    if (hProcess == NULL) {
        return FALSE;
    }

    memset(&mbi, 0, sizeof(mbi));
    if (VirtualQueryEx(hProcess, (LPCVOID)(ULONG_PTR)address,
                       &mbi, sizeof(mbi)) == 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    buffer = (UINT8*)malloc(scanSize);
    if (buffer == NULL) {
        CloseHandle(hProcess);
        return FALSE;
    }

    bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)address,
                           buffer, scanSize, &bytesRead) || bytesRead == 0) {
        free(buffer);
        CloseHandle(hProcess);
        return FALSE;
    }

    memset(event, 0, sizeof(*event));
    event->eventSequence = BofpNextEventSequence();
    event->processId = processId;
    event->targetAddress = address;
    GetSystemTimeAsFileTime(&event->timestamp);
    event->detectionMethod = BofDetect_PatternMatch;
    event->status = BofExploit_Unknown;
    event->severity = BofSeverity_Medium;

    suspicious = FALSE;
    curSeverity = BofSeverity_Medium;
    curType = BofOverflow_Unknown;

#define BOF_UPGRADE_FINDING(type, sev, fmt, ...)                               \
    do {                                                                       \
        _snwprintf_s(detailBuf, 256, _TRUNCATE, fmt, __VA_ARGS__);             \
        if (!suspicious || (int)(sev) > (int)curSeverity) {                    \
            event->type = (type);                                              \
            event->severity = (sev);                                           \
            curSeverity = (sev);                                               \
            curType = (type);                                                  \
        }                                                                      \
        if (event->details[0] != L'\0') {                                      \
            wcscat_s(event->details, BOF_MAX_DETAILS, L" | ");                 \
        }                                                                      \
        wcscat_s(event->details, BOF_MAX_DETAILS, detailBuf);                  \
        suspicious = TRUE;                                                     \
    } while (0)

    /* 1. NOP sled (≥32 连续 0x90) */
    {
        SIZE_T nopCount = 0;
        for (i = 0; i < bytesRead; i++) {
            if (buffer[i] == 0x90) {
                nopCount++;
                if (nopCount >= BOF_NOP_SLED_MIN) {
                    BOF_UPGRADE_FINDING(BofOverflow_StackSmashing,
                                        BofSeverity_High,
                                        L"NOP sled at 0x%llX (%Iu bytes)",
                                        address + i - nopCount + 1, nopCount);
                    break;
                }
            } else {
                nopCount = 0;
            }
        }
    }

    /* 2. RWX 内存区 */
    if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
        BOF_UPGRADE_FINDING(BofOverflow_StackSmashing,
                            BofSeverity_Critical,
                            L"RWX region at 0x%llX (size: 0x%llX)",
                            address, (UINT64)mbi.RegionSize);
    }

    /* 3. SYSCALL; RET 小工具 */
    for (i = 0; i + 2 < bytesRead; i++) {
        if (buffer[i] == 0x0F && buffer[i + 1] == 0x05 && buffer[i + 2] == 0xC3) {
            BOF_UPGRADE_FINDING(BofOverflow_StackSmashing,
                                BofSeverity_Critical,
                                L"SYSCALL;RET gadget at 0x%llX",
                                address + i);
            break;
        }
    }

#undef BOF_UPGRADE_FINDING

    if (suspicious) {
        event->status = BofExploit_Suspicious;
        event->corruptedDataSize = (UINT32)bytesRead;
        if (event->corruptedDataSize > BOF_CORRUPTED_DATA_MAX) {
            event->corruptedDataSize = BOF_CORRUPTED_DATA_MAX;
        }
        /* 样本截取 (SS 在扫描缓冲上按 MAX_CORRUPTED_BYTES 截取) */
        memcpy(event->corruptedData, buffer, event->corruptedDataSize);
    }

    free(buffer);
    CloseHandle(hProcess);

    if (suspicious) {
        BofpCacheEvent(event);
        BofpInvokeDetectionCallbacks(event);
        return TRUE;
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
BofValidateHeap(UINT32 processId, UINT64 heapHandle,
                BOF_HEAP_ANALYSIS_RESULT* result)
{
    if (result == NULL) {
        return FALSE;
    }
    BofpValidateHeapInternal(processId, heapHandle, result);
    return TRUE;
}

_Use_decl_annotations_
UINT32
BofValidateAllHeaps(UINT32 processId,
                    BOF_HEAP_ANALYSIS_RESULT* results, UINT32 maxResults)
{
    return BofpValidateAllHeapsInternal(processId, results, maxResults);
}

_Use_decl_annotations_
BOOLEAN
BofValidateStackCanary(UINT32 processId, UINT32 threadId)
{
    return BofpValidateStackCanaryInternal(processId, threadId);
}

_Use_decl_annotations_
UINT32
BofGetCallStack(UINT32 processId, UINT32 threadId, UINT32 maxFrames,
                BOF_STACK_FRAME_INFO* frames)
{
    return BofpGetCallStackInternal(processId, threadId, maxFrames, frames);
}

_Use_decl_annotations_
BOOLEAN
BofIsCETAvailable(VOID)
{
    return g_cetAvailable;
}

_Use_decl_annotations_
BOOLEAN
BofIsHardwareShadowStackAvailable(VOID)
{
    return g_shadowStackAvailable;
}

_Use_decl_annotations_
BOF_CPU_VENDOR
BofGetCpuVendor(VOID)
{
    return g_cpuVendor;
}

_Use_decl_annotations_
UINT64
BofGetHardwareFeatures(VOID)
{
    return g_hardwareFeatures;
}

_Use_decl_annotations_
VOID
BofRegisterDetectionCallback(BOF_DETECTED_CALLBACK callback)
{
    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = callback;
    ReleaseSRWLockExclusive(&g_callbackLock);
}

_Use_decl_annotations_
VOID
BofUnregisterCallbacks(VOID)
{
    AcquireSRWLockExclusive(&g_callbackLock);
    g_detectionCallback = NULL;
    ReleaseSRWLockExclusive(&g_callbackLock);
}

_Use_decl_annotations_
BOOLEAN
BofGetStatistics(BOF_STATS_SNAPSHOT* snapshot)
{
    if (snapshot == NULL) {
        return FALSE;
    }
    snapshot->processesMonitored = g_processesMonitored;
    snapshot->processesHardened = g_processesHardened;
    snapshot->exceptionsHandled = g_exceptionsHandled;
    snapshot->stackOverflowsDetected = g_stackOverflowsDetected;
    snapshot->heapCorruptionsDetected = g_heapCorruptionsDetected;
    snapshot->formatStringsDetected = g_formatStringsDetected;
    snapshot->integerOverflowsDetected = g_integerOverflowsDetected;
    snapshot->useAfterFreeDetected = g_useAfterFreeDetected;
    snapshot->exploitsBlocked = g_exploitsBlocked;
    snapshot->processesTerminated = g_processesTerminated;
    snapshot->canaryChecks = g_canaryChecks;
    snapshot->canaryFailures = g_canaryFailures;
    snapshot->startTime = g_startTime;
    snapshot->uptimeSeconds =
        (GetTickCount64() - g_startTick) / 1000ULL;
    return TRUE;
}

_Use_decl_annotations_
VOID
BofResetStatistics(VOID)
{
    InterlockedExchange64((volatile LONGLONG*)&g_processesMonitored, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_processesHardened, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_exceptionsHandled, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_stackOverflowsDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_heapCorruptionsDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_formatStringsDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_integerOverflowsDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_useAfterFreeDetected, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_exploitsBlocked, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_processesTerminated, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_canaryChecks, 0);
    InterlockedExchange64((volatile LONGLONG*)&g_canaryFailures, 0);
    GetSystemTimeAsFileTime(&g_startTime);
    g_startTick = GetTickCount64();
}

_Use_decl_annotations_
UINT32
BofGetRecentEvents(BOF_EVENT* events, UINT32 maxCount)
{
    UINT32 i;
    UINT32 n;

    if (events == NULL || maxCount == 0) {
        return 0;
    }

    /* 最新在前 (SS rbegin 遍历) */
    AcquireSRWLockShared(&g_eventsLock);
    n = g_eventsCount;
    if (n > maxCount) {
        n = maxCount;
    }
    for (i = 0; i < n; i++) {
        UINT32 idx = (g_eventsHead + BOF_MAX_RECENT_EVENTS - 1 - i) %
                     BOF_MAX_RECENT_EVENTS;
        events[i] = g_recentEvents[idx];
    }
    ReleaseSRWLockShared(&g_eventsLock);

    return n;
}

_Use_decl_annotations_
BOOLEAN
BofSelfTest(VOID)
{
    BOF_CPU_VENDOR vendor;
    BOF_EXCEPTION_CONTEXT testCtx;
    BOF_EVENT event;
    BOF_STATS_SNAPSHOT stats;

    /* 项 1: CPU 厂商检测 (未知不致命, 仅验证路径可执行) */
    vendor = BofGetCpuVendor();
    UNREFERENCED_PARAMETER(vendor);

    /* 项 2: 策略位组合评分合理 (SS 位掩码往返测试的降级替代) */
    {
        UINT64 base[] = {
            BOF_PROTECT_DEP, BOF_PROTECT_ASLR, BOF_PROTECT_CFG,
            BOF_PROTECT_HARDWARE_CET
        };
        double score = BofpCalculateHardeningScore(base, 4);
        if (score <= 0.0 || score > 100.0) {
            return FALSE;
        }
    }

    /* 项 3: 异常分类 (0xC0000409 → 栈 cookie 破坏确认利用) */
    memset(&testCtx, 0, sizeof(testCtx));
    testCtx.exceptionCode = 0xC0000409;
    testCtx.exceptionAddress = 0x7FFE0000;
    BofpAnalyzeExceptionInternal(GetCurrentProcessId(), &testCtx, &event);
    if (event.type != BofOverflow_StackCanaryCorrupt) {
        return FALSE;
    }

    /* 项 4: 统计更新 */
    if (!BofGetStatistics(&stats) || stats.exceptionsHandled == 0) {
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
PCWSTR
BofGetVersionString(VOID)
{
    return L"3.0.0";
}

_Use_decl_annotations_
VOID
BofProcessKernelMemoryAlert(UINT32 msgType, const void* data, SIZE_T dataSize)
{
    const UINT8* rawBytes;
    UINT32 processId;
    UINT32 exceptionCode;
    UINT64 exceptionAddress;
    BOF_EXCEPTION_CONTEXT ctx;
    BOF_EVENT event;
    UINT32 i;
    BOOLEAN processExplicitlyMonitored;
    BOOLEAN globalKernelAlertMode;

    UNREFERENCED_PARAMETER(msgType);

    if (data == NULL || dataSize < sizeof(UINT32)) {
        return;
    }
    rawBytes = (const UINT8*)data;
    memcpy(&processId, rawBytes, sizeof(processId));
    if (processId == 0) {
        return;
    }

    /* 监控判定: 显式监控 或 空集时全局内核告警模式
     * (SS m_acceptKernelAlertsWhenMonitorSetEmpty 显式语义,
     * 避免 "空集=全 PID" 隐式副作用)
     * 注意: 此处直接在持锁状态下遍历数组 (勿调用 BofpIsMonitoringInternal,
     * 其内部会再次获取 g_monitorLock, SRWLock 同名递归获取将死锁) */
    processExplicitlyMonitored = FALSE;
    AcquireSRWLockShared(&g_monitorLock);
    for (i = 0; i < g_monitoredCount; i++) {
        if (g_monitoredProcesses[i] == processId) {
            processExplicitlyMonitored = TRUE;
            break;
        }
    }
    globalKernelAlertMode = (g_monitoredCount == 0);
    ReleaseSRWLockShared(&g_monitorLock);
    if (!processExplicitlyMonitored && !globalKernelAlertMode) {
        return;
    }

    /* 载荷: [UINT32 pid][UINT32 excCode][UINT64 excAddr]
     * (内核报文布局) */
    memset(&ctx, 0, sizeof(ctx));
    exceptionCode = 0;
    exceptionAddress = 0;
    if (dataSize >= sizeof(UINT32) * 2) {
        memcpy(&exceptionCode, rawBytes + sizeof(UINT32), sizeof(UINT32));
    }
    if (dataSize >= sizeof(UINT32) * 2 + sizeof(UINT64)) {
        memcpy(&exceptionAddress, rawBytes + sizeof(UINT32) * 2,
               sizeof(UINT64));
    }
    ctx.exceptionCode = exceptionCode;
    ctx.exceptionAddress = exceptionAddress;

    BofpAnalyzeExceptionInternal(processId, &ctx, &event);
    /* SS 在此按 severity≥Medium 上报 ThreatDetector — 该依赖已裁剪,
     * 事件已入环形 + 回调, 由上层订阅者消费 */
}

/**************************************************/
/*  配置有效性                                    */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
BofConfigIsValid(const BOF_CONFIG* config)
{
    if (config == NULL) {
        return FALSE;
    }
    if (config->canaryCheckIntervalMs == 0) {
        return FALSE;
    }
    return TRUE;
}

/**************************************************/
/*  名称工具函数                                  */
/**************************************************/

_Use_decl_annotations_
PCWSTR
BofGetOverflowTypeName(BOF_OVERFLOW_TYPE type)
{
    switch (type) {
        case BofOverflow_Unknown:             return L"Unknown";
        case BofOverflow_StackSmashing:       return L"Stack Smashing";
        case BofOverflow_StackCanaryCorrupt:  return L"Stack Canary Corruption";
        case BofOverflow_SEHOverwrite:        return L"SEH Overwrite";
        case BofOverflow_HeapOverflow:        return L"Heap Overflow";
        case BofOverflow_HeapMetaCorrupt:     return L"Heap Metadata Corruption";
        case BofOverflow_FormatString:        return L"Format String";
        case BofOverflow_IntegerOverflow:     return L"Integer Overflow";
        case BofOverflow_IntegerUnderflow:    return L"Integer Underflow";
        case BofOverflow_UseAfterFree:        return L"Use After Free";
        case BofOverflow_DoubleFree:          return L"Double Free";
        case BofOverflow_HeapUseAfterRealloc: return L"Heap Use After Realloc";
        case BofOverflow_NullPointerDeref:    return L"Null Pointer Dereference";
        case BofOverflow_TypeConfusion:       return L"Type Confusion";
        case BofOverflow_OutOfBoundsRead:     return L"Out of Bounds Read";
        case BofOverflow_OutOfBoundsWrite:    return L"Out of Bounds Write";
        case BofOverflow_UninitializedMemory: return L"Uninitialized Memory";
        case BofOverflow_OffByOne:            return L"Off-by-One";
        default:                              return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
BofGetProtectionTechniqueName(UINT64 technique)
{
    switch (technique) {
        case BOF_PROTECT_STACK_CANARY:        return L"Stack Canary";
        case BOF_PROTECT_SAFE_SEH:            return L"SafeSEH";
        case BOF_PROTECT_SEHOP:               return L"SEHOP";
        case BOF_PROTECT_DEP:                 return L"DEP";
        case BOF_PROTECT_PERMANENT_DEP:       return L"Permanent DEP";
        case BOF_PROTECT_ASLR:                return L"ASLR";
        case BOF_PROTECT_HIGH_ENTROPY_ASLR:   return L"High-Entropy ASLR";
        case BOF_PROTECT_BOTTOM_UP_ASLR:      return L"Bottom-Up ASLR";
        case BOF_PROTECT_FORCE_RELOCATE:      return L"Force Relocate";
        case BOF_PROTECT_HEAP_TERMINATE:      return L"Heap Terminate on Corruption";
        case BOF_PROTECT_CFG:                 return L"Control Flow Guard";
        case BOF_PROTECT_STRICT_CFG:          return L"Strict CFG";
        case BOF_PROTECT_SHADOW_STACK:        return L"Shadow Stack";
        case BOF_PROTECT_HARDWARE_CET:        return L"Hardware CET";
        case BOF_PROTECT_RETURN_ADDR_VERIFY:  return L"Return Address Verification";
        case BOF_PROTECT_IMPORT_ADDR_FILTER:  return L"Import Address Filter";
        case BOF_PROTECT_EXPORT_ADDR_FILTER:  return L"Export Address Filter";
        case BOF_PROTECT_STRICT_HANDLE:       return L"Strict Handle Check";
        case BOF_PROTECT_DISABLE_DYN_CODE:    return L"Disable Dynamic Code";
        case BOF_PROTECT_DISALLOW_WIN32K:     return L"Disallow Win32k Syscalls";
        case BOF_PROTECT_DISABLE_EXT_PTS:     return L"Disable Extension Points";
        case BOF_PROTECT_BLOCK_REMOTE_IMG:    return L"Block Remote Images";
        case BOF_PROTECT_BLOCK_LOW_LABEL:     return L"Block Low-Label Images";
        case BOF_PROTECT_PREFER_SYSTEM32:     return L"Prefer System32 Images";
        case BOF_PROTECT_PROHIBIT_DYN_CODE:   return L"Prohibit Dynamic Code";
        case BOF_PROTECT_ALLOW_THREAD_OPTOUT: return L"Allow Thread Opt-Out";
        case BOF_PROTECT_AUDIT_ONLY:          return L"Audit Only Mode";
        default:                              return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
BofGetExploitStatusName(BOF_EXPLOIT_STATUS status)
{
    switch (status) {
        case BofExploit_Unknown:          return L"Unknown";
        case BofExploit_Safe:             return L"Safe";
        case BofExploit_Suspicious:       return L"Suspicious";
        case BofExploit_LikelyExploit:    return L"Likely Exploit";
        case BofExploit_ConfirmedExploit: return L"Confirmed Exploit";
        case BofExploit_Blocked:          return L"Blocked";
        case BofExploit_Terminated:       return L"Terminated";
        default:                          return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
BofGetExploitSeverityName(BOF_SEVERITY severity)
{
    switch (severity) {
        case BofSeverity_Information: return L"Information";
        case BofSeverity_Low:         return L"Low";
        case BofSeverity_Medium:      return L"Medium";
        case BofSeverity_High:        return L"High";
        case BofSeverity_Critical:    return L"Critical";
        default:                      return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
BofGetDetectionMethodName(BOF_DETECTION_METHOD method)
{
    switch (method) {
        case BofDetect_Unknown:          return L"Unknown";
        case BofDetect_ExceptionHandler: return L"Exception Handler";
        case BofDetect_CanaryCheck:      return L"Canary Check";
        case BofDetect_ShadowStackMis:   return L"Shadow Stack Mismatch";
        case BofDetect_HeapValidation:   return L"Heap Validation";
        case BofDetect_HookDetection:    return L"Hook Detection";
        case BofDetect_PatternMatch:     return L"Pattern Match";
        case BofDetect_Heuristic:        return L"Heuristic";
        case BofDetect_HardwareTrap:     return L"Hardware Trap";
        case BofDetect_ApiMonitoring:    return L"API Monitoring";
        default:                         return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
BofGetExceptionCodeName(UINT32 code, WCHAR* buffer, UINT32 bufferLen)
{
    switch (code) {
        case 0xC0000005: return L"EXCEPTION_ACCESS_VIOLATION";
        case 0xC00000FD: return L"EXCEPTION_STACK_OVERFLOW";
        case 0xC0000409: return L"STATUS_STACK_BUFFER_OVERRUN";
        case 0xC000001D: return L"EXCEPTION_ILLEGAL_INSTRUCTION";
        case 0xC0000094: return L"EXCEPTION_INT_DIVIDE_BY_ZERO";
        case 0xC000008C: return L"EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case 0xC0000095: return L"EXCEPTION_INT_OVERFLOW";
        case 0xC000008D: return L"EXCEPTION_FLT_DENORMAL_OPERAND";
        case 0xC000008E: return L"EXCEPTION_FLT_DIVIDE_BY_ZERO";
        default:
            if (buffer != NULL && bufferLen > 0) {
                _snwprintf_s(buffer, bufferLen, _TRUNCATE,
                             L"EXCEPTION_0x%08X", code);
                return buffer;
            }
            return L"EXCEPTION_UNKNOWN";
    }
}

_Use_decl_annotations_
BOOLEAN
BofIsExploitException(UINT32 exceptionCode)
{
    switch (exceptionCode) {
        case 0xC0000005:  /* EXCEPTION_ACCESS_VIOLATION */
        case 0xC00000FD:  /* EXCEPTION_STACK_OVERFLOW */
        case 0xC0000409:  /* STATUS_STACK_BUFFER_OVERRUN */
        case 0xC000001D:  /* EXCEPTION_ILLEGAL_INSTRUCTION */
        case 0xC000008C:  /* EXCEPTION_ARRAY_BOUNDS_EXCEEDED */
            return TRUE;
        default:
            return FALSE;
    }
}