/**************************************************/
/*  WkDefender 死代码 — 进程分析器搁置能力实现       */
/*  迁移自 ShadowStrike ProcessAnalyzer             */
/*  功能面全量迁移，当前不接入流水线（见头文件声明）   */
/**************************************************/

#include "ProcessAnalyzer_DeadCode.h"
#include "WkDefenderHeader.h"
#include "Storage/StorageEngine.h"
#include "IOA/IoaEngine.h"
#include "Process/ProcessTree.h"
#include "IOA/IoaTypes.h"
#include "IOC/IocScanner.h"
#include "IOC/IocProcessEnrich.h"
#include "IOC/PEAnalyzer/PeAnalyzer.h"
#include "Memory/MemoryScan.h"
#include "ProcessThreads.h"
#include "NetworkFootprint.h"
#include <tlhelp32.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "sqlite3.lib")

/**************************************************/
/*           ntdll 动态 API（句柄枚举）             */
/**************************************************/

typedef NTSTATUS (NTAPI* PNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* PNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI* PNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID      Object;
    ULONG_PTR  UniqueProcessId;
    ULONG_PTR  HandleValue;
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/* NtQueryObject(ObjectTypeInformation) 返回结构，仅需首字段 TypeName */
typedef struct _SYSTEM_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG          TotalNumberOfObjects;
    ULONG          TotalNumberOfHandles;
    ULONG          TotalPagedPoolUsage;
    ULONG          TotalNonPagedPoolUsage;
    ULONG          TotalNamePoolUsage;
    ULONG          TotalHandleTableUsage;
    ULONG          HighWaterNumberOfObjects;
    ULONG          HighWaterNumberOfHandles;
    ULONG          HighWaterPagedPoolUsage;
    ULONG          HighWaterNonPagedPoolUsage;
    ULONG          HighWaterNamePoolUsage;
    ULONG          HighWaterHandleTableUsage;
    ULONG          InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG          ValidAccessMask;
    BOOLEAN        SecurityRequired;
    BOOLEAN        MaintainHandleCount;
    BOOLEAN        MaintainTypeList;
    BOOLEAN        Unknown0;
} SYSTEM_OBJECT_TYPE_INFORMATION, *PSYSTEM_OBJECT_TYPE_INFORMATION;

#define WKD_SYS_HANDLE_INFO_EX   64   /* SystemExtendedHandleInformation */
#define WKD_OBJ_NAME_INFO        1    /* ObjectNameInformation */
#define WKD_OBJ_TYPE_INFO        2    /* ObjectTypeInformation */

static PNtQuerySystemInformation g_NtQuerySystemInformation = NULL;
static PNtDuplicateObject       g_NtDuplicateObject = NULL;
static PNtQueryObject           g_NtQueryObject = NULL;

static BOOLEAN
WkdPdLoadNtdllApis(VOID)
{
    if (g_NtQuerySystemInformation) return TRUE;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    g_NtQuerySystemInformation = (PNtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    g_NtDuplicateObject = (PNtDuplicateObject)
        GetProcAddress(hNtdll, "NtDuplicateObject");
    g_NtQueryObject = (PNtQueryObject)
        GetProcAddress(hNtdll, "NtQueryObject");

    return (g_NtQuerySystemInformation && g_NtDuplicateObject && g_NtQueryObject);
}

/**************************************************/
/*         ① 句柄分析（对齐 PS EnumerateHandles）  */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPdEnumerateHandles(
    DWORD               ProcessId,
    PWKD_HANDLE_SUMMARY Summary
    )
/*++
Routine Description:
    通过 NtQuerySystemInformation(SystemExtendedHandleInformation) 枚举全系统
    句柄，过滤目标进程，检测敏感访问模式（LSASS / 跨进程 / 敏感注册表 / 系统目录写）。

    ★ 死代码：需 SeDebugPrivilege 才能枚举他人句柄；且依赖 ObjectNotify
      事件流才能从"快照式枚举"升级为"实时事件"。当前不接入流水线。

Arguments:
    ProcessId - 目标进程 PID。
    Summary   - 输出句柄分析结果。

Return Value:
    NTSTATUS。
--*/
{
    ULONG bufSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION_EX pInfo = NULL;
    NTSTATUS status;
    ULONG retLen = 0;
    ULONG i;

    if (!Summary) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Summary, sizeof(*Summary));

    if (!WkdPdLoadNtdllApis()) return STATUS_PROCEDURE_NOT_FOUND;

    /* 首次查询确定缓冲区大小 */
    status = g_NtQuerySystemInformation(WKD_SYS_HANDLE_INFO_EX, NULL, 0, &retLen);
    if (status == STATUS_INFO_LENGTH_MISMATCH && retLen > 0) {
        bufSize = retLen + 4096;
    }

    pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufSize);
    if (!pInfo) return STATUS_NO_MEMORY;

    status = g_NtQuerySystemInformation(WKD_SYS_HANDLE_INFO_EX, pInfo, bufSize, &retLen);
    if (status < 0) {
        free(pInfo);
        return status;
    }

    /* 打开目标进程，用于 NtDuplicateObject 复制句柄到自身 */
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProc) {
        free(pInfo);
        return STATUS_ACCESS_DENIED;
    }

    /* 自身进程句柄，作为复制目标 */
    HANDLE hSelf = GetCurrentProcess();

    for (i = 0; i < pInfo->NumberOfHandles && Summary->AnalyzedCount < WKD_HANDLE_MAX_ANALYZE; i++) {
        const PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX h = &pInfo->Handles[i];
        if (h->UniqueProcessId != ProcessId) continue;

        Summary->TotalHandles++;

        /* 复制句柄到自身进程以查询 */
        HANDLE hDup = NULL;
        status = g_NtDuplicateObject(
            hProc,
            (HANDLE)(ULONG_PTR)h->HandleValue,
            hSelf, &hDup,
            0, 0, 0);
        if (status < 0 || !hDup) continue;

        /* 获取类型名 */
        BYTE typeBuf[512];
        ULONG typeLen = 0;
        WCHAR typeName[64] = { 0 };
        if (g_NtQueryObject(hDup, WKD_OBJ_TYPE_INFO, typeBuf, sizeof(typeBuf), &typeLen) >= 0) {
            /* OBJECT_TYPE_INFORMATION.TypeName 是 UNICODE_STRING */
            PUNICODE_STRING pus = &((PSYSTEM_OBJECT_TYPE_INFORMATION)typeBuf)->TypeName;
            if (pus->Buffer && pus->Length < sizeof(typeName)) {
                memcpy(typeName, pus->Buffer, pus->Length);
                typeName[pus->Length / sizeof(WCHAR)] = L'\0';
            }
        }

        /* 获取对象名 */
        BYTE nameBuf[1024];
        ULONG nameLen = 0;
        WCHAR objName[260] = { 0 };
        if (g_NtQueryObject(hDup, WKD_OBJ_NAME_INFO, nameBuf, sizeof(nameBuf), &nameLen) >= 0) {
            PUNICODE_STRING pus = (PUNICODE_STRING)nameBuf;
            if (pus->Buffer && pus->Length < sizeof(objName)) {
                memcpy(objName, pus->Buffer, pus->Length);
                objName[pus->Length / sizeof(WCHAR)] = L'\0';
            }
        }

        CloseHandle(hDup);

        /* ── 检测敏感访问模式（对齐 PS EnumerateHandlesInternal）── */
        PWKD_HANDLE_INFO info = &Summary->SuspiciousHandles[Summary->SuspiciousCount];
        info->HandleValue = h->HandleValue;
        info->GrantedAccess = h->GrantedAccess;
        wcsncpy_s(info->ObjectName, RTL_NUMBER_OF(info->ObjectName), objName, _TRUNCATE);

        /* 句柄类型分类 */
        if (_wcsicmp(typeName, L"Process") == 0)       info->Kind = WkdHk_Process;
        else if (_wcsicmp(typeName, L"Thread") == 0)   info->Kind = WkdHk_Thread;
        else if (_wcsicmp(typeName, L"Key") == 0)      info->Kind = WkdHk_Key;
        else if (_wcsicmp(typeName, L"File") == 0)     info->Kind = WkdHk_File;
        else if (_wcsicmp(typeName, L"Token") == 0)    info->Kind = WkdHk_Token;
        else if (_wcsicmp(typeName, L"DebugObject") == 0) info->Kind = WkdHk_DebugObject;
        else                                           info->Kind = WkdHk_Other;

        BOOLEAN suspicious = FALSE;

        /* 1. LSASS 访问 */
        if (wcsstr(objName, L"\\lsass") != NULL ||
            _wcsicmp(objName, L"lsass.exe") == 0) {
            Summary->HasLsassAccess = TRUE;
            info->Kind = WkdHk_Process;
            info->IsSuspicious = TRUE;
            info->RiskScore = 50;
            wcscpy_s(info->SuspicionReason, RTL_NUMBER_OF(info->SuspicionReason),
                     L"Handle to LSASS process");
            suspicious = TRUE;
        }

        /* 2. 跨进程句柄 */
        if (_wcsicmp(typeName, L"Process") == 0 && h->GrantedAccess != 0 &&
            !info->IsSuspicious) {
            Summary->HasCrossProcessHandles = TRUE;
            info->IsSuspicious = TRUE;
            info->RiskScore = 30;
            wcscpy_s(info->SuspicionReason, RTL_NUMBER_OF(info->SuspicionReason),
                     L"Cross-process handle");
            suspicious = TRUE;
        }

        /* 3. 敏感注册表访问 */
        if (wcsstr(objName, L"\\registry\\machine\\sam") != NULL ||
            wcsstr(objName, L"\\registry\\machine\\security") != NULL) {
            Summary->HasSensitiveRegAccess = TRUE;
            info->Kind = WkdHk_Key;
            info->IsSuspicious = TRUE;
            info->RiskScore = 40;
            wcscpy_s(info->SuspicionReason, RTL_NUMBER_OF(info->SuspicionReason),
                     L"Access to sensitive registry hive");
            suspicious = TRUE;
        }

        /* 4. 系统目录写访问 */
        if (wcsstr(objName, L"\\windows\\system32") != NULL &&
            (h->GrantedAccess & (GENERIC_WRITE | FILE_WRITE_DATA))) {
            Summary->HasSystemDirWrite = TRUE;
            info->IsSuspicious = TRUE;
            info->RiskScore = 35;
            wcscpy_s(info->SuspicionReason, RTL_NUMBER_OF(info->SuspicionReason),
                     L"Write access to system directory");
            suspicious = TRUE;
        }

        if (suspicious) {
            Summary->SuspiciousCount++;
        }

        Summary->AnalyzedCount++;
    }

    CloseHandle(hProc);
    free(pInfo);
    return STATUS_SUCCESS;
}

/**************************************************/
/*          ② 调用栈回溯（对齐 PS GetThreadCallStack）*/
/**************************************************/

typedef struct _WKD_STACK_MODULE {
    ULONG_PTR Base;
    SIZE_T    Size;
    WCHAR     Name[64];
} WKD_STACK_MODULE;

#define WKD_STACK_MAX_MODULES 512

static ULONG
WkdPdEnumerateModulesForStack(
    _In_  DWORD              ProcessId,
    _Out_ WKD_STACK_MODULE*  Modules,
    _In_  ULONG              Max
    )
{
    HANDLE hSnapshot;
    MODULEENTRY32W me;
    ULONG count = 0;

    hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (count >= Max) break;
            Modules[count].Base = (ULONG_PTR)me.modBaseAddr;
            Modules[count].Size = me.modBaseSize;
            wcsncpy_s(Modules[count].Name, RTL_NUMBER_OF(Modules[count].Name),
                      me.szModule, _TRUNCATE);
            count++;
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return count;
}

static BOOLEAN
WkdPdResolveFrameModule(
    _In_  ULONG_PTR Address,
    _In_  const WKD_STACK_MODULE* Modules,
    _In_  ULONG Count,
    _Out_writes_(OutCch) WCHAR* OutName,
    _In_  ULONG OutCch
    )
{
    ULONG i;
    for (i = 0; i < Count; i++) {
        if (Address >= Modules[i].Base &&
            Address < Modules[i].Base + Modules[i].Size) {
            wcsncpy_s(OutName, OutCch, Modules[i].Name, _TRUNCATE);
            return TRUE;
        }
    }
    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
WkdPdGetThreadCallStack(
    DWORD             ThreadId,
    PWKD_STACK_TRACE  Trace
    )
/*++
Routine Description:
    挂起线程，获取上下文，沿 RBP 链遍历调用栈，统计返回地址的模块支撑。

    ★ 死代码：RBP 链遍历对优化代码（省略帧指针）不完整，且需挂起线程
      有副作用。等 ThreadHijack 迁移后一并接入。

Arguments:
    ThreadId - 目标线程 TID。
    Trace    - 输出调用栈。

Return Value:
    NTSTATUS。
--*/
{
    HANDLE hThread;
    CONTEXT ctx;
    DWORD ownerPid;
    HANDLE hProcess = NULL;
    WKD_STACK_MODULE modules[WKD_STACK_MAX_MODULES];
    ULONG modCount;
    ULONG_PTR framePtr;
    ULONG frames = 0;

    if (!Trace) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Trace, sizeof(*Trace));

    hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
        FALSE, ThreadId);
    if (!hThread) return STATUS_UNSUCCESSFUL;

    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        return STATUS_UNSUCCESSFUL;
    }

    ctx.ContextFlags = CONTEXT_FULL;
    BOOL ok = GetThreadContext(hThread, &ctx);
    ownerPid = GetProcessIdOfThread(hThread);   /* 需在 CloseHandle 前获取 */
    ResumeThread(hThread);
    CloseHandle(hThread);

    if (!ok || ownerPid == 0) return STATUS_UNSUCCESSFUL;

    /* 模块预枚举一次 */
    modCount = WkdPdEnumerateModulesForStack(ownerPid, modules, WKD_STACK_MAX_MODULES);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ownerPid);
    if (!hProcess) return STATUS_UNSUCCESSFUL;

    Trace->CurrentIp = ctx.Rip;

    /* 沿 RBP 链回溯（对齐 PS 快速启发式，非 StackWalk64） */
    framePtr = ctx.Rbp;
    while (frames < WKD_STACK_MAX_FRAMES && framePtr != 0) {
        ULONG_PTR stackFrame[2] = { 0 };   /* [0]=next RBP, [1]=return addr */
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProcess, (LPCVOID)framePtr,
                               stackFrame, sizeof(stackFrame), &bytesRead) ||
            bytesRead < sizeof(stackFrame)) {
            break;
        }
        if (stackFrame[1] == 0) break;

        WKD_STACK_FRAME* f = &Trace->Frames[frames];
        f->ReturnAddress = stackFrame[1];
        f->IsBacked = WkdPdResolveFrameModule(
            stackFrame[1], modules, modCount,
            f->ModuleName, RTL_NUMBER_OF(f->ModuleName));
        if (!f->IsBacked) {
            Trace->UnbackedFrameCount++;
        }

        frames++;

        /* 防无限循环：下一帧指针必须递增 */
        if (stackFrame[0] <= framePtr) break;
        framePtr = stackFrame[0];
    }

    Trace->FrameCount = frames;
    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}

/**************************************************/
/*     ③ 行为编排骨架（对齐 PS AnalyzeBehavior）   */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPdAnalyzeBehavior(
    DWORD                    ProcessId,
    PWKD_BEHAVIOR_INDICATORS Indicators
    )
/*++
Routine Description:
    聚合 6 专项检测器 + 内存扫描器结果，产出行为指标。

    ProcessHollowing 已接入 IpeDetectProcessHollowing (主动扫描);
    其余检测器 (DLLInjection/Reflective/ThreadHijack/AtomBombing) 尚未迁移,
    保持 FALSE 待后续接线。

Arguments:
    ProcessId  - 目标进程 PID。
    Indicators - 输出行为指标。

Return Value:
    NTSTATUS。
--*/
{
    WKD_HOLLOWING_RESULT hollow = { 0 };

    if (!Indicators) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Indicators, sizeof(*Indicators));

    /* ProcessHollowing 主动扫描 (对齐 PS AnalyzeBehaviorInternal) */
    if (IpeDetectProcessHollowing(ProcessId, WkdMemScan_Normal, &hollow) &&
        hollow.IsHollowed) {
        Indicators->HasProcessHollowing = TRUE;
        Indicators->BehaviorRiskScore += 40;   /* RISK_WEIGHT_HOLLOWING */
    }

    /* 其余检测器迁移后在此接线:
     * HasRemoteThreads  = <ProcessInjectionDetector::IsProcessInjected(pid)> (+25)
     * HasDirectSyscalls = <MemoryScanner 直接系统调用检测> (+30)
     * HasAPCsQueued     = <AtomBombingDetector/APC 事件> (+?)
     */
    Indicators->BehaviorRiskScore = min(Indicators->BehaviorRiskScore, 100);

    return STATUS_SUCCESS;
}

/**************************************************/
/*    ④ 证书黑名单（对齐 PS IsCertificateCompromised）*/
/**************************************************/

_Use_decl_annotations_
BOOLEAN
WkdPdIsCertificateCompromised(
    PCWSTR Thumbprint
    )
/*++
Routine Description:
    查询 ioc_certs 表（DefIocSrc_CertBlacklist），判定证书是否在黑名单。
    wkd 表以 subject（证书主题）为键，传入指纹/主题字符串。

    ★ 死代码：依赖 ioc_certs 表已填充证书黑名单数据（当前无生产者）。

Arguments:
    Thumbprint - 证书指纹或主题字符串。

Return Value:
    TRUE = 命中黑名单。
--*/
{
    sqlite3_stmt* stmt = NULL;
    char utf8Subject[256] = { 0 };
    BOOLEAN found = FALSE;

    if (!Thumbprint || !Thumbprint[0]) return FALSE;
    if (!WkdStorageEngine.WarmDb) return FALSE;

    WideCharToMultiByte(CP_UTF8, 0, Thumbprint, -1,
                        utf8Subject, sizeof(utf8Subject), NULL, NULL);

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb,
            "SELECT verdict FROM ioc_certs WHERE subject=? LIMIT 1",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, utf8Subject, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            found = (sqlite3_column_int(stmt, 0) == DefIocVerdict_Malicious);
        }
        sqlite3_finalize(stmt);
    }

    return found;
}

/**************************************************/
/*   ⑤ 白名单强制完整性检查（对齐 PS L894）        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPdCheckWhitelistedIntegrity(
    DWORD                    ProcessId,
    PWKD_WHITELIST_INTEGRITY Result
    )
/*++
Routine Description:
    对白名单进程执行强制完整性检查：白名单不是免死金牌，
    命中镂空/反射/注入即撤销白名单信任。

    ★ 死代码：依赖 ProcessHollowingDetector / ReflectiveDLLDetector /
      ProcessInjectionDetector——检测器未迁移，当前全部 FALSE。
      检测器迁移后接线，命中分值与 PS 一致（镂空 95 / 反射 90 / 注入 85）。

Arguments:
    ProcessId - 白名单进程 PID。
    Result    - 输出完整性检查结果。

Return Value:
    NTSTATUS。
--*/
{
    UNREFERENCED_PARAMETER(ProcessId);

    if (!Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    /* 检测器迁移后接线示例：
     *   Result->HasProcessHollowing = <ProcessHollowingDetector::IsHollowed(ProcessId)>;
     *   Result->HasReflectiveDll    = <ReflectiveDLLDetector::HasReflectiveLoading(ProcessId)>;
     *   Result->HasInjection        = <ProcessInjectionDetector::IsProcessInjected(ProcessId)>;
     *   if (任一命中) { Result->IsTampered = TRUE;
     *       Result->RevokedTrustScore = (HasProcessHollowing ? 95 :
     *                                    HasReflectiveDll ? 90 : 85); }
     */

    return STATUS_SUCCESS;
}

/**************************************************/
/*   ⑥ 深度取证编排入口（对齐 PS AnalyzeProcess）  */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPdAnalyzeProcess(
    DWORD                       ProcessId,
    PWKD_PROCESS_FORENSICS_RESULT Result
    )
/*++
Routine Description:
    深度取证编排入口：综合调用已迁移的画像能力（签名/模块/内存/线程/
    网络/句柄/行为 + 父-子），填充 WKD_RISK_INPUT，计算进程级综合风险分。

    ★ 死代码：当前不接入 IoaObserve 主事件流。父-子分析依赖 IOA 谱系
      （事件驱动，未覆盖的进程跳过该维度）。

Arguments:
    ProcessId - 目标进程 PID。
    Result    - 输出各画像维度 + 综合风险。

Return Value:
    NTSTATUS。
--*/
{
    WCHAR filePath[MAX_PATH] = { 0 };
    WKD_SUSPICIOUS_MODULE modules[64];
    ULONG modCount = 0;
    ULONG suspiciousCount = 0, unsignedCount = 0;
    WKD_RISK_INPUT riskInput;
    WPA_RISK_LEVEL level;
    ULONG i;

    if (!Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    RtlZeroMemory(&riskInput, sizeof(riskInput));

    /* 1. 进程路径（对齐 PS SafeGetProcessInfo->executablePath） */
    {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
        if (hProc) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProc, 0, filePath, &size);
            CloseHandle(hProc);
        }
    }

    /* 2. 签名 + 恶意哈希（对齐 PS AnalyzeProcessInternal 先 IsKnownMalicious 再验签） */
    if (filePath[0] &&
        IocVerifySignature(filePath, &Result->Ioc) == STATUS_SUCCESS) {
        riskInput.CertStatus = Result->Ioc.CertStatus;

        /* 补算哈希并查询恶意库（VerifySignature 不填哈希，此处补全对齐 PS IsKnownMalicious） */
        DEF_SHA256_HASH hash;
        BOOLEAN malicious = FALSE;
        if (IocScanner_ComputeFileSha256(filePath, &hash) &&
            IocScanner_QueryHash(&hash, &malicious) == STATUS_SUCCESS && malicious) {
            riskInput.HashFoundMalicious = TRUE;
        }
    }

    /* 3. 模块可疑 + 未签名计数（IpeFindSuspiciousModules，含逐模块验签） */
    IpeFindSuspiciousModules(ProcessId, modules, 64, &modCount);
    for (i = 0; i < modCount; i++) {
        suspiciousCount++;
        if (modules[i].Flags & WKD_SMF_UNSIGNED) unsignedCount++;
    }
    riskInput.SuspiciousActiveModules = suspiciousCount;
    riskInput.UnsignedActiveModules = unsignedCount;

    /* 4. 内存画像（MsScanMemoryProfile） */
    MsScanMemoryProfile(ProcessId, &Result->Memory);
    riskInput.RwxRegionCount = Result->Memory.RwxRegionCount;
    riskInput.UnbackedExecRegionCount = Result->Memory.UnbackedExecRegionCount;

    /* 5. 线程画像（WptAnalyzeThreads） */
    WptAnalyzeThreads(ProcessId, &Result->Threads);
    riskInput.UnbackedStartCount = Result->Threads.UnbackedStartCount;

    /* 6. 网络足迹（WnfAnalyzeNetworkFootprint） */
    WnfAnalyzeNetworkFootprint(ProcessId, &Result->Network);

    /* 7. 父-子异常 + PPID（尽力而为：使用 IOA 谱系节点，谱系未覆盖则跳过） */
    {
        PWKD_PROCESS child = NULL;
        if (NT_SUCCESS(PsLookupWkdProcessByStrictProcessId(
                &WkdProcessTree, (HANDLE)(ULONG_PTR)ProcessId, NULL, &child))) {
            if (child && child->Parent) {
                WKD_PARENT_CHILD_RESULT pc;
                IpeAnalyzeParentChild(child, child->Parent, &pc);
                riskInput.ParentAnomaly = (pc.Anomaly != WkdPaNormal);
                riskInput.PpidSpoofed = pc.IsPpidSpoofed;
            }
            PsDereferenceWkdProcess(child);   /* 归还查找 pin */
        }
    }

    /* 8. 句柄分析（死代码）+ 行为编排（死代码） */
    WkdPdEnumerateHandles(ProcessId, &Result->Handles);
    WkdPdAnalyzeBehavior(ProcessId, &Result->Behavior);
    riskInput.HasProcessHollowing = Result->Behavior.HasProcessHollowing;
    riskInput.HasDirectSyscalls = Result->Behavior.HasDirectSyscalls;
    riskInput.HasRemoteThreads = Result->Behavior.HasRemoteThreads;

    /* 9. 综合评分（WpeCalculateOverallRisk，对齐 PS CalculateOverallRisk） */
    Result->OverallRiskScore = WpeCalculateOverallRisk(&riskInput, &level);
    Result->RiskLevel = level;

    return STATUS_SUCCESS;
}

/**************************************************/
/*   ⑦ 快评与工具方法（对齐 PS 末尾工具区）        */
/**************************************************/

static BOOLEAN
WkdPdStrStrI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T len;

    if (!Haystack || !Needle || !Needle[0]) return FALSE;
    len = wcslen(Needle);
    for (; *Haystack; Haystack++) {
        if (_wcsnicmp(Haystack, Needle, len) == 0) return TRUE;
    }
    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
WkdPdIsMicrosoftSigned(
    PCWSTR FilePath
    )
/*++
Routine Description:
    判定文件是否为微软签名（对齐 PS IsMicrosoftSignedInternal）：
    签名有效且签名者命中微软精确全串表。

Arguments:
    FilePath - 文件完整路径。

Return Value:
    TRUE = 微软签名。
--*/
{
    IOC_SCAN_RESULT ioc;

    if (!FilePath) return FALSE;
    if (IocVerifySignature(FilePath, &ioc) != STATUS_SUCCESS) return FALSE;
    if (ioc.CertStatus != DefCertStatus_Valid) return FALSE;
    /* 统一判定辅助 (2026-08 统一接入: 读统一入口填充的 SignerCategory,
     * 名称+指纹双通道; 原子串匹配绕过已修复) */
    return IocScan_IsMicrosoftSigned(&ioc);
}

_Use_decl_annotations_
NTSTATUS
WkdPdIsWhitelisted(
    DWORD    ProcessId,
    PBOOLEAN Whitelisted
    )
/*++
Routine Description:
    判定进程是否白名单（对齐 PS IsWhitelistedInternal）。
    PS 用白名单库 + 微软签名；wkd agent 侧白名单库在 driver（Exempts），
    此处以微软签名 + 系统目录路径近似。★ 死代码：接入时建议对接 driver 白名单。

Arguments:
    ProcessId  - 目标进程 PID。
    Whitelisted - 输出是否白名单。

Return Value:
    NTSTATUS。
--*/
{
    WCHAR filePath[MAX_PATH] = { 0 };
    HANDLE hProc;
    DWORD size;

    if (!Whitelisted) return STATUS_INVALID_PARAMETER;
    *Whitelisted = FALSE;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (!hProc) return STATUS_SUCCESS;
    size = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, filePath, &size);
    CloseHandle(hProc);

    if (!filePath[0]) return STATUS_SUCCESS;

    if (WkdPdIsMicrosoftSigned(filePath)) {
        *Whitelisted = TRUE;
        return STATUS_SUCCESS;
    }
    if (WkdPdStrStrI(filePath, L"\\windows\\system32") ||
        WkdPdStrStrI(filePath, L"\\windows\\syswow64")) {
        *Whitelisted = TRUE;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
WkdPdIsCriticalProcess(
    PCWSTR ProcessName
    )
/*++
Routine Description:
    判定进程名是否为关键进程（对齐 PS IsCriticalProcess）：
    csrss/lsass/services/smss/wininit/winlogon。

Arguments:
    ProcessName - 进程文件名或完整路径。

Return Value:
    TRUE = 关键进程。
--*/
{
    PCWSTR name;

    if (!ProcessName || !ProcessName[0]) return FALSE;

    name = wcsrchr(ProcessName, L'\\');
    name = name ? name + 1 : ProcessName;

    return (_wcsicmp(name, L"csrss.exe") == 0 ||
            _wcsicmp(name, L"lsass.exe") == 0 ||
            _wcsicmp(name, L"services.exe") == 0 ||
            _wcsicmp(name, L"smss.exe") == 0 ||
            _wcsicmp(name, L"wininit.exe") == 0 ||
            _wcsicmp(name, L"winlogon.exe") == 0);
}

typedef NTSTATUS (NTAPI* PNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

_Use_decl_annotations_
BOOLEAN
WkdPdIsBeingDebugged(
    DWORD ProcessId
    )
/*++
Routine Description:
    判定进程是否被调试（对齐 PS IsBeingDebugged）：查询 DebugPort。

Arguments:
    ProcessId - 目标进程 PID。

Return Value:
    TRUE = 被调试。
--*/
{
    static PNtQueryInformationProcess pNtQuery = NULL;
    HANDLE hProc;
    ULONG_PTR debugPort = 0;
    ULONG retLen = 0;
    NTSTATUS status;

    if (!pNtQuery) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pNtQuery = (PNtQueryInformationProcess)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
        if (!pNtQuery) return FALSE;
    }

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProc) return FALSE;

    /* ProcessDebugPort = 7 */
    status = pNtQuery(hProc, 7, &debugPort, sizeof(debugPort), &retLen);
    CloseHandle(hProc);

    if (status < 0) return FALSE;
    return (debugPort != 0);
}

_Use_decl_annotations_
BOOLEAN
WkdPdGetBackingModule(
    DWORD     ProcessId,
    ULONG_PTR Address,
    WCHAR*    ModuleName,
    ULONG     ModuleNameCch
    )
/*++
Routine Description:
    查询地址归属模块（对齐 PS GetBackingModule）：Toolhelp 模块枚举比对。

Arguments:
    ProcessId     - 目标进程 PID。
    Address       - 待查询地址。
    ModuleName    - 输出模块名。
    ModuleNameCch - 输出缓冲字符数。

Return Value:
    TRUE = 地址落在某模块内。
--*/
{
    HANDLE hSnapshot;
    MODULEENTRY32W me;
    BOOLEAN found = FALSE;

    if (!ModuleName || ModuleNameCch == 0) return FALSE;
    ModuleName[0] = L'\0';

    hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            ULONG_PTR base = (ULONG_PTR)me.modBaseAddr;
            if (Address >= base && Address < base + me.modBaseSize) {
                wcsncpy_s(ModuleName, ModuleNameCch, me.szModule, _TRUNCATE);
                found = TRUE;
                break;
            }
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return found;
}

_Use_decl_annotations_
NTSTATUS
WkdPdQuickAssessRisk(
    DWORD          ProcessId,
    PWPA_RISK_LEVEL Level
    )
/*++
Routine Description:
    快评 API（对齐 PS QuickAssessRiskInternal）：
      白名单 → Trusted；恶意哈希 → Malicious；微软签名 → Trusted；
      Revoked → Malicious；Unsigned → LowRisk；否则 Unknown。

Arguments:
    ProcessId - 目标进程 PID。
    Level     - 输出风险等级。

Return Value:
    NTSTATUS。
--*/
{
    WCHAR filePath[MAX_PATH] = { 0 };
    DEF_SHA256_HASH hash;
    BOOLEAN foundMalicious = FALSE;
    BOOLEAN whitelisted = FALSE;
    IOC_SCAN_RESULT ioc;
    HANDLE hProc;
    DWORD size;

    if (!Level) return STATUS_INVALID_PARAMETER;
    *Level = WkdRl_Unknown;

    /* 1. 白名单 → Trusted */
    WkdPdIsWhitelisted(ProcessId, &whitelisted);
    if (whitelisted) {
        *Level = WkdRl_Trusted;
        return STATUS_SUCCESS;
    }

    /* 2. 恶意哈希 → Malicious */
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProc) {
        size = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, filePath, &size);
        CloseHandle(hProc);
    }
    if (filePath[0] && IocScanner_ComputeFileSha256(filePath, &hash)) {
        if (IocScanner_QueryHash(&hash, &foundMalicious) == STATUS_SUCCESS &&
            foundMalicious) {
            *Level = WkdRl_Malicious;
            return STATUS_SUCCESS;
        }
    }

    /* 3. 签名判定 */
    if (filePath[0] &&
        IocVerifySignature(filePath, &ioc) == STATUS_SUCCESS) {
        if (ioc.CertStatus == DefCertStatus_Valid && WkdPdIsMicrosoftSigned(filePath)) {
            *Level = WkdRl_Trusted;
        } else if (ioc.CertStatus == DefCertStatus_Revoked) {
            *Level = WkdRl_Malicious;
        } else if (ioc.CertStatus == DefCertStatus_Unsigned) {
            *Level = WkdRl_LowRisk;
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*   ⑧ 完整模块清单（对齐 PS GetLoadedModules）    */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPdGetLoadedModules(
    DWORD             ProcessId,
    PWKD_LOADED_MODULE Modules,
    ULONG             MaxModules,
    PULONG            Count
    )
/*++
Routine Description:
    枚举进程全部已加载模块 + 逐模块验签状态
    （对齐 PS GetLoadedModulesInternal：模块清单 + 每模块签名验证）。

Arguments:
    ProcessId  - 目标进程 PID。
    Modules    - 输出模块数组。
    MaxModules - 输出缓冲上限。
    Count      - 输出实际模块数。

Return Value:
    NTSTATUS。
--*/
{
    HANDLE hSnapshot;
    MODULEENTRY32W me;
    ULONG found = 0;

    if (!Modules || MaxModules == 0 || !Count) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return STATUS_SUCCESS;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (found >= MaxModules) break;

            PWKD_LOADED_MODULE m = &Modules[found];
            m->BaseAddress = (ULONG_PTR)me.modBaseAddr;
            m->SizeOfImage = me.modBaseSize;
            wcsncpy_s(m->ModulePath, RTL_NUMBER_OF(m->ModulePath), me.szExePath, _TRUNCATE);
            wcsncpy_s(m->ModuleName, RTL_NUMBER_OF(m->ModuleName), me.szModule, _TRUNCATE);

            /* 逐模块验签（对齐 PS GetLoadedModulesInternal） */
            IOC_SCAN_RESULT sig;
            if (IocVerifySignature(me.szExePath, &sig) == STATUS_SUCCESS) {
                m->CertStatus = sig.CertStatus;
            } else {
                m->CertStatus = DefCertStatus_Unknown;
            }

            found++;
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    *Count = found;
    return STATUS_SUCCESS;
}
