/**************************************************/
/*  WkDefender — 进程创建 IOC 检测流水线             */
/*                                                   */
/*  采集: 令牌属性/特权枚举/SessionId/完整性等级       */
/*  检测: PPID 欺骗/特权/命令行/Ghosting/签名/谱系    */
/**************************************************/

#include "IocProcess.h"
#include "AnalysisEngine.h"
#include "../Callbacks/ProcessNotify.h"
#include "../Process/ProcessPairContext.h"
#include "../Common/PeParser.h"
#include "../Common/PeCallbacks.h"
#include <ntimage.h>    /* IMAGE_DOS_HEADER / IMAGE_NT_HEADERS 等 PE 结构（DEP 静态特征采集用） */

//
// 外部引用：进程监控器全局状态（用于统计计数）
//
extern WKD_PROCESS_MONITOR g_WkdProcessMonitor;

//
// 全局威胁评分引擎（在 WkdEntry.c 中初始化）
//
extern PTS_ENGINE WkdTsEngine;

//
// 函数指针：PsGetProcessSessionId（某些 WDK 版本未导出，通过 MmGetSystemRoutineAddress 获取）
//
extern ULONG(*pfnPsGetProcessSessionId)(PEPROCESS Process);

//
// NTSYSAPI 声明：ZwQueryInformationProcess（用于 IocpCapturePrivilegeInfo Phase 6
// 运行时 DEP 查询，迁移自 SS PapAnalyzeSecurityMitigations；仿 HandleScanner.c
// L20-42 声明模式）
//
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/**************************************************/
/*            特权索引                             */
/**************************************************/

#ifndef SE_CREATE_TOKEN_PRIVILEGE
#define SE_CREATE_TOKEN_PRIVILEGE           2
#endif
#ifndef SE_ASSIGNPRIMARYTOKEN_PRIVILEGE
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     3
#endif
#ifndef SE_TCB_PRIVILEGE
#define SE_TCB_PRIVILEGE                    7
#endif
#ifndef SE_DEBUG_PRIVILEGE
#define SE_DEBUG_PRIVILEGE                  20
#endif
#ifndef SE_IMPERSONATE_PRIVILEGE
#define SE_IMPERSONATE_PRIVILEGE            41
#endif
#ifndef SE_BACKUP_PRIVILEGE
#define SE_BACKUP_PRIVILEGE                 17
#endif
#ifndef SE_RESTORE_PRIVILEGE
#define SE_RESTORE_PRIVILEGE                18
#endif

//
// DllCharacteristics 缓解位（对齐 SS PA_IMAGE_DLLCHAR_*，防御旧 SDK 缺宏）
//
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE   0x0040   /* ASLR */
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT      0x0100   /* DEP */
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF       0x4000   /* CFG */
#endif

/**************************************************/
/*       工具函数：UNICODE_STRING 子串搜索         */
/**************************************************/

static
BOOLEAN
IocpFindInUnicodeString(
    _In_ PUNICODE_STRING Haystack,
    _In_ PUNICODE_STRING Needle
    )
{
    ULONG i, j;
    ULONG needleChars, haystackChars;

    if (Haystack == NULL || Needle == NULL ||
        Haystack->Buffer == NULL || Needle->Buffer == NULL) {
        return FALSE;
    }

    needleChars = Needle->Length / sizeof(WCHAR);
    haystackChars = Haystack->Length / sizeof(WCHAR);

    if (needleChars == 0 || needleChars > haystackChars) {
        return FALSE;
    }

    for (i = 0; i <= haystackChars - needleChars; i++) {
        BOOLEAN match = TRUE;

        for (j = 0; j < needleChars; j++) {
            WCHAR h = RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]);
            WCHAR n = RtlUpcaseUnicodeChar(Needle->Buffer[j]);

            if (h != n) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

/**************************************************/
/*       工具函数：哈希（大小写不敏感）             */
/**************************************************/

static
ULONG
IocpHashStringInsensitive(
    _In_ PCWSTR String,
    _In_ ULONG LengthInChars
    )
{
    ULONG hash = 5381;

    for (ULONG i = 0; i < LengthInChars && String[i] != L'\0'; i++) {
        WCHAR c = String[i];
        if (c >= L'A' && c <= L'Z') {
            c += (L'a' - L'A');
        }
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

/**************************************************/
/*       工具函数：提取文件名（最后一段）           */
/**************************************************/

static
BOOLEAN
IocpExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    )
{
    LONG i;

    if (!FullPath || !FullPath->Buffer || FullPath->Length == 0 || !FileName) {
        return FALSE;
    }

    ULONG charCount = FullPath->Length / sizeof(WCHAR);

    for (i = (LONG)charCount - 1; i >= 0; i--) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            i++;
            break;
        }
    }
    if (i < 0) i = 0;

    FileName->Buffer = &FullPath->Buffer[i];
    FileName->Length = (USHORT)((charCount - i) * sizeof(WCHAR));
    FileName->MaximumLength = FileName->Length;
    return TRUE;
}

/**************************************************/
/*       系统进程判定                             */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
WkdIsSystemProcess(
    _In_ HANDLE Pid
    )
{
    return (HandleToULong(Pid) <= 4);
}

/**************************************************/
/*       §1 PPID 欺骗检测                         */
/**************************************************/

//
// 创建时序合法性：声称父创建时间晚于子进程 → 时序异常（PID 复用 / 伪造父身份，
// 对齐 SS PctDetectSpoofing 创建时间序校验）。
// 从 EPROCESS 直取父创建时间（PsGetProcessCreateTimeQuadPart），不依赖 WKD_PROCESS
// 表——创建回调内父进程必然存活，但父可能未被 wkd 跟踪（boot-grace / Agent 未连接
// 快速路径不建条目）。查找失败静默跳过（不误报）。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
IocpIsParentCreatedAfterChild(
    _In_ HANDLE ParentProcessId,
    _In_ PLARGE_INTEGER ChildCreateTime
    )
{
    PEPROCESS parentProcess = NULL;
    LARGE_INTEGER parentCreateTime = { 0 };

    if (ParentProcessId == NULL || HandleToULong(ParentProcessId) <= 4) {
        return FALSE;   /* System/Idle 启动最早，无时序判定意义 */
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId(ParentProcessId, &parentProcess))) {
        parentCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(parentProcess);
        ObDereferenceObject(parentProcess);
        return (parentCreateTime.QuadPart > ChildCreateTime->QuadPart);
    }

    return FALSE;   /* 声称父已退出（查不到）→ 静默跳过，不误报 */
}

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
IocpDetectPpidSpoofing(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    AE_THREAT_SEVERITY severity = AeThreatSeverityNone;
    HANDLE parentPid, creatorPid;
    PWKD_PROCESS creator;

    if (!Pair || !WkdProcess || !WkdProcess->SecurityContext) {
        return STATUS_INVALID_PARAMETER;
    }
    WkdProcess->SecurityContext->PpidSpoofingDetected = FALSE;

    parentPid = WkdProcess->Core.ParentProcessId;
    creatorPid = WkdProcess->Core.CreatorProcessId;
    if (!parentPid || !creatorPid) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 本地创建 → 正常 */
    if (creatorPid == parentPid) return STATUS_SUCCESS;

    /* 例外1: 创建者是关键系统进程（排除命中）→ 放行 */
    creator = PsLookupWkdProcessByProcessId(creatorPid);
    if (creator) {
        if (creator->SecurityFlags.Trusted) {
            PsDereferenceWkdProcess(creator);
            return STATUS_SUCCESS;
        }
        PsDereferenceWkdProcess(creator);
    }

    /* 例外2: 自父化（orphaning 技术，可疑） */
    if (WkdProcess->Core.ProcessId == parentPid) {
        severity = AeThreatSeverityLow;
        goto Found;
    }

    /* 创建时序合法：父创建时间晚于子 → 时序异常（强信号）。
     * 时序命中合并进 PpidSpoofing 上报（用户决策，不复用 DeepPpidSpoofing）。 */
    if (IocpIsParentCreatedAfterChild(parentPid, &WkdProcess->Core.CreateTime)) {
        severity = AeThreatSeverityHigh;
    }

Found:
    WkdProcess->SecurityContext->PpidSpoofingDetected = TRUE;
    AeReportIndicatorEx(Pair, TsSourceIOC, TsIndicator_Process_PpidSpoofing, severity);
    return STATUS_SUCCESS;
}

/**************************************************/
/*       §2 令牌信息与特权捕获                    */
/**************************************************/

//
// 参考: ProcessAnalyzer.c PmCapturePrivilegeInfo（完整6阶段）
//
static
NTSTATUS
IocpCapturePrivilegeInfo(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    NTSTATUS status;
    PACCESS_TOKEN token;

    if (!WkdProcess || !WkdProcess->SecurityContext) {
        return STATUS_INVALID_PARAMETER;
    }

    token = PsReferencePrimaryToken(WkdProcess->Core.EProcess);
    if (!token) {
        return STATUS_UNSUCCESSFUL;
    }

    /* ---- Phase 1: 令牌属性 & 进程提权 ---- */
    {
        PTOKEN_ELEVATION elevated;

        /* 调用方负责释放内存 */
        status = SeQueryInformationToken(token, TokenElevation, &elevated);
        if (NT_SUCCESS(status)) {
            /* 该令牌是“提升的”或“高权限的”。通常指管理员账户经过 UAC 提升后获得的完全管理员令牌（完整权限）*/
            WkdProcess->SecurityContext->Elevated = elevated->TokenIsElevated;
            ExFreePool(elevated);
        }

        if (SeTokenIsRestricted(token)) {
            /* 受限令牌是通过 CreateRestrictedToken API（或其内核等效操作）创建的，
             * 它从父令牌中移除了部分权限和/或安全标识符（SID），或者给 SID 打上“限制性”标记。
             * 当一个进程使用受限令牌运行时，它只能访问那些同时被限制 SID 列表所允许的资源。
             */
            WkdProcess->SecurityContext->Restricted = TRUE;
        }
    }

    /* ---- Phase 2: 敏感特权枚举 ---- */
    {
        PTOKEN_PRIVILEGES privileges;

        // 获取令牌的所有特权列表
        status = SeQueryInformationToken(token, TokenPrivileges, &privileges);
        if (NT_SUCCESS(status)) {
            WkdProcess->SecurityContext->PrivilegeCount = privileges->PrivilegeCount;

            for (ULONG i = 0; i < privileges->PrivilegeCount; i++) {
                LUID tempLuid;
                PLUID_AND_ATTRIBUTES laa = &privileges->Privileges[i];

                if (!(laa->Attributes & SE_PRIVILEGE_ENABLED)) {
                    continue;
                }

                /*
                 * “替换进程级令牌”特权。
                 * 该特权允许进程调用 SetTokenInformation 或 NtSetInformationProcess 来替换进程的 Primary Token。
                 * 恶意软件可以用它来将一个受限令牌替换为高权限令牌（例如从 SYSTEM 线程窃取），实现提权。
                 */
                tempLuid = RtlConvertLongToLuid(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeAssignPrimaryTokenPrivilege = TRUE;
                    continue;
                }

                /*
                 * “以操作系统方式执行”特权（TCB，Trusted Computing Base）。
                 * 这是 Windows 中最高危险级别的特权之一。拥有该特权的进程相当于完全被信任，可以：
                 * - 访问任何受保护的对象
                 * - 调用 NtCreateToken 创建任意令牌
                 * - 突破对象安全性检查
                 * 绝大多数正常进程不会启用此特权。一旦发现，几乎可以确定为攻击行为
                 * （例如漏洞利用后提权，或进程本身就是 SYSTEM 且令牌被非法启用该特权）。
                 */
                tempLuid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeTcbPrivilege = TRUE;
                    AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_SeTcbPrivilege);
                    continue;
                }

                /*
                 * “加载和卸载设备驱动程序”特权。
                 * 启用此特权的进程可以加载内核驱动，而加载未签名或恶意驱动是 Rootkit 的常见初始步骤。
                 */
                tempLuid = RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeLoadDriverPrivilege = TRUE;
                    continue;
                }

                /* 
                 * “调试程序”特权。
                 * 这是恶意软件最爱的特权之一。启用后，进程可以：
                 * - 使用 OpenProcess 打开任意受保护进程（如 lsass.exe）的全部访问权限
                 * - 通过 WriteProcessMemory 或 CreateRemoteThread 进行代码注入
                 * - 调用 NtSetInformationProcess 篡改进程内存
                 * 虽然部分开发工具和调试器需要此特权，但在非预期进程（如 Office 宏、脚本引擎子进程）中出现时，
                 * 几乎就是凭据窃取或代码注入的前兆。
                 */
                tempLuid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeDebugPrivilege = TRUE;
                    AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_SeDebugPrivilege);
                    continue;
                }

                /*
                 * “身份验证后模拟客户端”特权。
                 * 允许进程模拟另一个用户的安全上下文。滥用它可以：
                 * - 通过 ImpersonateLoggedOnUser 等 API 获取 SYSTEM 权限（例如配合命名管道烟囱攻击） 
                 * - 在 RPC 调用中提升特权
                 * 该特权的启用常伴随横向移动或提权尝试
                 */
                tempLuid = RtlConvertLongToLuid(SE_IMPERSONATE_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeImpersonatePrivilege = TRUE;
                    AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_SeImpersonatePrivilege);
                    continue;
                }

                /*
                 * “备份文件和目录”特权（SE_BACKUP_PRIVILEGE）。
                 * 允许进程绕过 ACL 读取任意文件（含 SAM/SYSTEM 注册表配置单元），
                 * 是凭据转储（Credential Dumping）的常见前置特权。
                 * 对齐 SS PapAnalyzeProcessToken L2325-2326（仅置字段，不单独上报指示器）。
                 */
                tempLuid = RtlConvertLongToLuid(SE_BACKUP_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeBackupPrivilege = TRUE;
                    continue;
                }

                /*
                 * “还原文件和目录”特权（SE_RESTORE_PRIVILEGE）。
                 * 允许进程绕过 ACL 写入任意文件（含覆盖受保护系统文件），
                 * 常与 SeBackupPrivilege 成对出现，用于系统文件替换（SFC 绕过）。
                 * 对齐 SS PapAnalyzeProcessToken L2329-2330（仅置字段，不单独上报指示器）。
                 */
                tempLuid = RtlConvertLongToLuid(SE_RESTORE_PRIVILEGE);
                if (RtlEqualLuid(&laa->Luid, &tempLuid)) {
                    WkdProcess->SecurityContext->SeRestorePrivilege = TRUE;
                    continue;
                }
            }
        }

        // 调用者手动释放缓冲区
        ExFreePool(privileges);
    }

    /* ---- Phase 3: SessionId ---- */
    {
        ULONG sessionId = 0;

        if (NT_SUCCESS(SeQuerySessionIdToken(token, &sessionId))) {
            WkdProcess->SecurityContext->SessionId = sessionId;
        }

        // 获取父进程 SessionId
        if (WkdProcess->Core.ParentProcessId) {
            PEPROCESS parentProcess = NULL;

            if (NT_SUCCESS(PsLookupProcessByProcessId(
                WkdProcess->Core.ParentProcessId, &parentProcess))) {
                PACCESS_TOKEN parentToken =
                    PsReferencePrimaryToken(parentProcess);

                if (parentToken) {
                    ULONG parentSessionId = 0;

                    if (NT_SUCCESS(SeQuerySessionIdToken(parentToken,
                        &parentSessionId))) {
                        WkdProcess->SecurityContext->ParentSessionId = parentSessionId;
                    }

                    PsDereferencePrimaryToken(parentToken);
                }

                ObDereferenceObject(parentProcess);
            }
        }
    }

    /* ---- Phase 4: 进程属性 ---- */
    {
        ULONG integrityLevel = 0;
        PTOKEN_USER tokenUser = NULL;

        if (SeTokenIsAdmin(token)) {
            WkdProcess->SecurityContext->IsAdmin = TRUE;
        }
        
        // 完整性级别
        status = SeQueryInformationToken(token,
            TokenIntegrityLevel, &integrityLevel);
        if (NT_SUCCESS(status)) {
            WkdProcess->SecurityContext->IntegrityLevel = integrityLevel;

            if (integrityLevel == WkdIntegritySystem) {
                WkdProcess->SecurityContext->IsSystem = TRUE;
            }
        }

        // 检查用户账户
        /* 参考：https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_se_exports */
        status = SeQueryInformationToken(token, TokenUser, &tokenUser);
        if (NT_SUCCESS(status)) {

            if ((RtlEqualSid(tokenUser->User.Sid, SeExports->SeLocalSystemSid) ||
                RtlEqualSid(tokenUser->User.Sid, SeExports->SeLocalServiceSid) ||
                RtlEqualSid(tokenUser->User.Sid, SeExports->SeNetworkServiceSid))
                ) {
                WkdProcess->SecurityContext->IsService = TRUE;
            }

            ExFreePool(tokenUser);
        }        

        if (WkdProcess->SecurityContext->IsAdmin &&
            !WkdProcess->SecurityContext->IsService &&
            !WkdProcess->SecurityContext->IsSystem) {
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_Elevated);
        }
    }

    /* ---- Phase 5: 跨会话检测 ---- */
    if (WkdProcess->SecurityContext->ParentSessionId != INVALID_SESSION_ID &&
        WkdProcess->SecurityContext->SessionId != WkdProcess->SecurityContext->ParentSessionId) {

        if (WkdProcess->SecurityContext->ParentSessionId != 0 ||
            WkdProcess->SecurityContext->SessionId == 0) {
            /* 合法跨会话（服务启动用户进程）以外的 → IOC */
            WkdProcess->SecurityContext->CrossSessionDetected = TRUE;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_CrossSession);
        }
    }

    /* ---- Phase 6: 运行时 DEP 策略（迁移自 SS PapAnalyzeSecurityMitigations L2205-2266） ----
     * 查询 ProcessExecuteFlags（class 34）获取进程实际 DEP 策略，可能与 PE 头静态
     * DllCharacteristics 声明不一致（例如系统级强制 DEP / 策略组覆盖）。
     * MEM_EXECUTE_OPTION_DISABLE(0x1) 表示 DEP 已启用。
     * 查询/打开句柄失败时保守置 DepEnabled=TRUE（视为启用），避免 §8 缓解检测误报。
     * 上报语义：运行时缺失并入 §8 IocpCheckMitigations 的
     * TsIndicator_Process_MissingMitigations（运行时 ∪ 静态），由 §8 统一上报一次。 */
    {
        HANDLE processHandle = NULL;

        status = ObOpenObjectByPointer(
            WkdProcess->Core.EProcess,
            OBJ_KERNEL_HANDLE,
            NULL,
            PROCESS_QUERY_INFORMATION,
            *PsProcessType,
            KernelMode,
            &processHandle);

        if (NT_SUCCESS(status)) {
            ULONG executeFlags = 0;
            ULONG returnLength = 0;

            status = ZwQueryInformationProcess(
                processHandle,
                (PROCESSINFOCLASS)34,          /* ProcessExecuteFlags */
                &executeFlags,
                sizeof(executeFlags),
                &returnLength);

            if (NT_SUCCESS(status)) {
                WkdProcess->SecurityContext->DepEnabled = ((executeFlags & 0x1) != 0);
            } else {
                WkdProcess->SecurityContext->DepEnabled = TRUE;  /* 查询失败保守视为启用 */
            }

            ZwClose(processHandle);
        } else {
            WkdProcess->SecurityContext->DepEnabled = TRUE;      /* 无法打开进程句柄保守视为启用 */
        }
    }

    PsDereferencePrimaryToken(token);

    return status;
}

/**************************************************/
/*       §3 命令行深度分析                        */
/**************************************************/

//
// 参考: ProcessAnalyzer.c PmpAnalyzeCommandLine
//

//
// 前向声明：IocpIsScriptHost 定义于本文件 §7 脚本宿主检测区
//
static
BOOLEAN
IocpIsScriptHost(
    _In_ PCUNICODE_STRING ImagePath
    );

static
VOID
IocpDetectCommandLine(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS Process
    )
{
    ULONG i;
    SIZE_T cmdLenChars = 0;
    USHORT cmdLenBytes = 0;
    BOOLEAN isPowerShell = FALSE;
    UNICODE_STRING fileName;

    if (!Process || !Process->CommandLine || !Process->CommandLine->Buffer ||
        Process->CommandLine->Length == 0) {
        return;
    }

    cmdLenBytes = Process->CommandLine->Length;
    cmdLenChars = cmdLenBytes / sizeof(WCHAR);

    /* 0) PowerShell 上下文判定（-e/-ec 短参数门控，对齐 SS ClppDetectEncodedCommand L1690） */
    if (Process->Core.ImagePath &&
        IocpExtractFileName(Process->Core.ImagePath, &fileName)) {
        static const PCWSTR psPatterns[] = { L"powershell", L"pwsh" };
        for (i = 0; i < RTL_NUMBER_OF(psPatterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, psPatterns[i]);
            if (IocpFindInUnicodeString(&fileName, &pat)) {
                isPowerShell = TRUE;
                break;
            }
        }
    }

    /* PS 上下文全命令行回退（对齐 SS ClppDetectEncodedCommand L1699-1704：
     * ImagePath 无 PS 名时，命令行含 powershell/pwsh 也算 PS 上下文） */
    if (!isPowerShell) {
        static const PCWSTR clPatterns[] = { L"powershell", L"pwsh" };
        for (i = 0; i < RTL_NUMBER_OF(clPatterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, clPatterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                isPowerShell = TRUE;
                break;
            }
        }
    }

    /* 1) PowerShell 编码命令
     * 长参数 (-enc/-encodedcommand/-enco/-encod/-encode/-encoded) 无条件匹配；
     * 短参数 (-e/-ec) 仅 PS 上下文命中，防 "grep -e" 等正常参数误报
     * （对齐 SS L1718-1745）。 */
    {
        static const PCWSTR longPatterns[] = {
            L"-enc", L"-encodedcommand", L"-enco", L"-encod", L"-encode", L"-encoded",
            L"frombase64",   /* 对齐 SS PapDetectBehaviorFlags L2837 */
        };
        static const PCWSTR shortPatterns[] = { L"-e ", L"-ec " };
        BOOLEAN encodedHit = FALSE;

        for (i = 0; i < RTL_NUMBER_OF(longPatterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, longPatterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                encodedHit = TRUE;
                break;
            }
        }
        if (!encodedHit && isPowerShell) {
            for (i = 0; i < RTL_NUMBER_OF(shortPatterns); i++) {
                UNICODE_STRING pat;
                RtlInitUnicodeString(&pat, shortPatterns[i]);
                if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                    encodedHit = TRUE;
                    break;
                }
            }
        }
        if (encodedHit) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_ENCODED_CMD;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_EncodedCommand);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.EncodedCommands);
        }
    }

    /* 2) PowerShell 绕过标志（-w hidden/-windowstyle hidden 已拆分到隐藏窗口组）
     * 对齐 SS ClppDetectExecutionBypass：执行策略绕过 + AMSI + CLM + SBL +
     * Defender 排除组合。 */
    {
        static const PCWSTR patterns[] = {
            L"-nop", L"-noni", L"-ep bypass", L"-executionpolicy bypass",
            L"-exec bypass", L"-ep unrestricted", L"-executionpolicy unrestricted",
            L"set-executionpolicy", L"bypass",
            L"amsiutils", L"amsiinitfailed", L"amsi.dll", L"amsiscanbuffer",
            L"amsicontext", L"__pslockeddown", L"fulllanguage",
            L"scriptblocklogging", L"enablescriptblocklogging",
        };
        BOOLEAN bypassHit = FALSE;

        for (i = 0; i < RTL_NUMBER_OF(patterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, patterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                bypassHit = TRUE;
                break;
            }
        }

        /* Defender 排除组合：add-mppreference + -exclusion 同时命中才算 */
        if (!bypassHit) {
            UNICODE_STRING patMp;
            UNICODE_STRING patExc;

            RtlInitUnicodeString(&patMp, L"add-mppreference");
            RtlInitUnicodeString(&patExc, L"-exclusion");
            if (IocpFindInUnicodeString(Process->CommandLine, &patMp) &&
                IocpFindInUnicodeString(Process->CommandLine, &patExc)) {
                bypassHit = TRUE;
            }
        }

        if (bypassHit) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_SUSPICIOUS_PS;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_SuspiciousPowerShell);
        }
    }

    /* 3) 下载器（对齐 SS ClppDetectDownloadCradle：PS 下载方法 + certutil/bitsadmin/
     * curl/wget/wmic 组合 + URL 管道组合） */
    {
        static const PCWSTR patterns[] = {
            L"DownloadString", L"DownloadFile", L"DownloadData",
            L"WebClient", L"Invoke-WebRequest", L"Invoke-RestMethod",
            L"iwr ", L"irm ", L"Start-BitsTransfer", L"start-bitstransfer",
            L"net.webclient", L"httpwebrequest",
            L"wget ", L"curl ", L"bitsadmin",
        };
        BOOLEAN cradleHit = FALSE;

        for (i = 0; i < RTL_NUMBER_OF(patterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, patterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                cradleHit = TRUE;
                break;
            }
        }

        if (!cradleHit) {
            UNICODE_STRING patTool;
            UNICODE_STRING patArg;

            /* certutil ∧ (-urlcache/-verifyctl/-ping) */
            RtlInitUnicodeString(&patTool, L"certutil");
            RtlInitUnicodeString(&patArg, L"-urlcache");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }
            RtlInitUnicodeString(&patArg, L"-verifyctl");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }
            RtlInitUnicodeString(&patArg, L"-ping");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }

            /* bitsadmin ∧ (/transfer//create//addfile) */
            RtlInitUnicodeString(&patTool, L"bitsadmin");
            RtlInitUnicodeString(&patArg, L"/transfer");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }
            RtlInitUnicodeString(&patArg, L"/create");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }
            RtlInitUnicodeString(&patArg, L"/addfile");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }

            /* curl/wget ∧ (-o /--output/> ) */
            RtlInitUnicodeString(&patTool, L"curl ");
            RtlInitUnicodeString(&patArg, L"-o ");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }
            RtlInitUnicodeString(&patArg, L"--output");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }

            /* wmic ∧ http */
            RtlInitUnicodeString(&patTool, L"wmic");
            RtlInitUnicodeString(&patArg, L"http");
            if (!cradleHit &&
                IocpFindInUnicodeString(Process->CommandLine, &patTool) &&
                IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                cradleHit = TRUE;
            }

            /* URL ∧ (| / iex / invoke) */
            UNICODE_STRING patFtp;

            RtlInitUnicodeString(&patTool, L"http://");
            RtlInitUnicodeString(&patArg, L"https://");
            RtlInitUnicodeString(&patFtp, L"ftp://");
            if (!cradleHit &&
                (IocpFindInUnicodeString(Process->CommandLine, &patTool) ||
                 IocpFindInUnicodeString(Process->CommandLine, &patArg) ||
                 IocpFindInUnicodeString(Process->CommandLine, &patFtp))) {
                RtlInitUnicodeString(&patArg, L"|");
                if (IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                    cradleHit = TRUE;
                }
                RtlInitUnicodeString(&patArg, L"iex");
                if (!cradleHit &&
                    IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                    cradleHit = TRUE;
                }
                RtlInitUnicodeString(&patArg, L"invoke");
                if (!cradleHit &&
                    IocpFindInUnicodeString(Process->CommandLine, &patArg)) {
                    cradleHit = TRUE;
                }
            }
        }

        if (cradleHit) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_DOWNLOAD_CRADLE;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_DownloadCradle);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.DownloadCradles);
        }
    }

    /* 4) 反射/内存加载 */
    {
        static const PCWSTR patterns[] = {
            L"[Reflection.Assembly]", L"Reflection.Assembly",
            L"::Load(", L"FromBase64String",
        };
        for (i = 0; i < RTL_NUMBER_OF(patterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, patterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_REFLECTION_LOAD;
                AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_ReflectionLoad);
                InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ReflectiveLoads);
                break;
            }
        }
    }

    /* 5) cmd.exe 链式命令 */
    {
        BOOLEAN hasCmdSwitch = FALSE;
        static const PCWSTR switchPatterns[] = { L"/c ", L"/k " };
        for (i = 0; i < RTL_NUMBER_OF(switchPatterns); i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, switchPatterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                hasCmdSwitch = TRUE;
                break;
            }
        }
        if (hasCmdSwitch) {
            static const PCWSTR chainPatterns[] = { L"&&", L"| ", L"^" };
            for (i = 0; i < RTL_NUMBER_OF(chainPatterns); i++) {
                UNICODE_STRING pat;
                RtlInitUnicodeString(&pat, chainPatterns[i]);
                if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                    Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_SUSPICIOUS_CMD;
                    break;
                }
            }
        }
    }

    /* 6) 长命令行 */
    if (cmdLenChars > 2048) {
        Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_LONG_CMDLINE;
    }

    /* 7) 混淆检测（对齐 SS ClppDetectObfuscation L1760）
     * ^ 插入 / 环境变量滥用 / PS 反引号 / [char] 拼接 / iex 变体。 */
    {
        static const UNICODE_STRING c_obfTilde  = RTL_CONSTANT_STRING(L"~");
        static const UNICODE_STRING c_obfPlus   = RTL_CONSTANT_STRING(L"+[char]");
        static const UNICODE_STRING c_obfChar   = RTL_CONSTANT_STRING(L"[char]");
        static const UNICODE_STRING c_obfF      = RTL_CONSTANT_STRING(L"-f '");
        static const UNICODE_STRING c_obfIex1   = RTL_CONSTANT_STRING(L"iex ");
        static const UNICODE_STRING c_obfIex2   = RTL_CONSTANT_STRING(L"iex(");
        static const UNICODE_STRING c_obfIex3   = RTL_CONSTANT_STRING(L"|iex");
        static const UNICODE_STRING c_obfInvEx  = RTL_CONSTANT_STRING(L"invoke-expression");
        static const UNICODE_STRING c_obfIexT   = RTL_CONSTANT_STRING(L"i`e`x");
        static const UNICODE_STRING c_obfAmp    = RTL_CONSTANT_STRING(L"&(");
        static const UNICODE_STRING c_obfDot    = RTL_CONSTANT_STRING(L".(");
        static const UNICODE_STRING c_obfJoin   = RTL_CONSTANT_STRING(L"-join");
        static const UNICODE_STRING c_obfRep    = RTL_CONSTANT_STRING(L"-replace");
        ULONG caretCount = 0, percentCount = 0, tickCount = 0;
        BOOLEAN obfuscated = FALSE;
        SIZE_T j;

        for (j = 0; j < cmdLenChars; j++) {
            WCHAR ch = Process->CommandLine->Buffer[j];
            if (ch == L'^') {
                caretCount++;
            } else if (ch == L'%') {
                percentCount++;
            } else if (ch == L'`') {
                tickCount++;
            }
        }

        if (caretCount > 5 ||
            (percentCount > 10 &&
             IocpFindInUnicodeString(Process->CommandLine, &c_obfTilde)) ||
            tickCount > 3 ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfPlus) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfChar) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfF) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfIex1) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfIex2) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfIex3) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfInvEx) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfIexT) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfAmp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_obfDot) ||
            ((IocpFindInUnicodeString(Process->CommandLine, &c_obfJoin) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_obfRep)) &&
             (caretCount > 0 || tickCount > 0 || percentCount > 3))) {
            obfuscated = TRUE;
        }

        if (obfuscated) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_OBFUSCATED;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_Obfuscation);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ObfuscatedCommands);
        }
    }

    /* 8) 隐藏窗口执行（对齐 SS ClppDetectHiddenWindow L2005） */
    {
        static const UNICODE_STRING c_hw1   = RTL_CONSTANT_STRING(L"-w hidden");
        static const UNICODE_STRING c_hw2   = RTL_CONSTANT_STRING(L"-windowstyle hidden");
        static const UNICODE_STRING c_hw3   = RTL_CONSTANT_STRING(L"-win hidden");
        static const UNICODE_STRING c_hw4   = RTL_CONSTANT_STRING(L"-window hidden");
        static const UNICODE_STRING c_hw5   = RTL_CONSTANT_STRING(L"-wi hidden");
        static const UNICODE_STRING c_hw6   = RTL_CONSTANT_STRING(L"-winds hidden");
        static const UNICODE_STRING c_hwWsh = RTL_CONSTANT_STRING(L"wscript.shell");
        static const UNICODE_STRING c_hwC0  = RTL_CONSTANT_STRING(L", 0");
        static const UNICODE_STRING c_hwRun = RTL_CONSTANT_STRING(L".run");
        static const UNICODE_STRING c_hwC00 = RTL_CONSTANT_STRING(L", 0,");
        static const UNICODE_STRING c_hwSMin = RTL_CONSTANT_STRING(L"start /min");
        static const UNICODE_STRING c_hwSB   = RTL_CONSTANT_STRING(L"start /b");
        static const UNICODE_STRING c_hwNop  = RTL_CONSTANT_STRING(L"-nop");
        static const UNICODE_STRING c_hwNPro = RTL_CONSTANT_STRING(L"-noprofile");
        static const UNICODE_STRING c_hwNoni = RTL_CONSTANT_STRING(L"-noni");
        static const UNICODE_STRING c_hwNInt = RTL_CONSTANT_STRING(L"-noninteractive");
        BOOLEAN hiddenWindow = FALSE;

        if (IocpFindInUnicodeString(Process->CommandLine, &c_hw1) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hw2) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hw3) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hw4) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hw5) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hw6) ||
            (IocpFindInUnicodeString(Process->CommandLine, &c_hwWsh) &&
             IocpFindInUnicodeString(Process->CommandLine, &c_hwC0)) ||
            (IocpFindInUnicodeString(Process->CommandLine, &c_hwRun) &&
             IocpFindInUnicodeString(Process->CommandLine, &c_hwC00)) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hwSMin) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_hwSB) ||
            ((IocpFindInUnicodeString(Process->CommandLine, &c_hwNop) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_hwNPro)) &&
             (IocpFindInUnicodeString(Process->CommandLine, &c_hwNoni) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_hwNInt)))) {
            hiddenWindow = TRUE;
        }

        if (hiddenWindow) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_HIDDEN_WINDOW;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_HiddenWindow);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.HiddenWindowCommands);
        }
    }

    /* 9) 远程执行（对齐 SS ClppDetectRemoteExecution L2060） */
    {
        static const UNICODE_STRING c_re1     = RTL_CONSTANT_STRING(L"invoke-command");
        static const UNICODE_STRING c_re2     = RTL_CONSTANT_STRING(L"enter-pssession");
        static const UNICODE_STRING c_re3     = RTL_CONSTANT_STRING(L"new-pssession");
        static const UNICODE_STRING c_re4     = RTL_CONSTANT_STRING(L"-computername");
        static const UNICODE_STRING c_re5     = RTL_CONSTANT_STRING(L"-cn ");
        static const UNICODE_STRING c_re6     = RTL_CONSTANT_STRING(L"-session ");
        static const UNICODE_STRING c_reWmic  = RTL_CONSTANT_STRING(L"wmic");
        static const UNICODE_STRING c_reNode  = RTL_CONSTANT_STRING(L"/node:");
        static const UNICODE_STRING c_rePsEx  = RTL_CONSTANT_STRING(L"psexec");
        static const UNICODE_STRING c_reUnc   = RTL_CONSTANT_STRING(L"\\\\");
        static const UNICODE_STRING c_reCmd   = RTL_CONSTANT_STRING(L"cmd");
        static const UNICODE_STRING c_rePs    = RTL_CONSTANT_STRING(L"powershell");
        static const UNICODE_STRING c_reWinrs = RTL_CONSTANT_STRING(L"winrs");
        static const UNICODE_STRING c_reWinrm = RTL_CONSTANT_STRING(L"winrm ");
        static const UNICODE_STRING c_reAct   = RTL_CONSTANT_STRING(L"activator");
        static const UNICODE_STRING c_reCInst = RTL_CONSTANT_STRING(L"createinstance");
        BOOLEAN remoteExec = FALSE;

        if (IocpFindInUnicodeString(Process->CommandLine, &c_re1) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_re2) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_re3) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_re4) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_re5) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_re6) ||
            (IocpFindInUnicodeString(Process->CommandLine, &c_reWmic) &&
             IocpFindInUnicodeString(Process->CommandLine, &c_reNode)) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_rePsEx) ||
            (IocpFindInUnicodeString(Process->CommandLine, &c_reUnc) &&
             (IocpFindInUnicodeString(Process->CommandLine, &c_reCmd) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_rePs))) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_reWinrs) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_reWinrm) ||
            (IocpFindInUnicodeString(Process->CommandLine, &c_reAct) &&
             IocpFindInUnicodeString(Process->CommandLine, &c_reCInst))) {
            remoteExec = TRUE;
        }

        if (remoteExec) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_REMOTE_EXEC;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_RemoteExecution);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.RemoteExecCommands);
        }
    }

    /* 10) 可疑路径执行（对齐 SS ClppDetectSuspiciousPath L2121） */
    {
        static const UNICODE_STRING c_spTemp    = RTL_CONSTANT_STRING(L"\\temp\\");
        static const UNICODE_STRING c_spTmp     = RTL_CONSTANT_STRING(L"\\tmp\\");
        static const UNICODE_STRING c_spPTemp   = RTL_CONSTANT_STRING(L"%temp%");
        static const UNICODE_STRING c_spETemp   = RTL_CONSTANT_STRING(L"$env:temp");
        static const UNICODE_STRING c_spALocal  = RTL_CONSTANT_STRING(L"\\appdata\\local\\");
        static const UNICODE_STRING c_spARoam   = RTL_CONSTANT_STRING(L"\\appdata\\roaming\\");
        static const UNICODE_STRING c_spPApp    = RTL_CONSTANT_STRING(L"%appdata%");
        static const UNICODE_STRING c_spEApp    = RTL_CONSTANT_STRING(L"$env:appdata");
        static const UNICODE_STRING c_spRecy    = RTL_CONSTANT_STRING(L"\\$recycle.bin\\");
        static const UNICODE_STRING c_spRecy2   = RTL_CONSTANT_STRING(L"\\recycler\\");
        static const UNICODE_STRING c_spUPublic = RTL_CONSTANT_STRING(L"\\users\\public\\");
        static const UNICODE_STRING c_spPublic  = RTL_CONSTANT_STRING(L"\\public\\");
        static const UNICODE_STRING c_spPData   = RTL_CONSTANT_STRING(L"\\programdata\\");
        static const UNICODE_STRING c_spMsft    = RTL_CONSTANT_STRING(L"\\microsoft\\");
        static const UNICODE_STRING c_spPerf    = RTL_CONSTANT_STRING(L"\\perflogs\\");
        static const UNICODE_STRING c_spDnld    = RTL_CONSTANT_STRING(L"\\downloads\\");   /* 对齐 SS PapIsSuspiciousPath L2974 */
        static const UNICODE_STRING c_spExtScr  = RTL_CONSTANT_STRING(L".scr");           /* 对齐 SS L2984 */
        static const UNICODE_STRING c_spExtPif  = RTL_CONSTANT_STRING(L".pif");           /* 对齐 SS L2985 */
        static const UNICODE_STRING c_spExtCom  = RTL_CONSTANT_STRING(L".com");           /* 对齐 SS L2986 (子串匹配, 对齐 SS 语义) */
        BOOLEAN suspPath = FALSE;

        if (IocpFindInUnicodeString(Process->CommandLine, &c_spTemp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spTmp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spPTemp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spETemp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spALocal) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spARoam) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spPApp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spEApp) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spDnld) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spRecy) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spRecy2) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spUPublic) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spPublic) ||
            (IocpFindInUnicodeString(Process->CommandLine, &c_spPData) &&
             !IocpFindInUnicodeString(Process->CommandLine, &c_spMsft)) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_spPerf)) {
            suspPath = TRUE;
        }

        /* 镜像路径可疑目录 + 扩展名（对齐 SS PapIsSuspiciousPath L2958-2991，
         * 补 SS 独有的 \downloads\ 与 .scr/.pif/.com 扩展名子串） */
        if (Process->Core.ImagePath) {
            if (IocpFindInUnicodeString(Process->Core.ImagePath, &c_spTemp) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spTmp) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spDnld) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spUPublic) ||
                (IocpFindInUnicodeString(Process->Core.ImagePath, &c_spPData) &&
                 !IocpFindInUnicodeString(Process->Core.ImagePath, &c_spMsft)) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spRecy) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spRecy2) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spExtScr) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spExtPif) ||
                IocpFindInUnicodeString(Process->Core.ImagePath, &c_spExtCom)) {
                suspPath = TRUE;
            }
        }

        if (suspPath) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_SUSPICIOUS_PATH;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_SuspiciousPath);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.SuspiciousPathCommands);
        }
    }

    /* 11) 脚本文件执行（对齐 SS ClppDetectScriptExecution L2181）
     * 脚本宿主 + 脚本扩展名参数，或内联 javascript:/vbscript:。 */
    {
        static const UNICODE_STRING c_sfVbs    = RTL_CONSTANT_STRING(L".vbs");
        static const UNICODE_STRING c_sfVbe    = RTL_CONSTANT_STRING(L".vbe");
        static const UNICODE_STRING c_sfJs     = RTL_CONSTANT_STRING(L".js");
        static const UNICODE_STRING c_sfJse    = RTL_CONSTANT_STRING(L".jse");
        static const UNICODE_STRING c_sfWsf    = RTL_CONSTANT_STRING(L".wsf");
        static const UNICODE_STRING c_sfWsh    = RTL_CONSTANT_STRING(L".wsh");
        static const UNICODE_STRING c_sfHta    = RTL_CONSTANT_STRING(L".hta");
        static const UNICODE_STRING c_sfJsCol  = RTL_CONSTANT_STRING(L"javascript:");
        static const UNICODE_STRING c_sfVbsCol = RTL_CONSTANT_STRING(L"vbscript:");
        BOOLEAN scriptFile = FALSE;

        if ((IocpIsScriptHost(Process->Core.ImagePath) &&
             (IocpFindInUnicodeString(Process->CommandLine, &c_sfVbs) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_sfVbe) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_sfJs) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_sfJse) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_sfWsf) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_sfWsh) ||
              IocpFindInUnicodeString(Process->CommandLine, &c_sfHta))) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_sfJsCol) ||
            IocpFindInUnicodeString(Process->CommandLine, &c_sfVbsCol)) {
            scriptFile = TRUE;
        }

        if (scriptFile) {
            Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_SCRIPT_FILE;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_ScriptExecution);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ScriptFileCommands);
        }
    }
}

/**************************************************/
/*       §3.2 剪贴板窃取检测（T1115）              */
/*                                                 */
/*   迁移自 SS ClipboardMonitor.c CbMonCheckProcessCreate */
/*   双检测面: 命令行剪贴板关键词 + 已知窃取器镜像名。 */
/*   命中置 WKD_BEHAVIOR_CLIPBOARD + 提交            */
/*   TsIndicator_CmdLine_ClipboardAbuse(0x0206).     */
/*   镜像名命中 severity=High, 命令行命中=Medium      */
/*   （对齐 SS 调用方 ProcessNotify: base 15 +         */
/*    KnownStealerImage +25 加分语义）.               */
/**************************************************/

//
// 剪贴板窃取命令行关键词（对齐 SS g_ClipboardCmdPatterns 13 条；
// xclip/xsel/pbcopy 为 Unix/WSL 工具，Windows 本地价值≈0，裁剪为注释预留）
//
static const PCWSTR g_IocClipboardCmdPatterns[] = {
    L"Get-Clipboard",
    L"Set-Clipboard",
    L"clip.exe",
    L"[System.Windows.Forms.Clipboard]",
    L"win32_clipboard",
    L"ClipboardData",
    L"GetClipboardData",
    L"OpenClipboard",
    L"OleGetClipboard",
};
#define IOC_CLIPBOARD_CMD_COUNT \
    (sizeof(g_IocClipboardCmdPatterns) / sizeof(g_IocClipboardCmdPatterns[0]))

//
// 已知剪贴板窃取器镜像名（对齐 SS g_ClipboardStealerNames 6 条，文件名包含匹配）
//
static const PCWSTR g_IocClipboardStealerNames[] = {
    L"cliplogger",
    L"clipstealer",
    L"clipgrab",
    L"clipboard_monitor",
    L"clipboardspy",
    L"clipsvc_exploit",
};
#define IOC_CLIPBOARD_STEALER_COUNT \
    (sizeof(g_IocClipboardStealerNames) / sizeof(g_IocClipboardStealerNames[0]))

static
VOID
IocpDetectClipboardAbuse(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS Process
    )
{
    ULONG i;
    BOOLEAN cmdLineHit = FALSE;
    BOOLEAN stealerHit = FALSE;

    if (!Pair || !Process || !Process->SecurityContext) {
        return;
    }

    /* 1) 命令行剪贴板关键词匹配 */
    if (Process->CommandLine != NULL &&
        Process->CommandLine->Buffer != NULL &&
        Process->CommandLine->Length > 0) {
        for (i = 0; i < IOC_CLIPBOARD_CMD_COUNT; i++) {
            UNICODE_STRING pat;
            RtlInitUnicodeString(&pat, g_IocClipboardCmdPatterns[i]);
            if (IocpFindInUnicodeString(Process->CommandLine, &pat)) {
                cmdLineHit = TRUE;
                break;
            }
        }

        /* Add-Type + Clipboard 组合（对齐 SS：两条件同时命中才算，
         * 防 "Add-Type" 普通编译用法误报） */
        if (!cmdLineHit) {
            UNICODE_STRING patAddType;
            UNICODE_STRING patClipboard;

            RtlInitUnicodeString(&patAddType, L"Add-Type");
            RtlInitUnicodeString(&patClipboard, L"Clipboard");
            if (IocpFindInUnicodeString(Process->CommandLine, &patAddType) &&
                IocpFindInUnicodeString(Process->CommandLine, &patClipboard)) {
                cmdLineHit = TRUE;
            }
        }
    }

    /* 2) 已知窃取器镜像名匹配（文件名包含匹配） */
    if (Process->Core.ImagePath != NULL &&
        Process->Core.ImagePath->Buffer != NULL &&
        Process->Core.ImagePath->Length > 0) {
        UNICODE_STRING fileName;

        if (IocpExtractFileName(Process->Core.ImagePath, &fileName)) {
            for (i = 0; i < IOC_CLIPBOARD_STEALER_COUNT; i++) {
                UNICODE_STRING pat;
                RtlInitUnicodeString(&pat, g_IocClipboardStealerNames[i]);
                if (IocpFindInUnicodeString(&fileName, &pat)) {
                    stealerHit = TRUE;
                    break;
                }
            }
        }
    }

    if (!cmdLineHit && !stealerHit) {
        return;
    }

    Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_CLIPBOARD;
    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ClipboardMatches);

    /* SS CbMonCheckProcessCreate 命中后双路提交：
     *   ① BeEngineSubmitEvent(BehaviorEvent_ClipboardCommandLine, 50) 专属行为事件
     *      → wkD 由本提交（IOC 评分 0x0206）+ AeOrchestratorDispatch Phase 3 通用
     *        进程创建行为记录(IoaAnalysisBehavior) 叠加覆盖，不新增剪贴板专属行为类型；
     *   ② CbMonpLookupProcess(ProcessId, TRUE) 入追踪表供 CbMonCheckFileWrite 查询
     *      → wkD §8 追踪表死代码未接线，激活时在此补调
     *        IocpClipboardTrackProcess(ProcessId, indicators)。 */
    AeReportIndicatorEx(
        Pair,
        TsSourceIOC,
        TsIndicator_CmdLine_ClipboardAbuse,
        stealerHit ? AeThreatSeverityHigh : AeThreatSeverityMedium);
}

/**************************************************/
/*       §4 签名验证                              */
/**************************************************/

static
NTSTATUS
IocpVerifySignature(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdProcess || !WkdProcess->SecurityContext) {
        return STATUS_INVALID_PARAMETER;
    }

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
    {
        UCHAR signatureLevel = 0;
        UCHAR sectionSignatureLevel = 0;

        signatureLevel = pfnPsGetProcessSignatureLevel(
            WkdProcess->Core.EProcess,
            &sectionSignatureLevel);

        if (signatureLevel >= SE_SIGNING_LEVEL_AUTHENTICODE) {
            WkdProcess->SecurityContext->IsSignatureValid = TRUE;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Reputation_ValidSignature);
        } else {
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Reputation_UnsignedBinary);
        }
    }
#else
    status = STATUS_NOT_SUPPORTED;
#endif

    return status;
}

/**************************************************/
/*       §5 进程 Ghosting 检测（T1055.013）        */
/**************************************************/

//
// 参考: ProcessAnalyzer.c PmpCheckProcessGhosting
//
static
NTSTATUS
IocpDetectGhosting(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS Process
    )
{
    NTSTATUS status;
    PUNICODE_STRING imagePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo;

    if (!Process || !Process->SecurityContext) {
        return STATUS_INVALID_PARAMETER;
    }

    imagePath = Process->Core.ImagePath;

    /* Phase 1: 无映像路径 */
    if (!imagePath || !imagePath->Buffer || imagePath->Length == 0) {
        Process->SecurityContext->IsGhostingDetected = TRUE;
        AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Injection_ProcessHollowing);
        return STATUS_SUCCESS;
    }

    /* Phase 2: 尝试打开文件 */
    InitializeObjectAttributes(&objAttr, imagePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenFile(&fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objAttr, &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_DELETE_PENDING) {
            Process->SecurityContext->IsGhostingDetected = TRUE;
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Injection_ProcessHollowing);
        }
        return STATUS_SUCCESS;
    }

    /* Phase 3: 检查 DeletePending */
    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    status = ZwQueryInformationFile(fileHandle, &ioStatus,
        &fileInfo, sizeof(fileInfo), FileStandardInformation);

    if (NT_SUCCESS(status) && fileInfo.DeletePending) {
        Process->SecurityContext->IsGhostingDetected = TRUE;
        AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Injection_ProcessHollowing);
    }

    ZwClose(fileHandle);
    return STATUS_SUCCESS;
}

/**************************************************/
/*       §6 父进程谱系分析                        */
/**************************************************/

//
// 父进程校验全局表
//
#define WKD_MAX_KNOWN_PARENTS          64
#define WKD_MAX_PARENT_CHILD_RULES     64

static ULONG g_IocpKnownParentHashes[WKD_MAX_KNOWN_PARENTS];
static ULONG g_IocpKnownParentCount = 0;

typedef struct _IOCP_PARENT_CHILD_RULE {
    ULONG ParentHash;
    ULONG ChildHash;
    BOOLEAN IsSuspicious;
} IOCP_PARENT_CHILD_RULE;

static IOCP_PARENT_CHILD_RULE g_IocpParentChildRules[WKD_MAX_PARENT_CHILD_RULES];
static ULONG g_IocpParentChildRuleCount = 0;
static BOOLEAN g_IocpParentChildInitialized = FALSE;

//
// 已知良性父进程列表
//
static
VOID
IocpInitializeParentChildRules(
    VOID
    )
{
    ULONG i;

    static const PCWSTR KnownParents[] = {
        L"explorer.exe", L"services.exe", L"svchost.exe",
        L"csrss.exe", L"wininit.exe", L"winlogon.exe",
        L"smss.exe", L"lsass.exe", L"system",
        L"userinit.exe", L"sihost.exe", L"taskhostw.exe",
        L"runtimebroker.exe", L"searchindexer.exe", L"spoolsv.exe",
        L"dwm.exe", L"conhost.exe", L"dllhost.exe", L"wmiprvse.exe"
    };

    static const struct {
        PCWSTR Parent;
        PCWSTR Child;
    } SuspiciousRules[] = {
        /* wkd 独有：explorer 直接拉起脚本宿主/命令（SS 无，wkd 增强） */
        { L"explorer.exe", L"mshta.exe" },
        { L"explorer.exe", L"powershell.exe" },
        { L"explorer.exe", L"pwsh.exe" },
        { L"explorer.exe", L"wscript.exe" },
        { L"explorer.exe", L"cscript.exe" },
        { L"explorer.exe", L"cmd.exe" },
        { L"explorer.exe", L"regsvr32.exe" },
        /* 以下对齐 SS PapInitializeParentChildRules L3147-3181（30 条），
         * 2026-08 ProcessAnalyzer 迁移：补 winword/excel wscript·cscript·mshta、
         * powerpnt/notepad/iexplore/msedge/spoolsv/wmiprvse 全链 */
        { L"winword.exe", L"cmd.exe" },
        { L"winword.exe", L"powershell.exe" },
        { L"winword.exe", L"wscript.exe" },
        { L"winword.exe", L"cscript.exe" },
        { L"winword.exe", L"mshta.exe" },
        { L"excel.exe", L"cmd.exe" },
        { L"excel.exe", L"powershell.exe" },
        { L"excel.exe", L"wscript.exe" },
        { L"excel.exe", L"cscript.exe" },
        { L"excel.exe", L"mshta.exe" },
        { L"powerpnt.exe", L"cmd.exe" },
        { L"powerpnt.exe", L"powershell.exe" },
        { L"outlook.exe", L"cmd.exe" },
        { L"outlook.exe", L"powershell.exe" },
        { L"outlook.exe", L"wscript.exe" },
        { L"outlook.exe", L"mshta.exe" },
        { L"notepad.exe", L"cmd.exe" },
        { L"notepad.exe", L"powershell.exe" },
        { L"iexplore.exe", L"cmd.exe" },
        { L"iexplore.exe", L"powershell.exe" },
        { L"msedge.exe", L"cmd.exe" },
        { L"msedge.exe", L"powershell.exe" },
        { L"chrome.exe", L"cmd.exe" },
        { L"chrome.exe", L"powershell.exe" },
        { L"firefox.exe", L"cmd.exe" },
        { L"firefox.exe", L"powershell.exe" },
        { L"spoolsv.exe", L"cmd.exe" },
        { L"spoolsv.exe", L"powershell.exe" },
        { L"wmiprvse.exe", L"powershell.exe" },
        { L"wmiprvse.exe", L"cmd.exe" },
    };

    g_IocpKnownParentCount = 0;
    for (i = 0; i < RTL_NUMBER_OF(KnownParents) && g_IocpKnownParentCount < WKD_MAX_KNOWN_PARENTS; i++) {
        SIZE_T len = wcslen(KnownParents[i]);
        g_IocpKnownParentHashes[g_IocpKnownParentCount++] =
            IocpHashStringInsensitive(KnownParents[i], (ULONG)len);
    }

    g_IocpParentChildRuleCount = 0;
    for (i = 0; i < RTL_NUMBER_OF(SuspiciousRules) && g_IocpParentChildRuleCount < WKD_MAX_PARENT_CHILD_RULES; i++) {
        SIZE_T parentLen = wcslen(SuspiciousRules[i].Parent);
        SIZE_T childLen = wcslen(SuspiciousRules[i].Child);
        g_IocpParentChildRules[g_IocpParentChildRuleCount].ParentHash =
            IocpHashStringInsensitive(SuspiciousRules[i].Parent, (ULONG)parentLen);
        g_IocpParentChildRules[g_IocpParentChildRuleCount].ChildHash =
            IocpHashStringInsensitive(SuspiciousRules[i].Child, (ULONG)childLen);
        g_IocpParentChildRules[g_IocpParentChildRuleCount].IsSuspicious = TRUE;
        g_IocpParentChildRuleCount++;
    }

    g_IocpParentChildInitialized = TRUE;
}

static
BOOLEAN
IocpIsKnownParent(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING fileName;
    ULONG hash;

    if (!IocpExtractFileName(ImagePath, &fileName)) {
        return FALSE;
    }

    hash = IocpHashStringInsensitive(fileName.Buffer, fileName.Length / sizeof(WCHAR));

    for (ULONG i = 0; i < g_IocpKnownParentCount; i++) {
        if (g_IocpKnownParentHashes[i] == hash) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
IocpCheckParentChildMismatch(
    _In_ PCUNICODE_STRING ParentPath,
    _In_ PCUNICODE_STRING ChildPath
    )
{
    UNICODE_STRING parentName, childName;
    ULONG parentHash, childHash;

    if (!IocpExtractFileName(ParentPath, &parentName) ||
        !IocpExtractFileName(ChildPath, &childName)) {
        return FALSE;
    }

    parentHash = IocpHashStringInsensitive(parentName.Buffer, parentName.Length / sizeof(WCHAR));
    childHash = IocpHashStringInsensitive(childName.Buffer, childName.Length / sizeof(WCHAR));

    for (ULONG i = 0; i < g_IocpParentChildRuleCount; i++) {
        if (g_IocpParentChildRules[i].ParentHash == parentHash &&
            g_IocpParentChildRules[i].ChildHash == childHash &&
            g_IocpParentChildRules[i].IsSuspicious) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
IocpAnalyzeParentProcess(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS Process
    )
{
    NTSTATUS status;
    PEPROCESS parentProcess = NULL;
    PUNICODE_STRING parentImageName = NULL;

    if (!Process || !Process->SecurityContext ||
        Process->Core.ParentProcessId == NULL) {
        return;
    }

    status = PsLookupProcessByProcessId(Process->Core.ParentProcessId, &parentProcess);
    if (!NT_SUCCESS(status)) {
        return;
    }

    /* __try { */
        status = SeLocateProcessImageName(parentProcess, &parentImageName);
        if (NT_SUCCESS(status) && parentImageName != NULL) {

            if (!IocpIsKnownParent(parentImageName)) {
                Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_SUSPICIOUS_PARENT;
                AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_SuspiciousAncestry);
            }

            if (IocpCheckParentChildMismatch(parentImageName,
                    Process->Core.ImagePath)) {
                Process->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_PARENT_CHILD_MISMATCH;
                /* 父子组合失配属谱系/父子关系，不再污染 PPID 指示器 */
                AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_SuspiciousAncestry);
            }

            ExFreePool(parentImageName);
        }
    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
    } */

    if (parentProcess != NULL) {
        ObDereferenceObject(parentProcess);
    }
}

/**************************************************/
/*       §7 脚本宿主检测                          */
/**************************************************/

//
// 参考: ProcessAnalyzer.c PmpIsScriptHost
//
static
BOOLEAN
IocpIsScriptHost(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING fileName;

    if (!IocpExtractFileName(ImagePath, &fileName)) {
        return FALSE;
    }

    /* 脚本宿主列表：wkd 原有 + 对齐 SS BepIsScriptHost 补 pythonw/java/javaw */
    static const PCWSTR ScriptHosts[] = {
        L"powershell", L"pwsh", L"cmd.exe", L"wscript",
        L"cscript", L"mshta", L"wmic", L"bash",
        L"python", L"pythonw", L"perl", L"ruby",
        L"node.exe", L"java", L"javaw",
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(ScriptHosts); i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, ScriptHosts[i]);
        if (IocpFindInUnicodeString(&fileName, &pattern)) {
            return TRUE;
        }
    }

    return FALSE;
}

/**************************************************/
/*       §3.3 WSL/容器逃逸检测（迁移自 SS WSLMonitor）*/
/**************************************************/

//
// WSL 进程镜像名（对齐 SS WSLMonitor.c g_WslLauncher/Host/Service/Relay L99-102）。
// bash.exe 不在此表直接分类（SS WSL-11：Git Bash/Cygwin/MSYS2 同镜像名，
// 仅通过父链判定，杜绝误报）。
//
static const PCWSTR g_WslProcessNames[] = {
    L"wsl.exe",          // Launcher
    L"wslhost.exe",      // Host
    L"wslservice.exe",   // Service
    L"wslrelay.exe",     // Child
};

//
// WSL 上下文 spawn 的原生逃逸目标（对齐 SS WSLMonitor.c g_NativeEscapeTargets
// L108-124，T1611 Escape to Host）。WSL 父进程拉起这些 native 进程即为逃逸。
//
static const PCWSTR g_WslNativeEscapeTargets[] = {
    L"cmd.exe",          L"powershell.exe", L"pwsh.exe",      L"mshta.exe",
    L"wscript.exe",      L"cscript.exe",    L"regsvr32.exe",  L"rundll32.exe",
    L"certutil.exe",     L"bitsadmin.exe",  L"wmic.exe",      L"msbuild.exe",
    L"installutil.exe",  L"regasm.exe",     L"regsvcs.exe",
};

static
BOOLEAN
IocpWslIsNativeEscapeTarget(
    _In_ PCUNICODE_STRING ImageName
    )
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_WslNativeEscapeTargets); i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_WslNativeEscapeTargets[i]);
        if (RtlEqualUnicodeString(ImageName, &pattern, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
IocpDetectWsl(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS Proc,
    _In_opt_ PUNICODE_STRING ImageFileName
    )
/*++
Routine Description:
    进程创建 WSL/容器逃逸检测（对齐 SS WslMonCheckProcessCreate L300-502）。
    1) 镜像名分类（wsl.exe/wslhost.exe/wslservice.exe/wslrelay.exe）；
    2) 未命中则查父进程 WSL 标志 → 本进程标记 WSL 子进程（bash.exe 误报消除）；
    3) WSL 父 + native 逃逸目标 → TsIndicator_Wsl_EscapeToHost（T1611）。
    融合实现：WSL 状态打 SecurityContext->BehaviorFlags（WKD_BEHAVIOR_WSL_PROCESS），
    不建独立追踪表（WKD_PROCESS 权威副本覆盖生命周期与容量）。

Arguments:
    Pair           - 进程对（Source=父，Target=本进程）。
    Proc           - 本进程 WKD_PROCESS（已持锁 + 引用）。
    ImageFileName  - 镜像文件名（CreateInfo->ImageFileName，可为 NULL）。

Return Value:
    无。
--*/
{
    UNICODE_STRING imageName = { 0 };
    UNICODE_STRING fileName = { 0 };
    BOOLEAN hasImageName = FALSE;
    BOOLEAN isWsl = FALSE;
    BOOLEAN isWslParent = FALSE;

    /* Step 1: 提取镜像文件名（对齐 SS WslpExtractImageName，复用 IocpExtractFileName） */
    if (ImageFileName != NULL &&
        ImageFileName->Buffer != NULL &&
        ImageFileName->Length > 0) {
        if (IocpExtractFileName(ImageFileName, &fileName)) {
            imageName = fileName;
            hasImageName = TRUE;
        }
    }

    /* Step 2: 镜像名分类（bash.exe 不在此分类，SS WSL-11） */
    if (hasImageName) {
        for (ULONG i = 0; i < RTL_NUMBER_OF(g_WslProcessNames); i++) {
            UNICODE_STRING pattern;
            RtlInitUnicodeString(&pattern, g_WslProcessNames[i]);
            if (RtlEqualUnicodeString(&imageName, &pattern, TRUE)) {
                isWsl = TRUE;
                break;
            }
        }
    }

    /* Step 3: 仅当镜像未分类时查父链（对齐 SS Step 2）
     *   wslrelay.exe 虽在 Step 2 命中，但走分类分支，不进入父链逃逸判定。 */
    if (!isWsl && Pair->SourceProcessId != NULL) {
        PWKD_PROCESS parent = PsLookupWkdProcessByProcessId(Pair->SourceProcessId);
        if (parent != NULL) {
            if (parent->SecurityContext != NULL &&
                (parent->SecurityContext->BehaviorFlags & WKD_BEHAVIOR_WSL_PROCESS)) {
                isWslParent = TRUE;
                isWsl = TRUE;
            }
            PsDereferenceWkdProcess(parent);
        }

        if (isWslParent) {
            /* WSL 父 + native 逃逸目标 → 逃逸（T1611，对齐 SS L364-386，80 分） */
            if (hasImageName && IocpWslIsNativeEscapeTarget(&imageName)) {
                AeReportIndicatorEx(Pair, TsSourceIOC,
                    TsIndicator_Wsl_EscapeToHost, AeThreatSeverityCritical);
                InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslEscapeAttempts);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[WkDefender/WSL] ESCAPE: WSL->native process creation! "
                    "PID=%lu, Parent=%lu, Image=%wZ\n",
                    HandleToULong(Pair->TargetProcessId),
                    HandleToULong(Pair->SourceProcessId),
                    ImageFileName);
            }
            /* WSL 父 spawn 任意子进程（对齐 SS L357 SuspiciousSpawns++） */
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslSuspiciousSpawns);
        }
    }

    /* Step 4: WSL 进程打标志 + 计数（对齐 SS 入表段 + WslProcessesDetected++） */
    if (isWsl) {
        if (Proc->SecurityContext != NULL) {
            Proc->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_WSL_PROCESS;
        }
        InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslProcessesDetected);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "[WkDefender/WSL] WSL process tracked: PID=%lu\n",
            HandleToULong(Pair->TargetProcessId));
    }
}

/**************************************************/
/*       §8 缓解缺失检测（T1055 前置信号）          */
/*                                                 */
/*   迁移自 SS ProcessAnalyzer.c:                  */
/*     PapAnalyzePEHeaders L2129-2139              */
/*       (DllCharacteristics → DEP/ASLR/CFG)       */
/*     PapAnalyzeSecurityMitigations L2205-2266    */
/*       (ProcessExecuteFlags 运行时 DEP)          */
/*                                                 */
/*   功能面: 读取进程镜像 PE 头的 DllCharacteristics, */
/*   静态缺失 (无ASLR/无DEP/无CFG) 与运行时缺失      */
/*   (ExecuteFlags 无 DEP) 合并, 任一命中即上报      */
/*   TsIndicator_Process_MissingMitigations.       */
/*   权重 4 (ThreatScoring.c L200), 评分由          */
/*   TsSettleScores IOC 累加消费.                  */
/*                                                 */
/*   对齐 agent PeParser.c NoASLR/NoDEP/NoCFG:     */
/*     CFG 仅对 2014-01-01 后非 .NET 二进制计分     */
/*     (WpeAnom_NoCFG 时间戳门控), 避免旧二进制误报.*/
/**************************************************/

#define IOC_PE_READ_SIZE            4096
#define IOC_CFG_EPOCH_2014          0x52C41FA0   /* 2014-01-01 00:00:00 UTC */

static
NTSTATUS
IocpCheckMitigations(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_PROCESS Process
    )
{
    NTSTATUS status;
    PUNICODE_STRING imagePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PVOID buffer = NULL;
    BOOLEAN staticMissing = FALSE;
    BOOLEAN runtimeMissing = FALSE;

    if (!Process || !Process->SecurityContext) {
        return STATUS_INVALID_PARAMETER;
    }

    imagePath = Process->Core.ImagePath;
    if (!imagePath || !imagePath->Buffer || imagePath->Length == 0) {
        /* 无镜像路径（无背衬/系统初始化阶段）→ 跳过缓解判定 */
        return STATUS_SUCCESS;
    }

    /* 运行时 DEP（Phase 6 已填充 DepEnabled；FALSE = 运行时关闭 DEP） */
    runtimeMissing = !Process->SecurityContext->DepEnabled;

    /* 打开进程镜像文件（对齐 §5 Ghosting 的文件打开模式） */
    InitializeObjectAttributes(&objAttr, imagePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenFile(&fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr, &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        /* 文件打开失败（删除中/路径不可达）→ 仅保留运行时判定 */
        if (runtimeMissing) {
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_MissingMitigations);
        }
        return STATUS_SUCCESS;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, IOC_PE_READ_SIZE, 'mIgO');
    if (!buffer) {
        ZwClose(fileHandle);
        if (runtimeMissing) {
            AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_MissingMitigations);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, IOC_PE_READ_SIZE);
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus,
        buffer, IOC_PE_READ_SIZE, NULL, NULL);
    ZwClose(fileHandle);

    if (NT_SUCCESS(status) && ioStatus.Information > 0) {
        WKD_PE_PARSE_CONTEXT ctx;
        WKD_PE_MITIGATIONS mit;

        RtlZeroMemory(&ctx, sizeof(ctx));
        ctx.Data = buffer;
        ctx.DataSize = ioStatus.Information;
        ctx.Mode = WkdPeMode_File;
        ctx.MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;
        WkdPeCbMitigationsInit(&ctx, &mit);

        /* 统一解析核心（File 模式 + 缓解映射回调，对齐 SS PapAnalyzePEHeaders） */
        if (NT_SUCCESS(CoParsePe(&ctx)) && mit.IsPe) {
            /* 无 ASLR（对齐 SS PA_IMAGE_DLLCHAR_DYNAMIC_BASE） */
            if (!mit.HasAslr) {
                staticMissing = TRUE;
            }
            /* 无 DEP（对齐 SS PA_IMAGE_DLLCHAR_NX_COMPAT） */
            if (!mit.HasDep) {
                staticMissing = TRUE;
            }
            /* 无 CFG：2014-01-01 后且非 .NET 的二进制才计（对齐 agent PeParser.c L502-508） */
            if (mit.TimeDateStamp >= IOC_CFG_EPOCH_2014 && !mit.HasCfg) {
                if (!mit.IsDotNet) {
                    staticMissing = TRUE;
                }
            }
        }
    }

    ExFreePoolWithTag(buffer, 'mIgO');

    /* 静态 ∪ 运行时，统一上报一次（用户决策：运行时 DEP 并入缓解指示器） */
    if (staticMissing || runtimeMissing) {
        AeReportIndicator(Pair, TsSourceIOC, TsIndicator_Process_MissingMitigations);
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*       IocAnalysisProcess — 主入口                 */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IocAnalysisProcess(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS status;
    PWKD_PROCESS tgtWkdProcess;

    if (!Pair || !CreateInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    tgtWkdProcess = PsLookupWkdProcessByProcessId(Pair->TargetProcessId);
    if (!tgtWkdProcess) return STATUS_UNSUCCESSFUL;

    /* 2026-08-25 锁下沉: SecurityContext 字段操作持其内嵌推锁 (惰性指针, 判空保护) */
    if (!tgtWkdProcess->SecurityContext) {
        PsDereferenceWkdProcess(tgtWkdProcess);
        return STATUS_UNSUCCESSFUL;
    }
    WkdAcquirePushLockExclusive(&tgtWkdProcess->SecurityContext->Lock);

    /* §1 PPID 欺骗检测 */
    IocpDetectPpidSpoofing(Pair, tgtWkdProcess);

    /* §2 令牌信息 + 特权捕获（含跨会话/提权 IOC） */
    IocpCapturePrivilegeInfo(Pair, tgtWkdProcess);

    /* §3 命令行深度分析（2026-08 激活，迁移自 SS BehaviorEngine 事件流） */
    // IocpDetectCommandLine(Pair, tgtWkdProcess);

    /* §3.1 LOLBin 识别（对齐 SS BepIsLolBin，迁移自 BehaviorEngine） */
    //if (tgtWkdProcess->Core.ImagePath &&
    //    IocCheckLolbin(tgtWkdProcess->Core.ImagePath)) {
    //    tgtWkdProcess->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_LOLBIN;
    //    AeReportIndicator(Pair, TsSourceIOC, TsIndicator_CmdLine_LOLBin);
    //}

    /* §3.2 剪贴板窃取检测（T1115，迁移自 SS ClipboardMonitor） */
    // IocpDetectClipboardAbuse(Pair, tgtWkdProcess);

    /* §3.3 WSL/容器逃逸检测（T1611/T1059.004，迁移自 SS WSLMonitor）
     *   镜像分类 + 父链判定 + WSL 父 spawn native 逃逸目标 */
    // IocpDetectWsl(Pair, tgtWkdProcess, CreateInfo->ImageFileName);

    /* §4 签名验证 */
    // IocpVerifySignature(Pair, tgtWkdProcess);

    /* §5 进程 Ghosting 检测（T1055.013，对齐 SS PhAnalyzeAtCreation 门控：
     *   !IsSystem 才做——系统进程跳过比对，控制创建热路径成本） */
    //if (!tgtWkdProcess->SecurityContext->IsSystem) {
    //    IocpDetectGhosting(Pair, tgtWkdProcess);
    //}

    /* §6 父进程谱系分析（迁移自 SS PapAnalyzeParentProcess/PapDetectBehaviorFlags
     * 已知父名单(19) + 组合失配规则(对齐 SS 30 条)；父非已知→SuspiciousAncestry，
     * 组合失配→SuspiciousAncestry（谱系异常，不再归入 PPID 指示器）） */
    // IocpAnalyzeParentProcess(Pair, tgtWkdProcess);

    /* §7 脚本宿主标记（对齐 SS BepIsScriptHost，迁移自 BehaviorEngine） */
    //if (tgtWkdProcess->Core.ImagePath &&
    //    IocpIsScriptHost(tgtWkdProcess->Core.ImagePath)) {
    //    tgtWkdProcess->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_SCRIPT_HOST;
    //}

    /* §8 缓解缺失检测（迁移自 SS PapAnalyzePEHeaders + PapAnalyzeSecurityMitigations，
     * 门控 !IsSystem 对齐 §5 Ghosting；运行时 DEP 由 Phase 6 填充 DepEnabled） */
    //if (!tgtWkdProcess->SecurityContext->IsSystem) {
    //    IocpCheckMitigations(Pair, tgtWkdProcess);
    //}

    WkdReleasePushLockExclusive(&tgtWkdProcess->SecurityContext->Lock);
    PsDereferenceWkdProcess(tgtWkdProcess);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
IocInitializeParentChildRules(
    VOID
    )
{

    IocpInitializeParentChildRules();
}

/**************************************************/
/*       §8 剪贴板追踪表（死代码预留）             */
/*                                                 */
/*   迁移自 SS ClipboardMonitor.c per-PID 追踪表    */
/*   (CBMON_PROCESS_ENTRY 哈希表 + temp 快速写入    */
/*    速率窗口检测, T1115)                          */
/*                                                 */
/*   ★ 不接入原因:                                  */
/*     1. wkd 驱动文件系统 minifilter 未激活        */
/*        (WkdEntry.c FsInitialize 注释; Filter.c   */
/*        FspPreWrite 为空骨架), 无文件写入事件源;   */
/*     2. per-PID 追踪表与 WKD_PROCESS/进程对状态   */
/*        语义重叠, 进程创建信号已由 §3.2 活代码     */
/*        IocpDetectClipboardAbuse 直接提交评分.     */
/*   ★ 激活条件: 待 Filter.c 激活 IRP_MJ_WRITE 后,   */
/*     FspPreWrite 调 IocpClipboardCheckFileWrite;  */
/*     §3.2 命中后调 IocpClipboardTrackProcess 入表. */
/*                                                 */
/*   功能面: 对已标记剪贴板指标的进程, 检测 temp 路径 */
/*   快速写入 (≥10 次/5s), 命中置 RapidTempWrites.   */
/*   对齐 SS CbMonCheckFileWrite L459-554.          */
/*                                                 */
/*   说明: 死代码函数为非 static (无外部调用者不触发  */
/*   C4505), 未来接线时在 IocProcess.h 补声明.      */
/**************************************************/

#define IOC_CLIPBOARD_BUCKETS         256
#define IOC_CLIPBOARD_MAX_TRACKED     2048
#define IOC_CLIPBOARD_TEMP_THRESHOLD  10      // 窗口内快速写入阈值
#define IOC_CLIPBOARD_WINDOW_MS       5000    // 5 秒窗口
#define IOC_CLIPBOARD_MAX_BUCKET_WALK 64      // 抗损坏遍历上限

//
// 剪贴板指示器位（对齐 SS CBMON_INDICATOR；仅命令/镜像名/编码已由
// §3.2 活代码覆盖，RapidTempWrites 为写回调专用）
//
#define IOC_INDICATOR_CLIPBOARD_CMDLINE     0x00000001
#define IOC_INDICATOR_KNOWN_STEALER_IMAGE   0x00000002
#define IOC_INDICATOR_RAPID_TEMP_WRITES     0x00000004
#define IOC_INDICATOR_ENCODED_CLIPBOARD_CMD 0x00000040

//
// §8 追踪条目（对齐 SS CBMON_PROCESS_ENTRY L122-137）
//
typedef struct _IOC_CLIPBOARD_PROCESS_ENTRY {
    LIST_ENTRY Link;
    HANDLE ProcessId;
    ULONG Indicators;              // IOC_INDICATOR_* 位图
    volatile LONG TempFileWrites;  // 窗口内写入计数
    LARGE_INTEGER WindowStart;     // 当前计数窗口起始
    volatile LONG Flagged;         // 已上报标记（InterlockedExchange 需 LONG 宽）
    volatile LONG ReferenceCount;  // list 持有 1 + 调用者持有；防清理 UAF
} IOC_CLIPBOARD_PROCESS_ENTRY, *PIOC_CLIPBOARD_PROCESS_ENTRY;

//
// §8 全局状态（对齐 SS CBMON_STATE L139-150，裁剪 InitState/Rundown/Lookaside：
// 死代码未接线，lookaside 用 ExAllocatePoolWithTag 替代）
//
static struct {
    volatile BOOLEAN Initialized;
    LIST_ENTRY ProcessBuckets[IOC_CLIPBOARD_BUCKETS];
    EX_PUSH_LOCK BucketLocks[IOC_CLIPBOARD_BUCKETS];
    volatile LONG TrackedCount;
    volatile LONG64 FileWriteMatches;   // 快速 temp 写入命中数（对齐 SS Stats.FileWriteMatches）
} g_IocClipboardTrack;

static
ULONG
IocpClipboardHashPid(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    pid ^= (pid >> 16);
    pid *= 0x45d9f3b;
    pid ^= (pid >> 16);
    return (ULONG)(pid & (IOC_CLIPBOARD_BUCKETS - 1));
}

//
// 释放调用者引用；归零时（list 引用 + 最后调用者引用均释放）回池
//
static
VOID
IocpClipboardReleaseEntry(
    _In_ PIOC_CLIPBOARD_PROCESS_ENTRY Entry
    )
{
    if (Entry == NULL) {
        return;
    }
    if (InterlockedDecrement(&Entry->ReferenceCount) == 0) {
        ExFreePoolWithTag(Entry, 'bpCI');
    }
}

//
// 查/建追踪条目（对齐 SS CbMonpLookupProcess L597-691）
// 命中在桶共享锁内加 caller 引用返回；CreateIfMissing 在锁外分配、
// 独占锁内 TOCTOU 复查，避免并发重复插入。
//
static
PIOC_CLIPBOARD_PROCESS_ENTRY
IocpClipboardLookupProcess(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfMissing
    )
{
    ULONG bucket = IocpClipboardHashPid(ProcessId);
    PLIST_ENTRY listHead = &g_IocClipboardTrack.ProcessBuckets[bucket];
    PLIST_ENTRY entry;
    PIOC_CLIPBOARD_PROCESS_ENTRY procEntry = NULL;
    ULONG walkCount = 0;

    WkdAcquirePushLockShared(&g_IocClipboardTrack.BucketLocks[bucket]);

    for (entry = listHead->Flink;
         entry != listHead && walkCount < IOC_CLIPBOARD_MAX_BUCKET_WALK;
         entry = entry->Flink, walkCount++) {
        PIOC_CLIPBOARD_PROCESS_ENTRY candidate =
            CONTAINING_RECORD(entry, IOC_CLIPBOARD_PROCESS_ENTRY, Link);
        if (candidate->ProcessId == ProcessId) {
            /* 桶锁内加 caller 引用，防并发 IocpClipboardRemoveProcess 释放 */
            InterlockedIncrement(&candidate->ReferenceCount);
            procEntry = candidate;
            break;
        }
    }

    WkdReleasePushLockShared(&g_IocClipboardTrack.BucketLocks[bucket]);

    if (procEntry == NULL && CreateIfMissing) {
        /* 防资源耗尽 */
        if (g_IocClipboardTrack.TrackedCount >= IOC_CLIPBOARD_MAX_TRACKED) {
            return NULL;
        }

        procEntry = (PIOC_CLIPBOARD_PROCESS_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(IOC_CLIPBOARD_PROCESS_ENTRY), 'bpCI');
        if (procEntry == NULL) {
            return NULL;
        }

        RtlZeroMemory(procEntry, sizeof(IOC_CLIPBOARD_PROCESS_ENTRY));
        procEntry->ProcessId = ProcessId;
        procEntry->ReferenceCount = 2;   // list 持有 1 + caller 持有 1

        WkdAcquirePushLockExclusive(&g_IocClipboardTrack.BucketLocks[bucket]);

        /* TOCTOU: 独占锁下复查 */
        {
            PLIST_ENTRY check;
            ULONG reCheckWalk = 0;
            for (check = listHead->Flink;
                 check != listHead && reCheckWalk < IOC_CLIPBOARD_MAX_BUCKET_WALK;
                 check = check->Flink, reCheckWalk++) {
                PIOC_CLIPBOARD_PROCESS_ENTRY existing =
                    CONTAINING_RECORD(check, IOC_CLIPBOARD_PROCESS_ENTRY, Link);
                if (existing->ProcessId == ProcessId) {
                    /* 已存在：释放本线程分配，对 existing 加 caller 引用 */
                    InterlockedIncrement(&existing->ReferenceCount);
                    WkdReleasePushLockExclusive(&g_IocClipboardTrack.BucketLocks[bucket]);
                    ExFreePoolWithTag(procEntry, 'bpCI');
                    return existing;
                }
            }
        }

        InsertTailList(listHead, &procEntry->Link);
        InterlockedIncrement(&g_IocClipboardTrack.TrackedCount);

        WkdReleasePushLockExclusive(&g_IocClipboardTrack.BucketLocks[bucket]);
    }

    return procEntry;
}

static
BOOLEAN
IocpClipboardIsTempPath(
    _In_ PUNICODE_STRING FileName
    )
{
    /* 剪贴板倾倒目标路径（对齐 SS CbMonpIsTempPath L757-784） */
    static const WCHAR* tempPatterns[] = {
        L"\\Temp\\",
        L"\\AppData\\Local\\Temp\\",
        L"\\AppData\\Roaming\\",
        L"\\Local Settings\\Temp\\",
        L"\\$Recycle.Bin\\",
    };

    for (ULONG i = 0; i < sizeof(tempPatterns) / sizeof(tempPatterns[0]); i++) {
        UNICODE_STRING pat;
        RtlInitUnicodeString(&pat, tempPatterns[i]);
        if (IocpFindInUnicodeString(FileName, &pat)) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// 进程创建标记入表（对齐 SS CbMonCheckProcessCreate 入表段 L427-453）
// §3.2 命中剪贴板指标后调用，供未来文件写入检测查询。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocpClipboardTrackProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Indicators
    )
{
    PIOC_CLIPBOARD_PROCESS_ENTRY entry;

    if (Indicators == 0 || !g_IocClipboardTrack.Initialized) {
        return STATUS_SUCCESS;
    }

    entry = IocpClipboardLookupProcess(ProcessId, TRUE);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InterlockedOr((volatile LONG*)&entry->Indicators, (LONG)Indicators);
    IocpClipboardReleaseEntry(entry);

    return STATUS_SUCCESS;
}

//
// 文件写入回调判定（对齐 SS CbMonCheckFileWrite L459-554）
// 由 minifilter IRP_MJ_WRITE PreOperation 调用（待 Filter.c 激活接线）。
// 返回 TRUE = 命中剪贴板倾倒的快速 temp 写入模式。
//
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
IocpClipboardCheckFileWrite(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FileName
    )
{
    PIOC_CLIPBOARD_PROCESS_ENTRY entry;
    LARGE_INTEGER now;
    BOOLEAN suspicious = FALSE;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    if (!g_IocClipboardTrack.Initialized) {
        return FALSE;
    }

    /* 只检查已标记剪贴板指标的进程 */
    entry = IocpClipboardLookupProcess(ProcessId, FALSE);
    if (entry == NULL || entry->Indicators == 0) {
        if (entry != NULL) {
            IocpClipboardReleaseEntry(entry);
        }
        return FALSE;
    }

    /* 仅检测 temp/appdata 等倾倒目标路径 */
    if (!IocpClipboardIsTempPath(FileName)) {
        IocpClipboardReleaseEntry(entry);
        return FALSE;
    }

    /* 快速写入速率窗口（≥10 次 / 5s） */
    KeQuerySystemTime(&now);

    {
        LONGLONG elapsedMs = (now.QuadPart - entry->WindowStart.QuadPart) / 10000;

        if (elapsedMs > IOC_CLIPBOARD_WINDOW_MS || entry->WindowStart.QuadPart == 0) {
            /* 重置窗口 */
            entry->WindowStart = now;
            InterlockedExchange(&entry->TempFileWrites, 1);
        } else {
            LONG count = InterlockedIncrement(&entry->TempFileWrites);

            if (count >= IOC_CLIPBOARD_TEMP_THRESHOLD &&
                InterlockedCompareExchange(&entry->Flagged, 1, 0) == 0) {
                InterlockedOr((volatile LONG*)&entry->Indicators,
                              (LONG)IOC_INDICATOR_RAPID_TEMP_WRITES);
                InterlockedIncrement64(&g_IocClipboardTrack.FileWriteMatches);
                suspicious = TRUE;
                /* SS CbMonCheckFileWrite 命中后还 BeEngineSubmitEvent(
                 *   BehaviorEvent_ClipboardRapidTempWrites, 65)——wkD 由接线方
                 *   (未来 FspPreWrite) 决定上报方式, 此处仅置位返回 TRUE。 */
            }
        }
    }

    IocpClipboardReleaseEntry(entry);
    return suspicious;
}

//
// 进程退出清理（对齐 SS CbMonRemoveProcess L829-898）
// 由进程终止回调调用，防追踪表填满后永久失聪。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocpClipboardRemoveProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket;
    PLIST_ENTRY listHead;
    PLIST_ENTRY entry;
    PIOC_CLIPBOARD_PROCESS_ENTRY procEntry = NULL;
    ULONG walkCount = 0;

    if (!g_IocClipboardTrack.Initialized) {
        return;
    }

    bucket = IocpClipboardHashPid(ProcessId);
    listHead = &g_IocClipboardTrack.ProcessBuckets[bucket];

    WkdAcquirePushLockExclusive(&g_IocClipboardTrack.BucketLocks[bucket]);

    for (entry = listHead->Flink;
         entry != listHead && walkCount < IOC_CLIPBOARD_MAX_BUCKET_WALK;
         entry = entry->Flink, walkCount++) {
        PIOC_CLIPBOARD_PROCESS_ENTRY candidate =
            CONTAINING_RECORD(entry, IOC_CLIPBOARD_PROCESS_ENTRY, Link);
        if (candidate->ProcessId == ProcessId) {
            RemoveEntryList(&candidate->Link);
            procEntry = candidate;
            InterlockedDecrement(&g_IocClipboardTrack.TrackedCount);
            break;
        }
    }

    WkdReleasePushLockExclusive(&g_IocClipboardTrack.BucketLocks[bucket]);

    if (procEntry != NULL) {
        /* 释放 list 引用；若仍有调用者引用由最后一次 Release 回池 */
        IocpClipboardReleaseEntry(procEntry);
    }
}

//
// §8 初始化/清理（对齐 SS CbMonInitialize/Shutdown L224-314）
// 死代码未接线，由未来文件回调激活方显式调用。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocpClipboardInitialize(
    VOID
    )
{
    if (g_IocClipboardTrack.Initialized) {
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < IOC_CLIPBOARD_BUCKETS; i++) {
        InitializeListHead(&g_IocClipboardTrack.ProcessBuckets[i]);
        ExInitializePushLock(&g_IocClipboardTrack.BucketLocks[i]);
    }

    g_IocClipboardTrack.TrackedCount = 0;
    g_IocClipboardTrack.Initialized = TRUE;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocpClipboardShutdown(
    VOID
    )
{
    if (!g_IocClipboardTrack.Initialized) {
        return;
    }

    for (ULONG i = 0; i < IOC_CLIPBOARD_BUCKETS; i++) {
        ULONG drained = 0;
        while (!IsListEmpty(&g_IocClipboardTrack.ProcessBuckets[i]) &&
               drained < IOC_CLIPBOARD_MAX_TRACKED) {
            PLIST_ENTRY entry = RemoveHeadList(&g_IocClipboardTrack.ProcessBuckets[i]);
            PIOC_CLIPBOARD_PROCESS_ENTRY procEntry =
                CONTAINING_RECORD(entry, IOC_CLIPBOARD_PROCESS_ENTRY, Link);
            IocpClipboardReleaseEntry(procEntry);
            drained++;
        }
    }

    g_IocClipboardTrack.TrackedCount = 0;
    g_IocClipboardTrack.Initialized = FALSE;
}

/**************************************************/
/*       §9 WSL 文件访问检测（死代码预留）           */
/*                                                   */
/*   迁移自 SS WSLMonitor.c WslMonCheckFileAccess     */
/*   (L558-686)：WSL 进程访问宿主凭据文件(T1003)/     */
/*   驱动目录·System32(T1611) 逃逸检测。              */
/*                                                   */
/*   ★ 不接入原因:                                    */
/*     1. wkd 驱动文件系统 minifilter 未激活          */
/*        (WkdEntry.c FsInitialize 注释; Filter.c     */
/*        FspPreCreate 仅为 YARA 扫描回路), 无文件     */
/*        访问事件源;                                 */
/*     2. 依赖进程侧 WKD_BEHAVIOR_WSL_PROCESS 标志     */
/*        (§3.3 活代码已设置), 激活后即可短路查询。    */
/*   ★ 激活条件: 待 Filter.c FspPreCreate 激活后,      */
/*     在 FltGetFileNameInformation 之后、扩展名过滤    */
/*     之前调用（凭据文件无扩展名/非可扫扩展名, 必须    */
/*     在扩展名过滤前检查, 对齐 SS PreCreate.c L1088）。*/
/*                                                   */
/*   说明: 死代码函数为非 static（无外部调用者不触发    */
/*   C4505), 未来接线时在 IocProcess.h 补声明.         */
/**************************************************/

//
// 宿主凭据文件路径（对齐 SS WSLMonitor.c g_CredentialPaths L132-138）
//
static const PCWSTR g_WslCredentialPaths[] = {
    L"\\Windows\\System32\\config\\SAM",
    L"\\Windows\\System32\\config\\SECURITY",
    L"\\Windows\\System32\\config\\SYSTEM",
    L"\\Windows\\NTDS\\ntds.dit",
    L"\\Windows\\System32\\config\\DEFAULT",
};

//
// 凭据路径后缀匹配（对齐 SS WslpIsCredentialPath L848-871，
// 处理 \Device\HarddiskVolumeN 等卷前缀变化）
//
static
BOOLEAN
IocpWslIsCredentialPath(
    _In_ PUNICODE_STRING FileName
    )
{
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_WslCredentialPaths); i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_WslCredentialPaths[i]);
        if (FileName->Length >= pattern.Length) {
            UNICODE_STRING suffix;
            suffix.Buffer = FileName->Buffer +
                (FileName->Length - pattern.Length) / sizeof(WCHAR);
            suffix.Length = pattern.Length;
            suffix.MaximumLength = pattern.Length;
            if (RtlEqualUnicodeString(&suffix, &pattern, TRUE)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocpCheckWslFileAccess(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FileName
    )
/*++
Routine Description:
    WSL 进程文件访问逃逸检测（对齐 SS WslMonCheckFileAccess L558-686）。
    WSL 进程访问宿主凭据文件 → TsIndicator_Wsl_CredentialAccess（T1003）；
    访问 \drivers\ → TsIndicator_Wsl_DriverAccess（T1611）；访问 \System32\
    → TsIndicator_Wsl_System32Access（T1611）。非 WSL 进程短路返回。

Arguments:
    ProcessId  - 请求进程 PID（对齐 SS RequestorPid）。
    FileName   - 目标文件路径（FltGetFileNameInformation 归一化路径）。

Return Value:
    STATUS_SUCCESS（死代码预留，未来由文件回调接线方调用）。
--*/
{
    PWKD_PROCESS proc;

    /* 防御校验（对齐 SS WSL-14：FileName 可 NULL Buffer） */
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return STATUS_SUCCESS;
    }

    /* 非 WSL 进程短路（性能关键，§3.3 标志已设置） */
    proc = PsLookupWkdProcessByProcessId(ProcessId);
    if (proc == NULL) {
        return STATUS_SUCCESS;
    }
    if (proc->SecurityContext == NULL ||
        !(proc->SecurityContext->BehaviorFlags & WKD_BEHAVIOR_WSL_PROCESS)) {
        PsDereferenceWkdProcess(proc);
        return STATUS_SUCCESS;
    }
    PsDereferenceWkdProcess(proc);

    /* WSL 进程每次文件访问计数（对齐 SS L601-602 FileAccessCount/FileSystemCrossings，
     * FileAccessCount 为 per-process 字段已废弃，仅保留全局 FileSystemCrossings） */
    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslFileSystemCrossings);

    /* Priority 1: 凭据文件访问（T1003，对齐 SS L609-631，85 分） */
    if (IocpWslIsCredentialPath(FileName)) {
        AeReportIndicatorPair(ProcessId, ProcessId, TsSourceIOC,
            TsIndicator_Wsl_CredentialAccess, AeThreatSeverityCritical);
        InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslCredentialAccess);
        InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslEscapeAttempts);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender/WSL] CRITICAL: WSL credential access attempt! "
            "PID=%lu, File=%wZ\n", HandleToULong(ProcessId), FileName);
        return STATUS_SUCCESS;
    }

    /* Priority 2: 驱动目录访问（T1611，对齐 SS L639-662，60 分） */
    {
        UNICODE_STRING driversDir;
        RtlInitUnicodeString(&driversDir, L"\\drivers\\");
        if (IocpFindInUnicodeString(FileName, &driversDir)) {
            AeReportIndicatorPair(ProcessId, ProcessId, TsSourceIOC,
                TsIndicator_Wsl_DriverAccess, AeThreatSeverityHigh);
            InterlockedIncrement(&g_WkdProcessMonitor.Statistics.WslEscapeAttempts);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender/WSL] WSL driver directory access: "
                "PID=%lu, File=%wZ\n", HandleToULong(ProcessId), FileName);
            return STATUS_SUCCESS;
        }
    }

    /* Priority 3: System32 访问（T1611，对齐 SS L670-680，仅记录低分） */
    {
        UNICODE_STRING system32Dir;
        RtlInitUnicodeString(&system32Dir, L"\\System32\\");
        if (IocpFindInUnicodeString(FileName, &system32Dir)) {
            AeReportIndicatorPair(ProcessId, ProcessId, TsSourceIOC,
                TsIndicator_Wsl_System32Access, AeThreatSeverityLow);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "[WkDefender/WSL] WSL System32 access: "
                "PID=%lu, File=%wZ\n", HandleToULong(ProcessId), FileName);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*       死代码迁移区（对齐 SS ProcessNotify.c）     */
/**************************************************/
//
// 以下为 ShadowStrike ProcessNotify.c 创建路径分析链功能面迁移（重功能实现
// 非复制），当前不接入流水线。每个函数标注：对齐 SS 行号 / 不接入原因 /
// 激活条件。死代码 static 函数未引用，包裹 #pragma warning(4505) 抑制告警。
//
// 已覆盖无需迁移（本文件既有对等物）：
//   - 创建者上下文存储（SS ShadowStrikeStoreCreatingProcessContext L2722）：
//     WKD_PROCESS.Core.CreatorProcessId 已保存（PspCreateProcessContext Phase 1，
//     = CreateInfo->CreatingThreadId.UniqueProcess）。CreatingThreadId（UniqueThread）
//     未采集——agent EVENT_PAYLOAD_PROCESS_CREATE 无此字段，谱系/因果图为进程级，
//     源进程经消息头 SourceProcessId 传递；SS 的 CreatingThreadId 用于深度 PPID
//     校验，wkd 用 CreatorProcessId 进程级覆盖。
//   - 特权基线（SS PmRecordBaseline L1437-1452）：SecurityContext 创建时由
//     IocpCapturePrivilegeInfo 捕获的 5 特权 + IsSystem/IsService 即基线。
//   - 创建时句柄取证（SS HtSnapshotHandles L3392-3465）：wkd Hsp*（HandleTracker
//     迁移 #38）+ Ob 回调 IocDetectHandle 主路径已覆盖。
//

#pragma warning(push)
#pragma warning(disable:4505)

//
// [死代码] 创建时进程空洞/幽灵比对（对齐 SS PhAnalyzeAtCreation L2109-2156
//   调用段 + HollowingDetector.c 实现）
// 功能：进程创建回调内（进程未执行前）比对 PEB 内存镜像 vs 磁盘文件，
//   检测进程镂空（T1055.012）/ 幽灵（T1055.013）。
// 不接入原因：依赖驱动内存扫描能力（IoaHandleRealTimeMemoryEvent #12 死代码，
//   待驱动补镜像/载荷保护字段）；当前仅 Ghosting 基础版（IocpDetectGhosting §5
//   ZwOpenFile+DeletePending）已激活。
// 激活条件：驱动内存扫描子模块就绪后接线。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PnpAnalyzeAtCreation(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(WkdProcess);

    /* 对齐 SS PhAnalyzeAtCreation：读 PEB → 取内存镜像首节 → 读磁盘文件 →
     * 比对 MZ/节表/熵。wkd 无驱动内存读取能力（ReadProcessMemory 用户态，
     * 驱动侧需 MmCopyVirtualMemory + 手工解析），依赖缺口见上。 */
    return STATUS_NOT_IMPLEMENTED;
}

//
// [死代码] 环境变量分析（对齐 SS EmCaptureEnvironment L3314-3390 调用段 +
//   EnvironmentMonitor.c 实现）
// 功能：读进程 PEB 环境块，检测 PATH 劫持（T1574.007）/ DLL 搜索序劫持
//   （T1574.008）/ 代理操纵（T1090.001）/ TEMP 覆盖 / 编码载荷（T1027）。
// 不接入原因：agent 侧 IpeAnalyzeEnvironment（IocProcessEnrich #37）已全量
//   覆盖；驱动 PEB 环境块读（逐页 ReadProcessMemory + 宽串解析）成本高且
//   属 L2 分析，wkd 分层模型下沉 agent。
// 激活条件：agent 环境分析启用（g_IoaEnvironmentAnalyzerEnabled=FALSE 开关）
//   后，本函数可作驱动侧早期信号保留。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PnpCaptureEnvironment(
    _In_ PWKD_PROCESS Process
    )
{
    UNREFERENCED_PARAMETER(Process);

    /* 对齐 SS EmCaptureEnvironment：ProcessBasicInformation → PEB →
     * ProcessParameters.Environment 偏移（x64 0x80/x86 0x48）→ 逐 4KB 页
     * ReadProcessMemory + 双 null 终止扫描（cap 64KB）→ 宽串解析 PATH/
     * 代理/TEMP/熵判定。agent IpeAnalyzeEnvironment 为完整实现。 */
    return STATUS_NOT_IMPLEMENTED;
}

#pragma warning(pop)
