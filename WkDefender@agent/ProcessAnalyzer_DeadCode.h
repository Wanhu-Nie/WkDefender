/**************************************************/
/*  WkDefender 死代码 — 进程分析器搁置能力           */
/*  迁移自 ShadowStrike ProcessAnalyzer             */
/*                                                  */
/*  ★ 死代码声明 ★                                  */
/*  以下能力为功能面全量迁移，但当前不接入任何流水线，   */
/*  仅保持可编译。前置依赖满足后可恢复接入。           */
/*  ① 句柄分析    EnumerateHandlesInternal (L1307)   */
/*     前置: 需 SeDebugPrivilege + 依赖 ObjectNotify   */
/*     事件流（否则只有快照式枚举，无实时事件）        */
/*  ② 调用栈回溯  GetThreadCallStack (L3432)         */
/*     前置: 昂贵 RBP 链遍历，等 ThreadHijack 迁移后  */
/*     一并接入                                       */
/*  ③ 行为编排    AnalyzeBehaviorInternal (L2282)     */
/*     前置: 依赖 ProcessInjectionDetector/          */
/*     ThreadHijackDetector/DLLInjectionDetector/     */
/*     ReflectiveDLLDetector/ProcessHollowingDetector/ */
/*     MemoryScanner 检测器; AtomBombing 检测能力已    */
/*     迁移至 IOA/IoaInjectionClassifier (T1055.009) */
/*  ④ 证书黑名单  IsCertificateCompromised (L3570)   */
/*     前置: 依赖 ioc_certs 表已填充证书黑名单数据    */
/*                                                  */
/*  ★ 来源澄清（2026-08 ProcessAnalyzer 迁移）★      */
/*  本文件的 WkdPd* 函数对齐 SS 子子系统              */
/*  (HandleTracker/CommandLineParser/ParentChain-    */
/*  Tracker/TokenAnalyzer/PrivilegeMonitor/          */
/*  EnvironmentMonitor)，注释中的 PS (PhantomCore)    */
/*  命名与行号；非 SS ProcessAnalyzer.c (Pap* 前缀,   */
/*  3389 行)。两者功能面不重叠——Pap* 的 PE/令牌/父子/ */
/*  命令行/评分已由 IocProcessEnrich/IocScanner/      */
/*  驱动 IocProcess.c 覆盖。                          */
/*                                                  */
/*  SS ProcessAnalyzer.c (Pap*) → wkd 落点映射:      */
/*   PapAnalyzePEHeaders       → PEAnalyzer +        */
/*                              IpeValidateImageBase */
/*                              + ImgpAnalyzePeHeader*/
/*   PapAnalyzeSecurityMitig.  → driver IocpCapture  */
/*      (运行时DEP)             PrivilegeInfo Phase6 */
/*                              + IpeCollectUserCtx  */
/*   Pap* 缓解(DllChar)        → driver §8           */
/*                              IocpCheckMitigations */
/*   PapAnalyzeProcessToken    → driver IocpCapture  */
/*                              PrivilegeInfo +      */
/*                              IpeCollectPrivileges */
/*   PapAnalyzeParentProcess   → driver §6           */
/*                              IocpAnalyzeParent    */
/*                              Process +            */
/*                              IpeAnalyzeParentChild*/
/*   PapAnalyzeCommandLine     → driver §3           */
/*                              IocpDetectCommandLine*/
/*                              + CmdLineAnalyzer    */
/*   PapCalculateSuspicionScore→ driver              */
/*                              TsSettleScores(指示器)*/
/*   PapCalculateEntropy       → WpeCalculateEntropy */
/*   PapIsSuspiciousPath       → driver §10(命令行+  */
/*                              镜像路径)            */
/*                                                  */
/*  SS 死标志(头声明无设置点)→ wkd 覆盖:              */
/*   HOLLOWED      → IpeDetectProcessHollowing +    */
/*                    driver IocpDetectGhosting      */
/*   INJECTED      → IOA/IoaInjectionClassifier      */
/*   MASQUERADING  → Common/PathUtil WkdIsMasquerading*/
/*   DEBUGGER_PRESENT → WkdPdIsBeingDebugged(本文件) */
/*   ANOMALOUS_TOKEN/SYSTEM_IMPERSONATION            */
/*                → driver 令牌画像/SeImpersonate    */
/*   UNUSUAL_EXTENSION → driver §10 .scr/.pif/.com   */
/*   SHORT_LIVED   → 不迁移 (SS 无实现)              */
/**************************************************/

#pragma once

#include <windows.h>
#include <winnt.h>
#include "IOC/IocTypes.h"
#include "IOC/PEAnalyzer/PeAnalyzer.h"     /* WPA_RISK_LEVEL / WKD_RISK_INPUT */
#include "Memory/MemoryScan.h"     /* WKD_MEMORY_PROFILE */
#include "ProcessThreads.h"        /* WKD_THREAD_PROFILE */
#include "NetworkFootprint.h"      /* WKD_NETWORK_FOOTPRINT */

//
// ======================================================================
// ① 句柄分析（对齐 PS EnumerateHandlesInternal）
// ======================================================================

//
// 句柄类型分类
//
typedef enum _WKD_HANDLE_KIND {
    WkdHk_Unknown   = 0,
    WkdHk_File      = 1,
    WkdHk_Key       = 2,
    WkdHk_Process   = 3,
    WkdHk_Thread    = 4,
    WkdHk_Token     = 5,
    WkdHk_DebugObject = 6,
    WkdHk_Other     = 7,
} WKD_HANDLE_KIND, *PWKD_HANDLE_KIND;

//
// 单句柄信息
//
typedef struct _WKD_HANDLE_INFO {
    ULONG_PTR   HandleValue;
    WKD_HANDLE_KIND Kind;
    ULONG       GrantedAccess;
    WCHAR       ObjectName[260];     // LSASS / 注册表路径等
    BOOLEAN     IsSuspicious;
    ULONG       RiskScore;
    WCHAR       SuspicionReason[128];
} WKD_HANDLE_INFO, *PWKD_HANDLE_INFO;

//
// 句柄分析结果
//
#define WKD_HANDLE_MAX_ANALYZE   256

typedef struct _WKD_HANDLE_SUMMARY {
    ULONG           TotalHandles;
    ULONG           AnalyzedCount;
    BOOLEAN         HasLsassAccess;
    BOOLEAN         HasCrossProcessHandles;
    BOOLEAN         HasSensitiveRegAccess;
    BOOLEAN         HasSystemDirWrite;
    ULONG           SuspiciousCount;
    WKD_HANDLE_INFO SuspiciousHandles[WKD_HANDLE_MAX_ANALYZE];
} WKD_HANDLE_SUMMARY, *PWKD_HANDLE_SUMMARY;

//
// 枚举进程句柄并检测敏感访问模式（需 SeDebugPrivilege）
//
NTSTATUS
WkdPdEnumerateHandles(
    _In_  DWORD               ProcessId,
    _Out_ PWKD_HANDLE_SUMMARY Summary
    );

//
// ======================================================================
// ② 调用栈回溯（对齐 PS GetThreadCallStack）
// ======================================================================

//
// 单帧
//
typedef struct _WKD_STACK_FRAME {
    ULONG_PTR   ReturnAddress;
    BOOLEAN     IsBacked;           // 返回地址是否落在已知模块
    WCHAR       ModuleName[64];
} WKD_STACK_FRAME, *PWKD_STACK_FRAME;

#define WKD_STACK_MAX_FRAMES    64

typedef struct _WKD_STACK_TRACE {
    ULONG           FrameCount;
    ULONG           UnbackedFrameCount;
    ULONG_PTR       CurrentIp;
    WKD_STACK_FRAME Frames[WKD_STACK_MAX_FRAMES];
} WKD_STACK_TRACE, *PWKD_STACK_TRACE;

//
// 挂起线程并沿 RBP 链回溯调用栈（返回地址模块支撑统计）
//
NTSTATUS
WkdPdGetThreadCallStack(
    _In_  DWORD             ThreadId,
    _Out_ PWKD_STACK_TRACE  Trace
    );

//
// ======================================================================
// ③ 行为编排骨架（对齐 PS AnalyzeBehaviorInternal）
//    依赖各专项检测器，当前仅置标志占位
// ======================================================================

typedef struct _WKD_BEHAVIOR_INDICATORS {
    BOOLEAN     HasProcessHollowing;    // T1055.012
    BOOLEAN     HasRemoteThreads;       // T1055
    BOOLEAN     HasDirectSyscalls;      // T1106
    BOOLEAN     HasAPCsQueued;          // 数据源: WkdEvent_QueueApc (需驱动补 NtQueueApcThread case); 由 IoaInjectionClassifier 原子/APC 判定回填
    BOOLEAN     HasModifiedOtherProcesses;
    BOOLEAN     HasSuspiciousMemoryOperations;
    ULONG       BehaviorRiskScore;      // 0-100
} WKD_BEHAVIOR_INDICATORS, *PWKD_BEHAVIOR_INDICATORS;

//
// 聚合 6 检测器 + 内存扫描器结果（检测器未迁移时全部为 FALSE）
//
NTSTATUS
WkdPdAnalyzeBehavior(
    _In_  DWORD                    ProcessId,
    _Out_ PWKD_BEHAVIOR_INDICATORS Indicators
    );

//
// ======================================================================
// ④ 证书黑名单（对齐 PS IsCertificateCompromised）
//    查询 ioc_certs 表（DefIocSrc_CertBlacklist）
// ======================================================================

//
// 检查证书指纹是否命中黑名单
//
BOOLEAN
WkdPdIsCertificateCompromised(
    _In_ PCWSTR Thumbprint
    );

//
// ======================================================================
// ⑤ 白名单强制完整性检查（对齐 PS AnalyzeProcessInternal L894）
//    白名单进程仍强制检查镂空/反射/注入，命中即撤销信任。
// ======================================================================

typedef struct _WKD_WHITELIST_INTEGRITY {
    BOOLEAN     IsTampered;             // 白名单进程被篡改
    BOOLEAN     HasProcessHollowing;    // T1055.012
    BOOLEAN     HasReflectiveDll;       // T1620
    BOOLEAN     HasInjection;           // T1055
    ULONG       RevokedTrustScore;      // 命中后撤销白名单信任的分数
} WKD_WHITELIST_INTEGRITY, *PWKD_WHITELIST_INTEGRITY;

//
// 对白名单进程执行强制完整性检查（检测器未迁移时全部为 FALSE）
//
NTSTATUS
WkdPdCheckWhitelistedIntegrity(
    _In_  DWORD                    ProcessId,
    _Out_ PWKD_WHITELIST_INTEGRITY Result
    );

//
// ======================================================================
// ⑥ 深度取证编排入口（对齐 PS AnalyzeProcessInternal）
//    综合签名/模块/内存/线程/网络画像，输出进程级综合风险。
// ======================================================================

typedef struct _WKD_PROCESS_FORENSICS_RESULT {
    /* 各画像维度 */
    WKD_MEMORY_PROFILE     Memory;
    WKD_THREAD_PROFILE     Threads;
    WKD_NETWORK_FOOTPRINT  Network;
    IOC_SCAN_RESULT        Ioc;            // 签名/哈希/LOLBin/命令行
    WKD_HANDLE_SUMMARY     Handles;        // 死代码：句柄分析
    WKD_BEHAVIOR_INDICATORS Behavior;      // 死代码：行为编排

    /* 综合评分 */
    ULONG          OverallRiskScore;       // 0-100
    WPA_RISK_LEVEL RiskLevel;
} WKD_PROCESS_FORENSICS_RESULT, *PWKD_PROCESS_FORENSICS_RESULT;

//
// 深度取证编排入口：调用已迁移的画像能力，填充 WKD_RISK_INPUT 计算综合风险。
// 父-子异常/白名单强制检查依赖 IOA 节点，调用方需另行提供（见注释）。
//
NTSTATUS
WkdPdAnalyzeProcess(
    _In_  DWORD                       ProcessId,
    _Out_ PWKD_PROCESS_FORENSICS_RESULT Result
    );

//
// ======================================================================
// ⑦ 快评与工具方法（对齐 PS QuickAssessRisk / IsMicrosoftSigned /
//    IsWhitelisted / IsCriticalProcess / IsBeingDebugged / GetBackingModule）
// ======================================================================

//
// 判定文件是否为微软签名（签名有效且签名者名含 "microsoft"）
//
BOOLEAN
WkdPdIsMicrosoftSigned(
    _In_ PCWSTR FilePath
    );

//
// 判定进程是否白名单（微软签名 + 系统目录路径近似；wkd 白名单库在 driver）
//
NTSTATUS
WkdPdIsWhitelisted(
    _In_  DWORD    ProcessId,
    _Out_ PBOOLEAN Whitelisted
    );

//
// 判定进程名是否为关键进程（csrss/lsass/services/smss/wininit/winlogon）
//
BOOLEAN
WkdPdIsCriticalProcess(
    _In_ PCWSTR ProcessName
    );

//
// 判定进程是否被调试（NtQueryInformationProcess ProcessDebugPort）
//
BOOLEAN
WkdPdIsBeingDebugged(
    _In_ DWORD ProcessId
    );

//
// 查询地址归属模块（Toolhelp 模块枚举比对）
//
BOOLEAN
WkdPdGetBackingModule(
    _In_  DWORD     ProcessId,
    _In_  ULONG_PTR Address,
    _Out_writes_(ModuleNameCch) WCHAR* ModuleName,
    _In_  ULONG     ModuleNameCch
    );

//
// 快评 API（对齐 PS QuickAssessRiskInternal）：
//   白名单 → Trusted；恶意哈希 → Malicious；微软签名 → Trusted；
//   Revoked → Malicious；Unsigned → LowRisk；否则 Unknown。
//
NTSTATUS
WkdPdQuickAssessRisk(
    _In_  DWORD          ProcessId,
    _Out_ PWPA_RISK_LEVEL Level
    );

//
// ======================================================================
// ⑧ 完整模块清单（对齐 PS GetLoadedModulesInternal）
//    枚举全部已加载模块 + 逐模块验签状态。
// ======================================================================

typedef struct _WKD_LOADED_MODULE {
    ULONG_PTR      BaseAddress;
    SIZE_T         SizeOfImage;
    WCHAR          ModulePath[520];
    WCHAR          ModuleName[64];
    DEF_CERT_STATUS CertStatus;     // 每模块签名状态
} WKD_LOADED_MODULE, *PWKD_LOADED_MODULE;

#define WKD_LOADED_MODULE_MAX   2048

//
// 枚举进程全部已加载模块并逐模块验签（对齐 PS GetLoadedModulesInternal）
//
NTSTATUS
WkdPdGetLoadedModules(
    _In_  DWORD             ProcessId,
    _Out_writes_to_(MaxModules, *Count) PWKD_LOADED_MODULE Modules,
    _In_  ULONG             MaxModules,
    _Out_ PULONG            Count
    );
