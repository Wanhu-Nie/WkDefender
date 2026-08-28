#pragma once

#include <ntifs.h>

typedef unsigned char BYTE;

#define MAX_PATH 256

#define ALIGN_8(x) (((unsigned long)(x) + 7UL) & ~7UL)

//
// 会话ID常量定义
//
#define INVALID_SESSION_ID ((ULONG)-1)

//
// 哈希表大小定义
//
#define WKD_PROCESS_HASH_MAP_SIZE 64

//
// 跨进程攻击模式检测配置
//
#define WKD_CROSS_PROCESS_DETECTION_WINDOW_MS      1000 * 60 * 60 // 1个小时
#define WKD_CROSS_PROCESS_MAX_UNIQUE_TARGETS       8

//
// IOA 事件节点配置
//
#define WKD_MAX_IOA_EVENTS_PER_PROC                64      // 每个进程最多缓存的事件节点数

//
// 事件聚合常量
//
#define WKD_SYSCALL_SUPPRESS_WINDOW_MS             50      // Tier1 生产者侧抑制窗口（ms）
#define WKD_SYSCALL_AGGREGATE_WINDOW_MS            500     // Tier2 消费者侧折叠窗口（ms）

//
// 完整性级别定义（基于Windows MIC机制）
//
typedef enum _WKD_INTEGRITY_LEVEL {
    WkdIntegrityLow = 0x1000,               // Internet Explorer、沙盒应用
    WkdIntegrityMedium = 0x2000,            // 普通用户进程（默认）
    // WkdIntegrityMediumPlus = 0x2100,
    WkdIntegrityHigh = 0x3000,              // 以管理员身份运行的进程
    WkdIntegritySystem = 0x4000,            // 系统服务、内核组件
    WkdIntegrityEdr = 0x5000
} WKD_INTEGRITY_LEVEL, * PWKD_INTEGRITY_LEVEL;

//
// 威胁等级定义
//
typedef enum _AE_THREAT_SEVERITY {
    AeThreatSeverityNone = 0,
    AeThreatSeverityLow = 1,
    AeThreatSeverityMedium = 2,
    AeThreatSeverityHigh = 3,
    AeThreatSeverityCritical = 4
} AE_THREAT_SEVERITY, * PAE_THREAT_SEVERITY;

//
// 事件类型定义（MITRE ATT&CK ID映射）
//
typedef enum _WKD_THREAT_TYPE {
    WkdThreat_PpidSpoofing = 1,
    WkdThreat_ProcessInjection,
    WkdThreat_SuspendedCreate,
    WkdThreat_CrossSession,
    WkdThreat_ElevatedProcess,
    WkdThreat_PrivilegeAbuse,
    WkdThreat_DllSideLoading,
    WkdThreat_PathHijacking,
    WkdThreat_ReflectiveLoad,
    WkdThreat_PowershellEncoded,
    WkdThreat_Downloader,
    WkdThreat_LolbinAbuse,

    // === Syscall相关事件类型 ===
    WkdThreat_ProcessOpen,           // NtOpenProcess
    WkdThreat_MemoryAllocate,        // NtAllocateVirtualMemory
    WkdThreat_MemoryWrite,           // NtWriteVirtualMemory
    WkdThreat_ThreadCreate,          // NtCreateRemoteThread
    WkdThreat_MemoryRead,            // NtReadVirtualMemory
    WkdThreat_SectionMap             // NtMapViewOfSection
} WKD_THREAT_TYPE, * PWKD_THREAT_TYPE;

//
// 进程行为标识位
//
#define WKD_PROCESS_FLAG_SUSPICIOUS_CHAIN    0x00000001
#define WKD_PROCESS_FLAG_INJECTION_DETECTED   0x00000002
#define WKD_PROCESS_FLAG_PPID_SPOOFED        0x00000004
#define WKD_PROCESS_FLAG_CROSS_SESSION       0x00000008
#define WKD_PROCESS_FLAG_ELEVATED            0x00000010
#define WKD_PROCESS_FLAG_PRIVILEGE_ABUSE      0x00000020
#define WKD_PROCESS_FLAG_LOLBIN_DETECTED      0x00000040
#define WKD_PROCESS_FLAG_POWERSHELL_ENCODED   0x00000080
#define WKD_PROCESS_FLAG_DOWNLOADER_DETECTED  0x00000100
#define WKD_PROCESS_FLAG_REFLECTIVE_LOAD      0x00000200
#define WKD_PROCESS_FLAG_PE_HEADER_INVALID    0x00000400
#define WKD_PROCESS_FLAG_SIGNATURE_INVALID    0x00000800
#define WKD_PROCESS_FLAG_HOLLOWING_DETECTED   0x00001000
#define WKD_PROCESS_FLAG_PATH_HIJACKING       0x00002000
#define WKD_PROCESS_FLAG_DLL_SIDE_LOADING     0x00004000

//
// 跨进程操作标志位（由 BehaviorEngine 遍历 IoaEventHead 检测后设置）
//
#define WKD_PROCESS_FLAG_CROSS_PROCESS_MEMORY_ACCESS  0x00008000
#define WKD_PROCESS_FLAG_REMOTE_THREAD_CREATE         0x00010000
#define WKD_PROCESS_FLAG_APC_INJECTION                0x00020000
#define WKD_PROCESS_FLAG_CONTEXT_HIJACK               0x00040000
#define WKD_PROCESS_FLAG_MEMORY_READ_REMOTE           0x00080000
#define WKD_PROCESS_FLAG_SECTION_MAP_REMOTE           0x00100000

//
// 命令行匹配标志位
//
#define WKD_CMD_FLAG_POWERSHELL_ENCODED       0x00000001
#define WKD_CMD_FLAG_DOWNLOADER               0x00000002
#define WKD_CMD_FLAG_REFLECTIVE_LOAD          0x00000004
#define WKD_CMD_FLAG_SUSPICIOUS_CMD           0x00000008

//
// LOLBin文件名列表
//
extern const WCHAR* g_WkdLolbinList[];
extern const ULONG g_WkdLolbinCount;

//
// PowerShell检测模式
//
extern const WCHAR* g_WkdPowershellPatterns[];
extern const ULONG g_WkdPowershellPatternCount;

//
// 下载器检测模式
//
extern const WCHAR* g_WkdDownloaderPatterns[];
extern const ULONG g_WkdDownloaderPatternCount;

//
// 反射加载检测模式
//
extern const WCHAR* g_WkdReflectivePatterns[];
extern const ULONG g_WkdReflectivePatternCount;

//
// 敏感特权列表
//
extern const WCHAR* g_WkdSensitivePrivileges[];
extern const ULONG g_WkdSensitivePrivilegeCount;


//
// 敏感权限位定义 —— 常用于代码注入/进程操纵
//

/* 进程敏感权限 */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           0x0001
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD       0x0002
#endif

// 通过调用 user-mode WriteProcessMemory 和 VirtualProtectEx 例程来修改进程的地址空间。
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION        0x0008
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             0x0010
#endif

// 写入进程的地址空间，例如通过调用用户模式 WriteProcessMemory 例程。
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE            0x0020
#endif

// 通过调用用户模式 DuplicateHandle 例程，从进程的上下文中复制句柄。
//#ifndef PROCESS_DUP_HANDLE
//#define PROCESS_DUP_HANDLE          0x0040
//#endif

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS      0x0080
#endif

// 设置进程的工作集大小，例如通过调用用户模式 SetProcessWorkingSetSize 例程。
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA           0x0100
#endif

// 通过调用用户模式 SetPriorityClass 例程来修改进程设置。
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION     0x0200
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif

// 暂停或恢复进程。
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME      0x0800
#endif

// 检索进程的必要信息
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION   0x1000
#endif

#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS          0x1ffff
#endif

#define WKD_SENSITIVE_PROCESS_ACCESS    \
    (PROCESS_VM_WRITE          |        \
     PROCESS_VM_OPERATION      |        \
     PROCESS_CREATE_PROCESS    |        \
     PROCESS_CREATE_THREAD     |        \
     PROCESS_SUSPEND_RESUME    |        \
     PROCESS_SET_INFORMATION   |        \
     PROCESS_TERMINATE         |        \
     PROCESS_DUP_HANDLE)

// 需要从线程对象读取某些信息，例如退出代码（请参阅 GetExitCodeThread）。
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION        0x0040
#endif

// 通过调用用户模式 SetTokenInformation 例程来修改线程模拟令牌的属性。
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN         0x0080
#endif

// 模拟作系统的匿名登录令牌，例如通过调用用户模式 ImpersonateAnonymousToken 例程。
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE              0x0100
#endif

// 使服务器线程能够模拟其中一个客户端。
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION     0x0200
#endif

#define WKD_SENSITIVE_THREAD_ACCESS     \
    (THREAD_SET_CONTEXT        |        \
     THREAD_TERMINATE          |        \
     THREAD_IMPERSONATE        |        \
     THREAD_SUSPEND_RESUME     |        \
     THREAD_SET_THREAD_TOKEN   |        \
     THREAD_SET_INFORMATION    |        \
     THREAD_DIRECT_IMPERSONATION)