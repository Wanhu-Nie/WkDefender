/*++
    SelfProtection/CallbackProtection.h - 回调代码完整性保护引擎

    Purpose:
        保护内核回调注册（Process/Thread/Image 等）的代码不被篡改。
        通过 BCrypt SHA-256 哈希回调代码前 256 字节建立基线，
        定期验证完整性，发现篡改时通过 MDL 映射恢复原始代码，
        并通知上层注册的篡改回调。

    Architecture:
        - WKD_CALLBACK_PROTECTION 是不透明句柄（内部结构定义在 .c 中）
        - 所有公共 API 运行于 PASSIVE_LEVEL
        - 回调条目用 LIST_ENTRY + EX_PUSH_LOCK 管理（回调数目有限，线性查找）
        - 使用 BCrypt 替代 SS 的自实现 SHA-256
        - 使用 WkdTimer 替代 SS 的 TimerManager
        - 预留恢复回调接口，供后续接通自动恢复流水线

    Synchronization:
        - CallbackListLock（EX_PUSH_LOCK）保护回调链表的插入/移除
        - 异步校验（定时器线程/回调）执行前获取注入的引擎 EX_RUNDOWN_REF；
          条目生命周期由引擎 rundown 排空保证，无需条目级引用计数
        - 回调验证在 PASSIVE_LEVEL 系统线程中执行（Thread 模式）

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include "../Common/Constants.h"
#include "../Common/Lookaside.h"
#include "../Common/PeriodicTimer.h"
#include "SelfProtectionCompat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_CP_POOL_TAG                 'cPkW'
#define WKD_CP_POOL_TAG_ENTRY           'ePkW'
#define WKD_CP_MAX_CALLBACKS            128
#define WKD_CP_HASH_BYTES               256     // 每个回调哈希的代码字节数
#define WKD_CP_DEFAULT_INTERVAL_MS      5000    // 默认验证间隔（毫秒）

/* ============================================================================
 * 回调类型枚举
 * ============================================================================ */

typedef enum _WKD_CALLBACK_TYPE {
    WkdCallback_Process = 0,            // 进程创建/终止回调（PsSetCreateProcessNotifyRoutine）
    WkdCallback_Thread,                 // 线程创建/终止回调（PsSetCreateThreadNotifyRoutine）
    WkdCallback_Image,                  // 镜像加载回调（PsSetLoadImageNotifyRoutine）
    WkdCallback_Registry,               // 注册表回调（CmRegisterCallback，预留）
    WkdCallback_Object,                 // 对象回调（ObRegisterCallbacks，预留）
    WkdCallback_MaxType
} WKD_CALLBACK_TYPE;

/* ============================================================================
 * 篡改通知回调（检测到篡改时调用）
 * ============================================================================ */

//
// 篡改通知回调
// 运行环境: PASSIVE_LEVEL
// Type:        被篡改的回调类型
// Registration: 被篡改的回调注册句柄
// Context:     调用者提供的上下文
//
typedef
VOID
(*WKD_CP_TAMPER_CALLBACK)(
    _In_ WKD_CALLBACK_TYPE Type,
    _In_ PVOID Registration,
    _In_opt_ PVOID Context
    );

/* ============================================================================
 * 恢复回调（预留，供后续接通自动恢复流水线）
 * ============================================================================ */

//
// 自定义恢复回调
// 运行环境: PASSIVE_LEVEL
//
// 当默认的 MDL 恢复失败时，调用此回调进行自定义恢复。
// 调用者可以执行更高级的恢复逻辑，如：
// - 从远程拉取干净的回调代码镜像
// - 通知用户态 Agent 执行清理
// - 切换到降级模式
// - 触发系统安全重启
//
// 返回: TRUE = 恢复成功，FALSE = 恢复失败
//
typedef
BOOLEAN
(*WKD_CP_RESTORE_CALLBACK)(
    _In_ WKD_CALLBACK_TYPE Type,
    _In_ PVOID CallbackAddress,
    _In_reads_bytes_(WKD_CP_HASH_BYTES) const UCHAR OriginalBytes[WKD_CP_HASH_BYTES],
    _In_ SIZE_T CodeSize,
    _In_opt_ PVOID RestoreContext
    );

/* ============================================================================
 * 回调条目（公开视图，供查询使用）
 * ============================================================================ */

typedef struct _WKD_CALLBACK_ENTRY {
    WKD_CALLBACK_TYPE Type;             // 回调类型
    PVOID Registration;                 // 内核注册句柄
    PVOID Callback;                     // 回调函数指针
    UCHAR CodeHash[32];                 // 回调代码前 256 字节的 SHA-256 哈希
    BOOLEAN IsProtected;                // 是否处于保护状态
    BOOLEAN WasTampered;                // 是否曾被篡改
    LARGE_INTEGER LastVerifyTime;       // 上次验证时间
    ULONG VerifyCount;                  // 验证次数
    ULONG TamperCount;                  // 篡改次数
} WKD_CALLBACK_ENTRY, *PWKD_CALLBACK_ENTRY;

/* ============================================================================
 * 统计信息
 * ============================================================================ */

typedef struct _WKD_CP_STATISTICS {
    LONG64 CallbacksProtected;          // 累计保护的回调数量
    LONG64 TamperAttempts;              // 累计篡改尝试次数
    LONG64 CallbacksRestored;           // 累计恢复成功次数
    LONG64 VerificationsRun;            // 累计执行的验证次数
    ULONG CallbackCount;                // 当前受保护的回调数量
    LARGE_INTEGER UpTime;               // 保护器运行时间
} WKD_CP_STATISTICS, *PWKD_CP_STATISTICS;

/* ============================================================================
 * 不透明句柄
 * ============================================================================ */

typedef struct _WKD_CALLBACK_PROTECTION WKD_CALLBACK_PROTECTION, *PWKD_CALLBACK_PROTECTION;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化保护器（PASSIVE_LEVEL）
// EngineRundown: 注入的自防护子系统 EX_RUNDOWN_REF（必传，校验线程据此判活）
// 在 DriverEntry 中调用。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpInitializeCallbackProtection(
    _Out_ PWKD_CALLBACK_PROTECTION* Context
    );

//
// 关闭保护器（PASSIVE_LEVEL）
// 等待所有验证完成后释放资源。在 DriverUnload 中调用。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CpShutdown(
    _In_ _Post_invalid_ PWKD_CALLBACK_PROTECTION Context
    );

//
// 保护一个回调（PASSIVE_LEVEL）
// Type:     回调类型
// Callback: 回调函数指针
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpRegisterCallbackProtection(
    _Inout_ PWKD_CALLBACK_PROTECTION Protection,
    _In_ WKD_CALLBACK_TYPE Type,
    _In_ const PVOID Callback
    );

//
// 取消保护一个回调（PASSIVE_LEVEL）
// Type: 待取消保护的回调类型
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CpUnprotectCallback(
    _In_ PWKD_CALLBACK_PROTECTION Context,
    _In_ WKD_CALLBACK_TYPE Type
    );

//
// 注册篡改通知回调（PASSIVE_LEVEL）
// 当检测到回调代码被篡改时，调用此回调通知上层。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CpRegisterTamperCallback(
    _In_ PWKD_CALLBACK_PROTECTION Context,
    _In_ WKD_CP_TAMPER_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext
    );

//
// 注销篡改通知回调
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CpUnregisterTamperCallback(
    _In_ PWKD_CALLBACK_PROTECTION Context
    );

//
// 注册恢复回调（预留，供后续接通自动恢复流水线）
// 当默认的 MDL 恢复失败时，调用此回调进行自定义恢复。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CpRegisterRestoreCallback(
    _In_ PWKD_CALLBACK_PROTECTION Context,
    _In_ WKD_CP_RESTORE_CALLBACK Callback,
    _In_opt_ PVOID RestoreContext
    );

//
// 注销恢复回调
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CpUnregisterRestoreCallback(
    _In_ PWKD_CALLBACK_PROTECTION Context
    );

//
// 启用周期性验证（PASSIVE_LEVEL）
// IntervalMs: 验证间隔（毫秒），最小 WKD_TIMER_MIN_INTERVAL_MS
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpStartPeriodicCallbackProtection(
    _Inout_ PWKD_CALLBACK_PROTECTION Protection,
    _In_ const PEX_RUNDOWN_REF RundownRef,
    _In_ ULONG IntervalMs
    );

//
// 禁用周期性验证
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CpDisablePeriodicVerify(
    _In_ PWKD_CALLBACK_PROTECTION Context
    );

//
// 获取统计信息（PASSIVE_LEVEL）
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CpGetStatistics(
    _In_ PWKD_CALLBACK_PROTECTION Context,
    _Out_ PWKD_CP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
