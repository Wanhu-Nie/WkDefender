/*++
    SelfProtection/RegistryProtection.h - 注册表自保护（自防护的消费者组件）

    Purpose:
        作为独立 CM 回调节点（Callbacks/RegistryCallback.c）的【消费者】，
        为注册表自保护提供判定能力。本组件：
        - 【不】注册/持有 CM 回调（注册/注销由 RegistryCallback 管理）。
        - 维护受保护键列表（静态数组，前缀匹配）。
        - 提供 RgpShouldBlockRegistryAccess：结合引擎注入的豁免回调
          （受保护进程自改自键放行）与键前缀匹配，对危险操作（删除键/
          设置值/删除值/重命名/SetSecurity）判定 BLOCK 并上报 0x5030 段。

        事件子类型使用 0x5030 段：
        - RG_EVENT_SUBTYPE_DELETE_KEY   = 0x5030（删除受保护键被拦截）
        - RG_EVENT_SUBTYPE_SET_VALUE    = 0x5031（设置受保护键值被拦截）
        - RG_EVENT_SUBTYPE_DELETE_VALUE = 0x5032（删除受保护键值被拦截）
        - RG_EVENT_SUBTYPE_RENAME_KEY   = 0x5033（重命名受保护键被拦截）
        - RG_EVENT_SUBTYPE_SET_SECURITY = 0x5034（修改受保护键安全描述符被拦截）

    豁免回调（SpInitializeRegistryProtection 注入，由引擎提供）：
        自防护引擎注入的内部回调（SpEngineIsRegistryProcessExempt）判
        受保护进程（Pap 画像，PapProfile 非零，如主服务），使其对自身
        注册表键的修改不被 BLOCK——对齐 ShadowStrike 的
        ShadowStrikeIsProcessProtected 豁免语义。
        （2026-09-05：原查 AntiUnload 的 AuIsProcessProtectedById，该表已删除）

    Synchronization:
        - EX_SPIN_LOCK 保护键列表（管理路径排他，判定路径共享读，
          对齐 ShadowStrike g_ProtectedRegKeyLock）。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include "SelfProtectionCompat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_RG_MAX_PROTECTED_KEYS      32          /* 同时受保护的最大键数 */
#define WKD_RG_MAX_KEY_PATH_LEN        512         /* 键路径最大字符数（含 NUL） */

/* 事件子类型（0x5030 段，对齐 AD 0x5010 / IM 0x5020 分配方案） */
#define RG_EVENT_SUBTYPE_DELETE_KEY    0x5030      /* 删除受保护键被拦截 */
#define RG_EVENT_SUBTYPE_SET_VALUE     0x5031      /* 设置受保护键值被拦截 */
#define RG_EVENT_SUBTYPE_DELETE_VALUE  0x5032      /* 删除受保护键值被拦截 */
#define RG_EVENT_SUBTYPE_RENAME_KEY    0x5033      /* 重命名受保护键被拦截 */
#define RG_EVENT_SUBTYPE_SET_SECURITY  0x5034      /* 修改受保护键安全描述符被拦截 */

/* ============================================================================
 * 受保护键条目（Consumer 内，静态数组，前缀匹配）
 * ============================================================================ */

typedef struct _WKD_RG_PROTECTED_KEY {
    BOOLEAN InUse;           /* 槽位占用标记 */
    USHORT  KeyPathLength;   /* 键路径字符数（不含 NUL） */
    WCHAR   KeyPath[WKD_RG_MAX_KEY_PATH_LEN];
} WKD_RG_PROTECTED_KEY, *PWKD_RG_PROTECTED_KEY;

/* ============================================================================
 * 豁免回调
 * ============================================================================ */

//
// 豁免判定回调。由引擎注入（Context = Engine），2026-09-05 起受保护
// 判定收敛为 Pap 画像（PapProfile 非零，受保护进程自改自键放行）。
//
typedef BOOLEAN (*WKD_RG_EXEMPT_CALLBACK)(
    _In_ HANDLE RequestorProcessId,
    _In_opt_ PVOID Context
    );

/* ============================================================================
 * 注册表保护器（不透明句柄，结构定义在 .c 中）
 * ============================================================================ */

typedef struct _WKD_REGISTRY_PROTECTION WKD_REGISTRY_PROTECTION, *PWKD_REGISTRY_PROTECTION;

/* ============================================================================
 * 公共 API（内部组件前缀 Rgp*，仅供引擎调用）
 * ============================================================================ */

//
// 初始化注册表自保护（分配保护器，注入豁免回调）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpInitializeRegistryProtection(
    _Out_ PWKD_REGISTRY_PROTECTION* Protector,
    _In_ const WKD_RG_EXEMPT_CALLBACK ExemptCallback,
    _In_opt_ const PVOID Context
    );

//
// 关闭注册表自保护（释放保护器）。
// 调用前提：CM 回调节点已注销（无并发 RgpShouldBlockRegistryAccess 进入）。
// NULL 安全。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RgpShutdown(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector
    );

//
// 保护一个注册表键/键前缀（前缀匹配生效）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RgpProtectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    );

//
// 注销对一个注册表键/键前缀的保护。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RgpUnprotectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    );

//
// 判定是否应 BLOCK 对路径的注册表操作。
// 由 CM 回调节点（RegistryCallback.c）经引擎公共入口 SpEngineShouldBlockRegistryAccess
// 转调本函数。内部：
//   1. 豁免回调（受保护进程自改自键放行）
//   2. 键前缀匹配（RgpIsKeyProtected）
//   3. 危险操作过滤（DeleteKey/SetValue/DeleteValue/Rename/SetSecurity）
//   4. 命中则计数 + 上报 0x5030 段，返回 TRUE
// 运行环境: PASSIVE_LEVEL（CM 回调上下文；调用方已获取引擎 rundown）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
RgpShouldBlockRegistryAccess(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId
    );

#ifdef __cplusplus
}
#endif