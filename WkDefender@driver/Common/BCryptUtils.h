/*++
    Common/BCryptUtils.h - 内核 BCrypt 加密原语工具（通用设施）

    Purpose:
        基于内核 BCrypt API（bcrypt.sys，Windows 8+）封装通用加密算法，
        供全驱动任意模块复用（如 SHA-256 哈希计算）。
        与具体功能逻辑（自保护、签名校验、内存取证等）解耦。

    当前提供:
        - SHA-256: 初始化 / 关闭 / 单次计算

    Provider 句柄在模块级初始化时打开，全局复用。
    BCrypt 要求运行在 PASSIVE_LEVEL（Illegal 时返回 STATUS_INVALID_PARAMETER）。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include <bcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SHA-256 子系统
 * ============================================================================ */
    
#define BCRYPT_SHA256_SIZE          32      /* SHA-256 摘要字节数 */

//
// 初始化 SHA-256 子系统（打开 BCrypt Provider）
// 应在 DriverEntry 或驱动通用初始化阶段调用一次；卸载时调用 Shutdown。
// 可安全多次调用（幂等）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CoInitializeSha256Algorithm(
    VOID
    );

//
// 关闭 SHA-256 子系统（释放 BCrypt Provider）
// 可安全多次调用（幂等）。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdSha256Shutdown(
    VOID
    );

//
// 计算数据的 SHA-256 哈希
// 运行环境: PASSIVE_LEVEL（BCrypt 要求）
// Data/Size: 输入数据（必须非空且 Size > 0）
// Hash[32]:  输出 32 字节哈希值
// 返回: STATUS_SUCCESS 或 BCrypt 错误码 / STATUS_DEVICE_NOT_READY（未初始化）
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CoComputeSha256(
    _In_reads_bytes_(Size) const PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_writes_bytes_(BCRYPT_SHA256_SIZE) PUCHAR Hash
    );

#ifdef __cplusplus
}
#endif
