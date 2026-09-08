/*++
    Common/BCryptUtils.c - 内核 BCrypt 加密原语工具实现

    提供 SHA-256 哈希计算等通用加密设施。
    Provider 句柄全局复用，采用 Interlocked 原子标志保证句柄的单次初始化。

    Copyright (c) WkDefender Team
--*/

#include "BCryptUtils.h"

//
// 内核 BCrypt API（bcrypt.sys 导出）需要链接 WDK 的导入库。
// 项目 vcxproj 已全局链接 bcrypt.lib，此处保留 pragma 以便显式标记依赖。
//
#pragma comment(lib, "bcrypt.lib")

/* ============================================================================
 * SHA-256 全局状态
 * ============================================================================ */

static BCRYPT_ALG_HANDLE g_Sha256AlgHandle = NULL;
static volatile LONG g_Sha256Initialized = FALSE;

/* ============================================================================
 * SHA-256 初始化 / 关闭
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
CoInitializeSha256Algorithm(
    VOID
    )
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_Sha256Initialized, TRUE, FALSE) != FALSE) {
        return STATUS_SUCCESS;  // 已初始化
    }

    status = BCryptOpenAlgorithmProvider(
        &g_Sha256AlgHandle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,       // 默认实现
        0           // 无特殊标志
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[WkDefender] SHA256: BCryptOpenAlgorithmProvider failed: 0x%08X\n",
            status
        );
        g_Sha256AlgHandle = NULL;
        InterlockedExchange(&g_Sha256Initialized, FALSE);
        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[WkDefender] SHA256: Provider initialized successfully\n"
    );

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdSha256Shutdown(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_Sha256Initialized, FALSE, TRUE) != TRUE) {
        return;  // 未初始化
    }

    if (g_Sha256AlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(g_Sha256AlgHandle, 0);
        g_Sha256AlgHandle = NULL;
    }
}

/* ============================================================================
 * SHA-256 计算
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
CoComputeSha256(
    _In_reads_bytes_(Size) const PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_writes_bytes_(BCRYPT_SHA256_SIZE) PUCHAR Hash
    )
{
    NTSTATUS status;
    BCRYPT_HASH_HANDLE hashHandle = NULL;

    if (!Data || DataSize == 0 || !Hash) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_Sha256Initialized || !g_Sha256AlgHandle) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 创建哈希对象
    //
    status = BCryptCreateHash(
        g_Sha256AlgHandle,
        &hashHandle,
        NULL,           // 无 HashObject 缓冲区（BCrypt 自动分配）
        0,              // cbHashObject
        NULL,           // 无 Secret
        0,              // cbSecret
        0               // dwFlags
    );
    if (!NT_SUCCESS(status)) return status;

    //
    // 输入数据
    //
    status = BCryptHashData(
        hashHandle,
        (PUCHAR)Data,
        (ULONG)DataSize,
        0               // 无特殊标志
    );
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 获取最终哈希值
    //
    status = BCryptFinishHash(
        hashHandle,
        Hash,
        BCRYPT_SHA256_SIZE,     // SHA-256 输出 32 字节
        0
    );

Cleanup:
    if (hashHandle) BCryptDestroyHash(hashHandle);
    return status;
}
