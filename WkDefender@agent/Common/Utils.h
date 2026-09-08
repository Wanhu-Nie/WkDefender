#pragma once

#include "../DefendTypes.h"

LPVOID
UtHeapAlloc(
    _In_ SIZE_T Size
    );

VOID
UtHeapFree(
    _In_ LPVOID Mem
    );

/**************************************************/
/*        hex / base64 工具 (SS HashUtils/Base64)   */
/**************************************************/

/* 二进制 → 十六进制串 (小写/大写)。Out 容量需 ≥ Len*2+1 (对齐 SS HashUtils::ToHexLower/Upper) */
BOOLEAN
UtHexEncode(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Len,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch,
    _In_  BOOLEAN     Upper
    );

/* 十六进制串 → 二进制。要求偶数长度, ≤20MB (对齐 SS MAX_HEX_INPUT_SIZE), 大小写折叠。
   Out 容量需 ≥ Len/2。 */
BOOLEAN
UtHexDecode(
    _In_ PCSTR      Hex,
    _Out_ PBYTE     Out,
    _In_ ULONG      OutLen,
    _Out_opt_ PULONG Written
    );

/* 二进制 → 标准 Base64 串 (RFC 4648, 对齐 SS Base64Utils)。Out 容量需 ≥ (Len+2)/3*4+1 */
BOOLEAN
UtBase64Encode(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Len,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch
    );

/**************************************************/
/*        UNICODE_STRING 复制/释放辅助              */
/*  (对齐 WkDefender@driver\Common\Utils.c          */
/*   CoCopyUnicodeString, 用户态 UtHeapAlloc 版)    */
/**************************************************/

/* 深拷贝 UNICODE_STRING（结构体 + Buffer 两段分配, 按 MaximumLength 复制）。
   严格校验: Src 无效 → STATUS_INVALID_PARAMETER。释放配套 CoFreeUnicodeString。 */
NTSTATUS
CoCopyUnicodeString(
    _Outptr_ PUNICODE_STRING* Dst,
    _In_ PCUNICODE_STRING Src
    );

/* 释放 CoCopyUnicodeString 分配的 UNICODE_STRING（Buffer + 结构体）。对 NULL 安全。 */
VOID
CoFreeUnicodeString(
    _In_ PUNICODE_STRING String
    );

FORCEINLINE
BOOLEAN
CoCheckStringValidity(_In_ PCWSTR String) {
    if (!String || String[0] == 0) return FALSE;
    else return TRUE;
}

FORCEINLINE
BOOLEAN
CoCheckUnicodeStringValidity(_In_ PCUNICODE_STRING String) {
    if (!String || !String->Buffer || String->Length == 0) return FALSE;
    else return TRUE;
}

/**************************************************/
/*           用户态 Rundown Protection              */
/*  (对齐 WkDefender@driver 的                     */
/*   ExInitializeRundownProtection /               */
/*   ExAcquireRundownProtection 系列;               */
/*   用户态无锁原子版: 状态位 + 引用计数打包于一个   */
/*   volatile LONG, 配合 manual-reset 事件唤醒)      */
/**************************************************/

typedef struct _WKD_RUNDOWN_REF {
    volatile LONG  RefCount;    /* 高位=已 rundown 标志; 低 31 位=活跃引用数 */
    HANDLE         Event;       /* manual-reset, 引用归零时置位 */
} WKD_RUNDOWN_REF, * PWKD_RUNDOWN_REF;

/* 初始化: 零计数 + 创建 manual-reset 事件。失败返回 STATUS_NO_MEMORY。 */
NTSTATUS
CoInitializeRundownProtection(
    _Out_ PWKD_RUNDOWN_REF RundownRef
    );

/* 销毁: 释放事件句柄。调用方须先 CoWaitForRundownProtectionRelease,
   确保无活跃引用。重复调用安全(幂等)。 */
VOID
CoRundownCompleted(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    );

/* 获取引用: 原子地"检查 rundown 位 + 加计数"。已 rundown 返回 FALSE,
   调用方应放弃访问受保护资源。 */
BOOLEAN
CoAcquireRundownProtection(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    );

/* 释放引用: 原子减计数; 若减前已 rundown 且计数恰为 1→归零, 置位事件唤醒等待者。 */
VOID
CoReleaseRundownProtection(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    );

/* 等待所有引用释放: 置位 rundown 标志, 若仍有活跃引用则阻塞到最后一个 Release。 */
VOID
CoWaitForRundownProtectionRelease(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    );

/**************************************************/
/*           跨进程最小句柄辅助                     */
/*  (2026-09-07 自 AccessControl/AntiDebug 迁入:   */
/*   PEAnalyzer(IOC) 与 AccessControl 共用,        */
/*   避免 IOC → AccessControl 循环依赖)            */
/**************************************************/

/* 以最小读取权限打开进程句柄 (QUERY_LIMITED_INFORMATION|VM_READ)。
 * 供跨进程模块/IAT 比对 (PeVerifyFunctionAddressTable) 与反调试检测块共用。
 * ProcessId 为调用方持有的进程标识 (WKD_PROCESS.ProcessId 强转 ULONG)。 */
BOOLEAN
CoOpenProcessForQueryRead(
    _In_ ULONG ProcessId,
    _Out_ PHANDLE ProcessHandle
    );