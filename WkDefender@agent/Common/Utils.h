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