#include "Utils.h"

LPVOID
UtHeapAlloc(
    _In_ SIZE_T Size
    )
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

VOID
UtHeapFree(
    _In_ LPVOID Mem
    )
{
    if (Mem) {
        HeapFree(GetProcessHeap(), 0, Mem);
    }
}

/**************************************************/
/*        hex / base64 工具 (SS HashUtils/Base64)   */
/**************************************************/

/* 十六进制输入上限 (20MB hex = 10MB 二进制, 对齐 SS HashUtils MAX_HEX_INPUT_SIZE) */
#define UT_MAX_HEX_INPUT_SIZE  (20 * 1024 * 1024)

BOOLEAN
UtHexEncode(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Len,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch,
    _In_  BOOLEAN     Upper
    )
/*++
Routine Description:
    二进制 → 十六进制串。查表逐 nibble (对齐 SS HashUtils::ToHexLower/ToHexUpper)。

Arguments:
    Data   - 输入缓冲。
    Len    - 输入长度。
    Out    - 输出缓冲。
    OutCch - 输出容量 (含结尾 0)。
    Upper  - TRUE=大写, FALSE=小写。

Return Value:
    TRUE = 成功。
--*/
{
    static const CHAR lower[] = "0123456789abcdef";
    static const CHAR upper[] = "0123456789ABCDEF";
    const CHAR* table = Upper ? upper : lower;
    SIZE_T i;

    if (!Data || !Out) return FALSE;
    if (Len > (SIZE_MAX / 2)) return FALSE;
    if ((SIZE_T)OutCch < Len * 2 + 1) return FALSE;

    for (i = 0; i < Len; i++) {
        Out[i * 2]     = table[(Data[i] >> 4) & 0x0F];
        Out[i * 2 + 1] = table[Data[i] & 0x0F];
    }
    Out[Len * 2] = 0;
    return TRUE;
}

BOOLEAN
UtHexDecode(
    _In_ PCSTR      Hex,
    _Out_ PBYTE     Out,
    _In_ ULONG      OutLen,
    _Out_opt_ PULONG Written
    )
/*++
Routine Description:
    十六进制串 → 二进制。偶数长度, ≤20MB 上限, 大小写折叠, 非法字符失败
    (对齐 SS HashUtils::FromHex L316-358)。

Arguments:
    Hex     - 输入 hex 串。
    Out     - 输出缓冲。
    OutLen  - 输出容量。
    Written - 输出字节数 (可选)。

Return Value:
    TRUE = 成功。
--*/
{
    SIZE_T len;
    ULONG i, j;

    if (!Hex || !Out) return FALSE;

    len = strlen(Hex);
    if ((len & 1) != 0) return FALSE;                       /* 偶数长度 */
    if (len > UT_MAX_HEX_INPUT_SIZE) return FALSE;          /* DoS 上限 */
    if (len / 2 > OutLen) return FALSE;

    for (i = 0, j = 0; i < len; i += 2, j++) {
        CHAR cHi = Hex[i], cLo = Hex[i + 1];
        INT hi, lo;

        if (cHi >= '0' && cHi <= '9') hi = cHi - '0';
        else if (cHi >= 'a' && cHi <= 'f') hi = 10 + (cHi - 'a');
        else if (cHi >= 'A' && cHi <= 'F') hi = 10 + (cHi - 'A');
        else return FALSE;

        if (cLo >= '0' && cLo <= '9') lo = cLo - '0';
        else if (cLo >= 'a' && cLo <= 'f') lo = 10 + (cLo - 'a');
        else if (cLo >= 'A' && cLo <= 'F') lo = 10 + (cLo - 'A');
        else return FALSE;

        Out[j] = (BYTE)((hi << 4) | lo);
    }

    if (Written) *Written = j;
    return TRUE;
}

BOOLEAN
UtBase64Encode(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Len,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch
    )
/*++
Routine Description:
    二进制 → 标准 Base64 串 (RFC 4648 字母表, 对齐 SS Base64Utils)。

Arguments:
    Data   - 输入缓冲。
    Len    - 输入长度。
    Out    - 输出缓冲。
    OutCch - 输出容量 (含结尾 0)。

Return Value:
    TRUE = 成功。
--*/
{
    static const CHAR b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    SIZE_T outLen;
    SIZE_T i, o;

    if (!Data || !Out) return FALSE;

    outLen = ((Len + 2) / 3) * 4;
    if ((SIZE_T)OutCch < outLen + 1) return FALSE;

    for (i = 0, o = 0; i + 2 < Len; i += 3) {
        ULONG v = ((ULONG)Data[i] << 16) | ((ULONG)Data[i + 1] << 8) | Data[i + 2];
        Out[o++] = b64[(v >> 18) & 0x3F];
        Out[o++] = b64[(v >> 12) & 0x3F];
        Out[o++] = b64[(v >> 6) & 0x3F];
        Out[o++] = b64[v & 0x3F];
    }
    if (i < Len) {                                          /* 尾部 1-2 字节 + 填充 */
        ULONG v = (ULONG)Data[i] << 16;
        if (i + 1 < Len) v |= (ULONG)Data[i + 1] << 8;
        Out[o++] = b64[(v >> 18) & 0x3F];
        Out[o++] = b64[(v >> 12) & 0x3F];
        Out[o++] = (i + 1 < Len) ? b64[(v >> 6) & 0x3F] : '=';
        Out[o++] = '=';
    }

    Out[o] = 0;
    return TRUE;
}

/**************************************************/
/*        UNICODE_STRING 复制/释放辅助              */
/*  (对齐 WkDefender@driver\Common\Utils.c          */
/*   CoCopyUnicodeString, 用户态 UtHeapAlloc 版)    */
/**************************************************/

NTSTATUS
CoCopyUnicodeString(
    _Outptr_ PUNICODE_STRING* Dst,
    _In_ PCUNICODE_STRING Src
    )
/*++
Routine Description:
    从 Src 在堆上分配一份完整副本（UNICODE_STRING 结构体 + Buffer）。
    实现骨架与 driver 侧 CoCopyUnicodeString 一致：
      1. 严格参数校验（Dst/Src/Buffer/Length 无效 → STATUS_INVALID_PARAMETER）；
      2. 两段分配：UNICODE_STRING 结构体 + Buffer（容量 = Src->MaximumLength）；
      3. 按 MaximumLength 整容量复制（与 driver 语义一致，源串由
         RtlInitUnicodeString / 消息体构造 / 前次复制保证 MaximumLength >= Length）。
    释放配套使用 CoFreeUnicodeString。

Arguments:
    Dst — 输出，接收新分配的 UNICODE_STRING 指针（成功时）。
    Src — 源 UNICODE_STRING。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NO_MEMORY。
--*/
{
    PUNICODE_STRING string;

    if (!(Dst && CoCheckUnicodeStringValidity(Src))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 分配 UNICODE_STRING 结构体 */
    string = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
    if (!string)  return STATUS_NO_MEMORY;

    string->Length = Src->Length;
    string->MaximumLength = Src->Length + sizeof(WCHAR);
    string->Buffer = (PWCHAR)malloc(string->MaximumLength);
    if (!string->Buffer) {
        free(string);
        return STATUS_NO_MEMORY;
    }
    
    RtlCopyMemory(string->Buffer, Src->Buffer, Src->Length);
    string->Buffer[string->Length / sizeof(WCHAR)] = L'\0';

    *Dst = string;
    return STATUS_SUCCESS;
}

VOID
CoFreeUnicodeString(
    _In_ PUNICODE_STRING Strting
    )
/*++
Routine Description:
    释放 CoCopyUnicodeString 分配的 UNICODE_STRING（先释放 Buffer，再释放结构体）。
    对 NULL 安全。

Arguments:
    Str — 要释放的 UNICODE_STRING。

Return Value:
    无。
--*/
{
    if (Strting) {
        if (Strting->Buffer) {
            free(Strting->Buffer);
        }
        free(Strting);
    }
}

/**************************************************/
/*           用户态 Rundown Protection 实现          */
/**************************************************/

/* rundown 已开始标志: 占用 LONG 最高位表示禁止获取 rundown, 低 31 位作引用计数 */
#define WKD_RUNDOWN_ACTIVE_BIT  0x80000000UL

_Use_decl_annotations_
NTSTATUS
CoInitializeRundownProtection(
    _Out_ PWKD_RUNDOWN_REF RundownRef
    )
/*++
Routine Description:
    初始化 rundown protection 结构: 计数零化 + 创建 manual-reset 事件。

Arguments:
    RundownRef — 待初始化结构。

Return Value:
    STATUS_SUCCESS / STATUS_NO_MEMORY。
--*/
{
    if (!RundownRef) return STATUS_INVALID_PARAMETER;

    RundownRef->RefCount = 1;   /* 表示 Rundown 活跃 */
    RundownRef->Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (RundownRef->Event == NULL) {
        return STATUS_UNSUCCESSFUL;
    } else return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
CoRundownCompleted(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    )
/*++
Routine Description:
    释放事件句柄。调用方须确保已 CoWaitForRundownProtectionRelease。
    重复调用安全: 第二次起 Event 为 NULL 直接返回。

Arguments:
    RundownRef — 待清理结构。

Return Value:
    无。
--*/
{
    if (RundownRef->Event != NULL) {
        CloseHandle(RundownRef->Event);
        RundownRef->Event = NULL;
    }
    RundownRef->RefCount = 0;
}

_Use_decl_annotations_
BOOLEAN
CoAcquireRundownProtection(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    )
/*++
Routine Description:
    原子地"检查 rundown 位 + 加计数"。用 InterlockedCompareExchange 合成
    单一原子操作, 避免 TOCTOU: 检查未 rundown 之后、加一之前 rundown 发生
    导致漏保护的竞态。rundown 已开始则直接失败。

Arguments:
    RundownRef — 目标结构。

Return Value:
    TRUE  = 获取成功(调用方须配对 CoReleaseRundownProtection);
    FALSE = 资源正在卸载, 拒绝新引用。
--*/
{
    LONG old;
    LONG new;

    do {
        old = InterlockedCompareExchange(&RundownRef->RefCount, 0, 0);
        if ((ULONG)old & WKD_RUNDOWN_ACTIVE_BIT) return FALSE;
        new = old + 1;
    } while (InterlockedCompareExchange(&RundownRef->RefCount, new, old) != old);

    return TRUE;
}

_Use_decl_annotations_
VOID
CoReleaseRundownProtection(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    )
/*++
Routine Description:
    原子减引用计数。若减之前"已 rundown 且计数恰为 1"→ 减后归零,
    置位事件唤醒 CoWaitForRundownProtectionRelease。

Arguments:
    RundownRef — 目标结构。

Return Value:
    无。
--*/
{
    LONG ref = InterlockedDecrement(&RundownRef->RefCount);
    if ((ref & WKD_RUNDOWN_ACTIVE_BIT) &&
        ((ref & ~WKD_RUNDOWN_ACTIVE_BIT) == 1)) {
        SetEvent(RundownRef->Event);
    }
}

_Use_decl_annotations_
VOID
CoWaitForRundownProtectionRelease(
    _Inout_ PWKD_RUNDOWN_REF RundownRef
    )
/*++
Routine Description:
    标记 rundown 开始(置位最高位), 阻塞直到所有已获取引用释放。
    置位前若仍有活跃引用, 则等待最后一个 CoReleaseRundownProtection 的 SetEvent。

Arguments:
    RundownRef — 目标结构。

Return Value:
    无。
--*/
{
    LONG ref = InterlockedOr(&RundownRef->RefCount, WKD_RUNDOWN_ACTIVE_BIT);
    if ((ref & ~WKD_RUNDOWN_ACTIVE_BIT) != 0) {
        WaitForSingleObject(RundownRef->Event, INFINITE);
    }
}