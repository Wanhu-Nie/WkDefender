/**************************************************/
/*  WkDefender Common — 通用文本消毒实现              */
/**************************************************/

#include "TextSanitize.h"

/**************************************************/
/*               函数实现                           */
/**************************************************/

VOID
TxtSanitizeForDisplay(
    _In_ PCWSTR In,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
/*++
Routine Description:
    清洗字符串, 将 C0 控制符 (0x00-0x1F) 与 DEL (0x7F) 替换为 '?',
    截断到 MaxLen-1。CR/LF 被替换为 '?', 防止 CRLF 日志拆分与
    UI splice 攻击 (攻击者可通过进程名/路径注入控制序列)。
    Out 始终以 NUL 结尾; 被截断时追加省略号标记。

Arguments:
    In      - 输入字符串 (NULL 视为空串)。
    Out     - 输出缓冲区 (必填)。
    MaxLen  - 输出缓冲区大小 (WCHAR 数, 含结尾 NUL)。

Return Value:
    无。
--*/
{
    ULONG i;
    ULONG o;

    if (!Out || MaxLen == 0) {
        return;
    }

    if (!In) {
        Out[0] = L'\0';
        return;
    }

    for (i = 0, o = 0; In[i] != L'\0' && o + 1 < MaxLen; i++) {
        WCHAR c = In[i];
        if (c == L'\0' || (c >= 0x01 && c <= 0x1F) || c == 0x7F) {
            Out[o++] = L'?';
        } else {
            Out[o++] = c;
        }
    }

    /* 被截断时追加省略号, 标明内容被截断 */
    if (o + 1 < MaxLen && In[i] != L'\0') {
        Out[o++] = L'…';
    }

    Out[o] = L'\0';
}
