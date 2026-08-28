/**************************************************/
/*  WkDefender Common — 通用文本消毒 (防日志/UI注入) */
/*                                                  */
/*  职责: 清洗攻击者可控字符串 (进程名/路径/命令行)   */
/*        防止 CRLF 日志拆分 / 控制字符注入 / 缓冲溢出 */
/*                                                  */
/*  移植自: ShadowStrike SanitizeForDisplay          */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               常量                               */
/**************************************************/

#define TXT_DISPLAY_MAX_LEN     260     /* 对齐 ShadowStrike kMaxDisplayNameLen */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * TxtSanitizeForDisplay — 清洗宽字符串用于日志/告警/UI。
 *
 * 参数:
 *   In      - 输入字符串 (可为 NULL)。
 *   Out     - 输出缓冲区 (必填)。
 *   MaxLen  - 输出缓冲区大小 (WCHAR 数, 含结尾 NUL)。
 *
 * 返回值:
 *   无。Out 始终以 NUL 结尾。
 */
VOID
TxtSanitizeForDisplay(
    _In_ PCWSTR In,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    );
