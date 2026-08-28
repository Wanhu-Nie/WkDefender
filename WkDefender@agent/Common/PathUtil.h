/**************************************************/
/*  WkDefender Common — 路径规范化与系统路径判定      */
/*                                                  */
/*  职责: NT/设备路径 → Win32 路径转换 (Normalize),   */
/*        系统/临时/用户目录判定,                    */
/*        DLL 名称仿冒系统 DLL 检测 (Levenshtein)     */
/*                                                  */
/*  移植自: ShadowStrike DLLInjectionDetector 辅助集 */
/*         (NormalizePath / IsSystemDirectory /      */
/*          IsTempDirectory / IsUserProfilePath /    */
/*          IsMasquerading / LevenshteinDistance)     */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               常量                               */
/**************************************************/

#define PATHP_PATH_BUFFER_MAX    520     /* 规范化中间缓冲 (WCHAR) */
#define PATHP_MASQUERADE_MAX_LEN 32      /* 仿冒检测 DLL 名长度上限 */
#define PATHP_LEVENSHTEIN_MAX    64      /* Levenshtein 输入长度上限 */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * WkdNormalizePath — 将 NT/设备/扩展前缀路径规范化为标准 Win32 路径。
 *
 * 处理前缀: \\?\  \??\  \\.\  \SystemRoot\  \Device\HarddiskVolumeN\
 * 规范组件: . 与 .., 统一反斜杠分隔, 转为小写, 去除尾斜杠。
 *
 * 参数:
 *   Path    - 输入路径 (可为 NT 风格或 Win32 风格)。
 *   Out     - 输出缓冲区 (必填)。
 *   OutLen  - 输出缓冲区容量 (WCHAR 数, 含结尾 NUL)。
 *
 * 返回值:
 *   STATUS_SUCCESS    — 成功, Out 已填充。
 *   STATUS_BUFFER_TOO_SMALL — 输出缓冲不足。
 *   STATUS_INVALID_PARAMETER — 参数非法。
 */
NTSTATUS
WkdNormalizePath(
    _In_ PCWSTR Path,
    _Out_writes_(OutLen) WCHAR* Out,
    _In_ ULONG OutLen
    );

/*
 * WkdIsSystemDirectory — 路径是否位于系统/Windows 目录下。
 *
 * 参数:
 *   Path - 输入路径。
 *
 * 返回值:
 *   TRUE 表示位于 system32 或 Windows 目录。
 */
BOOLEAN
WkdIsSystemDirectory(
    _In_ PCWSTR Path
    );

/*
 * WkdIsTempDirectory — 路径是否位于临时目录下。
 *
 * 判定: 环境 TEMP 目录前缀, 或含 \temp\ / \tmp\ 段。
 *
 * 参数:
 *   Path - 输入路径。
 *
 * 返回值:
 *   TRUE 表示位于临时目录。
 */
BOOLEAN
WkdIsTempDirectory(
    _In_ PCWSTR Path
    );

/*
 * WkdIsUserProfilePath — 路径是否位于用户配置文件目录下。
 *
 * 参数:
 *   Path - 输入路径。
 *
 * 返回值:
 *   TRUE 表示位于 USERPROFILE 目录。
 */
BOOLEAN
WkdIsUserProfilePath(
    _In_ PCWSTR Path
    );

/*
 * WkdIsMasquerading — DLL 文件名是否仿冒系统 DLL (编辑距离 ≤ 2)。
 *
 * 判定: 名称长度 > 32 直接放行; 精确命中系统 DLL 名单不算仿冒;
 *        与任一系统 DLL 名的 Levenshtein 距离在 (0, 2] 区间即判定仿冒。
 *
 * 参数:
 *   DllName - DLL 文件名 (不含路径)。
 *
 * 返回值:
 *   TRUE 表示判定为仿冒系统 DLL 名。
 */
BOOLEAN
WkdIsMasquerading(
    _In_ PCWSTR DllName
    );

/*
 * WkdIsSystemDllName — DLL 文件名是否精确命中系统 DLL 名单。
 *
 * 用于搜索顺序劫持判定: 系统 DLL 名 + 非系统目录加载。
 *
 * 参数:
 *   DllName - DLL 文件名 (不含路径)。
 *
 * 返回值:
 *   TRUE 表示命中系统 DLL 名单。
 */
BOOLEAN
WkdIsSystemDllName(
    _In_ PCWSTR DllName
    );
