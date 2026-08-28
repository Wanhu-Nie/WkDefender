/**************************************************/
/*  WkDefender IOC 引擎 — 脚本分析                  */
/*  迁移自 ShadowStrike PowerShell/Python/JS/VBS    */
/*  ScriptScanner (Stage 4.6)                       */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  依赖缺失:                                       */
/*   - AMSI provider 注册 (COM) → 绕过检测表保留    */
/*   - PyInstaller 解包 → 骨架预留                  */
/**************************************************/

#pragma once

#include <windows.h>

/**************************************************/
/*               脚本类型                           */
/**************************************************/

typedef enum _WKD_SCRIPT_TYPE {
    WkdScript_Unknown = 0,
    WkdScript_PowerShell,
    WkdScript_Python,
    WkdScript_JavaScript,
    WkdScript_VBScript,
    WkdScript_Batch,
} WKD_SCRIPT_TYPE, *PWKD_SCRIPT_TYPE;

/**************************************************/
/*               状态                               */
/**************************************************/

typedef enum _WKD_SCRIPT_STATUS {
    WkdScriptStatus_Clean = 0,
    WkdScriptStatus_Suspicious,
    WkdScriptStatus_Malicious,
} WKD_SCRIPT_STATUS;

/* 混淆类型 */
typedef enum _WKD_SCRIPT_OBFUSCATION {
    WkdObf_None = 0,
    WkdObf_Base64,
    WkdObf_HexEncoding,
    WkdObf_XorEncryption,
    WkdObf_StringConcat,
    WkdObf_HighEntropy,
    WkdObf_EncodedCommand,   /* PS */
    WkdObf_ExecEval,         /* Py */
} WKD_SCRIPT_OBFUSCATION;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

#define WKD_SCRIPT_MAX_SUSPICIOUS  16
#define WKD_SCRIPT_MAX_IOC         8

typedef struct _WKD_SCRIPT_SCAN_RESULT {
    WKD_SCRIPT_TYPE         Type;
    WKD_SCRIPT_STATUS       Status;
    ULONG                   RiskScore;          /* 0-100 */

    CHAR                    ThreatName[64];
    CHAR                    ThreatCategory[32];
    BOOLEAN                 IsObfuscated;
    WKD_SCRIPT_OBFUSCATION  ObfuscationType;

    ULONG                   SuspiciousCount;
    CHAR                    Suspicious[WKD_SCRIPT_MAX_SUSPICIOUS][128];

    CHAR                    Urls[WKD_SCRIPT_MAX_IOC][256];
    ULONG                   UrlCount;
} WKD_SCRIPT_SCAN_RESULT, *PWKD_SCRIPT_SCAN_RESULT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    检测脚本类型 (扩展名 + 首行 shebang)。

Arguments:
    FilePath - 文件完整路径。
    Type     - 输出 WKD_SCRIPT_TYPE。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocScript_DetectType(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_SCRIPT_TYPE  Type
    );

/*++
Routine Description:
    脚本威胁扫描主入口 (死代码，未接入流水线)。
    读取文件 → 按类型分派 (PS/Py/JS/VBS/Batch) →
    混淆检测 / 可疑关键字 / 评分判定。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocScript_ScanFile(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_SCRIPT_SCAN_RESULT Result
    );

/*++
Routine Description:
    脚本内容扫描核心 (供内存扫描/AMSI 接入复用)。

Arguments:
    Buf    - 脚本内容。
    Len    - 内容长度。
    Type   - 脚本类型。
    Result - 输出扫描结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocScript_ScanContent(
    _In_ const BYTE*        Buf,
    _In_ SIZE_T             Len,
    _In_ WKD_SCRIPT_TYPE    Type,
    _Out_ PWKD_SCRIPT_SCAN_RESULT Result
    );
