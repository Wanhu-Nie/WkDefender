/**************************************************/
/*  WkDefender — 命令行深度分析引擎                   */
/*  迁移自 ShadowStrike CommandLineParser.{c,h}     */
/*  ClpParse / ClpAnalyze / ClpDecodeBase64 /       */
/*  ClppDetectEncodedCommand / Obfuscation / ...    */
/*                                                  */
/*  LOLBin 库统一走 IOC/IocLolbinDb.h (76 条)，     */
/*  不再维护独立 LOLBin 表。                         */
/**************************************************/

#pragma once

#include <windows.h>

//
// 怀疑标志（对齐 PS CLP_SUSPICION）
//
#define WPA_CMD_SUSPICION_NONE              0x00000000
#define WPA_CMD_SUSPICION_ENCODED           0x00000001
#define WPA_CMD_SUSPICION_OBFUSCATED        0x00000002
#define WPA_CMD_SUSPICION_DOWNLOAD_CRADLE   0x00000004
#define WPA_CMD_SUSPICION_EXEC_BYPASS       0x00000008
#define WPA_CMD_SUSPICION_HIDDEN_WINDOW     0x00000010
#define WPA_CMD_SUSPICION_REMOTE_EXEC       0x00000020
#define WPA_CMD_SUSPICION_LOLBIN            0x00000040
#define WPA_CMD_SUSPICION_SCRIPT_EXEC       0x00000080
#define WPA_CMD_SUSPICION_SUSPICIOUS_PATH   0x00000100
#define WPA_CMD_SUSPICION_LONG_CMD          0x00000200

//
// 解码内容长度上限（对齐 SS CLP_MAX_DECODED_LENGTH）
//
#define WPA_MAX_DECODED_CHARS               4096

//
// 分析结果
//
typedef struct _WPA_CMDLINE_RESULT {
    ULONG SuspicionFlags;
    ULONG SuspicionScore;       // 0-100
    BOOLEAN IsLOLBin;
    PCWSTR LOLBinName;          // 指向调用方缓冲区（ImageFileName），仅本调用内有效
    ULONG LOLBinThreatLevel;    // 1-3（由 IocLolbinDb RiskScore 映射）
    ULONG LOLBinCategory;       // LOLBIN_CAT_*（IocLolbinDb.h）
    BOOLEAN WasDecoded;         // PowerShell -EncodedCommand 解码成功
    WCHAR DecodedContent[WPA_MAX_DECODED_CHARS];  // 解码后的 UTF-16LE 命令
} WPA_CMDLINE_RESULT, *PWPA_CMDLINE_RESULT;

//
// 命令行分析入口
//
VOID
WpaAnalyzeCommandLine(
    _In_  PCWSTR           CmdLine,        // 完整命令行（可空）
    _In_opt_ PCWSTR        ImageFileName,  // 可执行文件映像名（PS 上下文门控，可空）
    _Out_ PWPA_CMDLINE_RESULT Result
    );
