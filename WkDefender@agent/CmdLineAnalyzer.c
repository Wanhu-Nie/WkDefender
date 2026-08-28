/**************************************************/
/*  WkDefender — 命令行深度分析引擎实现                */
/*  迁移自 ShadowStrike CommandLineParser.c           */
/*  10 类检测 + PowerShell -EncodedCommand Base64      */
/*  解码 + LOLBin 查询（统一 IOC/IocLolbinDb.h）       */
/*                                                  */
/*  按功能融合，非源码复制。评分沿用 SS cap-100 权重，  */
/*  供后续 IoaObserve 接线（EnableCmdLineAnalyzer）    */
/*  或 PolicyEngine 序列规则消费。                    */
/**************************************************/

#include "CmdLineAnalyzer.h"
#include "IOC/IocLolbinDb.h"
#include <windows.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>

//
// 检测阈值（对齐 SS CLP_*）
//
#define WPA_OBFUSCATION_CARET_THRESHOLD     5
#define WPA_OBFUSCATION_PERCENT_THRESHOLD   10
#define WPA_OBFUSCATION_TICK_THRESHOLD      3
#define WPA_LONG_CMDLINE_THRESHOLD          2048
#define WPA_VERY_LONG_THRESHOLD             8192
#define WPA_MIN_BASE64_LENGTH               8

//
// 评分权重（对齐 SS CLP_SCORE_*）
//
#define WPA_SCORE_ENCODED_COMMAND       25
#define WPA_SCORE_OBFUSCATED            20
#define WPA_SCORE_DOWNLOAD_CRADLE       30
#define WPA_SCORE_EXECUTION_BYPASS      15
#define WPA_SCORE_HIDDEN_WINDOW         10
#define WPA_SCORE_REMOTE_EXECUTION      25
#define WPA_SCORE_LOLBIN_ABUSE          15
#define WPA_SCORE_SCRIPT_EXECUTION      10
#define WPA_SCORE_SUSPICIOUS_PATH       15
#define WPA_SCORE_LONG_COMMAND          5
#define WPA_SCORE_VERY_LONG_COMMAND     10
#define WPA_SCORE_LOLBIN_ENCODED_COMBO  10
#define WPA_SCORE_LOLBIN_DOWNLOAD_COMBO 10
#define WPA_SCORE_MAX                   100

/**************************************************/
/*        工具函数                                  */
/**************************************************/

//
// 大小写不敏感子串搜索（对齐 SS ClppContainsPatternBounded）
//
static
BOOLEAN
WpaContainsPatternCI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T hayLen, needleLen, i;

    if (!Haystack || !Needle) {
        return FALSE;
    }

    hayLen = wcslen(Haystack);
    needleLen = wcslen(Needle);

    if (needleLen == 0 || needleLen > hayLen) {
        return FALSE;
    }

    for (i = 0; i <= hayLen - needleLen; i++) {
        SIZE_T j;
        BOOLEAN match = TRUE;

        for (j = 0; j < needleLen; j++) {
            WCHAR c1 = Haystack[i + j];
            WCHAR c2 = Needle[j];

            if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
            if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');
            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 大小写不敏感子串搜索，返回命中位置（供参数提取）
//
static
PCWSTR
WpaFindPatternCI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T hayLen, needleLen, i;

    if (!Haystack || !Needle) {
        return NULL;
    }

    hayLen = wcslen(Haystack);
    needleLen = wcslen(Needle);

    if (needleLen == 0 || needleLen > hayLen) {
        return NULL;
    }

    for (i = 0; i <= hayLen - needleLen; i++) {
        SIZE_T j;
        BOOLEAN match = TRUE;

        for (j = 0; j < needleLen; j++) {
            WCHAR c1 = Haystack[i + j];
            WCHAR c2 = Needle[j];

            if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
            if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');
            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return &Haystack[i];
        }
    }
    return NULL;
}

//
// 从完整路径提取文件名（最后一段）
//
static
BOOLEAN
WpaExtractFileName(
    _In_  PCWSTR FullPath,
    _Out_writes_(FileNameSizeChars) PWCHAR FileName,
    _In_  ULONG  FileNameSizeChars
    )
{
    SIZE_T len;
    LONG i;

    FileName[0] = L'\0';
    if (!FullPath || !FullPath[0]) {
        return FALSE;
    }

    len = wcslen(FullPath);
    for (i = (LONG)len - 1; i >= 0; i--) {
        if (FullPath[i] == L'\\' || FullPath[i] == L'/') {
            i++;
            break;
        }
    }
    if (i < 0) {
        i = 0;
    }

    wcsncpy_s(FileName, FileNameSizeChars, FullPath + i, _TRUNCATE);
    return TRUE;
}

//
// PowerShell 上下文判定（对齐 SS ClppDetectEncodedCommand IsPowerShell 判定 L1689-1704）
//
static
BOOLEAN
WpaIsPowerShell(
    _In_ PCWSTR ImageFileName
    )
{
    return (ImageFileName != NULL && ImageFileName[0] != L'\0' &&
            (WpaContainsPatternCI(ImageFileName, L"powershell") ||
             WpaContainsPatternCI(ImageFileName, L"pwsh")));
}

/**************************************************/
/*       检测函数（对齐 SS ClppDetect*）            */
/**************************************************/

//
// 编码命令检测（对齐 SS ClppDetectEncodedCommand L1677）
// 长参数无条件；短参数 (-e/-ec) 仅 PS 上下文，防误报。
//
static
BOOLEAN
WpaDetectEncodedCommand(
    _In_ PCWSTR CmdLine,
    _In_ BOOLEAN IsPowerShell
    )
{
    if (WpaContainsPatternCI(CmdLine, L"-enc") ||
        WpaContainsPatternCI(CmdLine, L"-encodedcommand") ||
        WpaContainsPatternCI(CmdLine, L"-enco") ||
        WpaContainsPatternCI(CmdLine, L"-encod") ||
        WpaContainsPatternCI(CmdLine, L"-encode") ||
        WpaContainsPatternCI(CmdLine, L"-encoded")) {
        return TRUE;
    }
    if (IsPowerShell &&
        (WpaContainsPatternCI(CmdLine, L"-e ") ||
         WpaContainsPatternCI(CmdLine, L"-ec "))) {
        return TRUE;
    }
    return FALSE;
}

//
// 混淆检测（对齐 SS ClppDetectObfuscation L1760）
//
static
BOOLEAN
WpaDetectObfuscation(
    _In_ PCWSTR CmdLine
    )
{
    SIZE_T i;
    ULONG caretCount = 0, percentCount = 0, tickCount = 0;

    if (!CmdLine) {
        return FALSE;
    }

    for (i = 0; CmdLine[i]; i++) {
        if (CmdLine[i] == L'^') {
            caretCount++;
        } else if (CmdLine[i] == L'%') {
            percentCount++;
        } else if (CmdLine[i] == L'`') {
            tickCount++;
        }
    }

    if (caretCount > WPA_OBFUSCATION_CARET_THRESHOLD ||
        (percentCount > WPA_OBFUSCATION_PERCENT_THRESHOLD &&
         WpaContainsPatternCI(CmdLine, L"~")) ||
        tickCount > WPA_OBFUSCATION_TICK_THRESHOLD ||
        WpaContainsPatternCI(CmdLine, L"+[char]") ||
        WpaContainsPatternCI(CmdLine, L"[char]") ||
        WpaContainsPatternCI(CmdLine, L"-f '") ||
        WpaContainsPatternCI(CmdLine, L"iex ") ||
        WpaContainsPatternCI(CmdLine, L"iex(") ||
        WpaContainsPatternCI(CmdLine, L"|iex") ||
        WpaContainsPatternCI(CmdLine, L"invoke-expression") ||
        WpaContainsPatternCI(CmdLine, L"i`e`x") ||
        WpaContainsPatternCI(CmdLine, L"&(") ||
        WpaContainsPatternCI(CmdLine, L".(") ||
        ((WpaContainsPatternCI(CmdLine, L"-join") ||
          WpaContainsPatternCI(CmdLine, L"-replace")) &&
         (caretCount > 0 || tickCount > 0 || percentCount > 3))) {
        return TRUE;
    }
    return FALSE;
}

//
// 下载器检测（对齐 SS ClppDetectDownloadCradle L1861）
//
static
BOOLEAN
WpaDetectDownloadCradle(
    _In_ PCWSTR CmdLine
    )
{
    /* PS 下载方法单条 */
    if (WpaContainsPatternCI(CmdLine, L"downloadstring") ||
        WpaContainsPatternCI(CmdLine, L"downloadfile") ||
        WpaContainsPatternCI(CmdLine, L"downloaddata") ||
        WpaContainsPatternCI(CmdLine, L"webclient") ||
        WpaContainsPatternCI(CmdLine, L"invoke-webrequest") ||
        WpaContainsPatternCI(CmdLine, L"iwr ") ||
        WpaContainsPatternCI(CmdLine, L"invoke-restmethod") ||
        WpaContainsPatternCI(CmdLine, L"irm ") ||
        WpaContainsPatternCI(CmdLine, L"start-bitstransfer") ||
        WpaContainsPatternCI(CmdLine, L"net.webclient") ||
        WpaContainsPatternCI(CmdLine, L"httpwebrequest")) {
        return TRUE;
    }
    /* certutil 下载 */
    if (WpaContainsPatternCI(CmdLine, L"certutil") &&
        (WpaContainsPatternCI(CmdLine, L"-urlcache") ||
         WpaContainsPatternCI(CmdLine, L"-verifyctl") ||
         WpaContainsPatternCI(CmdLine, L"-ping"))) {
        return TRUE;
    }
    /* bitsadmin 下载 */
    if (WpaContainsPatternCI(CmdLine, L"bitsadmin") &&
        (WpaContainsPatternCI(CmdLine, L"/transfer") ||
         WpaContainsPatternCI(CmdLine, L"/create") ||
         WpaContainsPatternCI(CmdLine, L"/addfile"))) {
        return TRUE;
    }
    /* curl/wget 带输出 */
    if ((WpaContainsPatternCI(CmdLine, L"curl ") ||
         WpaContainsPatternCI(CmdLine, L"curl.exe") ||
         WpaContainsPatternCI(CmdLine, L"wget ") ||
         WpaContainsPatternCI(CmdLine, L"wget.exe")) &&
        (WpaContainsPatternCI(CmdLine, L"-o ") ||
         WpaContainsPatternCI(CmdLine, L"--output") ||
         WpaContainsPatternCI(CmdLine, L"> "))) {
        return TRUE;
    }
    /* wmic 远程下载 */
    if (WpaContainsPatternCI(CmdLine, L"wmic") &&
        WpaContainsPatternCI(CmdLine, L"http")) {
        return TRUE;
    }
    /* URL 结合执行 */
    if ((WpaContainsPatternCI(CmdLine, L"http://") ||
         WpaContainsPatternCI(CmdLine, L"https://") ||
         WpaContainsPatternCI(CmdLine, L"ftp://")) &&
        (WpaContainsPatternCI(CmdLine, L"|") ||
         WpaContainsPatternCI(CmdLine, L"iex") ||
         WpaContainsPatternCI(CmdLine, L"invoke"))) {
        return TRUE;
    }
    return FALSE;
}

//
// 执行绕过检测（对齐 SS ClppDetectExecutionBypass L1941）
//
static
BOOLEAN
WpaDetectExecutionBypass(
    _In_ PCWSTR CmdLine
    )
{
    /* 执行策略绕过 */
    if (WpaContainsPatternCI(CmdLine, L"-ep bypass") ||
        WpaContainsPatternCI(CmdLine, L"-executionpolicy bypass") ||
        WpaContainsPatternCI(CmdLine, L"-exec bypass") ||
        WpaContainsPatternCI(CmdLine, L"-ep unrestricted") ||
        WpaContainsPatternCI(CmdLine, L"-executionpolicy unrestricted") ||
        WpaContainsPatternCI(CmdLine, L"set-executionpolicy")) {
        return TRUE;
    }
    /* bypass + powershell 组合 */
    if (WpaContainsPatternCI(CmdLine, L"bypass") &&
        WpaContainsPatternCI(CmdLine, L"powershell")) {
        return TRUE;
    }
    /* AMSI 绕过 */
    if (WpaContainsPatternCI(CmdLine, L"amsiutils") ||
        WpaContainsPatternCI(CmdLine, L"amsiinitfailed") ||
        WpaContainsPatternCI(CmdLine, L"amsi.dll") ||
        WpaContainsPatternCI(CmdLine, L"amsiscanbuffer") ||
        WpaContainsPatternCI(CmdLine, L"amsicontext")) {
        return TRUE;
    }
    /* CLM 绕过 */
    if (WpaContainsPatternCI(CmdLine, L"__pslockeddown") ||
        WpaContainsPatternCI(CmdLine, L"fulllanguage")) {
        return TRUE;
    }
    /* 脚本块日志绕过 */
    if (WpaContainsPatternCI(CmdLine, L"scriptblocklogging") ||
        WpaContainsPatternCI(CmdLine, L"enablescriptblocklogging")) {
        return TRUE;
    }
    /* Defender 排除 */
    if (WpaContainsPatternCI(CmdLine, L"add-mppreference") &&
        WpaContainsPatternCI(CmdLine, L"-exclusion")) {
        return TRUE;
    }
    return FALSE;
}

//
// 隐藏窗口检测（对齐 SS ClppDetectHiddenWindow L2005）
//
static
BOOLEAN
WpaDetectHiddenWindow(
    _In_ PCWSTR CmdLine
    )
{
    if (WpaContainsPatternCI(CmdLine, L"-w hidden") ||
        WpaContainsPatternCI(CmdLine, L"-windowstyle hidden") ||
        WpaContainsPatternCI(CmdLine, L"-win hidden") ||
        WpaContainsPatternCI(CmdLine, L"-window hidden") ||
        WpaContainsPatternCI(CmdLine, L"-wi hidden") ||
        WpaContainsPatternCI(CmdLine, L"-winds hidden")) {
        return TRUE;
    }
    /* VBScript/WScript 隐藏 */
    if (WpaContainsPatternCI(CmdLine, L"wscript.shell") &&
        WpaContainsPatternCI(CmdLine, L", 0")) {
        return TRUE;
    }
    /* VBS Run 隐藏 */
    if (WpaContainsPatternCI(CmdLine, L".run") &&
        WpaContainsPatternCI(CmdLine, L", 0,")) {
        return TRUE;
    }
    /* CMD 后台启动 */
    if (WpaContainsPatternCI(CmdLine, L"start /min") ||
        WpaContainsPatternCI(CmdLine, L"start /b")) {
        return TRUE;
    }
    /* NoProfile + NonInteractive 组合 */
    if ((WpaContainsPatternCI(CmdLine, L"-nop") ||
         WpaContainsPatternCI(CmdLine, L"-noprofile")) &&
        (WpaContainsPatternCI(CmdLine, L"-noni") ||
         WpaContainsPatternCI(CmdLine, L"-noninteractive"))) {
        return TRUE;
    }
    return FALSE;
}

//
// 远程执行检测（对齐 SS ClppDetectRemoteExecution L2060）
//
static
BOOLEAN
WpaDetectRemoteExecution(
    _In_ PCWSTR CmdLine
    )
{
    /* PowerShell 远程 */
    if (WpaContainsPatternCI(CmdLine, L"invoke-command") ||
        WpaContainsPatternCI(CmdLine, L"enter-pssession") ||
        WpaContainsPatternCI(CmdLine, L"new-pssession") ||
        WpaContainsPatternCI(CmdLine, L"-computername") ||
        WpaContainsPatternCI(CmdLine, L"-cn ") ||
        WpaContainsPatternCI(CmdLine, L"-session ")) {
        return TRUE;
    }
    /* WMI 远程执行 */
    if (WpaContainsPatternCI(CmdLine, L"wmic") &&
        WpaContainsPatternCI(CmdLine, L"/node:")) {
        return TRUE;
    }
    /* PsExec */
    if (WpaContainsPatternCI(CmdLine, L"psexec")) {
        return TRUE;
    }
    /* UNC 路径 + 命令 */
    if (WpaContainsPatternCI(CmdLine, L"\\\\") &&
        (WpaContainsPatternCI(CmdLine, L"cmd") ||
         WpaContainsPatternCI(CmdLine, L"powershell"))) {
        return TRUE;
    }
    /* WinRM/WinRS */
    if (WpaContainsPatternCI(CmdLine, L"winrs") ||
        WpaContainsPatternCI(CmdLine, L"winrm ")) {
        return TRUE;
    }
    /* DCOM 执行 */
    if (WpaContainsPatternCI(CmdLine, L"activator") &&
        WpaContainsPatternCI(CmdLine, L"createinstance")) {
        return TRUE;
    }
    return FALSE;
}

//
// 可疑路径检测（对齐 SS ClppDetectSuspiciousPath L2121）
//
static
BOOLEAN
WpaDetectSuspiciousPath(
    _In_ PCWSTR CmdLine
    )
{
    /* Temp 目录 */
    if (WpaContainsPatternCI(CmdLine, L"\\temp\\") ||
        WpaContainsPatternCI(CmdLine, L"\\tmp\\") ||
        WpaContainsPatternCI(CmdLine, L"%temp%") ||
        WpaContainsPatternCI(CmdLine, L"$env:temp")) {
        return TRUE;
    }
    /* AppData */
    if (WpaContainsPatternCI(CmdLine, L"\\appdata\\local\\") ||
        WpaContainsPatternCI(CmdLine, L"\\appdata\\roaming\\") ||
        WpaContainsPatternCI(CmdLine, L"%appdata%") ||
        WpaContainsPatternCI(CmdLine, L"$env:appdata")) {
        return TRUE;
    }
    /* 回收站 */
    if (WpaContainsPatternCI(CmdLine, L"\\$recycle.bin\\") ||
        WpaContainsPatternCI(CmdLine, L"\\recycler\\")) {
        return TRUE;
    }
    /* 公共目录 */
    if (WpaContainsPatternCI(CmdLine, L"\\users\\public\\") ||
        WpaContainsPatternCI(CmdLine, L"\\public\\")) {
        return TRUE;
    }
    /* ProgramData（负滤 microsoft 合法路径） */
    if (WpaContainsPatternCI(CmdLine, L"\\programdata\\") &&
        !WpaContainsPatternCI(CmdLine, L"\\microsoft\\")) {
        return TRUE;
    }
    /* Perflogs */
    if (WpaContainsPatternCI(CmdLine, L"\\perflogs\\")) {
        return TRUE;
    }
    return FALSE;
}

//
// 脚本执行检测（对齐 SS ClppDetectScriptExecution L2181）
//
static
BOOLEAN
WpaDetectScriptExecution(
    _In_ PCWSTR CmdLine,
    _In_ BOOLEAN IsScriptHost
    )
{
    /* 脚本宿主 + 脚本扩展名参数 */
    if (IsScriptHost &&
        (WpaContainsPatternCI(CmdLine, L".vbs") ||
         WpaContainsPatternCI(CmdLine, L".vbe") ||
         WpaContainsPatternCI(CmdLine, L".js") ||
         WpaContainsPatternCI(CmdLine, L".jse") ||
         WpaContainsPatternCI(CmdLine, L".wsf") ||
         WpaContainsPatternCI(CmdLine, L".wsh") ||
         WpaContainsPatternCI(CmdLine, L".hta"))) {
        return TRUE;
    }
    /* 内联脚本 */
    if (WpaContainsPatternCI(CmdLine, L"javascript:") ||
        WpaContainsPatternCI(CmdLine, L"vbscript:")) {
        return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*       PowerShell -EncodedCommand Base64 解码    */
/*  对齐 SS ClppDecodeBase64Unicode（用户态简化）   */
/**************************************************/

//
// Base64 字符有效性
//
static
BOOLEAN
WpaIsValidBase64Char(
    _In_ WCHAR Ch
    )
{
    return ((Ch >= L'A' && Ch <= L'Z') ||
            (Ch >= L'a' && Ch <= L'z') ||
            (Ch >= L'0' && Ch <= L'9') ||
            Ch == L'+' || Ch == L'/' || Ch == L'=');
}

//
// Base64 字符 → 6-bit 值
//
static
UCHAR
WpaBase64CharToValue(
    _In_ WCHAR Ch,
    _Out_ PBOOLEAN IsValid
    )
{
    *IsValid = TRUE;
    if (Ch >= L'A' && Ch <= L'Z') return (UCHAR)(Ch - L'A');
    if (Ch >= L'a' && Ch <= L'z') return (UCHAR)(Ch - L'a' + 26);
    if (Ch >= L'0' && Ch <= L'9') return (UCHAR)(Ch - L'0' + 52);
    if (Ch == L'+') return 62;
    if (Ch == L'/') return 63;
    if (Ch == L'=') return 0;
    *IsValid = FALSE;
    return 0;
}

//
// 解码 Base64 → UTF-16LE（PS -EncodedCommand 格式）
//
static
BOOLEAN
WpaDecodeBase64(
    _In_  PCWSTR Encoded,
    _Out_writes_(MaxChars) PWCHAR Decoded,
    _In_  ULONG  MaxChars
    )
{
    SIZE_T srcLen, validChars = 0, decodedByteLen, byteIndex = 0, i;
    UCHAR quad[4];
    ULONG quadIndex;
    PUCHAR decodedBytes = NULL;
    BOOLEAN isValid;

    Decoded[0] = L'\0';
    if (!Encoded || !Encoded[0]) {
        return FALSE;
    }

    srcLen = wcslen(Encoded);

    /* 统计有效字符（跳过空白，遇到 padding 停止） */
    for (i = 0; i < srcLen; i++) {
        if (Encoded[i] == L'=') {
            break;
        }
        if (Encoded[i] == L' ' || Encoded[i] == L'\t' ||
            Encoded[i] == L'\r' || Encoded[i] == L'\n') {
            continue;
        }
        if (!WpaIsValidBase64Char(Encoded[i])) {
            return FALSE;
        }
        validChars++;
    }

    if (validChars < WPA_MIN_BASE64_LENGTH) {
        return FALSE;
    }

    /* 每 4 个 Base64 字符 = 3 字节 */
    decodedByteLen = (validChars * 3) / 4;

    /* 处理 padding */
    for (i = srcLen; i > 0 && Encoded[i - 1] == L'='; i--) {
        if (decodedByteLen > 0) {
            decodedByteLen--;
        }
    }
    if (decodedByteLen == 0) {
        return FALSE;
    }

    decodedBytes = (PUCHAR)malloc(decodedByteLen);
    if (!decodedBytes) {
        return FALSE;
    }
    memset(decodedBytes, 0, decodedByteLen);

    /* 解码 */
    i = 0;
    while (i < srcLen && byteIndex < decodedByteLen) {
        quadIndex = 0;
        memset(quad, 0, sizeof(quad));

        while (quadIndex < 4 && i < srcLen) {
            WCHAR ch = Encoded[i++];

            if (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n') {
                continue;
            }
            if (ch == L'=') {
                quad[quadIndex++] = 0;
                continue;
            }
            quad[quadIndex] = WpaBase64CharToValue(ch, &isValid);
            if (!isValid) {
                free(decodedBytes);
                return FALSE;
            }
            quadIndex++;
        }
        if (quadIndex < 4) {
            break;
        }

        if (byteIndex < decodedByteLen) {
            decodedBytes[byteIndex++] = (UCHAR)((quad[0] << 2) | (quad[1] >> 4));
        }
        if (byteIndex < decodedByteLen) {
            decodedBytes[byteIndex++] = (UCHAR)((quad[1] << 4) | (quad[2] >> 2));
        }
        if (byteIndex < decodedByteLen) {
            decodedBytes[byteIndex++] = (UCHAR)((quad[2] << 6) | quad[3]);
        }
    }

    /* 转换为 WCHAR 数组（解码字节即 UTF-16LE） */
    {
        SIZE_T decodedChars = byteIndex / sizeof(WCHAR);

        if (decodedChars == 0 || decodedChars >= MaxChars) {
            free(decodedBytes);
            return FALSE;
        }
        memcpy(Decoded, decodedBytes, decodedChars * sizeof(WCHAR));
        Decoded[decodedChars] = L'\0';
    }

    free(decodedBytes);
    return TRUE;
}

//
// 从命令行提取 PowerShell -enc 后的 Base64 参数
// 长参数无条件；短参数 (-e/-ec，带空格边界) 仅 PS 上下文。
//
static
BOOLEAN
WpaExtractEncodedArgument(
    _In_  PCWSTR CmdLine,
    _In_  BOOLEAN IsPowerShell,
    _Out_writes_(MaxChars) PWCHAR Encoded,
    _In_  ULONG  MaxChars
    )
{
    static const PCWSTR longFlags[] = {
        L"-encodedcommand", L"-encoded", L"-encode", L"-encod", L"-enco", L"-enc",
    };
    static const PCWSTR shortFlags[] = { L"-e ", L"-ec " };
    ULONG f;

    Encoded[0] = L'\0';
    if (!CmdLine) {
        return FALSE;
    }

    for (f = 0; f < ARRAYSIZE(longFlags); f++) {
        PCWSTR pos = WpaFindPatternCI(CmdLine, longFlags[f]);

        if (pos) {
            PCWSTR arg = pos + wcslen(longFlags[f]);
            PCWSTR p = arg;
            SIZE_T len = 0;

            while (*p == L' ' || *p == L'\t' || *p == L'=') {
                p++;
            }
            while (*p && *p != L' ' && *p != L'\t' &&
                   *p != L'\r' && *p != L'\n' && len < MaxChars - 1) {
                Encoded[len++] = *p++;
            }
            Encoded[len] = L'\0';
            if (len >= WPA_MIN_BASE64_LENGTH) {
                return TRUE;
            }
        }
    }

    if (IsPowerShell) {
        for (f = 0; f < ARRAYSIZE(shortFlags); f++) {
            PCWSTR pos = WpaFindPatternCI(CmdLine, shortFlags[f]);

            if (pos) {
                PCWSTR arg = pos + wcslen(shortFlags[f]);
                PCWSTR p = arg;
                SIZE_T len = 0;

                while (*p == L' ' || *p == L'\t' || *p == L'=') {
                    p++;
                }
                while (*p && *p != L' ' && *p != L'\t' &&
                       *p != L'\r' && *p != L'\n' && len < MaxChars - 1) {
                    Encoded[len++] = *p++;
                }
                Encoded[len] = L'\0';
                if (len >= WPA_MIN_BASE64_LENGTH) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/**************************************************/
/*           主分析函数（对齐 SS ClpAnalyze）       */
/**************************************************/

VOID
WpaAnalyzeCommandLine(
    _In_  PCWSTR           CmdLine,
    _In_opt_ PCWSTR        ImageFileName,
    _Out_ PWPA_CMDLINE_RESULT Result
    )
{
    WCHAR exeFileName[260];
    WCHAR encodedArg[WPA_MAX_DECODED_CHARS];
    SIZE_T cmdLen;
    BOOLEAN isPowerShell = FALSE;
    BOOLEAN isScriptHost = FALSE;
    const LOLBIN_ENTRY* lolbin = NULL;
    ULONG flags = 0;
    ULONG score = 0;

    if (!Result) {
        return;
    }
    memset(Result, 0, sizeof(*Result));

    if (!CmdLine || !CmdLine[0]) {
        return;
    }

    cmdLen = wcslen(CmdLine);

    /* 提取可执行文件名 */
    exeFileName[0] = L'\0';
    if (ImageFileName && ImageFileName[0]) {
        WpaExtractFileName(ImageFileName, exeFileName, ARRAYSIZE(exeFileName));
    }

    /* PS 上下文 + 脚本宿主判定
     * 对齐 SS ClppDetectEncodedCommand L1690-1704：ImageFileName 无 PS 名时，
     * 命令行含 powershell/pwsh 也算 PS 上下文（短参数 -e/-ec 命中）。 */
    isPowerShell = WpaIsPowerShell(exeFileName) ||
                   WpaContainsPatternCI(CmdLine, L"powershell") ||
                   WpaContainsPatternCI(CmdLine, L"pwsh");
    isScriptHost = isPowerShell ||
                   WpaContainsPatternCI(exeFileName, L"wscript") ||
                   WpaContainsPatternCI(exeFileName, L"cscript") ||
                   WpaContainsPatternCI(exeFileName, L"mshta");

    /* 1. 编码命令检测（对齐 SS ClpAnalyze L709） */
    if (WpaDetectEncodedCommand(CmdLine, isPowerShell)) {
        flags |= WPA_CMD_SUSPICION_ENCODED;
        score += WPA_SCORE_ENCODED_COMMAND;

        /* 尝试 Base64 解码（对齐 SS L716-768） */
        if (WpaExtractEncodedArgument(CmdLine, isPowerShell,
                                      encodedArg, ARRAYSIZE(encodedArg)) &&
            WpaDecodeBase64(encodedArg, Result->DecodedContent,
                            ARRAYSIZE(Result->DecodedContent))) {
            Result->WasDecoded = TRUE;
        }
    }

    /* 2. 混淆检测 */
    if (WpaDetectObfuscation(CmdLine)) {
        flags |= WPA_CMD_SUSPICION_OBFUSCATED;
        score += WPA_SCORE_OBFUSCATED;
    }

    /* 3. 下载器检测 */
    if (WpaDetectDownloadCradle(CmdLine)) {
        flags |= WPA_CMD_SUSPICION_DOWNLOAD_CRADLE;
        score += WPA_SCORE_DOWNLOAD_CRADLE;
    }

    /* 4. 执行绕过检测 */
    if (WpaDetectExecutionBypass(CmdLine)) {
        flags |= WPA_CMD_SUSPICION_EXEC_BYPASS;
        score += WPA_SCORE_EXECUTION_BYPASS;
    }

    /* 5. 隐藏窗口检测 */
    if (WpaDetectHiddenWindow(CmdLine)) {
        flags |= WPA_CMD_SUSPICION_HIDDEN_WINDOW;
        score += WPA_SCORE_HIDDEN_WINDOW;
    }

    /* 6. 远程执行检测 */
    if (WpaDetectRemoteExecution(CmdLine)) {
        flags |= WPA_CMD_SUSPICION_REMOTE_EXEC;
        score += WPA_SCORE_REMOTE_EXECUTION;
    }

    /* 7. LOLBin 检测（统一 IocLolbinDb.h）
     * 排除脚本解释器（powershell/pwsh/cmd/wscript/cscript/mshta）——
     * 解释器由步骤8 ScriptExecution 覆盖，对齐 SS g_LOLBinDefinitions
     * 53 条不含解释器（wkd IocLolbinDb 含解释器是为注入白名单设计）。 */
    if (exeFileName[0] != L'\0') {
        BOOLEAN isInterpreter =
            WpaContainsPatternCI(exeFileName, L"powershell") ||
            WpaContainsPatternCI(exeFileName, L"pwsh") ||
            WpaContainsPatternCI(exeFileName, L"cmd.exe") ||
            WpaContainsPatternCI(exeFileName, L"wscript") ||
            WpaContainsPatternCI(exeFileName, L"cscript") ||
            WpaContainsPatternCI(exeFileName, L"mshta");

        if (!isInterpreter) {
            lolbin = IocLolbinLookup(exeFileName);
        }
        if (lolbin) {
            flags |= WPA_CMD_SUSPICION_LOLBIN;
            score += WPA_SCORE_LOLBIN_ABUSE;
            Result->IsLOLBin = TRUE;
            Result->LOLBinName = lolbin->FileName;
            Result->LOLBinThreatLevel = (lolbin->RiskScore >= 80) ? 3 :
                                        (lolbin->RiskScore >= 60) ? 2 : 1;
            Result->LOLBinCategory = lolbin->Category;

            /* LOLBin + 编码组合（对齐 SS CLP_SCORE_LOLBIN_ENCODED_COMBO=10） */
            if (flags & WPA_CMD_SUSPICION_ENCODED) {
                score += WPA_SCORE_LOLBIN_ENCODED_COMBO;
            }
            /* LOLBin + 下载器组合（对齐 SS CLP_SCORE_LOLBIN_DOWNLOAD_COMBO=10） */
            if (flags & WPA_CMD_SUSPICION_DOWNLOAD_CRADLE) {
                score += WPA_SCORE_LOLBIN_DOWNLOAD_COMBO;
            }
        }
    }

    /* 8. 脚本执行检测 */
    if (WpaDetectScriptExecution(CmdLine, isScriptHost)) {
        flags |= WPA_CMD_SUSPICION_SCRIPT_EXEC;
        score += WPA_SCORE_SCRIPT_EXECUTION;
    }

    /* 9. 可疑路径检测 */
    if (WpaDetectSuspiciousPath(CmdLine)) {
        flags |= WPA_CMD_SUSPICION_SUSPICIOUS_PATH;
        score += WPA_SCORE_SUSPICIOUS_PATH;
    }

    /* 10. 长命令行检测（对齐 SS L851-858） */
    if (cmdLen > WPA_VERY_LONG_THRESHOLD) {
        flags |= WPA_CMD_SUSPICION_LONG_CMD;
        score += WPA_SCORE_VERY_LONG_COMMAND;
    } else if (cmdLen > WPA_LONG_CMDLINE_THRESHOLD) {
        flags |= WPA_CMD_SUSPICION_LONG_CMD;
        score += WPA_SCORE_LONG_COMMAND;
    }

    /* 11. 解码内容二次检测（对齐 SS L863-873；SS 仅查 download cradle，
     *     此处补充混淆检测增强） */
    if (Result->WasDecoded && Result->DecodedContent[0]) {
        if (!(flags & WPA_CMD_SUSPICION_DOWNLOAD_CRADLE) &&
            WpaDetectDownloadCradle(Result->DecodedContent)) {
            flags |= WPA_CMD_SUSPICION_DOWNLOAD_CRADLE;
            score += WPA_SCORE_DOWNLOAD_CRADLE;
        }
        if (!(flags & WPA_CMD_SUSPICION_OBFUSCATED) &&
            WpaDetectObfuscation(Result->DecodedContent)) {
            flags |= WPA_CMD_SUSPICION_OBFUSCATED;
            score += WPA_SCORE_OBFUSCATED;
        }
    }

    /* 封顶 100 */
    if (score > WPA_SCORE_MAX) {
        score = WPA_SCORE_MAX;
    }

    Result->SuspicionFlags = flags;
    Result->SuspicionScore = score;
}
