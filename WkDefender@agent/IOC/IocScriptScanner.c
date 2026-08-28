/**************************************************/
/*  WkDefender IOC 引擎 — 脚本分析实现              */
/*  迁移自 SS PowerShell/Python/JS/VBS ScriptScanner */
/**************************************************/

#include "IocScriptScanner.h"

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <ntstatus.h>
#include <winternl.h>    /* NT_SUCCESS 宏 */

/**************************************************/
/*               可疑关键字表                       */
/*  { 小写关键字, 风险分, 威胁类别, 威胁名 }        */
/**************************************************/

typedef struct _WKD_SCRIPT_SIGNATURE {
    const char* Keyword;
    int         Score;
    const char* Category;
    const char* ThreatName;
} WKD_SCRIPT_SIGNATURE;

/* PowerShell (对齐 SS PowerShellScanner Heuristics) */
static const WKD_SCRIPT_SIGNATURE g_PsSignatures[] = {
    { "invoke-expression", 70, "Downloader",  "PS.InvokeExpression" },
    { " iex ",             70, "Downloader",  "PS.InvokeExpression" },
    { "net.webclient",     60, "Downloader",  "PS.WebClient" },
    { "downloadstring",    60, "Downloader",  "PS.WebClient" },
    { "downloadfile",      60, "Downloader",  "PS.WebClient" },
    { "mimikatz",         100, "Credential",  "PS.Mimikatz" },
    { "sekurlsa",         100, "Credential",  "PS.Mimikatz" },
    { "reflection.assembly", 90, "ProcessInjection", "PS.ReflectiveLoad" },
    { "virtualalloc",      90, "ProcessInjection", "PS.Shellcode" },
    { "add-type",          90, "ProcessInjection", "PS.AddType" },
    { "createremotethread", 95, "ProcessInjection", "PS.Shellcode" },
    { "win32_process",     80, "Persistence", "PS.WMIPersistence" },
    { "system.management", 80, "Persistence", "PS.WMIPersistence" },
    { "tcpclient",         90, "ReverseShell", "PS.ReverseShell" },
    { "getsystem",         90, "ReverseShell", "PS.ReverseShell" },
    { "amsiutils",        100, "AMSI",        "PS.AMSI.Bypass" },
    { "amsiinitfailed",   100, "AMSI",        "PS.AMSI.Bypass" },
    { "amsiscanbuffer",   100, "AMSI",        "PS.AMSI.Bypass" },
    { "frombase64string",  50, "Obfuscation", "PS.EncodedCommand" },
    { "encodedcommand",    50, "Obfuscation", "PS.EncodedCommand" },
    { "-version 2",       100, "AMSI",        "PS.V2Downgrade" },
    { "-v 2",             100, "AMSI",        "PS.V2Downgrade" },
    { "constrainedlanguage", 90, "Evasion",   "PS.LanguageModeBypass" },
};

/* Python (对齐 SS PythonScriptScanner capability 权重) */
static const WKD_SCRIPT_SIGNATURE g_PySignatures[] = {
    { "browser_cookie3",   35, "Credential",  "Py.CredentialTheft" },
    { "win32crypt",        35, "Credential",  "Py.CredentialTheft" },
    { "keyring",           35, "Credential",  "Py.CredentialTheft" },
    { "pynput",            35, "Keylogging",  "Py.Keylogger" },
    { "getasynckeystate",  35, "Keylogging",  "Py.Keylogger" },
    { "pyautogui",         25, "ScreenCapture", "Py.ScreenCapture" },
    { "imagegrab",         25, "ScreenCapture", "Py.ScreenCapture" },
    { "fernet",            25, "Ransomware",  "Py.FileEncryption" },
    { "pycryptodome",      25, "Ransomware",  "Py.FileEncryption" },
    { "ctypes",            15, "ProcessInjection", "Py.CTypes" },
    { "createremotethread", 40, "ProcessInjection", "Py.ProcessInjection" },
    { "virtualalloc",      40, "ProcessInjection", "Py.ProcessInjection" },
    { "minidump",          50, "Credential",  "Py.LsassDump" },
    { "lsass",             50, "Credential",  "Py.LsassDump" },
    { "impacket",          45, "AttackFramework", "Py.Impacket" },
    { "msfrpc",            45, "AttackFramework", "Py.Metasploit" },
    { "exec(",             25, "Obfuscation", "Py.DynamicExec" },
    { "eval(",             25, "Obfuscation", "Py.DynamicExec" },
    { "vbox",              20, "AntiVM",      "Py.AntiVM" },
    { "vmware",            20, "AntiVM",      "Py.AntiVM" },
    { "virtualbox",        20, "AntiVM",      "Py.AntiVM" },
    { "qemu",              20, "AntiVM",      "Py.AntiVM" },
};

/* JavaScript (对齐 SS JavaScriptScanner) */
static const WKD_SCRIPT_SIGNATURE g_JsSignatures[] = {
    { "wscript.shell",     70, "ProcessExec", "JS.WScript" },
    { "activexobject",     70, "ProcessExec", "JS.ActiveX" },
    { "shell.exec",        70, "ProcessExec", "JS.ShellExec" },
    { "xmldom",            60, "Downloader",  "JS.XMLHTTP" },
    { "xmlhttprequest",    60, "Downloader",  "JS.XMLHTTP" },
    { "new-request",       60, "Downloader",  "JS.Downloader" },
    { "process.create",    70, "ProcessExec", "JS.ProcessCreate" },
    { "unescape(",         40, "Obfuscation", "JS.Unescape" },
    { "fromcharcode",      40, "Obfuscation", "JS.FromCharCode" },
};

/* VBScript (对齐 SS VBScriptScanner) */
static const WKD_SCRIPT_SIGNATURE g_VbsSignatures[] = {
    { "wscript.shell",     70, "ProcessExec", "VBS.WScript" },
    { "shell.exec",        70, "ProcessExec", "VBS.ShellExec" },
    { "shellexecute",      70, "ProcessExec", "VBS.ShellExecute" },
    { "msxml2.xmlhttp",    60, "Downloader",  "VBS.XMLHTTP" },
    { "adodb.stream",      65, "Downloader",  "VBS.ADODB" },
    { "createobject",      40, "ProcessExec", "VBS.CreateObject" },
};

/* Batch (PS 下载执行 / 持久化) */
static const WKD_SCRIPT_SIGNATURE g_BatchSignatures[] = {
    { "powershell",        50, "Downloader",  "Batch.PowerShell" },
    { "certutil",          70, "Downloader",  "Batch.Certutil" },
    { "bitsadmin",         70, "Downloader",  "Batch.Bitsadmin" },
    { "reg add",           60, "Persistence", "Batch.RegPersistence" },
};

/**************************************************/
/*               内部辅助                           */
/**************************************************/

/* 读取文件为字节缓冲 */
static BYTE*
WkdScriptReadFile(
    _In_ PCWSTR FilePath,
    _Out_ SIZE_T* Len
    )
{
    HANDLE h;
    LARGE_INTEGER size;
    BYTE* buf;
    DWORD rd = 0;

    *Len = 0;
    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0 || size.QuadPart > 50 * 1024 * 1024) {
        CloseHandle(h);
        return NULL;
    }

    buf = (BYTE*)malloc((SIZE_T)size.QuadPart);
    if (!buf) { CloseHandle(h); return NULL; }

    if (!ReadFile(h, buf, (DWORD)size.QuadPart, &rd, NULL)) {
        free(buf); CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *Len = rd;
    return buf;
}

/* 小写拷贝 */
static char*
WkdScriptToLower(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    char* out;
    SIZE_T i;

    out = (char*)malloc(Len + 1);
    if (!out) return NULL;
    for (i = 0; i < Len; i++) {
        char c = (char)Buf[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 0x20) : c;
    }
    out[Len] = '\0';
    return out;
}

static double
WkdScriptEntropy(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    double freq[256] = { 0 };
    double ent = 0.0;
    SIZE_T i;

    if (Len == 0) return 0.0;
    for (i = 0; i < Len; i++) freq[Buf[i]]++;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / (double)Len;
            ent -= p * log(p) / log(2.0);
        }
    }
    return ent;
}

/* 简化 URL 提取 */
static void
WkdScriptExtractUrls(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_ CHAR       Out[][256],
    _Out_ PULONG     Count
    )
{
    static const char* markers[] = { "http://", "https://" };
    ULONG n = 0;
    SIZE_T i, m;

    *Count = 0;
    for (i = 0; i < Len && n < 8; i++) {
        for (m = 0; m < 2; m++) {
            SIZE_T mlen = strlen(markers[m]);
            if (i + mlen <= Len &&
                _strnicmp((const char*)Buf + i, markers[m], mlen) == 0) {
                SIZE_T end = i + mlen;
                while (end < Len && end - i < 200 &&
                       Buf[end] > 0x20 && Buf[end] != '"' && Buf[end] != '\'' &&
                       Buf[end] != '<' && Buf[end] != '>') {
                    end++;
                }
                if (end - i < 256) {
                    SIZE_T c;
                    for (c = 0; c < end - i; c++) Out[n][c] = (char)Buf[i + c];
                    Out[n][end - i] = '\0';
                    n++;
                }
                break;
            }
        }
    }
    *Count = n;
}

/**************************************************/
/*               签名匹配                           */
/**************************************************/

static VOID
WkdScriptMatch(
    _In_  const char* Lower,
    _In_  const WKD_SCRIPT_SIGNATURE* Sigs,
    _In_  ULONG SigCount,
    _Inout_ PWKD_SCRIPT_SCAN_RESULT R
    )
{
    ULONG i;

    for (i = 0; i < SigCount; i++) {
        if (strstr(Lower, Sigs[i].Keyword)) {
            if (R->SuspiciousCount < WKD_SCRIPT_MAX_SUSPICIOUS) {
                strncpy_s(R->Suspicious[R->SuspiciousCount],
                          sizeof(R->Suspicious[0]),
                          Sigs[i].ThreatName, _TRUNCATE);
                R->SuspiciousCount++;
            }
            R->RiskScore += (ULONG)Sigs[i].Score;
            if (R->RiskScore > 100) R->RiskScore = 100;
            if (R->ThreatCategory[0] == '\0') {
                strncpy_s(R->ThreatCategory, sizeof(R->ThreatCategory),
                          Sigs[i].Category, _TRUNCATE);
            }
        }
    }
}

/**************************************************/
/*               混淆检测                           */
/**************************************************/

static VOID
WkdScriptDetectObfuscation(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _In_  PCSTR       Lower,
    _Inout_ PWKD_SCRIPT_SCAN_RESULT R
    )
{
    double ent = WkdScriptEntropy(Buf, Len);

    if (R->Type == WkdScript_PowerShell &&
        (strstr(Lower, "frombase64string") || strstr(Lower, "encodedcommand"))) {
        R->IsObfuscated = TRUE;
        R->ObfuscationType = WkdObf_EncodedCommand;
        R->RiskScore += 25;
    } else if (R->Type == WkdScript_Python &&
               (strstr(Lower, "exec(") || strstr(Lower, "eval("))) {
        R->IsObfuscated = TRUE;
        R->ObfuscationType = WkdObf_ExecEval;
        R->RiskScore += 40;
    } else if (strstr(Lower, "fromcharcode") || strstr(Lower, "unescape(")) {
        R->IsObfuscated = TRUE;
        R->ObfuscationType = WkdObf_StringConcat;
        R->RiskScore += 25;
    } else if (ent > 6.0 && Len > 512) {
        R->IsObfuscated = TRUE;
        R->ObfuscationType = WkdObf_HighEntropy;
        R->RiskScore += 25;
    }

    if (R->RiskScore > 100) R->RiskScore = 100;
}

/**************************************************/
/*               类型检测                           */
/**************************************************/

NTSTATUS
IocScript_DetectType(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_SCRIPT_TYPE  Type
    )
{
    PCWSTR dot;
    WCHAR lower[MAX_PATH];

    if (!FilePath || !Type) return STATUS_INVALID_PARAMETER;
    *Type = WkdScript_Unknown;

    dot = wcsrchr(FilePath, L'.');
    if (!dot) return STATUS_SUCCESS;

    wcscpy_s(lower, MAX_PATH, dot);
    _wcslwr_s(lower, MAX_PATH);

    if (wcsstr(lower, L".ps1") || wcsstr(lower, L".psm1") || wcsstr(lower, L".psd1")) {
        *Type = WkdScript_PowerShell;
    } else if (wcsstr(lower, L".py") || wcsstr(lower, L".pyw")) {
        *Type = WkdScript_Python;
    } else if (wcsstr(lower, L".js") || wcsstr(lower, L".jse")) {
        *Type = WkdScript_JavaScript;
    } else if (wcsstr(lower, L".vbs") || wcsstr(lower, L".vbe")) {
        *Type = WkdScript_VBScript;
    } else if (wcsstr(lower, L".bat") || wcsstr(lower, L".cmd")) {
        *Type = WkdScript_Batch;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               内容扫描核心                       */
/**************************************************/

NTSTATUS
IocScript_ScanContent(
    _In_ const BYTE*        Buf,
    _In_ SIZE_T             Len,
    _In_ WKD_SCRIPT_TYPE    Type,
    _Out_ PWKD_SCRIPT_SCAN_RESULT Result
    )
{
    char* lower;

    if (!Buf || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    Result->Type = Type;

    if (Len == 0) return STATUS_SUCCESS;

    lower = WkdScriptToLower(Buf, Len);
    if (!lower) return STATUS_NO_MEMORY;

    switch (Type) {
    case WkdScript_PowerShell:
        WkdScriptMatch(lower, g_PsSignatures,
            (ULONG)(sizeof(g_PsSignatures) / sizeof(g_PsSignatures[0])), Result);
        break;
    case WkdScript_Python:
        WkdScriptMatch(lower, g_PySignatures,
            (ULONG)(sizeof(g_PySignatures) / sizeof(g_PySignatures[0])), Result);
        break;
    case WkdScript_JavaScript:
        WkdScriptMatch(lower, g_JsSignatures,
            (ULONG)(sizeof(g_JsSignatures) / sizeof(g_JsSignatures[0])), Result);
        break;
    case WkdScript_VBScript:
        WkdScriptMatch(lower, g_VbsSignatures,
            (ULONG)(sizeof(g_VbsSignatures) / sizeof(g_VbsSignatures[0])), Result);
        break;
    case WkdScript_Batch:
        WkdScriptMatch(lower, g_BatchSignatures,
            (ULONG)(sizeof(g_BatchSignatures) / sizeof(g_BatchSignatures[0])), Result);
        break;
    default:
        break;
    }

    /* 混淆检测 */
    WkdScriptDetectObfuscation(Buf, Len, lower, Result);

    /* IOC 提取 */
    WkdScriptExtractUrls(Buf, Len, Result->Urls, &Result->UrlCount);
    Result->RiskScore += (Result->UrlCount > 4 ? 20 : Result->UrlCount * 5);
    if (Result->RiskScore > 100) Result->RiskScore = 100;

    /* 判定 (对齐 SS: >=80 Malicious, >=50 Suspicious) */
    if (Result->RiskScore >= 80) {
        Result->Status = WkdScriptStatus_Malicious;
        if (Result->ThreatName[0] == '\0') {
            strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Script.Malicious");
        }
    } else if (Result->RiskScore >= 50) {
        Result->Status = WkdScriptStatus_Suspicious;
        if (Result->ThreatName[0] == '\0') {
            strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Script.Suspicious");
        }
    } else {
        Result->Status = WkdScriptStatus_Clean;
    }

    free(lower);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               文件扫描入口                       */
/**************************************************/

NTSTATUS
IocScript_ScanFile(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_SCRIPT_SCAN_RESULT Result
    )
{
    WKD_SCRIPT_TYPE type;
    BYTE* buf;
    SIZE_T len;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    status = IocScript_DetectType(FilePath, &type);
    if (!NT_SUCCESS(status)) return status;
    if (type == WkdScript_Unknown) return STATUS_SUCCESS;

    buf = WkdScriptReadFile(FilePath, &len);
    if (!buf) return STATUS_SUCCESS;

    status = IocScript_ScanContent(buf, len, type, Result);
    free(buf);
    return status;
}
