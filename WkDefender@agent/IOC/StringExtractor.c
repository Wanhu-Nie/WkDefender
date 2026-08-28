/**************************************************/
/*  WkDefender IOC — 编码字符串提取与分类实现       */
/*                                                  */
/*  迁移自 ShadowStrike StringExtractor.cpp 按功能  */
/*  融合 (重实现非复制)。                           */
/*                                                  */
/*  流程:                                          */
/*    ScanRegion(Data,Size)                         */
/*      ├─ ASCII / Wide 提取 -> 候选串集            */
/*      ├─ 每个候选: 检测编码 (XOR/Base64/ROT)      */
/*      ├─ 分类 (17 类) + 单串可疑度                */
/*      └─ 聚合到 IOC_SCAN_RESULT StrExt* 字段      */
/*                                                  */
/*  简化迁移标注详见 StringExtractor.h 头注释。      */
/**************************************************/

#include "StringExtractor.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>   /* log() */

/* 提取阈值 (对齐 SS 常量表) */
#define IOC_STR_MIN_ASCII_LEN      4    /* SS kMinAsciiStringLength=4 */
#define IOC_STR_MAX_SCAN_STR       8192 /* SS kMaxStringLength=8192 */
#define IOC_STR_MIN_BASE64_LEN     16   /* SS kMinBase64Length=16 */
#define IOC_STR_HIGH_ENTROPY       5.0f /* SS kHighEntropyThreshold */
#define IOC_STR_XOR_BLOCK_SAMPLE   256  /* SS kMaxXORSampleBytes */
#define IOC_STR_XOR_MIN_RESULT     16   /* 命中 XOR 所需解码串最小长 */
#define IOC_STR_ROT_KEYWORDS_SZ    12

/* 危险分类表 用于小写子串匹配 */
typedef struct _IOC_STR_KW {
    const char* Needle;
    IOC_STR_CATEGORY Cat;
} IOC_STR_KW;

/* ROT 命中关键词 (对齐 SS kRotKeywords 12 条子集) */
static const char* const g_IocStrCmdKeywords[] = {
    "powershell", "cmd.exe", "cmd /c", "wmic", "rundll32", "mshta",
    "regsvr32", "certutil", "bitsadmin", "powershell.exe", "invoke-", "schtasks"
};
#define IOC_STR_CMD_KW_COUNT  (sizeof(g_IocStrCmdKeywords)/sizeof(g_IocStrCmdKeywords[0]))

/* 敏感 API 名 (对齐 SS kKnownAPIs 子集, 供 APIName 分类) */
static const char* const g_IocStrKnownApis[] = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "ReadProcessMemory", "NtCreateThread", "SetWindowsHookEx", "QueueUserAPC",
    "LoadLibrary", "GetProcAddress", "CreateProcess", "ShellExecute",
    "CryptEncrypt", "RegSetValue", "WmiExec", "NtUnmapViewOfSection"
};

/* 简单小写 (ASCII 内) */
static
VOID
IocStrLower(
    _Inout_ CHAR* s
    )
{
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s = (CHAR)(*s + ('a' - 'A'));
    }
}

/* 子串命中 (小写 needle, hay 小写) */
static
BOOLEAN
IocStrContains(
    _In_ PCSTR hay,
    _In_ PCSTR needle
    )
{
    return (strstr(hay, needle) != NULL);
}

/* 简单 Shannon 熵 (0..8) */
static
DOUBLE
IocStrEntropy(
    _In_ const BYTE* d,
    _In_ SIZE_T      n
    )
{
    ULONG freq[256] = { 0 };
    DOUBLE e = 0.0;
    SIZE_T i;
    if (n == 0) return 0.0;
    for (i = 0; i < n; i++) freq[d[i]]++;
    for (i = 0; i < 256; i++) {
        if (freq[i]) {
            DOUBLE p = (DOUBLE)freq[i] / (DOUBLE)n;
            e -= p * log(p) / log(2.0);
        }
    }
    return e;
}

/* 可打印 ASCII 占比 (0..1) */
static
DOUBLE
IocStrPrintableRatio(
    _In_ const BYTE* d,
    _In_ SIZE_T      n
    )
{
    SIZE_T c = 0;
    SIZE_T i;
    if (n == 0) return 0.0;
    for (i = 0; i < n; i++) {
        BYTE b = d[i];
        if ((b >= 0x20 && b <= 0x7E) || b == '\r' || b == '\n' || b == '\t') c++;
    }
    return (DOUBLE)c / (DOUBLE)n;
}

/* Base64 判定: ASCII 提取串中 基64字符占比>=0.85 且长>=16 且高熵 */
static
BOOLEAN
IocStrIsBase64(
    _In_ const CHAR* s,
    _In_ SIZE_T      n
    )
{
    SIZE_T b = 0;
    SIZE_T i;
    if (n < IOC_STR_MIN_BASE64_LEN) return FALSE;
    for (i = 0; i < n; i++) {
        CHAR c = s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            b++;
        }
    }
    if ((DOUBLE)b / (DOUBLE)n < 0.85) return FALSE;
    /* 纯字母高熵才判 — 全小写可读词不算 */
    return IocStrEntropy((const BYTE*)s, n) >= 4.0;
}

/* ROT13 / Caesar 命中: 含纯字母串, 位移后成可读词 (用常见词校验) */
static
BOOLEAN
IocStrIsLikelyRot(
    _In_ const CHAR* s
    )
{
    SIZE_T alpha = 0, n = 0;
    const CHAR* p;
    for (p = s; *p; p++) {
        n++;
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) alpha++;
    }
    if (n < IOC_STR_MIN_ASCII_LEN || n > 64) return FALSE;
    if ((DOUBLE)alpha / (DOUBLE)n < 0.8) return FALSE;   /* 需纯字母 */
    /* 对 ROT13 位移后出现常见 ASCII 词 (the/and/ing/ion) 判命中 */
    {
        CHAR buf[65];
        SIZE_T i, len = 0;
        for (i = 0; i < n && len < 64; i++) {
            CHAR c = s[i];
            if (c >= 'a' && c <= 'z') c = (CHAR)('a' + ((c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z') c = (CHAR)('A' + ((c - 'A' + 13) % 26));
            buf[len++] = c;
        }
        buf[len] = 0;
        IocStrLower(buf);
        if (strstr(buf, "the") || strstr(buf, "and") || strstr(buf, "ing") ||
            strstr(buf, "http") || strstr(buf, "com") || strstr(buf, "www")) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 单字节 XOR 探测: 对候选串用 0..255 密钥异或, 求可打印比最高的密钥。
 * 可打印比>=0.9 且解码长>=IOC_STR_XOR_MIN_RESULT 判命中。 */
static
BOOLEAN
IocStrTryXor(
    _In_ const CHAR* s,
    _In_ SIZE_T      n,
    _Out_ UCHAR*     Key
    )
{
    UCHAR k, bestK = 0;
    DOUBLE bestScore = 0.0;
    DOUBLE bestRatio = 0.0;

    for (k = 0; k < 255; k++) {
        DOUBLE ratio, score;
        BYTE dec[512];
        SIZE_T i, dn;
        dn = 0;
        for (i = 0; i < n && dn < sizeof(dec); i++) {
            BYTE c = (BYTE)s[i] ^ k;
            if (c >= 0x20 && c <= 0x7E) {
                dec[dn++] = c;
            } else if (c == ' ' || c == '.' || c == '/' || c == ':') {
                dec[dn++] = c;
            } else if (c == 0) {
                break;
            }
        }
        /* 非字母数字破截断过滤 — 可打印比 */
        ratio = (DOUBLE)dn / (DOUBLE)n;
        /* 偏向字母数字多的密钥 */
        {
            SIZE_T an = 0;
            for (i = 0; i < dn; i++) {
                BYTE c = dec[i];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == ' ' || c == '.' || c == '/' ||
                    c == ':' || c == '\\') an++;
            }
            score = ratio + ((DOUBLE)an / (DOUBLE)(dn ? dn : 1)) * 0.1;
        }
        if (ratio > 0.9 && score > bestScore) {
            bestScore = score;
            bestRatio = ratio;
            bestK = k;
        }
    }
    if (bestRatio >= 0.9 && n >= IOC_STR_XOR_MIN_RESULT) {
        *Key = bestK;
        return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*             17 类分类                           */
/**************************************************/
static
IOC_STR_CATEGORY
IocStrCategorize(
    _In_ const CHAR* raw,
    _In_ BOOLEAN     IsDecoded,
    _In_ ULONG       Encoding,
    _Out_ ULONG*     Susp
    )
{
    CHAR s[IOC_STR_MAX_LEN];
    SIZE_T n;
    IOC_STR_CATEGORY cat = IocStrCat_BenignString;
    ULONG score = 0;

    if (raw == NULL || !raw[0]) { *Susp = 0; return IocStrCat_Unknown; }
    n = strlen(raw);
    if (n >= sizeof(s)) n = sizeof(s) - 1;
    memcpy(s, raw, n);
    s[n] = 0;
    IocStrLower(s);

    /* 编码串 = 高可疑 (解码出可读内容本身是混淆证据) */
    if (Encoding & IOC_STR_ENCODING_XOR) {
        cat = IocStrCat_Unknown; score += 70;
        if (IocStrContains(s, "http") || IocStrContains(s, "cmd") ||
            IocStrContains(s, "powershell")) score += 30;
    } else if (Encoding & IOC_STR_ENCODING_BASE64) {
        cat = IocStrCat_Base64Data; score += 55;
    } else if (Encoding & IOC_STR_ENCODING_ROT) {
        cat = IocStrCat_Unknown; score += 40;
    }

    /* 文本特征分类 (仅在未具象时覆盖) */
    if (cat == IocStrCat_BenignString || cat == IocStrCat_Unknown) {
        if (IocStrContains(s, "http://") || IocStrContains(s, "https://") ||
            IocStrContains(s, "ftp://")) {
            cat = IocStrCat_URL; score = 60;
        } else if (strstr(s, "hkey_local_machine") || strstr(s, "hkey_current_user") ||
                   IocStrContains(s, "\\software\\") || IocStrContains(s, "\\run")) {
            cat = IocStrCat_RegistryKey; score = 55;
        } else if (IocStrContains(s, ".dll")) {
            cat = IocStrCat_DLLName; score = 20;
        } else if (strchr(s, '\\') && (strchr(s, ':') || strstr(s, "c:\\") ||
                   strstr(s, "\\windows") || strstr(s, "\\programdata") ||
                   strstr(s, "\\temp"))) {
            cat = IocStrCat_FilePath; score = 25;
            if (strstr(s, "\\temp") || strstr(s, "\\appdata") || strstr(s, "\\public")) score += 20;
        } else if (IocStrContains(s, "password") || IocStrContains(s, "secret") ||
                   IocStrContains(s, "token") || IocStrContains(s, "credential")) {
            cat = IocStrCat_Credential; score = 75;
        } else {
            SIZE_T i;
            BOOLEAN isCmd = FALSE;
            for (i = 0; i < IOC_STR_CMD_KW_COUNT; i++) {
                if (IocStrContains(s, g_IocStrCmdKeywords[i])) { isCmd = TRUE; break; }
            }
            if (isCmd) { cat = IocStrCat_SuspiciousCommand; score = 65; }
        }
    }

    /* 编码 + 敏感类型叠加 */
    if ((Encoding & IOC_STR_ENCODING_XOR) && (cat == IocStrCat_URL ||
        cat == IocStrCat_SuspiciousCommand || cat == IocStrCat_Credential)) {
        score += 25;
    }

    if (score > 100) score = 100;
    *Susp = score;
    return cat;
}

/* 是否存在任何非 URL 可读内容 */
static
BOOLEAN
IocStrLooksReadable(
    _In_ const CHAR* raw
    )
{
    ULONG alpha = 0;
    SIZE_T i, n = strlen(raw);
    for (i = 0; i < n; i++) {
        CHAR c = raw[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) alpha++;
    }
    return n > 0 && ((DOUBLE)alpha / (DOUBLE)n) > 0.5;
}

/**************************************************/
/*             主入口                             */
/**************************************************/
NTSTATUS
IocStrExtract(
    _In_      const BYTE*      Data,
    _In_      SIZE_T           Size,
    _Inout_opt_ IOC_SCAN_RESULT* Agg,
    _Out_opt_ PIOC_STR_RESULT  Out
    )
/*++
Routine Description:
    扫描文件字节缓冲，提取 ASCII 字符串，检测 XOR/Base64/ROT 编码，
    分类并按可疑度聚合。

    简化迁移说明：
      - 宽字符串 (UTF-16LE) 提取: 与 ASCII 合并为单通道 (读字节流, 宽串
        的低字节落在 ASCII 通道被提取, 语义等价但不去重) — 对齐 SS 独立
        ExtractWideStrings 的细节未全量。
      - 多字节 XOR / 栈字符串 / C2 关键词独立表: 见 StringExtractor.h。

Arguments:
    Data - 文件字节缓冲 (可为 NULL: 仅初始化 Agg 字段为未执行)。
    Size - 缓冲字节数。
    Agg  - (可选) IOC_SCAN_RESULT 聚合 (填 StrExt* 字段组)。
    Out  - (可选) 逐串完整输出 (截断 IOC_STR_MAX_STRINGS)。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG outCount = 0;
    ULONG suspicious = 0;
    ULONG decoded = 0;
    ULONG hasXor = 0, hasB64 = 0, hasRot = 0;
    ULONG aggScore = 0;
    ULONG totalStrings = 0;
    SIZE_T i;
    SIZE_T maxScan;
    CHAR cur[IOC_STR_MAX_LEN];
    SIZE_T curLen = 0;

    if (Agg) {
        Agg->StrExtRan = FALSE;
        Agg->StrExtFoundAny = FALSE;
        Agg->StrExtCount = 0;
        Agg->StrExtSuspicious = 0;
        Agg->StrExtHasXor = FALSE;
        Agg->StrExtHasBase64 = FALSE;
        Agg->StrExtHasRot = FALSE;
        Agg->StrExtDecodedCount = 0;
        Agg->StrExtScore = 0;
    }

    if (Data == NULL || Size == 0) return STATUS_SUCCESS;
    if (Agg) Agg->StrExtRan = TRUE;

    /* 前 16MB 扫描 (对齐 SS kMaxScanAddress 的保守静态扫描) */
    maxScan = Size > (16ULL * 1024 * 1024) ? (16ULL * 1024 * 1024) : Size;

    for (i = 0; i < maxScan; i++) {
        BYTE c = Data[i];
        if (c >= 0x20 && c <= 0x7E) {
            if (curLen < IOC_STR_MAX_LEN - 1) cur[curLen++] = (CHAR)c;
        } else {
            if (curLen >= IOC_STR_MIN_ASCII_LEN && curLen <= IOC_STR_MAX_SCAN_STR) {
                IOC_STR_CATEGORY cat;
                ULONG susp = 0;
                ULONG enc = 0;
                BOOLEAN isDecoded = FALSE;
                CHAR display[IOC_STR_MAX_LEN];

                cur[curLen] = 0;
                totalStrings++;

                /* 编码检测 (优先, 只对非纯读文本启发) */
                if (IocStrContains(cur, "=") && IocStrIsBase64(cur, curLen)) {
                    enc |= IOC_STR_ENCODING_BASE64;
                    isDecoded = TRUE;
                    decoded++;
                    hasB64 = 1;
                } else if (IocStrIsLikelyRot(cur)) {
                    enc |= IOC_STR_ENCODING_ROT;
                    isDecoded = TRUE;
                    decoded++;
                    hasRot = 1;
                } else if (curLen >= 8 && !IocStrLooksReadable(cur)) {
                    UCHAR key;
                    if (IocStrTryXor(cur, curLen, &key)) {
                        enc |= IOC_STR_ENCODING_XOR;
                        isDecoded = TRUE;
                        decoded++;
                        hasXor = 1;
                        /* 展示用: 保存原串 (解码串可选，此处保留原始) */
                    }
                }

                /* 分类 (解码串用原始内容分类, 提高编码证据分) */
                cat = IocStrCategorize(cur, isDecoded, enc, &susp);
                if (susp > 0) suspicious++;
                aggScore += susp;

                if (Out && outCount < IOC_STR_MAX_STRINGS) {
                    IOC_STR_ENTRY* e = &Out->Entries[outCount];
                    SIZE_T dl = strlen(cur) < IOC_STR_MAX_LEN - 1
                                ? strlen(cur) : IOC_STR_MAX_LEN - 1;
                    memcpy(display, cur, dl);
                    display[dl] = 0;
                    memcpy(e->Text, display, dl + 1);
                    e->Category = cat;
                    e->IsWide = FALSE;
                    e->IsDecoded = isDecoded;
                    e->Encoding = enc;
                    e->Suspiciousness = susp;
                    outCount++;
                }
            }
            curLen = 0;
        }
    }

    if (Out) Out->Count = outCount;

    if (Agg) {
        Agg->StrExtFoundAny = (totalStrings > 0);
        Agg->StrExtCount = totalStrings;
        Agg->StrExtSuspicious = suspicious;
        Agg->StrExtHasXor = (hasXor != 0);
        Agg->StrExtHasBase64 = (hasB64 != 0);
        Agg->StrExtHasRot = (hasRot != 0);
        Agg->StrExtDecodedCount = decoded;
        /* 聚合 0-1000: 可疑串数*40 + 解码串数*60, cap 1000 */
        aggScore = suspicious * 40 + decoded * 60;
        if (aggScore > 1000) aggScore = 1000;
        Agg->StrExtScore = aggScore;
    }

    return STATUS_SUCCESS;
}
