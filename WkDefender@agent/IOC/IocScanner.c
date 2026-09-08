/**************************************************/
/*  WkDefender IOC ���� �� ��̬ɨ����ʵ��            */
/*  ��ϣ��ѯ / LOLBin / ������ / PEͷ / ����ʽ      */
/*  ֤����֤������ IOC/Signature/ (2026-08 �ع�)     */
/**************************************************/

#include "IocScanner.h"
#include "../Common/FileUtils.h"
#include "Signature/SignatureVerifier.h"   /* IocVerifyTrust / IocScan_ReputationScore (֤����֤����ģ��) */
#include "Signature/SignatureHunting.h"   /* ǩ�� APT ���� (SS DSV AnalyzeSignature Ǩ��, �ſ� g_IoaSignatureHuntingEnabled) */
#include "IocLolbinDb.h"
#include "PEAnalyzer/PeAnalyzer.h" /* Ψһ������� */
#include "IocMatcher.h"          /* ��¡���������ٷ� */
#include "../Storage/StorageEngine.h"
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

/* CERT_EV_PROP_ID δ�� 26100 SDK ���� (SS FileReputation Ǩ������,
 * ΢���ĵ�ֵ 63, ΢��˽�� prop id) */
#ifndef CERT_EV_PROP_ID
#define CERT_EV_PROP_ID  63
#endif
#include <sqlite3.h>
#include <bcrypt.h>
#include <intrin.h>       /* __cpuidex (��������Ӳ�����ټ��) */
#include <ctype.h>
#include <math.h>        /* log2 (ý����� DCT ��д��׼��, SS MediaFileScanner Ǩ��) */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../Common/Utils.h"   /* UtHexEncode/UtHexDecode/UtBase64Encode (SS HashUtils/Base64) */
#include "../Common/TextSanitize.h"   /* TxtSanitizeForDisplay (SS FileReputation ��������, 2026-08-06) */

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

/**************************************************/
/*               ����: �����ִ�Сд�Ӵ�ƥ��         */
/**************************************************/

static inline PCWSTR
IocStrStrI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T needleLen;
    if (!Haystack || !Needle || !Needle[0]) return NULL;
    needleLen = wcslen(Needle);
    for (; *Haystack; Haystack++) {
        if (_wcsnicmp(Haystack, Needle, needleLen) == 0) return Haystack;
    }
    return NULL;
}

/**************************************************/
/*           ���㷨��ϣ���� (SS FileHasher)          */
/*  �������: һ�ζ��ļ���ι N �� BCrypt ���      */
/*  (���� SS FileHasher.hpp single-pass ���� +      */
/*   HashUtils::ComputeFile ��ȫ����)               */
/**************************************************/



/* SHA3 �㷨��ʶ (Win10 1903+/SDK 10.0.18362+, �� SDK fallback ����) */
#ifndef BCRYPT_SHA3_256_ALGORITHM
#  define BCRYPT_SHA3_256_ALGORITHM L"SHA3-256"
#endif
#ifndef BCRYPT_SHA3_512_ALGORITHM
#  define BCRYPT_SHA3_512_ALGORITHM L"SHA3-512"
#endif

/* ���ļ�: ˳��� + reparse �ܾ� + 4GB Ԥ�� (���� SS HashUtils::ComputeFile L1056-1120) */
static VOID
IocScan_HashQuery(
    _In_    PDEF_SHA256_HASH    ImageHash,
    _Inout_ IOC_SCAN_RESULT*    Result
    )
{
    Result->HashChecked = FALSE;
    Result->HashVerdict = DefIocVerdict_Unknown;
    Result->HashConfidence = 0;

    if (!ImageHash || !ImageHash->Data[0]) return;

    /* ��¡���������ٷ� �� O(1) Ԥ�죬���� SQLite I/O */
    if (!IocMatcher_BloomCheck(IocType_FileHash_SHA256,
                               (PCUCHAR)ImageHash->Data,
                               DEF_SHA256_SIZE)) {
        /* ��¡˵"һ��������" �� ֱ�ӷ��أ�����Ҫ�� SQLite */
        return;
    }

    /* ��ѯ SQLite ioc_hashes */
    if (WkdStorageEngine.WarmDb) {
        WCHAR sha256Hex[65] = { 0 };
        char  utf8Hash[128] = { 0 };
        sqlite3_stmt* stmt = NULL;

        /* ��ϣתСд hex (SS FileReputation Ǩ�� 2026-08-06: �������/����/
         * file_reputation ��ͳһСдԼ��; ԭ %02X ��д, ioc_hashes �޴���) */
        for (ULONG i = 0; i < DEF_SHA256_SIZE; i++) {
            swprintf_s(sha256Hex + i * 2, 3, L"%02x", ImageHash->Data[i]);
        }
        WideCharToMultiByte(CP_UTF8, 0, sha256Hex, -1, utf8Hash, sizeof(utf8Hash), NULL, NULL);

        if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb,
            "SELECT verdict,confidence FROM ioc_hashes WHERE sha256_hex=? LIMIT 1",
            -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, utf8Hash, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                Result->HashChecked = TRUE;
                Result->HashVerdict = (DEF_IOC_VERDICT)sqlite3_column_int(stmt, 0);
                Result->HashConfidence = (ULONG)sqlite3_column_int(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }
}


/**************************************************/
/*               3. LOLBin ���                     */
/**************************************************/

static VOID
IocScan_LolbinCheck(
    _In_    PCWSTR              FileName,
    _Inout_ IOC_SCAN_RESULT*    Result
    )
{
    const LOLBIN_ENTRY* entry;

    Result->IsLolbin = FALSE;
    Result->LolbinConfidence = 0;

    if (!FileName || !FileName[0]) return;

    entry = IocLolbinLookup(FileName);
    if (!entry) return;

    Result->IsLolbin = TRUE;
    Result->LolbinConfidence = entry->RiskScore * 10;
}

/**************************************************/
/*               4. ������ɨ��                      */
/**************************************************/

VOID
IocScan_Cmdline(
    _In_    PCWSTR              CmdLine,
    _Inout_ IOC_SCAN_RESULT*    Result
    )
{
    ULONG flags = 0;
    ULONG confidence = 0;

    Result->CmdlineFlags = 0;
    Result->CmdlineConfidence = 0;

    if (!CmdLine || !CmdLine[0]) return;

    /* PowerShell ����/���� */
    if (IocStrStrI(CmdLine, L"-EncodedCommand") ||
        IocStrStrI(CmdLine, L"-e ") || IocStrStrI(CmdLine, L"-ec ") ||
        IocStrStrI(CmdLine, L"FromBase64String") ||
        IocStrStrI(CmdLine, L"IEX(") ||
        IocStrStrI(CmdLine, L"Invoke-Expression")) {
        flags |= IOC_CMD_FLAG_PS_ENCODED;
        confidence += 50;
    }

    /* ������ */
    if (IocStrStrI(CmdLine, L"Net.WebClient") ||
        IocStrStrI(CmdLine, L"DownloadString") ||
        IocStrStrI(CmdLine, L"DownloadFile") ||
        IocStrStrI(CmdLine, L"Invoke-WebRequest") ||
        IocStrStrI(CmdLine, L"Invoke-RestMethod") ||
        IocStrStrI(CmdLine, L"Start-BitsTransfer") ||
        IocStrStrI(CmdLine, L"curl ") || IocStrStrI(CmdLine, L"wget ") ||
        IocStrStrI(CmdLine, L"certutil -urlcache") ||
        IocStrStrI(CmdLine, L"bitsadmin /transfer")) {
        flags |= IOC_CMD_FLAG_DOWNLOADER;
        confidence += 60;
    }

    /* ���� DLL ע�� */
    if (IocStrStrI(CmdLine, L"ReflectiveLoader") ||
        IocStrStrI(CmdLine, L"Invoke-ReflectivePEInjection") ||
        IocStrStrI(CmdLine, L"Assembly.Load(") ||
        IocStrStrI(CmdLine, L"[System.Reflection.Assembly]")) {
        flags |= IOC_CMD_FLAG_REFLECTIVE;
        confidence += 70;
    }

    /* ͨ�ÿ��� */
    if (IocStrStrI(CmdLine, L"-WindowStyle Hidden") ||
        IocStrStrI(CmdLine, L"-w hidden") ||
        IocStrStrI(CmdLine, L"-ExecutionPolicy Bypass") ||
        IocStrStrI(CmdLine, L"-ep bypass") ||
        IocStrStrI(CmdLine, L"-NoProfile -NonInteractive")) {
        flags |= IOC_CMD_FLAG_SUSPICIOUS;
        confidence += 30;
    }

    /* ƾ֤ת�� */
    if (IocStrStrI(CmdLine, L"mimikatz") ||
        IocStrStrI(CmdLine, L"procdump -ma lsass") ||
        IocStrStrI(CmdLine, L"procdump -accepteula") ||
        IocStrStrI(CmdLine, L"comsvcs.dll MiniDump") ||
        IocStrStrI(CmdLine, L"sekurlsa::")) {
        flags |= IOC_CMD_FLAG_CREDENTIAL_DUMP;
        confidence += 80;
    }

    /* �������� (������/���ַ�) */
    {
        ULONG backtick = 0, caret = 0;
        for (PCWSTR p = CmdLine; *p && backtick < 10 && caret < 10; p++) {
            if (*p == L'`') backtick++;
            if (*p == L'^') caret++;
        }
        if (backtick >= 5 || caret >= 5) {
            flags |= IOC_CMD_FLAG_OBFUSCATED;
            confidence += 25;
        }
    }

    Result->CmdlineFlags = flags;
    Result->CmdlineConfidence = min(confidence, 1000);
}

/**************************************************/
/*         5. ����ʽ��̬����                        */
/*   (SS HeuristicAnalyzer Ǩ��, 2026-08-04)        */
/*                                                 */
/*   �������ںϽ� IocScanner, ������ģ��:            */
/*     5.1 ���� API ����� (SS SuspiciousAPICategory) */
/*     5.2 �ӿǽ�����    (SS InitializePackerSignatures) */
/*     5.3 IAT �������+ImpHash (SS AnalyzeImports/CalculateImpHash, �� IAT ����) */
/*     5.4 �ӿǼ��      (SS DetectPacker)          */
/*     5.5 �ַ�������    (SS AnalyzeStrings/AnalyzeExtractedStringImpl) */
/*     5.6 PE �쳣����   (SS AnalyzePE/DetectHeuristicAnomalies) */
/*     5.7 �������      (SS AnalyzeCode, ������)   */
/*     5.8 �ű�����      (SS AnalyzeScript, ������) */
/*     5.9 ģ��ƥ��      (SS FuzzyMatch ȫ��, ������, SS δ�� ssdeep/TLSH) */
/*                                                 */
/*   ��������: 0-1000, ��ά�ȷ֡�10 �ۺ� cap 1000��  */
/**************************************************/









VOID
IocScan_Aggregate(
    _Inout_ IOC_SCAN_RESULT* Result
    )
{
    DEF_IOC_VERDICT verdict = DefIocVerdict_Clean;
    ULONG confidence = 0;
    ULONG evidenceCount = 0;

    /* ��ϣ������ �� ֱ�Ӷ��� */
    if (Result->HashChecked && Result->HashVerdict == DefIocVerdict_Malicious) {
        verdict = DefIocVerdict_Malicious;
        confidence = max(confidence, Result->HashConfidence);
        evidenceCount++;
    }

    /* ƾ֤ת��ģʽ �� ���� */
    if (Result->CmdlineFlags & IOC_CMD_FLAG_CREDENTIAL_DUMP) {
        verdict = max(verdict, DefIocVerdict_Malicious);
        confidence = max(confidence, Result->CmdlineConfidence);
        evidenceCount++;
    }

    /* ֤������ */
    if (Result->CertScore >= 20) evidenceCount++;

    /* ǩ�� APT ���� (SS DSV AnalyzeSignature Ǩ��, 2026-08-09, �ſ����):
     * RiskScore ��90 �� Malicious; ��60 �� Suspicious (���� IoaScan ��ֵ)��
     * ����֤�� (100)/δǩ������ (100)/���� (95)/����ǩ�� (75) �ȸ�Σ�źš�
     * Confidence �� RiskScore��10 (0-1000, ���� HeuristicConfidence �߶�)�� */
    if (Result->SignatureHunt.Ran) {
        if (Result->SignatureHunt.RiskScore >= 90) {
            verdict = max(verdict, DefIocVerdict_Malicious);
        } else if (Result->SignatureHunt.RiskScore >= 60) {
            verdict = max(verdict, DefIocVerdict_Suspicious);
        }
        if (Result->SignatureHunt.RiskScore >= 60) {
            confidence = max(confidence, Result->SignatureHunt.RiskScore * 10);
            evidenceCount++;
        }
    }

    /* LOLBin */
    if (Result->IsLolbin) {
        verdict = max(verdict, DefIocVerdict_Suspicious);
        confidence = max(confidence, Result->LolbinConfidence);
        evidenceCount++;
    }

    /* �����п��� */
    if (Result->CmdlineFlags & (IOC_CMD_FLAG_PS_ENCODED | IOC_CMD_FLAG_DOWNLOADER |
                                 IOC_CMD_FLAG_REFLECTIVE | IOC_CMD_FLAG_OBFUSCATED)) {
        verdict = max(verdict, DefIocVerdict_Suspicious);
        confidence = max(confidence, Result->CmdlineConfidence);
        evidenceCount++;
    }

    /* PE ͷ�쳣 */
    if (Result->HasSuspiciousSections || Result->HasSuspiciousImports) {
        verdict = max(verdict, DefIocVerdict_Suspicious);
        evidenceCount++;
    }

    /* ����ʽ��̬���� (SS HeuristicAnalyzer Ǩ��): ��Ȩ���ɶ� */
    if (Result->HeuristicRan) {
        if (Result->HeuristicConfidence >= 700) {
            verdict = max(verdict, DefIocVerdict_Malicious);
        } else if (Result->HeuristicConfidence >= 300) {
            verdict = max(verdict, DefIocVerdict_Suspicious);
        }
        confidence = max(confidence, Result->HeuristicConfidence);
        if (Result->HeuristicConfidence >= 200) evidenceCount++;
    }

    /* ֤�ݽ��� */
    confidence = min(confidence + min(evidenceCount * 50, 300), 1000);

    Result->FinalVerdict = verdict;
    Result->FinalConfidence = confidence;
    Result->EvidenceCount = evidenceCount;
}



/**************************************************/
/*   5.7-5.9 ������Ǩ�� (SS HeuristicAnalyzer)     */
/*   ����ʵ������, �ݲ�������ˮ�ߡ�                 */
/**************************************************/

/* -- 5.7 ������� (SS AnalyzeCode): opcode Ƶ��/�����/API-hash -------------
 * ����: NOP sled(>16) +150, jmp_minus_one(EB FF) +100, API-hash ROR13
 *   (C1 CF 0D, >=2 ��) +100, cap 270 (���� MAX_OBFUSCATION(15)*WEIGHT(1.8))��
 * ������ԭ��: ��̬�ļ�����ڷ�����ֵ����; wkd �����ڴ����� MsDetectShellcode/
 *   MsDetectReflectiveLoader (MemoryScan) �����Ҹ����ơ� */

static ULONG
IocScan_CodeAnalysis(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    ULONG score = 0;
    ULONG nopRun = 0, hashPatterns = 0;
    ULONG i;

    if (!Data || Size == 0) return 0;

    for (i = 0; i < Size; i++) {
        if (Data[i] == 0x90) {
            if (++nopRun > 16) { score += 150; break; }
        } else {
            nopRun = 0;
        }
    }
    for (i = 0; i + 1 < Size; i++) {
        if (Data[i] == 0xEB && Data[i + 1] == 0xFF) { score += 100; break; }
    }
    for (i = 0; i + 2 < Size; i++) {
        if (Data[i] == 0xC1 && Data[i + 1] == 0xCF && Data[i + 2] == 0x0D) {
            if (++hashPatterns >= 2) { score += 100; break; }
        }
    }

    if (score > 270) score = 270;
    return score;
}


/* -- 5.9 ģ��ƥ�� (SS FuzzyHasher CTPH ȫ��Ǩ��, ��ʵ�ַǸ���) -----------------
 * �� CTPH (Context-Triggered Piecewise Hashing): ssdeep ʽ���б���,
 *   ���� SS DigestGenerator/RollingHash/ChunkHash/DigestComparer��
 * ����: ���С 3��2^n �� ���� 7 ������������ϣ�����ֿ� �� FNV-1a ���ϣ
 *   �� Base64 �ַ� �� "blockSize:sig1:sig2" (���͸���/�ֽڼ�����β/ϡ����ɨ)��
 * �Ƚ�: ��ߴ���Ȼ� 2�� �� EliminateSequences �� HasCommonSubstring(��7)
 *   �� ��Ȩ�༭����(ins/del=1, sub=3) �� 0-100 �÷֡�
 * TLSH: SS FileHasher ��δ���� libtlsh (ComputeTLSHImpl ���ؿ�), ���ֿտǡ�
 * ������ԭ��: wkd ��ȷ��ϣƥ������ IocScanner_QueryHash + IocMatcher ����;
 *   CTPH ���������/�������ƶ�ʶ��, ���׶λ�����԰����޵����ߡ� */

/* CTPH ���� (���� SS DigestGenerator.hpp/RollingHash.hpp/ChunkHash.hpp/EditDistance.hpp) */
#define WKD_CTPH_MIN_BLOCK        3
#define WKD_CTPH_SIG_MAX          64      /* kDigestComponentLength */
#define WKD_CTPH_SIG2_MAX         32      /* kHalfDigestLength */
#define WKD_CTPH_WINDOW           7       /* kRollingWindowSize */
#define WKD_CTPH_FNV_OFFSET       0x811c9dc5u
#define WKD_CTPH_FNV_PRIME        0x01000193u
#define WKD_CTPH_MAX_HASHABLE     (200ULL * 1024 * 1024)   /* kMaxHashableSize */
#define WKD_CTPH_MAX_DIGEST_LEN   200     /* kMaxDigestStringLength */


/* �ַ����Ƿ�Ǳ�� IOC (URL/ע���/onion, ���� SS IsPotentialIOC) */
static BOOLEAN
IocScan_IsPotentialIoc(
    _In_ PCSTR Str
    )
{
    CHAR lower[512];
    SIZE_T len;
    SIZE_T i;

    if (!Str || strlen(Str) < 4) return FALSE;
    len = strlen(Str);
    if (len >= sizeof(lower)) len = sizeof(lower) - 1;
    for (i = 0; i < len; i++) lower[i] = (CHAR)tolower((UCHAR)Str[i]);
    lower[len] = 0;

    return (strstr(lower, "http") != NULL ||
            strstr(lower, "hkey_") != NULL ||
            strstr(lower, ".onion") != NULL);
}

/* ��ȡ URL (���� SS ExtractURLs, ���� MaxUrls, ����ָ�� Str ���Ӵ�) */
static ULONG
IocScan_ExtractUrls(
    _In_  PCSTR Str,
    _Out_writes_(MaxUrls) PCSTR* Urls,
    _In_  ULONG MaxUrls
    )
{
    CHAR lower[2048];
    SIZE_T len, pos = 0;
    SIZE_T i;
    ULONG count = 0;

    if (!Str || !Urls || MaxUrls == 0) return 0;
    len = strlen(Str);
    if (len >= sizeof(lower)) len = sizeof(lower) - 1;
    for (i = 0; i < len; i++) lower[i] = (CHAR)tolower((UCHAR)Str[i]);
    lower[len] = 0;

    while (count < MaxUrls) {
        PCSTR hit = strstr(lower + pos, "http");
        SIZE_T start;
        SIZE_T end;
        if (!hit) break;
        start = (SIZE_T)(hit - lower);
        end = start;
        while (end < len) {
            char c = Str[end];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                c == '\'' || c == '"' || c == '>' || c == ';' || c == ')') break;
            end++;
        }
        Urls[count++] = Str + start;
        pos = end;
    }
    return count;
}

/* ��ȡ IP ��ַ (���� SS ExtractIPs L2469-2490: ����+������, 3 ��,
 * ��>=7, ���� MaxIps)������ָ�� Str ���Ӵ��� */
static ULONG
IocScan_ExtractIps(
    _In_  PCSTR Str,
    _Out_writes_(MaxIps) PCSTR* Ips,
    _In_  ULONG MaxIps
    )
{
    SIZE_T len;
    SIZE_T i = 0;
    ULONG count = 0;

    if (!Str || !Ips || MaxIps == 0) return 0;
    len = strlen(Str);

    while (i < len && count < MaxIps) {
        if (Str[i] >= '0' && Str[i] <= '9') {
            SIZE_T start = i;
            SIZE_T end = i;
            ULONG dots = 0;
            BOOLEAN valid = TRUE;
            SIZE_T k;

            /* �ռ� [����|.] ������ */
            while (end < len &&
                   ((Str[end] >= '0' && Str[end] <= '9') || Str[end] == '.')) {
                if (Str[end] == '.') dots++;
                end++;
            }

            /* ��֤: ǡ�� 3 ����, ȫ���ֵ�, ����>=7 (���� SS) */
            if (dots == 3 && (end - start) >= 7) {
                for (k = start; k < end; k++) {
                    char c = Str[k];
                    if (c != '.' && (c < '0' || c > '9')) { valid = FALSE; break; }
                }
                if (valid) Ips[count++] = Str + start;
            }
            i = end;
        } else {
            i++;
        }
    }
    return count;
}

/* �ļ������Ƿ� PE (���� SS ContainsPE L2492-2505: �� MZ, У�� e_lfanew
 * �� PE ǩ��)���ļ�����; �ڴ漶�� MsContainsPE (MemoryScan.c) ���ǡ� */
VOID
IocScan_AnalyzeScript(
    _In_  const BYTE*          Data,
    _In_  ULONG                Size,
    _Inout_ PWKD_FILE_TYPE_INFO Info
    )
{
    CHAR content[4096];
    SIZE_T cLen;
    ULONG i;

    if (!Data || !Info || Size < 2) return;

    /* BOM ��� (SS L1660-1669) */
    if (Size >= 3 && Data[0] == 0xEF && Data[1] == 0xBB && Data[2] == 0xBF) {
        Info->HasBOM = TRUE;
        strcpy_s(Info->BomType, sizeof(Info->BomType), "UTF-8");
    } else if (Size >= 2 && Data[0] == 0xFF && Data[1] == 0xFE) {
        Info->HasBOM = TRUE;
        strcpy_s(Info->BomType, sizeof(Info->BomType), "UTF-16 LE");
    } else if (Size >= 2 && Data[0] == 0xFE && Data[1] == 0xFF) {
        Info->HasBOM = TRUE;
        strcpy_s(Info->BomType, sizeof(Info->BomType), "UTF-16 BE");
    }

    /* Shebang ��ȡ (SS L1671-1692, cap 256 + �����ַ�����) */
    if (Data[0] == '#' && Data[1] == '!') {
        SIZE_T endPos = 2;
        SIZE_T kHardCap = (Size < (256 + 2)) ? Size : (256 + 2);
        Info->HasShebang = TRUE;
        while (endPos < kHardCap && Data[endPos] != '\n' && Data[endPos] != '\r') endPos++;
        if (endPos > 2) {
            SIZE_T len = (endPos - 2 < sizeof(Info->ShebangInterpreter) - 1)
                         ? (endPos - 2) : (sizeof(Info->ShebangInterpreter) - 1);
            memcpy(Info->ShebangInterpreter, Data + 2, len);
            Info->ShebangInterpreter[len] = '\0';
            for (i = 0; i < len; i++) {
                if ((UCHAR)Info->ShebangInterpreter[i] < 0x20 ||
                    (UCHAR)Info->ShebangInterpreter[i] == 0x7F) {
                    Info->ShebangInterpreter[i] = '?';   /* ���� SS SanitizeForLog CWE-117 */
                }
            }
        }
    }

    /* �ı����� + �ؼ��� (SS L1694-1752) */
    if (!IocScan_IsTextContent(Data, Size)) return;

    cLen = (Size < (SIZE_T)sizeof(content) - 1) ? Size : (SIZE_T)sizeof(content) - 1;
    for (i = 0; i < cLen; i++) {
        CHAR c = (CHAR)Data[i];
        content[i] = (c >= 'A' && c <= 'Z') ? (CHAR)(c - 'A' + 'a') : c;
    }
    content[cLen] = '\0';

    if (strstr(content, "param(") != NULL || strstr(content, "function ") != NULL ||
        strstr(content, "$_") != NULL || strstr(content, "write-host") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "PowerShell");
    }
    if (strstr(content, "dim ") != NULL || strstr(content, "wscript.") != NULL ||
        strstr(content, "msgbox") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "VBScript");
    }
    if (strstr(content, "import ") != NULL || strstr(content, "def ") != NULL ||
        strstr(content, "__name__") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "Python");
    }
    if (strstr(content, "function(") != NULL || strstr(content, "var ") != NULL ||
        strstr(content, "const ") != NULL || strstr(content, "console.log") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "JavaScript");
    }
    if (strstr(content, "@echo off") != NULL || strstr(content, "goto ") != NULL ||
        strstr(content, "setlocal") != NULL || strstr(content, "%~") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "Batch");
    }
    if (strstr(content, "<hta:application") != NULL || strstr(content, "hta:application") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "HTA");
    }
}

/* �ű������ж� (���� SS DetectScriptType L1758-1791:
 * �ı� �� Shebang ������ �� �ؼ���) */
WKD_FILE_FORMAT
IocScan_DetectScriptType(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    WKD_FILE_TYPE_INFO info;
    ULONG i;

    if (!IocScan_IsTextContent(Data, Size)) return WkdFmt_Unknown;

    RtlZeroMemory(&info, sizeof(info));
    IocScan_AnalyzeScript(Data, Size, &info);

    if (info.HasShebang && info.ShebangInterpreter[0]) {
        CHAR interp[64];
        strncpy_s(interp, sizeof(interp), info.ShebangInterpreter, _TRUNCATE);
        _strlwr_s(interp, sizeof(interp));
        if (strstr(interp, "python") != NULL) return WkdFmt_Python;
        if (strstr(interp, "ruby") != NULL) return WkdFmt_Ruby;
        if (strstr(interp, "perl") != NULL) return WkdFmt_Perl;
        if (strstr(interp, "bash") != NULL) return WkdFmt_ShellScript;
        if (strstr(interp, "sh") != NULL) return WkdFmt_ShellScript;
        if (strstr(interp, "php") != NULL) return WkdFmt_Php;
    }

    if (info.HasScriptKeywords) {
        for (i = 0; i < info.KeywordCount; i++) {
            if (_stricmp(info.DetectedKeywords[i], "PowerShell") == 0) return WkdFmt_PowerShell;
            if (_stricmp(info.DetectedKeywords[i], "VBScript") == 0) return WkdFmt_VBScript;
            if (_stricmp(info.DetectedKeywords[i], "Python") == 0) return WkdFmt_Python;
            if (_stricmp(info.DetectedKeywords[i], "JavaScript") == 0) return WkdFmt_JavaScript;
            if (_stricmp(info.DetectedKeywords[i], "Batch") == 0) return WkdFmt_Batch;
            if (_stricmp(info.DetectedKeywords[i], "HTA") == 0) return WkdFmt_Hta;
        }
    }
    return WkdFmt_Unknown;
}

/**************************************************/
/*  5.5 ��չ����ƭ��� (SS HasRTLOverrideImpl       */
/*       L2236-2253 / HasDoubleExtensionImpl       */
/*       L2255-2298 / DetectSpoofingImpl           */
/*       L2152-2234 / Analyze path ��ȫ L1408-1451) */
/**************************************************/

/* RTLO ˫������ַ���� �� ȫ 7 �� (���� SS L2236-2253):
 * U+202A-202E (LRE/RLE/PDF/LRO/RLO) / U+2066-2069 (LRI/RLI/FSI/PDI) /
 * U+200E-200F (LRM/RLM) / U+061C (ALM) / U+200B-200D (ZWSP/ZWNJ/ZWJ) /
 * U+FEFF (BOM/ZWNNBSP) */
BOOLEAN
IocScan_HasRtlOverride(
    _In_ PCWSTR Filename
    )
{
    PCWSTR p;

    if (!Filename) return FALSE;
    for (p = Filename; *p; p++) {
        WCHAR ch = *p;
        if (ch >= 0x202A && ch <= 0x202E) return TRUE;
        if (ch >= 0x2066 && ch <= 0x2069) return TRUE;
        if (ch == 0x200E || ch == 0x200F) return TRUE;
        if (ch == 0x061C) return TRUE;
        if (ch >= 0x200B && ch <= 0x200D) return TRUE;
        if (ch == 0xFEFF) return TRUE;
    }
    return FALSE;
}

/* ˫��չ����� (���� SS HasDoubleExtensionImpl L2255-2298:
 * ������չ��Σ�� �� ǰһ����չ����ȫ �� file.txt.exe) */
BOOLEAN
IocScan_HasDoubleExtension(
    _In_ PCWSTR Filename
    )
{
    static const PCWSTR safeExtensions[] = {
        L".txt", L".pdf", L".doc", L".docx", L".xls", L".xlsx",
        L".ppt", L".pptx", L".jpg", L".jpeg", L".png", L".gif",
        L".bmp", L".tif", L".tiff", L".csv", L".rtf", L".odt",
        L".ods", L".odp", L".mp3", L".mp4", L".wav", L".avi",
        L".html", L".htm", L".xml", L".json", L".yaml", L".yml",
        L".log", L".cfg", L".ini", L".zip", L".rar", L".7z",
    };
    static const PCWSTR dangerousExtensions[] = {
        L".exe", L".scr", L".bat", L".cmd", L".com", L".pif",
        L".vbs", L".vbe", L".js", L".jse", L".wsf", L".wsh",
        L".ps1", L".psm1", L".hta", L".cpl", L".msi", L".msp",
        L".dll", L".sys", L".lnk",
    };
    WCHAR lower[260];
    PCWSTR lastDot;
    PCWSTR prevDot;
    PCWSTR scan;
    SIZE_T j;
    BOOLEAN finalIsDangerous = FALSE;
    BOOLEAN prevIsSafe = FALSE;
    SIZE_T i;

    if (!Filename || !Filename[0]) return FALSE;
    if (wcslen(Filename) >= RTL_NUMBER_OF(lower)) return FALSE;
    for (i = 0; Filename[i]; i++) lower[i] = (WCHAR)towlower(Filename[i]);
    lower[i] = L'\0';

    lastDot = wcsrchr(lower, L'.');
    if (!lastDot || lastDot == lower) return FALSE;

    for (j = 0; j < RTL_NUMBER_OF(dangerousExtensions); j++) {
        if (_wcsicmp(lastDot, dangerousExtensions[j]) == 0) { finalIsDangerous = TRUE; break; }
    }
    if (!finalIsDangerous) return FALSE;

    prevDot = NULL;
    for (scan = lower; scan < lastDot; scan++) {
        if (*scan == L'.') prevDot = scan;
    }
    if (!prevDot) return FALSE;
    for (j = 0; j < RTL_NUMBER_OF(safeExtensions); j++) {
        if (_wcsicmp(prevDot, safeExtensions[j]) == 0) { prevIsSafe = TRUE; break; }
    }
    return prevIsSafe;
}

/* ��չ��-���ݲ�ƥ���� (���� SS DetectSpoofingImpl L2152-2234,
 * ���Ϸ������չ��������: PE .exe/.scr/.com/.pif��DLL .dll/.ocx/.cpl/.drv��
 * SYS .sys��.NET .exe/.dll��ZIP docx/xlsx/...��OLE doc/dot/wbk/msg ��) */
BOOLEAN
IocScan_CheckExtMismatch(
    _Inout_ PWKD_FILE_TYPE_INFO Info
    )
{
    static const PCWSTR validZipExts[] = {
        L".docx", L".docm", L".xlsx", L".xlsm", L".xlsb",
        L".pptx", L".pptm", L".odt", L".ods", L".odp",
        L".jar", L".war", L".ear", L".apk", L".xpi",
        L".epub", L".cbz", L".nupkg", L".vsix",
    };
    PCWSTR disk;
    PCWSTR expected;
    SIZE_T j;

    if (!Info || Info->DiskExtension[0] == L'\0' || Info->Extension[0] == L'\0') return FALSE;

    disk = Info->DiskExtension;
    expected = Info->Extension;

    if (_wcsicmp(disk, expected) == 0) return FALSE;

    /* PE ��ִ�п��ж��ֺϷ���չ�� */
    if (Info->Format == WkdFmt_Pe32 || Info->Format == WkdFmt_Pe64) {
        if (_wcsicmp(disk, L".exe") == 0 || _wcsicmp(disk, L".scr") == 0 ||
            _wcsicmp(disk, L".com") == 0 || _wcsicmp(disk, L".pif") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Dll32 || Info->Format == WkdFmt_Dll64) {
        if (_wcsicmp(disk, L".dll") == 0 || _wcsicmp(disk, L".ocx") == 0 ||
            _wcsicmp(disk, L".cpl") == 0 || _wcsicmp(disk, L".drv") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Sys32 || Info->Format == WkdFmt_Sys64) {
        if (_wcsicmp(disk, L".sys") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_DotNetAssembly) {
        if (_wcsicmp(disk, L".exe") == 0 || _wcsicmp(disk, L".dll") == 0) return FALSE;
    }

    /* ZIP ������ʽ�Ϸ���չ������ */
    if (Info->Format == WkdFmt_Zip) {
        for (j = 0; j < RTL_NUMBER_OF(validZipExts); j++) {
            if (_wcsicmp(disk, validZipExts[j]) == 0) return FALSE;
        }
    }

    /* OLE �����ļ� */
    if (Info->Format == WkdFmt_Doc) {
        if (_wcsicmp(disk, L".doc") == 0 || _wcsicmp(disk, L".dot") == 0 ||
            _wcsicmp(disk, L".wbk") == 0 || _wcsicmp(disk, L".msg") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Xls) {
        if (_wcsicmp(disk, L".xls") == 0 || _wcsicmp(disk, L".xlt") == 0 ||
            _wcsicmp(disk, L".xla") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Ppt) {
        if (_wcsicmp(disk, L".ppt") == 0 || _wcsicmp(disk, L".pot") == 0 ||
            _wcsicmp(disk, L".pps") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Msi) {
        if (_wcsicmp(disk, L".msi") == 0 || _wcsicmp(disk, L".msp") == 0 ||
            _wcsicmp(disk, L".mst") == 0) return FALSE;
    }

    /* ��չ����ƥ�� �� �����Ǹ����ص���ƭ (RTLO/ADS/β����) */
    if (!Info->IsSpoofed) {
        Info->IsSpoofed = TRUE;
        Info->SpoofingType = WkdSpoof_ExtensionMismatch;
    }
    wcscpy_s(Info->SuggestedExt, RTL_NUMBER_OF(Info->SuggestedExt), expected);
    return TRUE;
}

/* ·������ƭ�ۺ� (���� SS Analyze path ��ȫ��� L1408-1451:
 * Ƕ�� NUL �ض� / ADS ð�� / RTLO / β���ո��)��
 * ע: NUL �ضϹ��� (SS L1408-1414) ��� C++ wstring ��Ƕ NUL; wkd C PCWSTR
 * �ӿ��� wcslen �ض�, ��Ƕ NUL �����ܵ���˺��� �� ��Ȼ����, �߼���Ǩ�ơ� */
VOID
IocScan_DetectPathSpoofing(
    _In_ PCWSTR        FilePath,
    _Inout_ PWKD_FILE_TYPE_INFO Info
    )
{
    PCWSTR filename;
    PCWSTR lastSlash;
    const WCHAR* colonPos;
    BOOLEAN isDriveLetter;

    if (!FilePath || !Info) return;

    lastSlash = wcsrchr(FilePath, L'\\');
    {
        PCWSTR s2 = wcsrchr(FilePath, L'/');
        if (s2 && (!lastSlash || s2 > lastSlash)) lastSlash = s2;
    }
    filename = (lastSlash) ? (lastSlash + 1) : FilePath;

    /* NTFS ADS (�ļ�����ð��, �ų��̷� "C:") �� ���� SS L1423-1435 */
    colonPos = wcschr(filename, L':');
    if (colonPos != NULL) {
        isDriveLetter = (colonPos == filename + 1 &&
                         lastSlash == NULL &&
                         ((filename[0] >= L'A' && filename[0] <= L'Z') ||
                          (filename[0] >= L'a' && filename[0] <= L'z')));
        if (!isDriveLetter) {
            Info->IsSpoofed = TRUE;
            Info->SpoofingType = WkdSpoof_HiddenExtension;
            return;
        }
    }

    /* RTLO ˫������ַ� �� ���� SS L1437-1443 */
    if (IocScan_HasRtlOverride(filename)) {
        Info->IsSpoofed = TRUE;
        Info->SpoofingType = WkdSpoof_RtlOverride;
        return;
    }

    /* β���ո�/�� (NTFS �淶���ƹ�) �� ���� SS L1445-1450 */
    if (filename[0] != L'\0' &&
        (filename[wcslen(filename) - 1] == L' ' || filename[wcslen(filename) - 1] == L'.')) {
        Info->IsSpoofed = TRUE;
        Info->SpoofingType = WkdSpoof_HiddenExtension;
        return;
    }
}

/**************************************************/
/*  5.6 �ļ�ͷ��ȡ + ��������� + �ַ����          */
/*  (SS ReadFileHeader L247-307 / AnalyzeBuffer    */
/*   L2015-2126 / Analyze L1397-1519)              */
/**************************************************/

/* ͷ��ȡ�ֽ�����: ���� SS MAX_HEADER_SIZE (64KB), ���� ISO@0x8001 �ȶ�ƫ��ǩ�� */
static DOUBLE
IocScan_CalculateChiSquare(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    ULONG freq[256];
    DOUBLE expected;
    DOUBLE chi = 0.0;
    ULONG i;

    if (!Data || Size == 0) return 0.0;
    memset(freq, 0, sizeof(freq));
    for (i = 0; i < Size; i++) freq[Data[i]]++;

    expected = (DOUBLE)Size / 256.0;
    for (i = 0; i < 256; i++) {
        DOUBLE diff = (DOUBLE)freq[i] - expected;
        chi += (diff * diff) / expected;
    }
    return chi;
}

/* �Ƿ����Ƽ���/��� (���� SS IsLikelyEncrypted: ��>7.8 �� chi<293.25)��
 * 0-1000 ������ֵ 780 ���� 7.8/8.0�� */
static BOOLEAN
IocScan_IsLikelyEncrypted(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    ULONG entropy = 0;
    if (!Data || Size < 256) return FALSE;
    entropy = (ULONG)(CoEntropyBinary((PVOID)Data, Size, 0) * 1000.0);
    if (entropy < 7800) return FALSE;
    return (IocScan_CalculateChiSquare(Data, Size) < 293.25);
}

/**************************************************/
/*       ý���ļ����� (SS MediaFileScanner Ǩ��)     */
/*  ��ʽ��֤/��д���/Ԫ���ݡ�EXIF/©���غ�/׷������  */
/*  (2026-08-06, �������ںϽ� IocScanner ��̬����,  */
/*   �ع���ʵ�ַ�Դ�븴��; ö��/�ṹ�� IocTypes.h)    */
/*  ���� API ���� (IocScanner.h); ���ߵ�             */
/*  (FUTURE): ScanManager.ScanFileDirect ���� 5/6 �� */
/*  �� IocMedia_ScanFile �� IocMedia_ResultToIocScan  */
/*  �� HeuristicConfidence ͨ�� �� IocScan_Aggregate. */
/**************************************************/

/* ==================================================
 * ��Я��ȫ������ȡ (���� SS SafeRead L123-144, ��δ���� UB)
 * ================================================== */
static inline UINT16
IocMedia_U16BE(
    _In_ const BYTE* p
    )
{
    return (UINT16)(((UINT16)p[0] << 8) | p[1]);
}

static inline UINT16
IocMedia_U16LE(
    _In_ const BYTE* p
    )
{
    return (UINT16)(p[0] | ((UINT16)p[1] << 8));
}

static inline UINT32
IocMedia_U32BE(
    _In_ const BYTE* p
    )
{
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) |
           ((UINT32)p[2] << 8)  | (UINT32)p[3];
}

static inline UINT32
IocMedia_U32LE(
    _In_ const BYTE* p
    )
{
    return ((UINT32)p[0]) | ((UINT32)p[1] << 8) |
           ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

/* ==================================================
 * ���� + ý�������ж� (���� SS L289-317 / L376-419)
 * ================================================== */

static const BYTE IocMedia_PngSig[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

/*++
Routine Description:
    �����ļ� (100MB cap, ���� SS ReadFileCapped L289-317 + MAX_SCAN_FILE_SIZE)��
    ���� CoOpenFileForSequentialRead �� reparse �ܾ�/4GB Ԥ�커��;
    �� 100MB ���� STATUS_FILE_TOO_LARGE (���÷����� header-only ����)��

Arguments:
    FilePath - �ļ�·����
    OutBuf   - ��� malloc �ѻ��� (���÷� free)��
    OutLen   - ���ʵ�ʶ����ֽڡ�

Return Value:
    NTSTATUS��
--*/
static NTSTATUS
IocMedia_ReadFileCapped(
    _In_  PCWSTR FilePath,
    _Out_ BYTE** OutBuf,
    _Out_ PULONG OutLen
    )
{
    HANDLE hFile;
    BOOLEAN tooLarge = FALSE;
    LARGE_INTEGER fileSize;
    ULONG64 size;
    BYTE* buf;

    if (!FilePath || !OutBuf || !OutLen) return STATUS_INVALID_PARAMETER;
    *OutBuf = NULL;
    *OutLen = 0;

    hFile = CoOpenFileForSequentialRead(FilePath, &tooLarge);
    if (hFile == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;

    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 0) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }
    size = (ULONG64)fileSize.QuadPart;
    if (size > WKD_MEDIA_MAX_FILE_SIZE) {
        CloseHandle(hFile);
        return STATUS_FILE_TOO_LARGE;
    }
    if (size == 0) {
        CloseHandle(hFile);
        return STATUS_SUCCESS;   /* ���ļ�, OutBuf=NULL/OutLen=0 */
    }

    buf = (BYTE*)malloc((size_t)size);
    if (!buf) {
        CloseHandle(hFile);
        return STATUS_NO_MEMORY;
    }
    {
        ULONG64 remaining = size;
        PBYTE p = buf;
        while (remaining > 0) {
            DWORD rd = 0;
            ULONG chunk = (remaining > 0xFFFFFFFF) ? 0xFFFFFFFF : (ULONG)remaining;
            if (!ReadFile(hFile, p, chunk, &rd, NULL) || rd == 0) {
                free(buf);
                CloseHandle(hFile);
                return STATUS_UNSUCCESSFUL;
            }
            p += rd;
            remaining -= rd;
        }
    }
    CloseHandle(hFile);
    *OutBuf = buf;
    *OutLen = (ULONG)size;
    return STATUS_SUCCESS;
}

/*++
Routine Description:
    WKD_FILE_FORMAT �� WKD_MEDIA_TYPE ӳ�� (wkd ħ�����Ѹ���ȫ��ý���ʽ,
    �ļ������� CoDetermineFileTypeFromBuffer �ж��󾭴�������ý������)��

Arguments:
    Format - �ļ�����ʶ������

Return Value:
    WKD_MEDIA_TYPE; ��ý�巵�� WkdMedia_Unknown��
--*/
static WKD_MEDIA_TYPE
IocMedia_FormatToMediaType(
    _In_ WKD_FILE_FORMAT Format
    )
{
    switch (Format) {
    case WkdFmt_Jpeg: return WkdMedia_Jpeg;
    case WkdFmt_Png:  return WkdMedia_Png;
    case WkdFmt_Gif:  return WkdMedia_Gif;
    case WkdFmt_Bmp:  return WkdMedia_Bmp;
    case WkdFmt_Tiff: return WkdMedia_Tiff;
    case WkdFmt_Webp: return WkdMedia_Webp;
    case WkdFmt_Mp3:  return WkdMedia_Mp3;
    case WkdFmt_Wav:  return WkdMedia_Wav;
    case WkdFmt_Mp4:  return WkdMedia_Mp4;
    default:          return WkdMedia_Unknown;
    }
}

/*++
Routine Description:
    ����ý�������ж� (���� SS DetectMediaTypeFromData L376-419;
    ħ���ж����� wkd �ļ�����ʶ��ħ����, ���ظ�ʵ��)��

Arguments:
    Data - �ļ����� (�������ݻ�ͷ������, ħ����ͷ��)��
    Size - �ֽ�����

Return Value:
    WKD_MEDIA_TYPE��
--*/
static WKD_MEDIA_TYPE
IocMedia_DetectMediaTypeFromData(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    WKD_FILE_TYPE_INFO fti;

    if (!Data || Size == 0) return WkdMedia_Unknown;
    if (!NT_SUCCESS(CoDetermineFileTypeFromBuffer(Data, Size, NULL, &fti))) return WkdMedia_Unknown;
    return IocMedia_FormatToMediaType(fti.Format);
}

/* ==================================================
 * ý��ṹ���� (���� SS FindJpegLastEoi L340-351 /
 *  AddRisk L357-361; PNG chunk ����Ϊ���ó���)
 * ================================================== */

/*++
Routine Description:
    �� JPEG ���һ�� EOI (FFD9) ���λ�� (���� SS FindJpegLastEoi L340-351)��

Arguments:
    Data    - JPEG ���塣
    Size    - �ֽ�����
    OutEoi  - ��� EOI ��ƫ�� (i+2)��

Return Value:
    TRUE=�ҵ�; FALSE=δ�ҵ���
--*/
static BOOLEAN
IocMedia_FindJpegLastEoi(
    _In_  const BYTE* Data,
    _In_  ULONG       Size,
    _Out_ PSIZE_T     OutEoi
    )
{
    SIZE_T last = (SIZE_T)-1;
    ULONG i;

    if (Size < 4) return FALSE;
    for (i = 0; i + 1 < Size; i++) {
        if (Data[i] == 0xFF && Data[i + 1] == 0xD9) last = (SIZE_T)i + 2;
    }
    if (last == (SIZE_T)-1) return FALSE;
    if (OutEoi) *OutEoi = last;
    return TRUE;
}

/*++
Routine Description:
    ���շ��ۼ�, uint32 �ۼ� clamp 100 (���� SS AddRisk L357-361)��

Arguments:
    Result - ý��ɨ������
    Points - �ӷ֡�
--*/
static VOID
IocMedia_AddRisk(
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result,
    _In_    ULONG                  Points
    )
{
    ULONG total;
    if (!Result) return;
    total = Result->RiskScore + Points;
    Result->RiskScore = (total > 100) ? 100 : total;
}

/*++
Routine Description:
    ��в����, ���� cap 8 (SS vector ������ �� �����ü�)��

Arguments:
    Result   - ý��ɨ������
    Type     - ��в���͡�
    Severity - ���ض� 0-10��
    Desc     - ������
    Offset   - �ֽ�ƫ�ơ�
--*/
static VOID
IocMedia_AddThreat(
    _Inout_ PWKD_MEDIA_SCAN_RESULT   Result,
    _In_    WKD_MEDIA_THREAT_TYPE    Type,
    _In_    ULONG                    Severity,
    _In_    PCSTR                    Desc,
    _In_    ULONG                    Offset
    )
{
    PWKD_MEDIA_THREAT t;

    if (!Result) return;
    if (Result->ThreatCount >= WKD_MEDIA_MAX_THREATS) return;
    t = &Result->Threats[Result->ThreatCount++];
    t->Type = Type;
    t->Severity = Severity;
    t->Offset = Offset;
    strncpy_s(t->Description, sizeof(t->Description), (Desc ? Desc : ""), _TRUNCATE);
}

/* PNG chunk �����ص�: ���� TRUE ֹͣ���� */
typedef BOOLEAN (*IocMedia_PngChunkCb)(
    _In_ const CHAR* ChunkType,   /* 4 �ֽ�����, �� NUL ��ֹ */
    _In_ ULONG       ChunkLen,    /* chunk ���ݳ��� */
    _In_ const BYTE* ChunkData,   /* chunk ����ָ�� */
    _In_ PVOID       Ctx
    );

/*++
Routine Description:
    PNG chunk ���� (���� SS �� chunk ѭ�� L508-513/L903-913/L1244-1258/
    L1721-1733 ���븴��: ValidatePNG ǰ�� + Metadata + �غ� + ׷�ӹ���)��

Arguments:
    Data - PNG ���塣
    Size - �ֽ�����
    Cb   - �� chunk �ص� (���� TRUE ��ǰֹͣ)��
    Ctx  - �ص������ġ�

Return Value:
    TRUE=�ص�����ֹͣ; FALSE=����������������Ч��
--*/
static BOOLEAN
IocMedia_PngChunkWalk(
    _In_ const BYTE*    Data,
    _In_ ULONG          Size,
    _In_ IocMedia_PngChunkCb Cb,
    _In_opt_ PVOID      Ctx
    )
{
    SIZE_T pos;

    if (!Data || Size < 8 || memcmp(Data, IocMedia_PngSig, 8) != 0) return FALSE;
    pos = 8;
    while (pos + 12 <= Size) {
        UINT32 chunkLen = IocMedia_U32BE(Data + pos);
        const BYTE* ct;
        if (chunkLen > Size - pos - 12) break;
        ct = Data + pos + 4;
        if (Cb && Cb((const CHAR*)ct, chunkLen, Data + pos + 8, Ctx)) return TRUE;
        pos += 12 + chunkLen;
    }
    return FALSE;
}

/* ==================================================
 * ��ʽ��֤ (���� SS ValidateFormat L425-620)
 *   JPEG marker �α��� / PNG IHDR / GIF �ߴ� /
 *   BMP ������� / TIFF IFD ����ȡ���Ŀ���޷� DoS
 * ================================================== */

static BOOLEAN
IocMedia_ValidateJpeg(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    ULONG pos;
    BOOLEAN foundSos = FALSE;

    if (Size < 4) return FALSE;
    if (Data[0] != 0xFF || Data[1] != 0xD8) return FALSE;
    pos = 2;
    while (pos + 1 < Size) {
        BYTE marker;
        UINT16 segLen;
        if (Data[pos] != 0xFF) {
            if (foundSos) break;
            return FALSE;
        }
        while (pos + 1 < Size && Data[pos + 1] == 0xFF) ++pos;
        if (pos + 1 >= Size) break;
        marker = Data[pos + 1];
        pos += 2;
        if (marker == 0xD9) return TRUE;
        if (marker == 0xDA) { foundSos = TRUE; break; }
        if (marker == 0x00) continue;
        if (marker >= 0xD0 && marker <= 0xD7) continue;
        if (pos + 1 >= Size) return FALSE;
        segLen = IocMedia_U16BE(Data + pos);
        if (segLen < 2) return FALSE;
        if ((ULONG)(pos + segLen) > Size) return FALSE;
        pos += segLen;
    }
    if (foundSos) {
        SIZE_T eoi;
        return IocMedia_FindJpegLastEoi(Data, Size, &eoi);
    }
    return FALSE;
}

static BOOLEAN
IocMedia_ValidatePng(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    UINT32 ihdrLen, width, height;

    if (Size < 29) return FALSE;
    if (memcmp(Data, IocMedia_PngSig, 8) != 0) return FALSE;
    if (Data[12] != 'I' || Data[13] != 'H' || Data[14] != 'D' || Data[15] != 'R') return FALSE;
    ihdrLen = IocMedia_U32BE(Data + 8);
    if (ihdrLen != 13) return FALSE;
    width = IocMedia_U32BE(Data + 16);
    height = IocMedia_U32BE(Data + 20);
    if (width == 0 || height == 0 || width > 100000 || height > 100000) return FALSE;
    return TRUE;
}

static BOOLEAN
IocMedia_ValidateGif(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    UINT16 w, h;

    if (Size < 13) return FALSE;
    if (memcmp(Data, "GIF87a", 6) != 0 && memcmp(Data, "GIF89a", 6) != 0) return FALSE;
    w = IocMedia_U16LE(Data + 6);
    h = IocMedia_U16LE(Data + 8);
    if (w == 0 || h == 0) return FALSE;
    return TRUE;
}

static BOOLEAN
IocMedia_ValidateBmp(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    UINT32 dataOffset, dibSize;

    if (Size < 26) return FALSE;
    if (Data[0] != 0x42 || Data[1] != 0x4D) return FALSE;
    dataOffset = IocMedia_U32LE(Data + 10);
    dibSize = IocMedia_U32LE(Data + 14);
    if (dataOffset > Size) return FALSE;
    if (dibSize >= 40 && Size >= 30) {
        INT32 w = (INT32)IocMedia_U32LE(Data + 18);
        INT32 h = (INT32)IocMedia_U32LE(Data + 22);
        UINT16 bpp = IocMedia_U16LE(Data + 28);
        INT32 ah;
        UINT64 pixelSize;
        if (w <= 0 || w > 100000) return FALSE;
        ah = (h < 0) ? -h : h;
        if (ah <= 0 || ah > 100000) return FALSE;
        pixelSize = (UINT64)w * (UINT64)ah * ((bpp > 0) ? ((bpp + 7u) / 8u) : 1u);
        if (pixelSize > 4ULL * 1024 * 1024 * 1024) return FALSE;
    }
    return TRUE;
}

static BOOLEAN
IocMedia_ValidateTiff(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    BOOLEAN le, be;
    UINT16 magic;
    UINT32 cur;
    INT depth = 0;

    if (Size < 8) return FALSE;
    le = (Data[0] == 0x49 && Data[1] == 0x49);
    be = (Data[0] == 0x4D && Data[1] == 0x4D);
    if (!le && !be) return FALSE;
    magic = le ? IocMedia_U16LE(Data + 2) : IocMedia_U16BE(Data + 2);
    if (magic != 42) return FALSE;
    cur = le ? IocMedia_U32LE(Data + 4) : IocMedia_U32BE(Data + 4);
    if (cur >= Size || cur < 8) return FALSE;
    while (cur != 0 && depth < 8) {
        UINT16 n;
        SIZE_T nextOff;
        if ((SIZE_T)cur + 2 > Size) break;   /* SIZE_T �� 32 λ UINT32 ��� */
        n = le ? IocMedia_U16LE(Data + cur) : IocMedia_U16BE(Data + cur);
        if (n > 200) return FALSE;
        nextOff = (SIZE_T)cur + 2 + (SIZE_T)n * 12;
        if (nextOff + 4 > Size) break;
        cur = le ? IocMedia_U32LE(Data + nextOff) : IocMedia_U32BE(Data + nextOff);
        ++depth;
    }
    if (depth >= 8) return FALSE;
    return TRUE;
}

/*++
Routine Description:
    ��ʽ��֤���� (���� SS ValidateFormat L425-442; Unknown ֱ����Ϊ�Ϸ�)��

Arguments:
    Data - ý�建�塣
    Size - �ֽ�����
    Type - ý�����͡�

Return Value:
    TRUE=�ṹ�Ϸ���
--*/
static BOOLEAN
IocMedia_ValidateFormat(
    _In_ const BYTE*    Data,
    _In_ ULONG          Size,
    _In_ WKD_MEDIA_TYPE Type
    )
{
    switch (Type) {
    case WkdMedia_Jpeg: return IocMedia_ValidateJpeg(Data, Size);
    case WkdMedia_Png:  return IocMedia_ValidatePng(Data, Size);
    case WkdMedia_Gif:  return IocMedia_ValidateGif(Data, Size);
    case WkdMedia_Bmp:  return IocMedia_ValidateBmp(Data, Size);
    case WkdMedia_Tiff: return IocMedia_ValidateTiff(Data, Size);
    default:            return TRUE;
    }
}

/* ==================================================
 * ý��ö�� �� �ַ��� (���� SS MediaTypeToString L150-170 /
 *  StegoTechniqueToString L172-183 / MediaThreatTypeToString L185-198)
 *   StegoTechniqueToString ����д��в����; MediaTypeToString ����չ��ʧ��
 *   ����; MediaThreatTypeToString ����ˮ�ߵ����� (SS ��δ����, ������)
 * ================================================== */
#pragma warning(push)
#pragma warning(disable: 4505)   /* MediaThreatTypeToString �޵����� (������, ������Ŀ����) */

static PCSTR
IocMedia_MediaTypeToString(
    _In_ WKD_MEDIA_TYPE Type
    )
{
    switch (Type) {
    case WkdMedia_Jpeg: return "JPEG";
    case WkdMedia_Png:  return "PNG";
    case WkdMedia_Gif:  return "GIF";
    case WkdMedia_Bmp:  return "BMP";
    case WkdMedia_Tiff: return "TIFF";
    case WkdMedia_Webp: return "WebP";
    case WkdMedia_Mp3:  return "MP3";
    case WkdMedia_Wav:  return "WAV";
    case WkdMedia_Mp4:  return "MP4";
    default:            return "Unknown";
    }
}

static PCSTR
IocMedia_StegoTechniqueToString(
    _In_ WKD_STEGO_TECHNIQUE Tech
    )
{
    switch (Tech) {
    case WkdStego_Lsb:         return "Least Significant Bit";
    case WkdStego_Dct:         return "DCT Coefficients";
    case WkdStego_EofAppended: return "End-of-File Appended";
    case WkdStego_Metadata:    return "Metadata Hiding";
    default:                   return "None";
    }
}

static PCSTR
IocMedia_MediaThreatTypeToString(
    _In_ WKD_MEDIA_THREAT_TYPE Type
    )
{
    switch (Type) {
    case WkdMediaThreat_Steganography:      return "Steganography";
    case WkdMediaThreat_MalformedHeader:    return "Malformed Header";
    case WkdMediaThreat_BufferOverflow:     return "Buffer Overflow Trigger";
    case WkdMediaThreat_EmbeddedExecutable: return "Embedded Executable";
    case WkdMediaThreat_AppendedArchive:    return "Appended Archive";
    case WkdMediaThreat_Polyglot:           return "Polyglot File";
    case WkdMediaThreat_ScriptInjection:    return "Script Injection";
    case WkdMediaThreat_CveExploit:         return "CVE Exploit";
    default:                                return "None";
    }
}

#pragma warning(pop)

/* ==================================================
 * ��д��� (���� SS AnalyzeSteganography L736-1011)
 *   �� BMP ������ LSB ���� (PNG ȱ�ݱ�ע) /
 *   JPEG EOI �� EOF ׷�� / ��Ԫ���ݶ� / JPEG DCT LSB
 * ================================================== */

/*++
Routine Description:
    LSB ������� (���� SS DetectLSBStego L764-833, PoV ��������)��
    SS ȱ��: PNG IDAT Ϊ zlib ѹ������, �ֽڷֲ���Ȼ����,
    ������ѹ�����ݱ�Ȼ���"����"�� �� LSB ��д (L764-833 �� PNG ��Ч)��
    �����汣���ο�, ʵ���ж��� BMP δѹ����������Ч��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Type   - ý������ (�� BMP ��Ч)��
    Result - �����д������
--*/
static VOID
IocMedia_DetectLsbStego(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _In_ WKD_MEDIA_TYPE      Type,
    _Inout_ PWKD_STEGO_ANALYSIS Result
    )
{
    UINT64 histogram[256];
    SIZE_T dataStart, analysisEnd;
    ULONG pairsAnalyzed = 0;
    ULONG k;
    double chiSquare = 0.0;

    if (Type != WkdMedia_Bmp) return;   /* PNG ȱ������, ������ͷע�� */
    if (Size < 1024) return;

    dataStart = (Size >= 14) ? IocMedia_U32LE(Data + 10) : 0;
    if (dataStart >= Size) dataStart = 0;
    analysisEnd = (dataStart + 100000 < Size) ? dataStart + 100000 : Size;
    if (analysisEnd <= dataStart + 256) return;

    memset(histogram, 0, sizeof(histogram));
    {
        SIZE_T i;
        for (i = dataStart; i < analysisEnd; i++) histogram[Data[i]]++;
    }

    for (k = 0; k < 128; k++) {
        UINT64 c0 = histogram[2 * k];
        UINT64 c1 = histogram[2 * k + 1];
        double expected = (double)(c0 + c1) / 2.0;
        if (expected > 5.0) {
            double d0 = (double)c0 - expected;
            double d1 = (double)c1 - expected;
            chiSquare += (d0 * d0) / expected + (d1 * d1) / expected;
            pairsAnalyzed++;
        }
    }
    if (pairsAnalyzed < 10) return;

    {
        double normalized = chiSquare / (double)pairsAnalyzed;
        if (normalized < 1.0) {
            Result->StegoDetected = TRUE;
            Result->Technique = WkdStego_Lsb;
            Result->Confidence = (ULONG)((0.9 - normalized * 0.2) * 100.0);
            if (Result->Confidence > 95) Result->Confidence = 95;
            snprintf(Result->AnalysisDetails, sizeof(Result->AnalysisDetails),
                     "PoV chi-square: %.2f (normalized: %.4f, %lu pairs)",
                     chiSquare, normalized, pairsAnalyzed);
        } else if (normalized < 2.0) {
            Result->StegoDetected = TRUE;
            Result->Technique = WkdStego_Lsb;
            Result->Confidence = 50;
            snprintf(Result->AnalysisDetails, sizeof(Result->AnalysisDetails),
                     "PoV chi-square marginal: %.4f", normalized);
        }
    }
}

/*++
Routine Description:
    JPEG EOI ��׷��������д (���� SS DetectEOFStego L835-870)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Type   - ý������ (�� JPEG)��
    Result - �����д������
--*/
static VOID
IocMedia_DetectEofStego(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _In_ WKD_MEDIA_TYPE      Type,
    _Inout_ PWKD_STEGO_ANALYSIS Result
    )
{
    SIZE_T eoiPos;
    ULONG appendedSize;

    if (Type != WkdMedia_Jpeg) return;
    if (!IocMedia_FindJpegLastEoi(Data, Size, &eoiPos)) return;
    if (eoiPos >= Size) return;
    appendedSize = Size - (ULONG)eoiPos;
    if (appendedSize <= 16) return;   /* MIN_APPENDED_THRESHOLD */

    Result->StegoDetected = TRUE;
    Result->Technique = WkdStego_EofAppended;
    Result->Confidence = 90;
    Result->EstimatedPayloadSize = appendedSize;
    snprintf(Result->AnalysisDetails, sizeof(Result->AnalysisDetails),
             "%lu bytes after JPEG EOI marker", appendedSize);
}

/*++
Routine Description:
    ��Ԫ���ݶ���д (���� SS DetectMetadataStego L872-933:
    JPEG APPn/COM �� + PNG tEXt/zTXt/iTXt ���ܴ�С >10KB ����)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Result - �����д������
--*/
static VOID
IocMedia_DetectMetadataStego(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _Inout_ PWKD_STEGO_ANALYSIS Result
    )
{
    ULONG64 totalMetaSize = 0;

    /* JPEG APP/COM marker �� (���� SS L879-897) */
    if (Size >= 4 && Data[0] == 0xFF && Data[1] == 0xD8) {
        SIZE_T pos = 2;
        while (pos + 3 < Size) {
            BYTE marker;
            UINT16 segLen;
            if (Data[pos] != 0xFF) break;
            marker = Data[pos + 1];
            if (marker == 0xDA || marker == 0xD9) break;
            if (marker == 0x00 || (marker >= 0xD0 && marker <= 0xD7)) { pos += 2; continue; }
            segLen = IocMedia_U16BE(Data + pos + 2);
            if (segLen < 2 || pos + 2 + segLen > Size) break;
            if ((marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE) totalMetaSize += segLen;
            pos += 2 + segLen;
        }
    }

    /* PNG �ı��� (���� SS L899-914) */
    if (Size >= 8 && memcmp(Data, IocMedia_PngSig, 8) == 0) {
        SIZE_T pos = 8;
        while (pos + 12 <= Size) {
            UINT32 chunkLen = IocMedia_U32BE(Data + pos);
            const BYTE* ct;
            if (chunkLen > Size - pos - 12) break;
            ct = Data + pos + 4;
            if (memcmp(ct, "tEXt", 4) == 0 || memcmp(ct, "zTXt", 4) == 0 ||
                memcmp(ct, "iTXt", 4) == 0) totalMetaSize += chunkLen;
            if (memcmp(ct, "IEND", 4) == 0) break;
            pos += 12 + chunkLen;
        }
    }

    if (totalMetaSize > 10000) {   /* SUSPICIOUS_META_SIZE */
        Result->StegoDetected = TRUE;
        Result->Technique = WkdStego_Metadata;
        Result->Confidence = (ULONG)((0.55 + (double)(totalMetaSize - 10000) / 100000.0) * 100.0);
        if (Result->Confidence > 85) Result->Confidence = 85;
        Result->EstimatedPayloadSize = totalMetaSize;
        snprintf(Result->AnalysisDetails, sizeof(Result->AnalysisDetails),
                 "%llu bytes in metadata segments", (unsigned long long)totalMetaSize);
    }
}

/*++
Routine Description:
    JPEG DCT ϵ�� LSB ƽ���� (���� SS DetectDctStego L935-1011:
    SOS ���ر������ >7.0 �� LSB ƽ��� >0.98 ����)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Result - �����д������
--*/
static VOID
IocMedia_DetectDctStego(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _Inout_ PWKD_STEGO_ANALYSIS Result
    )
{
    UINT64 histogram[256];
    SIZE_T sosPos = 0;
    SIZE_T analyzeEnd;
    ULONG64 entropySamples = 0;
    ULONG i;
    double entropy = 0.0;
    double lsbRatio;
    UINT64 lsb0 = 0, lsb1 = 0;

    if (Size < 100) return;

    /* �� SOS (FFDA) ��λ�ر������� (���� SS L942-952) */
    for (i = 2; i + 3 < Size; i++) {
        if (Data[i] == 0xFF && Data[i + 1] == 0xDA) {
            UINT16 hdrLen = IocMedia_U16BE(Data + i + 2);
            if (i + 2 + hdrLen < Size) sosPos = i + 2 + hdrLen;
            break;
        }
    }
    if (sosPos == 0 || sosPos >= Size) return;

    memset(histogram, 0, sizeof(histogram));
    analyzeEnd = (sosPos + 200000 < Size) ? sosPos + 200000 : Size;
    for (i = (ULONG)sosPos; i < analyzeEnd; i++) {
        if (Data[i] == 0xFF && i + 1 < analyzeEnd) {
            if (Data[i + 1] == 0x00) { ++i; continue; }
            if (Data[i + 1] == 0xD9) break;
            if (Data[i + 1] >= 0xD0 && Data[i + 1] <= 0xD7) { ++i; continue; }
        }
        histogram[Data[i]]++;
        entropySamples++;
    }
    if (entropySamples < 1000) return;

    for (i = 0; i < 256; i++) {
        if (histogram[i] == 0) continue;
        {
            double p = (double)histogram[i] / (double)entropySamples;
            entropy -= p * log2(p);
        }
    }
    for (i = 0; i < 256; i += 2) { lsb0 += histogram[i]; lsb1 += histogram[i + 1]; }
    lsbRatio = (entropySamples > 0)
        ? (double)((lsb0 < lsb1) ? lsb0 : lsb1) / (double)((lsb0 > lsb1) ? lsb0 : lsb1)
        : 0.0;

    if (lsbRatio > 0.98 && entropy > 7.0) {
        Result->StegoDetected = TRUE;
        Result->Technique = WkdStego_Dct;
        Result->Confidence = (ULONG)((0.65 + (lsbRatio - 0.98) * 5.0) * 100.0);
        if (Result->Confidence > 90) Result->Confidence = 90;
        snprintf(Result->AnalysisDetails, sizeof(Result->AnalysisDetails),
                 "DCT entropy: %.3f bits, LSB ratio: %.4f (%llu samples)",
                 entropy, lsbRatio, (unsigned long long)entropySamples);
    }
}

/*++
Routine Description:
    ��д�ۺ�: 4 ����ȡ���Ŷ������, ��60 �ж� StegoDetected
    (���� SS AnalyzeSteganography L736-762, double 0.6 �� 0-100 �߶�)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Type   - ý�����͡�
    Result - �����д������
--*/
static VOID
IocMedia_AnalyzeSteganography(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _In_ WKD_MEDIA_TYPE      Type,
    _Inout_ PWKD_STEGO_ANALYSIS Result
    )
{
    WKD_STEGO_ANALYSIS best;
    WKD_STEGO_ANALYSIS cand;

    if (!Result) return;
    memset(&best, 0, sizeof(best));

    memset(&cand, 0, sizeof(cand));
    IocMedia_DetectLsbStego(Data, Size, Type, &cand);
    if (cand.Confidence > best.Confidence) best = cand;

    memset(&cand, 0, sizeof(cand));
    IocMedia_DetectEofStego(Data, Size, Type, &cand);
    if (cand.Confidence > best.Confidence) best = cand;

    memset(&cand, 0, sizeof(cand));
    IocMedia_DetectMetadataStego(Data, Size, &cand);
    if (cand.Confidence > best.Confidence) best = cand;

    if (Type == WkdMedia_Jpeg) {
        memset(&cand, 0, sizeof(cand));
        IocMedia_DetectDctStego(Data, Size, &cand);
        if (cand.Confidence > best.Confidence) best = cand;
    }

    if (best.Confidence >= 60) best.StegoDetected = TRUE;   /* SS: confidence >= 0.6 */
    *Result = best;
}

/* ==================================================
 * Ԫ����/EXIF ��ȡ (���� SS ParseMetadata L1017-1321)
 *   JPEG APP1 EXIF IFD �ݹ� / PNG tEXt / BMP / TIFF
 * ================================================== */

/* EXIF ��ȡ�� (���� SS ExifReader L1037-1070, tiff-relative ƫ��) */
typedef struct _IOC_MEDIA_EXIF_READER {
    const BYTE* Base;
    SIZE_T      TiffStart;
    SIZE_T      MaxLen;
    BOOLEAN     BigEndian;
} IOC_MEDIA_EXIF_READER;

static BOOLEAN
IocMedia_ExifValid(
    _In_ const IOC_MEDIA_EXIF_READER* r,
    _In_ SIZE_T                       Off,
    _In_ SIZE_T                       Len
    )
{
    SIZE_T abs = r->TiffStart + Off;
    return (abs + Len <= r->MaxLen) && (abs + Len >= abs);
}

static UINT16
IocMedia_ExifU16(
    _In_ const IOC_MEDIA_EXIF_READER* r,
    _In_ SIZE_T                       Off
    )
{
    SIZE_T abs = r->TiffStart + Off;
    if (abs + 2 > r->MaxLen) return 0;
    return r->BigEndian ? IocMedia_U16BE(r->Base + abs)
                        : IocMedia_U16LE(r->Base + abs);
}

static UINT32
IocMedia_ExifU32(
    _In_ const IOC_MEDIA_EXIF_READER* r,
    _In_ SIZE_T                       Off
    )
{
    SIZE_T abs = r->TiffStart + Off;
    if (abs + 4 > r->MaxLen) return 0;
    return r->BigEndian ? IocMedia_U32BE(r->Base + abs)
                        : IocMedia_U32LE(r->Base + abs);
}

static VOID
IocMedia_ExifReadAscii(
    _In_  const IOC_MEDIA_EXIF_READER* r,
    _In_  SIZE_T                       Off,
    _In_  ULONG                        Len,
    _Out_ CHAR*                        Out,
    _In_  ULONG                        OutCch
    )
{
    SIZE_T abs;
    SIZE_T safe;
    SIZE_T i;

    if (!r || !Out || OutCch == 0) return;
    Out[0] = '\0';
    if (Len == 0 || !IocMedia_ExifValid(r, Off, Len)) return;

    abs = r->TiffStart + Off;
    safe = Len;
    if (safe > (SIZE_T)OutCch - 1) safe = (SIZE_T)OutCch - 1;
    if (safe > 2048) safe = 2048;   /* SS readAscii cap 2048 */
    memcpy(Out, r->Base + abs, safe);
    Out[safe] = '\0';
    while (safe > 0 && (Out[safe - 1] == '\0' || (UCHAR)Out[safe - 1] < ' ')) {
        Out[--safe] = '\0';
    }
}

/*++
Routine Description:
    �� IFD ����, �ݹ� EXIF �� IFD + ������ (���� SS ParseExifIfd L1072-1160,
    ������� 8 / ��Ŀ���� 200 / ֵ��С���� 1MB)��

Arguments:
    r        - EXIF ��ȡ����
    IfdOffset - tiff-relative IFD ƫ�ơ�
    Meta     - ���Ԫ���ݡ�
    Depth    - ��ǰ��ȡ�
--*/
static VOID
IocMedia_ParseExifIfd(
    _In_ const IOC_MEDIA_EXIF_READER* r,
    _In_ UINT32                       IfdOffset,
    _Inout_ PWKD_MEDIA_METADATA       Meta,
    _In_ INT                          Depth
    )
{
    static const SIZE_T typeSizes[] = { 0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8 };
    UINT16 entryCount;
    UINT16 i;

    if (!r || !Meta) return;
    if (Depth > 8 || IfdOffset == 0) return;
    if (!IocMedia_ExifValid(r, IfdOffset, 2)) return;

    entryCount = IocMedia_ExifU16(r, IfdOffset);
    if (entryCount > 200) return;

    for (i = 0; i < entryCount; i++) {
        SIZE_T eOff = (SIZE_T)IfdOffset + 2 + (SIZE_T)i * 12;
        UINT16 tag, type;
        UINT32 count;
        SIZE_T valueSize;
        UINT32 valOff;

        if (!IocMedia_ExifValid(r, eOff, 12)) return;
        tag = IocMedia_ExifU16(r, eOff);
        type = IocMedia_ExifU16(r, eOff + 2);
        count = IocMedia_ExifU32(r, eOff + 4);
        if (type == 0 || type > 12) continue;

        valueSize = (SIZE_T)count * typeSizes[type];
        if (count > 0 && valueSize / count != typeSizes[type]) continue;
        if (valueSize > 1024 * 1024) continue;

        if (valueSize <= 4) valOff = (UINT32)(eOff + 8);
        else valOff = IocMedia_ExifU32(r, eOff + 8);

        switch (tag) {
        case 0x0100:   /* ImageWidth */
            Meta->Width = (type == 3) ? IocMedia_ExifU16(r, valOff)
                                      : IocMedia_ExifU32(r, valOff);
            break;
        case 0x0101:   /* ImageHeight */
            Meta->Height = (type == 3) ? IocMedia_ExifU16(r, valOff)
                                       : IocMedia_ExifU32(r, valOff);
            break;
        case 0x0102:   /* BitsPerSample */
            if (type == 3) Meta->BitDepth = IocMedia_ExifU16(r, valOff);
            break;
        case 0x010F:   /* Make */
            if (type == 2)
                IocMedia_ExifReadAscii(r, valOff, count, Meta->CameraMake, sizeof(Meta->CameraMake));
            break;
        case 0x0110:   /* Model */
            if (type == 2)
                IocMedia_ExifReadAscii(r, valOff, count, Meta->CameraModel, sizeof(Meta->CameraModel));
            break;
        case 0x010E:   /* ImageDescription */
        case 0x9286: { /* UserComment */
            if (type == 2 || type == 7) {
                CHAR tmp[2048];
                IocMedia_ExifReadAscii(r, valOff, count, tmp, sizeof(tmp));
                if (tmp[0] && Meta->CommentCount < WKD_MEDIA_MAX_COMMENTS) {
                    strncpy_s(Meta->Comments[Meta->CommentCount], 256, tmp, _TRUNCATE);
                    Meta->CommentCount++;
                }
            }
            break;
        }
        case 0x0201:   /* JPEGInterchangeFormat (thumbnail offset) */
            if (IocMedia_ExifU32(r, valOff) > 0) Meta->HasThumbnail = TRUE;
            break;
        case 0x8825:   /* GPS IFD */
            Meta->HasGPS = TRUE;
            break;
        case 0x8769:   /* EXIF sub-IFD */
            IocMedia_ParseExifIfd(r, IocMedia_ExifU32(r, valOff), Meta, Depth + 1);
            break;
        }
    }

    /* ������ (���� SS L1152-1160) */
    {
        SIZE_T nextOff = (SIZE_T)IfdOffset + 2 + (SIZE_T)entryCount * 12;
        if (IocMedia_ExifValid(r, nextOff, 4)) {
            UINT32 nextIfd = IocMedia_ExifU32(r, nextOff);
            if (nextIfd > 0) IocMedia_ParseExifIfd(r, nextIfd, Meta, Depth + 1);
        }
    }
}

/*++
Routine Description:
    JPEG Ԫ������ȡ (���� SS ExtractJPEGMetadata L1162-1231:
    APP1 EXIF / COM ע�� / SOF �ߴ�)��

Arguments:
    Data - JPEG ���塣
    Size - �ֽ�����
    Meta - ���Ԫ���ݡ�
--*/
static VOID
IocMedia_ExtractJpegMetadata(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _Inout_ PWKD_MEDIA_METADATA Meta
    )
{
    SIZE_T pos = 2;

    if (!Data || !Meta || Size < 4) return;
    while (pos + 3 < Size) {
        BYTE marker;
        UINT16 segLen;
        if (Data[pos] != 0xFF) break;
        marker = Data[pos + 1];
        if (marker == 0xDA || marker == 0xD9) break;
        if (marker == 0x00 || (marker >= 0xD0 && marker <= 0xD7)) { pos += 2; continue; }
        if (pos + 3 >= Size) break;
        segLen = IocMedia_U16BE(Data + pos + 2);
        if (segLen < 2 || pos + 2 + segLen > Size) break;

        /* APP1 �� EXIF (���� SS L1184-1204) */
        if (marker == 0xE1 && segLen > 10) {
            const BYTE* seg = Data + pos + 4;
            SIZE_T segDataLen = segLen - 2;
            if (segDataLen > 8 && seg[0] == 'E' && seg[1] == 'x' &&
                seg[2] == 'i' && seg[3] == 'f' && seg[4] == 0 && seg[5] == 0) {
                SIZE_T tiffLen = segDataLen - 6;
                if (tiffLen >= 8) {
                    IOC_MEDIA_EXIF_READER reader;
                    reader.Base = seg;
                    reader.TiffStart = 6;
                    reader.MaxLen = segDataLen;
                    reader.BigEndian = (seg[6] == 'M' && seg[7] == 'M');
                    {
                        UINT32 ifd0 = IocMedia_ExifU32(&reader, 4);
                        if (ifd0 > 0 && ifd0 < tiffLen)
                            IocMedia_ParseExifIfd(&reader, ifd0, Meta, 0);
                    }
                }
            }
        }

        /* COM �� comment (���� SS L1207-1216) */
        if (marker == 0xFE && segLen > 2) {
            SIZE_T cLen = segLen - 2;
            SIZE_T i;
            if (cLen > 4096) cLen = 4096;
            if (Meta->CommentCount < WKD_MEDIA_MAX_COMMENTS) {
                CHAR* dst = Meta->Comments[Meta->CommentCount];
                SIZE_T n = (cLen < 255) ? cLen : 255;
                for (i = 0; i < n; i++) {
                    CHAR c = (CHAR)Data[pos + 4 + i];
                    if (c == '\0' || (UCHAR)c < ' ') break;
                    dst[i] = c;
                }
                dst[i] = '\0';
                if (i > 0) Meta->CommentCount++;
            }
        }

        /* SOF �� dimensions (���� SS L1219-1226) */
        if ((marker >= 0xC0 && marker <= 0xCF) &&
            marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
            if (segLen >= 7) {
                Meta->BitDepth = Data[pos + 4];
                Meta->Height = IocMedia_U16BE(Data + pos + 5);
                Meta->Width  = IocMedia_U16BE(Data + pos + 7);
            }
        }

        pos += 2 + segLen;
    }
}

/* PNG �ı�����ȡ�ص� (tEXt, ���� SS ExtractPNGMetadata L1249-1255) */
static BOOLEAN
IocMedia_PngTextCb(
    _In_ const CHAR* ChunkType,
    _In_ ULONG       ChunkLen,
    _In_ const BYTE* ChunkData,
    _In_ PVOID       Ctx
    )
{
    PWKD_MEDIA_METADATA Meta = (PWKD_MEDIA_METADATA)Ctx;
    if (memcmp(ChunkType, "tEXt", 4) == 0 && ChunkLen > 0 && ChunkLen <= 65535) {
        SIZE_T len = ChunkLen;
        SIZE_T i;
        if (len > 4096) len = 4096;
        if (Meta->CommentCount < WKD_MEDIA_MAX_COMMENTS) {
            CHAR* dst = Meta->Comments[Meta->CommentCount];
            SIZE_T n = (len < 255) ? len : 255;
            for (i = 0; i < n; i++) {
                CHAR c = (CHAR)ChunkData[i];
                if (c == '\0' || (UCHAR)c < ' ') break;
                dst[i] = c;
            }
            dst[i] = '\0';
            if (i > 0) Meta->CommentCount++;
        }
    }
    if (memcmp(ChunkType, "IEND", 4) == 0) return TRUE;
    return FALSE;
}

/*++
Routine Description:
    PNG Ԫ������ȡ (���� SS ExtractPNGMetadata L1233-1263:
    IHDR �ߴ�/λ�� + tEXt ע��)��

Arguments:
    Data - PNG ���塣
    Size - �ֽ�����
    Meta - ���Ԫ���ݡ�
--*/
static VOID
IocMedia_ExtractPngMetadata(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _Inout_ PWKD_MEDIA_METADATA Meta
    )
{
    if (!Data || !Meta || Size < 29) return;
    Meta->Width = IocMedia_U32BE(Data + 16);
    Meta->Height = IocMedia_U32BE(Data + 20);
    Meta->BitDepth = Data[24];
    IocMedia_PngChunkWalk(Data, Size, IocMedia_PngTextCb, Meta);
}

static VOID
IocMedia_ExtractBmpMetadata(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _Inout_ PWKD_MEDIA_METADATA Meta
    )
{
    UINT32 dibSize;

    if (!Data || !Meta || Size < 30) return;
    dibSize = IocMedia_U32LE(Data + 14);
    if (dibSize >= 40) {
        Meta->Width = IocMedia_U32LE(Data + 18);
        {
            INT32 h = (INT32)IocMedia_U32LE(Data + 22);
            Meta->Height = (h < 0) ? (UINT32)-h : (UINT32)h;
        }
        Meta->BitDepth = IocMedia_U16LE(Data + 28);
    }
}

static VOID
IocMedia_ExtractTiffMetadata(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _Inout_ PWKD_MEDIA_METADATA Meta
    )
{
    BOOLEAN le;
    UINT32 ifdOff;
    UINT16 entries;
    UINT16 i;

    if (!Data || !Meta || Size < 8) return;
    le = (Data[0] == 0x49);
    ifdOff = le ? IocMedia_U32LE(Data + 4) : IocMedia_U32BE(Data + 4);
    if (ifdOff + 2 > Size) return;
    entries = le ? IocMedia_U16LE(Data + ifdOff) : IocMedia_U16BE(Data + ifdOff);
    if (entries > 200) return;
    for (i = 0; i < entries; i++) {
        SIZE_T eOff = (SIZE_T)ifdOff + 2 + (SIZE_T)i * 12;
        UINT16 tag, type;
        if (eOff + 12 > Size) break;
        tag = le ? IocMedia_U16LE(Data + eOff) : IocMedia_U16BE(Data + eOff);
        type = le ? IocMedia_U16LE(Data + eOff + 2) : IocMedia_U16BE(Data + eOff + 2);
        switch (tag) {
        case 0x0100:
            Meta->Width = (type == 3) ? (le ? IocMedia_U16LE(Data + eOff + 8) : IocMedia_U16BE(Data + eOff + 8))
                                      : (le ? IocMedia_U32LE(Data + eOff + 8) : IocMedia_U32BE(Data + eOff + 8));
            break;
        case 0x0101:
            Meta->Height = (type == 3) ? (le ? IocMedia_U16LE(Data + eOff + 8) : IocMedia_U16BE(Data + eOff + 8))
                                       : (le ? IocMedia_U32LE(Data + eOff + 8) : IocMedia_U32BE(Data + eOff + 8));
            break;
        case 0x0102:
            Meta->BitDepth = (le ? IocMedia_U16LE(Data + eOff + 8) : IocMedia_U16BE(Data + eOff + 8));
            break;
        }
    }
}

/*++
Routine Description:
    Ԫ������ȡ���� (���� SS ParseMetadata L1017-1033)��

Arguments:
    Data - ý�建�塣
    Size - �ֽ�����
    Type - ý�����͡�
    Meta - ���Ԫ���ݡ�
--*/
static VOID
IocMedia_ParseMetadata(
    _In_ const BYTE*         Data,
    _In_ ULONG               Size,
    _In_ WKD_MEDIA_TYPE      Type,
    _Inout_ PWKD_MEDIA_METADATA Meta
    )
{
    if (!Meta) return;
    RtlZeroMemory(Meta, sizeof(*Meta));
    switch (Type) {
    case WkdMedia_Jpeg: IocMedia_ExtractJpegMetadata(Data, Size, Meta); break;
    case WkdMedia_Png:  IocMedia_ExtractPngMetadata(Data, Size, Meta); break;
    case WkdMedia_Bmp:  IocMedia_ExtractBmpMetadata(Data, Size, Meta); break;
    case WkdMedia_Tiff: IocMedia_ExtractTiffMetadata(Data, Size, Meta); break;
    default: break;
    }
}

/* ==================================================
 * ©��/�����غɼ�� (���� SS DetectExploits L1327-1708)
 *   EmbeddedPe (SS ȫ��Χ����ȱ�ݾ�ƫ����) / Polyglot /
 *   SVG��HTA �ű�ע�� / TIFF ������ / EXIF �������� /
 *   ��չ��ʧ�� (���� IocScan_CheckExtMismatch)
 * ================================================== */

/*++
Routine Description:
    ��ָ���ֽڷ�Χ������ PE (MZ+e_lfanew+ǩ��) / ELF ǩ��
    (���� SS FindEmbeddedExecutable L1378-1411 �ĵ����ж��߼�)��

Arguments:
    Data     - ý�建�塣
    Size     - �ֽ�����
    Start    - ������㡣
    End      - �����յ� (clamp �� Size)��
    OutOffset - �������ƫ�ơ�

Return Value:
    TRUE=���С�
--*/
static BOOLEAN
IocMedia_ScanRangeForPe(
    _In_  const BYTE* Data,
    _In_  ULONG       Size,
    _In_  ULONG       Start,
    _In_  ULONG       End,
    _Out_ PULONG      OutOffset
    )
{
    ULONG i;

    if (End > Size) End = Size;
    if (Start + 4 > End) return FALSE;
    for (i = Start; i + 4 <= End; i++) {
        if (Data[i] == 'M' && Data[i + 1] == 'Z') {
            if ((SIZE_T)i + 0x3F < Size) {   /* SIZE_T �� 32 λ��� */
                UINT32 peOff = IocMedia_U32LE(Data + i + 0x3C);
                if (peOff < 1024 && i + peOff + 4 <= Size &&
                    Data[i + peOff] == 'P' && Data[i + peOff + 1] == 'E' &&
                    Data[i + peOff + 2] == 0 && Data[i + peOff + 3] == 0) {
                    if (OutOffset) *OutOffset = i;
                    return TRUE;
                }
            }
        }
        if (Data[i] == 0x7F && Data[i + 1] == 'E' &&
            Data[i + 2] == 'L' && Data[i + 3] == 'F') {
            if (OutOffset) *OutOffset = i;
            return TRUE;
        }
    }
    return FALSE;
}

/*++
Routine Description:
    ý����Ƕ��ִ���غɼ�� (���� SS FindEmbeddedExecutable L1378-1411)��
    SS ȱ�ݾ�ƫ: ȫ��Χ���ֽ� MZ �����ԺϷ� JPEG ��Դ�� (����ͼ/Ƕ�밲װ��)
    ��; �˴�����������Χ���������� ���� JPEG EOI ��׷���� / PNG IEND ��
    ׷���� + tEXt��zTXt��iTXt �ı��� / BMP ����������ʼ����

Arguments:
    Data     - ý�建�塣
    Size     - �ֽ�����
    Type     - ý�����͡�
    OutOffset - �������ƫ�ơ�

Return Value:
    TRUE=���С�
--*/
static BOOLEAN
IocMedia_FindEmbeddedPe(
    _In_  const BYTE*    Data,
    _In_  ULONG          Size,
    _In_  WKD_MEDIA_TYPE Type,
    _Out_ PULONG         OutOffset
    )
{
    /* JPEG EOI ��׷���� */
    if (Type == WkdMedia_Jpeg) {
        SIZE_T eoi;
        if (IocMedia_FindJpegLastEoi(Data, Size, &eoi) && eoi + 4 <= Size) {
            if (IocMedia_ScanRangeForPe(Data, Size, (ULONG)eoi, Size, OutOffset)) return TRUE;
        }
    }

    /* PNG IEND ��׷���� + �ı��� */
    if (Type == WkdMedia_Png) {
        SIZE_T iendEnd = 0;
        SIZE_T pos = 8;
        while (pos + 12 <= Size) {
            UINT32 chunkLen = IocMedia_U32BE(Data + pos);
            const BYTE* ct;
            if (chunkLen > Size - pos - 12) break;
            ct = Data + pos + 4;
            pos += 12 + chunkLen;
            if (memcmp(ct, "IEND", 4) == 0) { iendEnd = pos; break; }
        }
        if (iendEnd > 0 && iendEnd + 4 <= Size) {
            if (IocMedia_ScanRangeForPe(Data, Size, (ULONG)iendEnd, Size, OutOffset)) return TRUE;
        }
        pos = 8;
        while (pos + 12 <= Size) {
            UINT32 chunkLen = IocMedia_U32BE(Data + pos);
            const BYTE* ct;
            if (chunkLen > Size - pos - 12) break;
            ct = Data + pos + 4;
            if (chunkLen >= 4 &&
                (memcmp(ct, "tEXt", 4) == 0 || memcmp(ct, "zTXt", 4) == 0 ||
                 memcmp(ct, "iTXt", 4) == 0)) {
                if (IocMedia_ScanRangeForPe(Data, Size, pos + 8, pos + 8 + chunkLen, OutOffset)) return TRUE;
            }
            if (memcmp(ct, "IEND", 4) == 0) break;
            pos += 12 + chunkLen;
        }
    }

    /* BMP ���������� (���� SS BMP+PE polyglot L1454-1465 ��������) */
    if (Type == WkdMedia_Bmp && Size >= 0x40) {
        UINT32 dataOff = IocMedia_U32LE(Data + 10);
        if (dataOff + 4 <= Size &&
            IocMedia_ScanRangeForPe(Data, Size, dataOff, Size, OutOffset)) return TRUE;
    }

    return FALSE;
}

/*++
Routine Description:
    Polyglot ��� (���� SS DetectPolyglot L1413-1480:
    JPEG+ZIP / PNG+HTML / BMP+PE / ͨ�� Image+ZIP)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Type   - ý�����͡�
    Result - ý��ɨ������
--*/
static VOID
IocMedia_DetectPolyglot(
    _In_ const BYTE*          Data,
    _In_ ULONG                Size,
    _In_ WKD_MEDIA_TYPE       Type,
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    CHAR desc[128];

    if (Size < 16) return;

    /* JPEG+ZIP: ZIP ǩ���� JPEG EOI �� (���� SS L1419-1428) */
    if (Type == WkdMedia_Jpeg) {
        SIZE_T eoi;
        if (IocMedia_FindJpegLastEoi(Data, Size, &eoi) && eoi + 4 <= Size &&
            Data[eoi] == 'P' && Data[eoi + 1] == 'K' &&
            Data[eoi + 2] == 0x03 && Data[eoi + 3] == 0x04) {
            strcpy_s(desc, sizeof(desc), "JPEG+ZIP polyglot");
            IocMedia_AddThreat(Result, WkdMediaThreat_Polyglot, 8, desc, (ULONG)eoi);
            IocMedia_AddRisk(Result, 40);
            return;
        }
    }

    /* PNG+HTML: IEND �� HTML ��ǩ (���� SS L1431-1451) */
    if (Type == WkdMedia_Png) {
        SIZE_T pos = 8;
        while (pos + 12 <= Size) {
            UINT32 cLen = IocMedia_U32BE(Data + pos);
            const BYTE* ct;
            ULONG tailLen;
            ULONG i;
            if (cLen > Size - pos - 12) break;
            ct = Data + pos + 4;
            pos += 12 + cLen;
            if (memcmp(ct, "IEND", 4) == 0 && pos + 15 < Size) {
                tailLen = Size - (ULONG)pos;
                if (tailLen > 1024) tailLen = 1024;
                for (i = 0; i + 7 <= tailLen; i++) {
                    if (memcmp(Data + pos + i, "<html", 5) == 0 ||
                        memcmp(Data + pos + i, "<HTML", 5) == 0 ||
                        memcmp(Data + pos + i, "<script", 7) == 0) {
                        strcpy_s(desc, sizeof(desc), "PNG+HTML polyglot");
                        IocMedia_AddThreat(Result, WkdMediaThreat_Polyglot, 8, desc, (ULONG)pos);
                        IocMedia_AddRisk(Result, 40);
                        return;
                    }
                }
                break;
            }
        }
    }

    /* BMP+PE: PE ����������ƫ�ƴ� (���� SS L1454-1465) */
    if (Type == WkdMedia_Bmp && Size >= 0x40) {
        UINT32 dataOff = IocMedia_U32LE(Data + 10);
        if (dataOff + 0x40 <= Size && Data[dataOff] == 'M' && Data[dataOff + 1] == 'Z') {
            UINT32 peOff = IocMedia_U32LE(Data + dataOff + 0x3C);
            if (peOff < 1024 && dataOff + peOff + 4 <= Size &&
                Data[dataOff + peOff] == 'P' && Data[dataOff + peOff + 1] == 'E') {
                strcpy_s(desc, sizeof(desc), "BMP+PE polyglot");
                IocMedia_AddThreat(Result, WkdMediaThreat_Polyglot, 8, desc, dataOff);
                IocMedia_AddRisk(Result, 40);
                return;
            }
        }
    }

    /* ͨ��: ������� ZIP (���� SS L1467-1478) */
    if (Type != WkdMedia_Unknown && Size > 32) {
        ULONG half = Size / 2;
        ULONG i;
        for (i = (half > 16) ? half : 16; i + 4 <= Size; i++) {
            if (Data[i] == 'P' && Data[i + 1] == 'K' &&
                Data[i + 2] == 0x03 && Data[i + 3] == 0x04) {
                snprintf(desc, sizeof(desc), "Image+ZIP polyglot (ZIP at offset %lu)", i);
                IocMedia_AddThreat(Result, WkdMediaThreat_Polyglot, 8, desc, i);
                IocMedia_AddRisk(Result, 40);
                return;
            }
        }
    }
}

/*++
Routine Description:
    SVG JavaScript �¼������� / HTA αװ��� (���� SS DetectScriptInjection
    L1482-1559; �ı����ж�ǰ������ IocScan_IsTextContent ����)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Result - ý��ɨ������
--*/
static VOID
IocMedia_DetectScriptInjection(
    _In_ const BYTE*          Data,
    _In_ ULONG                Size,
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    static const char* scriptPatterns[] = {
        "<script", "javascript:", "onload=", "onerror=",
        "onmouseover=", "onclick=", "onfocus=", "eval(",
        "document.cookie", "XMLHttpRequest", "fetch(",
        "String.fromCharCode"
    };
    CHAR content[32768];
    ULONG cLen;
    BOOLEAN isSvg;
    ULONG i;

    if (Size < 5) return;

    /* �ı������ж� (���� SS L1487-1498: ǰ 256 �ֽڿɴ�ӡ) */
    {
        ULONG checkLen = (Size < 256) ? Size : 256;
        for (i = 0; i < checkLen; i++) {
            BYTE c = Data[i];
            if (c < 0x09 || (c > 0x0D && c < 0x20 && c != 0x1B)) return;
        }
    }

    cLen = (Size < sizeof(content) - 1) ? Size : (ULONG)(sizeof(content) - 1);
    memcpy(content, Data, cLen);
    content[cLen] = '\0';

    /* SVG ��Ƕ JS (���� SS L1505-1529) */
    isSvg = (strstr(content, "<svg") != NULL || strstr(content, "<SVG") != NULL);
    if (isSvg) {
        for (i = 0; i < RTL_NUMBER_OF(scriptPatterns); i++) {
            if (strstr(content, scriptPatterns[i]) != NULL) {
                IocMedia_AddThreat(Result, WkdMediaThreat_ScriptInjection, 9,
                                   "SVG with embedded JavaScript/event handlers", 0);
                IocMedia_AddRisk(Result, 50);
                return;
            }
        }
    }

    /* HTA αװ (���� SS L1545-1558, mshta ����Լ��������) */
    if (strstr(content, "<HTA:APPLICATION") != NULL ||
        strstr(content, "<hta:application") != NULL ||
        strstr(content, "mshta.exe") != NULL || strstr(content, "mshta ") != NULL ||
        strstr(content, "mshta\t") != NULL || strstr(content, "mshta\"") != NULL ||
        strstr(content, "mshta'") != NULL || strstr(content, "mshta:") != NULL ||
        strstr(content, "mshta\\") != NULL) {
        IocMedia_AddThreat(Result, WkdMediaThreat_ScriptInjection, 10,
                           "HTA application disguised as media file", 0);
        IocMedia_AddRisk(Result, 50);
    }
}

/*++
Routine Description:
    TIFF IFD ��������� (���� SS DetectTiffAttacks L1594-1667:
    ѭ�� IFD �� DoS / Խ��ֵ���� BufferOverflow)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Result - ý��ɨ������
--*/
static VOID
IocMedia_DetectTiffAttacks(
    _In_ const BYTE*          Data,
    _In_ ULONG                Size,
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    static const SIZE_T ts[] = { 0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8 };
    BOOLEAN le;
    UINT32 cur;
    INT depth = 0;
    UINT32 visited[16];
    ULONG visitedCount = 0;

    if (Size < 8) return;
    le = (Data[0] == 0x49);
    cur = le ? IocMedia_U32LE(Data + 4) : IocMedia_U32BE(Data + 4);

    while (cur != 0 && depth < 8) {
        UINT16 n;
        SIZE_T nextOff;
        ULONG v;
        BOOLEAN circular = FALSE;

        for (v = 0; v < visitedCount; v++) {
            if (visited[v] == cur) { circular = TRUE; break; }
        }
        if (circular) {
            IocMedia_AddThreat(Result, WkdMediaThreat_CveExploit, 8,
                               "TIFF: circular IFD chain (DoS/exploit attempt)", cur);
            IocMedia_AddRisk(Result, 40);
            return;
        }
        if (visitedCount < RTL_NUMBER_OF(visited)) visited[visitedCount++] = cur;

        if ((SIZE_T)cur + 2 > Size) break;   /* SIZE_T �� 32 λ UINT32 ��� */
        n = le ? IocMedia_U16LE(Data + cur) : IocMedia_U16BE(Data + cur);
        if (n > 200) break;

        {
            UINT16 i;
            for (i = 0; i < n; i++) {
                SIZE_T eOff = (SIZE_T)cur + 2 + (SIZE_T)i * 12;
                UINT16 type;
                UINT32 count;
                if (eOff + 12 > Size) break;
                type = le ? IocMedia_U16LE(Data + eOff + 2) : IocMedia_U16BE(Data + eOff + 2);
                count = le ? IocMedia_U32LE(Data + eOff + 4) : IocMedia_U32BE(Data + eOff + 4);
                if (type > 0 && type <= 12) {
                    SIZE_T valSize = (SIZE_T)count * ts[type];
                    if (valSize > 4) {
                        UINT32 valOff = le ? IocMedia_U32LE(Data + eOff + 8) : IocMedia_U32BE(Data + eOff + 8);
                        if ((SIZE_T)valOff + valSize > Size) {
                            CHAR d[128];
                            snprintf(d, sizeof(d),
                                     "TIFF: IFD entry points outside file (offset %u + %zu bytes)",
                                     valOff, valSize);
                            IocMedia_AddThreat(Result, WkdMediaThreat_BufferOverflow, 7, d, (ULONG)eOff);
                            IocMedia_AddRisk(Result, 30);
                        }
                    }
                }
            }
        }

        nextOff = (SIZE_T)cur + 2 + (SIZE_T)n * 12;
        if (nextOff + 4 > Size) break;
        cur = le ? IocMedia_U32LE(Data + nextOff) : IocMedia_U32BE(Data + nextOff);
        ++depth;
    }
}

/*++
Routine Description:
    EXIF/Ԫ����ע�Ͷ���ģʽ��� (���� SS DetectMaliciousExif L1561-1592:
    ����/�ű�ģʽ������Ԫ����ע����)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Result - ý��ɨ������
--*/
static VOID
IocMedia_DetectMaliciousExif(
    _In_ const BYTE*          Data,
    _In_ ULONG                Size,
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    static const char* malPatterns[] = {
        "cmd.exe", "powershell", "cmd /c", "/bin/sh", "/bin/bash",
        "wget ", "curl ", "certutil", "bitsadmin",
        "<?php", "eval(", "exec(", "system(",
        "<script", "javascript:", "vbscript:",
        "base64_decode", "gzinflate",
        "rundll32", "regsvr32", "mshta",
        "WScript.Shell", "ActiveXObject"
    };
    ULONG c;
    ULONG p;

    (void)Data; (void)Size;
    if (Result->Metadata.CommentCount == 0) return;
    for (c = 0; c < Result->Metadata.CommentCount; c++) {
        for (p = 0; p < RTL_NUMBER_OF(malPatterns); p++) {
            if (strstr(Result->Metadata.Comments[c], malPatterns[p]) != NULL) {
                CHAR d[128];
                snprintf(d, sizeof(d), "Malicious content in metadata: '%s' pattern", malPatterns[p]);
                IocMedia_AddThreat(Result, WkdMediaThreat_ScriptInjection, 9, d, 0);
                IocMedia_AddRisk(Result, 45);
                return;
            }
        }
    }
}

/*++
Routine Description:
    ©��/�����غɼ����� (���� SS DetectExploits L1327-1376)��
    ��չ��ʧ�临�� CoDetermineFileTypeFromBuffer + IocScan_CheckExtMismatch
    (wkd �ļ�����ʶ���Ѹ���, ���ظ�ʵ��)��

Arguments:
    Data     - ý�建�塣
    Size     - �ֽ�����
    FilePath - �ļ�·�� (��չ��ʧ���ж���)��
    Result   - ý��ɨ������
--*/
static VOID
IocMedia_DetectExploits(
    _In_ const BYTE*          Data,
    _In_ ULONG                Size,
    _In_opt_ PCWSTR           FilePath,
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    ULONG off;

    /* MalformedHeader (���� SS L1331-1338) */
    if (!Result->IsValid) {
        IocMedia_AddThreat(Result, WkdMediaThreat_MalformedHeader, 6,
                           "Malformed media header detected", 0);
        IocMedia_AddRisk(Result, 30);
    }

    /* EmbeddedExecutable (���� SS L1340-1351) */
    if (IocMedia_FindEmbeddedPe(Data, Size, Result->MediaType, &off)) {
        CHAR d[128];
        snprintf(d, sizeof(d), "Embedded executable at offset %lu", off);
        IocMedia_AddThreat(Result, WkdMediaThreat_EmbeddedExecutable, 9, d, off);
        IocMedia_AddRisk(Result, 50);
        Result->Verdict = 2;   /* SS: isMalicious ֱ�� */
    }

    /* Polyglot (���� SS L1353-1362) */
    IocMedia_DetectPolyglot(Data, Size, Result->MediaType, Result);

    /* ScriptInjection (���� SS L1364) */
    IocMedia_DetectScriptInjection(Data, Size, Result);

    /* TIFF ������ (���� SS L1366-1367) */
    if (Result->MediaType == WkdMedia_Tiff) {
        IocMedia_DetectTiffAttacks(Data, Size, Result);
    }

    /* EXIF �������� (���� SS L1369) */
    IocMedia_DetectMaliciousExif(Data, Size, Result);

    /* ��չ��ʧ�� (���� SS DetectExtensionMismatch L1669-1708, ���� wkd ʵ��) */
    if (FilePath) {
        WKD_FILE_TYPE_INFO fti;
        PCWSTR dot = wcsrchr(FilePath, L'.');
        if (dot && dot != FilePath &&
            NT_SUCCESS(CoDetermineFileTypeFromBuffer(Data, Size, dot, &fti)) &&
            IocScan_CheckExtMismatch(&fti)) {
            CHAR d[128];
            snprintf(d, sizeof(d), "Extension mismatch: claims %ls but magic indicates %s",
                     fti.DiskExtension, IocMedia_MediaTypeToString(Result->MediaType));
            IocMedia_AddThreat(Result, WkdMediaThreat_MalformedHeader, 7, d, 0);
            IocMedia_AddRisk(Result, 25);
        }
    }
}

/* ==================================================
 * ׷�����ݷ��� (���� SS AnalyzeAppendedData L1714-1786)
 *   JPEG EOI / PNG IEND ��׷���� �� �鵵ǩ��
 * ================================================== */

/*++
Routine Description:
    �鵵ǩ���ж� (���� SS IsArchiveSignature L1770-1786: ZIP/RAR/7z/GZIP)��

Arguments:
    p    - ������ʼ��
    Size - �����ֽ�����

Return Value:
    TRUE=�鵵ǩ����
--*/
static BOOLEAN
IocMedia_IsArchiveSignature(
    _In_ const BYTE* p,
    _In_ ULONG       Size
    )
{
    if (Size < 4) return FALSE;
    if (p[0] == 'P' && p[1] == 'K' && p[2] == 0x03 && p[3] == 0x04) return TRUE;
    if (Size >= 7 && p[0] == 'R' && p[1] == 'a' && p[2] == 'r' && p[3] == '!') return TRUE;
    if (Size >= 6 && p[0] == '7' && p[1] == 'z' && p[2] == 0xBC && p[3] == 0xAF) return TRUE;
    if (p[0] == 0x1F && p[1] == 0x8B) return TRUE;
    return FALSE;
}

/*++
Routine Description:
    ׷�����ݷ��� (���� SS AnalyzeAppendedData L1714-1768:
    ���ݽ��� (JPEG EOI / PNG IEND) ����� >16 �ֽ�׷���� �� �鵵��в)��

Arguments:
    Data   - ý�建�塣
    Size   - �ֽ�����
    Result - ý��ɨ������
--*/
static VOID
IocMedia_AnalyzeAppendedData(
    _In_ const BYTE*          Data,
    _In_ ULONG                Size,
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    SIZE_T endOfContent = 0;
    BOOLEAN hasEnd = FALSE;
    ULONG appSize;

    if (Result->MediaType == WkdMedia_Jpeg) {
        if (IocMedia_FindJpegLastEoi(Data, Size, &endOfContent)) hasEnd = TRUE;
    } else if (Result->MediaType == WkdMedia_Png) {
        SIZE_T pos = 8;
        while (pos + 12 <= Size) {
            UINT32 cLen = IocMedia_U32BE(Data + pos);
            const BYTE* ct;
            if (cLen > Size - pos - 12) break;
            ct = Data + pos + 4;
            pos += 12 + cLen;
            if (memcmp(ct, "IEND", 4) == 0) { endOfContent = pos; hasEnd = TRUE; break; }
        }
    }

    if (!hasEnd || endOfContent >= Size) return;
    appSize = Size - (ULONG)endOfContent;
    if (appSize <= 16) return;   /* MIN_APPENDED_THRESHOLD */

    Result->HasAppendedData = TRUE;
    Result->AppendedDataSize = appSize;

    if (IocMedia_IsArchiveSignature(Data + endOfContent, appSize)) {
        CHAR d[128];
        snprintf(d, sizeof(d), "Appended archive (%lu bytes)", appSize);
        IocMedia_AddThreat(Result, WkdMediaThreat_AppendedArchive, 8, d, (ULONG)endOfContent);
        IocMedia_AddRisk(Result, 35);
    }
}

/* ==================================================
 * ������ϲ�ӳ�� (���� SS L697-701 + ResultToIocScan)
 * ================================================== */

/*++
Routine Description:
    �ж����� (���� SS ScanImpl L697-701: riskScore>=80 Malicious /
    >=40 Suspicious; EmbeddedExecutable ��ֱ�� Verdict=2 ����; stego �� Suspicious)��

Arguments:
    Result - ý��ɨ������
--*/
static VOID
IocMedia_CalculateVerdict(
    _Inout_ PWKD_MEDIA_SCAN_RESULT Result
    )
{
    if (Result->Verdict < 2 && Result->RiskScore >= 80) Result->Verdict = 2;
    else if (Result->Verdict < 1 && Result->RiskScore >= 40) Result->Verdict = 1;
    if (Result->Verdict < 1 && Result->Stego.StegoDetected) Result->Verdict = 1;
}

/* ==================================================
 * ������� (���� SS ScanImpl L626-730 + ���� API L1792-1856)
 * ================================================== */

/*++
Routine Description:
    ý��ɨ����ʵ�� (���� SS ScanImpl L626-730):
    ����(100MB cap, ���� header-only ����) �� �����ж� �� ��ʽ��֤ ��
    Ԫ���� �� ��д(����������) �� ©���غ� �� ׷������(����������) �� �ж���

Arguments:
    FilePath - �ļ�·����
    Result   - ���ý��ɨ���� (���÷��ѷ���)��

Return Value:
    NTSTATUS��
--*/
static NTSTATUS
IocMedia_ScanFileImpl(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_MEDIA_SCAN_RESULT   Result
    )
{
    BYTE* data = NULL;
    ULONG size = 0;
    NTSTATUS status;
    BOOLEAN fullData = FALSE;
    WKD_FILE_TYPE_INFO fti;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    /* ����, ���޻��� header-only (���� SS L645-656) */
    status = IocMedia_ReadFileCapped(FilePath, &data, &size);
    if (NT_SUCCESS(status) && data && size > 0) {
        fullData = TRUE;
        Result->FileSize = size;
    } else {
        ULONG64 fileSize = 0;
        BYTE* header = NULL;
        ULONG headerLen = 0;
        if (!CoReadFileHeader(FilePath, &fileSize, &header, &headerLen) ||
            !header || headerLen == 0) {
            if (header) free(header);
            return STATUS_UNSUCCESSFUL;
        }
        data = header;
        size = headerLen;
        Result->FileSize = fileSize;
    }
    if (size == 0) {
        if (data) free(data);
        return STATUS_SUCCESS;
    }

    /* �����ж� (�����ļ�����ʶ��ħ����) */
    if (NT_SUCCESS(CoDetermineFileTypeFromBuffer(data, size, NULL, &fti))) {
        Result->MediaType = IocMedia_FormatToMediaType(fti.Format);
    }

    /* ��ʽ��֤ */
    Result->IsValid = IocMedia_ValidateFormat(data, size, Result->MediaType);

    /* Ԫ���� */
    IocMedia_ParseMetadata(data, size, Result->MediaType, &Result->Metadata);

    /* ��д (����������) */
    if (fullData) {
        IocMedia_AnalyzeSteganography(data, size, Result->MediaType, &Result->Stego);
        if (Result->Stego.StegoDetected) {
            CHAR d[128];
            snprintf(d, sizeof(d), "Steganography detected: %s",
                     IocMedia_StegoTechniqueToString(Result->Stego.Technique));
            IocMedia_AddRisk(Result, 40);
            IocMedia_AddThreat(Result, WkdMediaThreat_Steganography, 7, d, 0);
        }
    }

    /* ©��/�����غ� */
    IocMedia_DetectExploits(data, size, FilePath, Result);

    /* ׷������ (����������) */
    if (fullData) {
        IocMedia_AnalyzeAppendedData(data, size, Result);
    }

    /* �ж� */
    IocMedia_CalculateVerdict(Result);

    if (data) free(data);
    return STATUS_SUCCESS;
}

NTSTATUS
IocMedia_ScanFile(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_MEDIA_SCAN_RESULT   Result
    )
/*++
Routine Description:
    ý���ļ���ȫ��������� (���� SS MediaFileScanner::Scan)��
    ������ȫ��, ���ߵ�� ScanManager.ScanFileDirect ���ߡ�

Arguments:
    FilePath - �ļ�·����
    Result   - ��� WKD_MEDIA_SCAN_RESULT (~3.5KB, ���÷���ѷ���)��

Return Value:
    NTSTATUS��
--*/
{
    return IocMedia_ScanFileImpl(FilePath, Result);
}

NTSTATUS
IocMedia_ResultToIocScan(
    _In_  PWKD_MEDIA_SCAN_RESULT  Media,
    _Inout_ PIOC_SCAN_RESULT      Ioc
    )
/*++
Routine Description:
    ý��ɨ�����ϲ��� IOC_SCAN_RESULT (���� IocDocument_ResultToIocScan):
    �� HeuristicConfidence ͨ������ IocScan_Aggregate ��ֵ
    (RiskScore��10: 80��800��700 Malicious / 40��400��300 Suspicious),
    ���׸��� None ��вд ThreatName "Media.*"��

Arguments:
    Media - ý��ɨ���� (IocMedia_ScanFile ���)��
    Ioc   - IOC ɨ���� (�ϲ�Ŀ��)��

Return Value:
    STATUS_SUCCESS��
--*/
{
    static const struct {
        WKD_MEDIA_THREAT_TYPE Type;
        PCSTR                 Name;
    } nameMap[] = {
        { WkdMediaThreat_Steganography,      "Media.Stego" },
        { WkdMediaThreat_MalformedHeader,    "Media.MalformedHeader" },
        { WkdMediaThreat_BufferOverflow,     "Media.BufferOverflow" },
        { WkdMediaThreat_EmbeddedExecutable, "Media.EmbeddedPe" },
        { WkdMediaThreat_AppendedArchive,    "Media.AppendedArchive" },
        { WkdMediaThreat_Polyglot,           "Media.Polyglot" },
        { WkdMediaThreat_ScriptInjection,    "Media.ScriptInjection" },
        { WkdMediaThreat_CveExploit,         "Media.TiffChain" },
    };
    ULONG i;

    if (!Media || !Ioc) return STATUS_INVALID_PARAMETER;
    if (Media->RiskScore == 0 && Media->ThreatCount == 0) return STATUS_SUCCESS;

    Ioc->HeuristicRan = TRUE;
    if (Media->RiskScore * 10 > Ioc->HeuristicConfidence) {
        Ioc->HeuristicConfidence = Media->RiskScore * 10;
    }
    Ioc->EvidenceCount += Media->ThreatCount;
    if (Media->Stego.StegoDetected) Ioc->EvidenceCount += 1;

    if (Ioc->ThreatName[0] == '\0') {
        ULONG tc = (Media->ThreatCount < WKD_MEDIA_MAX_THREATS) ? Media->ThreatCount : WKD_MEDIA_MAX_THREATS;
        for (i = 0; i < tc; i++) {
            ULONG m;
            for (m = 0; m < RTL_NUMBER_OF(nameMap); m++) {
                if (Media->Threats[i].Type == nameMap[m].Type) {
                    strncpy_s(Ioc->ThreatName, sizeof(Ioc->ThreatName), nameMap[m].Name, _TRUNCATE);
                    return STATUS_SUCCESS;
                }
            }
        }
    }
    return STATUS_SUCCESS;
}

/*-- �����뵼�� (SS ���� API, ������ȫ��; ����ˮ�ߵ������಻�澯) --*/

NTSTATUS
IocMedia_DetectSteganography(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_STEGO_ANALYSIS      Result
    )
/*++
Routine Description:
    ��д��������� (���� SS DetectSteganography L1917-1925)��
    ������: ������ȫ��, �������ѷ�������

Arguments:
    FilePath - �ļ�·����
    Result   - �����д������

Return Value:
    NTSTATUS��
--*/
{
    BYTE* data = NULL;
    ULONG size = 0;
    WKD_MEDIA_TYPE type;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    if (!NT_SUCCESS(IocMedia_ReadFileCapped(FilePath, &data, &size)) || !data || size == 0) {
        if (data) free(data);
        return STATUS_UNSUCCESSFUL;
    }
    type = IocMedia_DetectMediaTypeFromData(data, size);
    IocMedia_AnalyzeSteganography(data, size, type, Result);
    free(data);
    return STATUS_SUCCESS;
}

NTSTATUS
IocMedia_ExtractMetadata(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_MEDIA_METADATA      Result
    )
/*++
Routine Description:
    Ԫ������ȡ������� (���� SS ExtractMetadata L1927-1935)��
    ������: ������ȫ��, �������ѷ�������

Arguments:
    FilePath - �ļ�·����
    Result   - ���Ԫ���ݡ�

Return Value:
    NTSTATUS��
--*/
{
    BYTE* data = NULL;
    ULONG size = 0;
    WKD_MEDIA_TYPE type;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    if (!NT_SUCCESS(IocMedia_ReadFileCapped(FilePath, &data, &size)) || !data || size == 0) {
        if (data) free(data);
        return STATUS_UNSUCCESSFUL;
    }
    type = IocMedia_DetectMediaTypeFromData(data, size);
    IocMedia_ParseMetadata(data, size, type, Result);
    free(data);
    return STATUS_SUCCESS;
}

BOOLEAN
IocMedia_HasAppendedData(
    _In_ PCWSTR FilePath
    )
/*++
Routine Description:
    �Ƿ�׷������ (���� SS HasAppendedData L1937-1944, ��ǰ�� JPEG)��
    ������: ������ȫ��, �������ѷ�������

Arguments:
    FilePath - �ļ�·����

Return Value:
    TRUE=����׷�����ݡ�
--*/
{
    BYTE* data = NULL;
    ULONG size = 0;
    WKD_MEDIA_TYPE type;
    SIZE_T eoi;
    BOOLEAN result = FALSE;

    if (!FilePath) return FALSE;
    if (!NT_SUCCESS(IocMedia_ReadFileCapped(FilePath, &data, &size)) || !data || size == 0) {
        if (data) free(data);
        return FALSE;
    }
    type = IocMedia_DetectMediaTypeFromData(data, size);
    if (type == WkdMedia_Jpeg && IocMedia_FindJpegLastEoi(data, size, &eoi) && eoi < size) {
        result = (size - (ULONG)eoi) > 16;
    }
    free(data);
    return result;
}

NTSTATUS
IocMedia_ExtractAppendedData(
    _In_  PCWSTR    FilePath,
    _Out_ BYTE**    OutBuf,
    _Out_ PULONG    OutLen
    )
/*++
Routine Description:
    ��ȡ׷������ (���� SS ExtractAppendedData L1946-1953, ��ǰ�� JPEG;
    cap 10MB)��*OutBuf Ϊ malloc �ѻ���, ���÷� free��
    ������: ������ȫ��, �������ѷ�������

Arguments:
    FilePath - �ļ�·����
    OutBuf   - ����ѻ��� (���÷� free)��
    OutLen   - ����ֽ�����

Return Value:
    NTSTATUS��
--*/
{
    BYTE* data = NULL;
    ULONG size = 0;
    WKD_MEDIA_TYPE type;
    SIZE_T eoi;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!FilePath || !OutBuf || !OutLen) return STATUS_INVALID_PARAMETER;
    *OutBuf = NULL;
    *OutLen = 0;
    if (!NT_SUCCESS(IocMedia_ReadFileCapped(FilePath, &data, &size)) || !data || size == 0) {
        if (data) free(data);
        return STATUS_UNSUCCESSFUL;
    }
    type = IocMedia_DetectMediaTypeFromData(data, size);
    if (type == WkdMedia_Jpeg && IocMedia_FindJpegLastEoi(data, size, &eoi) && eoi < size) {
        ULONG app = size - (ULONG)eoi;
        if (app > 16) {
            ULONG cap = (app < WKD_MEDIA_MAX_APPENDED) ? app : WKD_MEDIA_MAX_APPENDED;
            *OutBuf = (BYTE*)malloc(cap);
            if (*OutBuf) {
                memcpy(*OutBuf, data + eoi, cap);
                *OutLen = cap;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NO_MEMORY;
            }
        }
    }
    free(data);
    return status;
}

/* ==================================================
 * MEDIA_SELFTEST (�� IocDocumentScanner DOC_SELFTEST,
 *  ��������: cl /D MEDIA_SELFTEST IocScanner.c ...)
 * ================================================== */
#ifdef MEDIA_SELFTEST

#include <assert.h>

int
main(
    VOID
    )
{
    printf("MEDIA_SELFTEST (buffered checks)\n");

    /* ���弶��ʽ��֤ */
    {
        /* SOI + DQT(segLen=4) + SOS(segLen=2) + EOI �� �ṹ�Ϸ� */
        BYTE jpeg[] = { 0xFF,0xD8, 0xFF,0xDB,0x00,0x04,0x00,0x00,
                        0xFF,0xDA,0x00,0x02,0x00, 0xFF,0xD9 };
        assert(IocMedia_ValidateFormat(jpeg, sizeof(jpeg), WkdMedia_Jpeg) == TRUE);
    }
    {
        BYTE png[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                       0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
                       0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                       0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77 };
        assert(IocMedia_ValidateFormat(png, sizeof(png), WkdMedia_Png) == TRUE);
    }
    /* BMP: dataOffset Խ�� �� MalformedHeader ��֤ */
    {
        BYTE bmp[] = { 0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x28, 0x00,
                       0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
                       0x00, 0x00, 0x01, 0x00 };
        assert(IocMedia_ValidateFormat(bmp, sizeof(bmp), WkdMedia_Bmp) == FALSE);
    }
    /* �鵵ǩ�� */
    {
        BYTE zip[] = { 'P', 'K', 0x03, 0x04, 0x00, 0x00 };
        assert(IocMedia_IsArchiveSignature(zip, sizeof(zip)) == TRUE);
    }
    /* JPEG EOI ���� */
    {
        BYTE jpeg[] = { 0xFF, 0xD8, 0xFF, 0xD9, 0x00, 0x01, 0x02 };
        SIZE_T eoi;
        assert(IocMedia_FindJpegLastEoi(jpeg, sizeof(jpeg), &eoi) == TRUE);
        assert(eoi == 4);
    }
    /* EOF ��д (JPEG EOI ��׷�� >16 �ֽ�) */
    {
        BYTE data[] = { 0xFF,0xD8, 0xFF,0xDB,0x00,0x02,0x00,
                        0xFF,0xD9,
                        'P','K',0x03,0x04, 0x00,0x00,0x00,0x00, 0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
        WKD_STEGO_ANALYSIS stego;
        memset(&stego, 0, sizeof(stego));
        IocMedia_DetectEofStego(data, sizeof(data), WkdMedia_Jpeg, &stego);
        assert(stego.StegoDetected == TRUE);
        assert(stego.Technique == WkdStego_EofAppended);
    }
    /* PNG �ı���Ԫ���� */
    {
        BYTE png[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                       0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
                       0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                       0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77,
                       0x00, 0x00, 0x00, 0x0A, 't', 'E', 'X', 't',
                       'p', 'o', 'w', 'e', 'r', 's', 'h', 'e', 'l', 'l',
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        WKD_MEDIA_METADATA meta;
        memset(&meta, 0, sizeof(meta));
        IocMedia_ExtractPngMetadata(png, sizeof(png), &meta);
        assert(meta.CommentCount >= 1);
        assert(strstr(meta.Comments[0], "powershell") != NULL);
    }

    printf("MEDIA_SELFTEST PASSED\n");
    return 0;
}

#endif /* MEDIA_SELFTEST */

NTSTATUS
IocScanner_QueryHash(
    _In_  PDEF_SHA256_HASH Hash,
    _Out_ PBOOLEAN         FoundMalicious
    )
/*++
Routine Description:
    ��ѯ��ϣ�Ƿ����� ioc_hashes ����⡣������װ��������/�ⲿ���á�

Arguments:
    Hash           - �ļ� SHA256��
    FoundMalicious - ����Ƿ����ж����ж���

Return Value:
    NTSTATUS��
--*/
{
    IOC_SCAN_RESULT r;

    if (!Hash || !FoundMalicious) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&r, sizeof(r));
    IocScan_HashQuery(Hash, &r);
    *FoundMalicious = (r.HashChecked && r.HashVerdict == DefIocVerdict_Malicious);

    return STATUS_SUCCESS;
}

NTSTATUS
IocScanner_ScanFileWithHint(
    _In_    PCWSTR              FilePath,
    _In_opt_ const PE_INFO*    PeInfo,
    _Out_   IOC_SCAN_RESULT*    Result
    )
/*++
Routine Description:
    ���ļ�ִ������ IOC ��̬ɨ�衣

Arguments:
    FilePath �� �ļ�����·����
    Result   �� ���ɨ������

Return Value:
    NTSTATUS��
--*/
{
    PCWSTR fileName;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    /* ��ȡ�ļ��� */
    fileName = wcsrchr(FilePath, L'\\');
    fileName = fileName ? fileName + 1 : FilePath;

    
    IocHeuristicPeAnalysis(FilePath, PeInfo, Result);

    /* ǩ�� APT ���� (SS DSV AnalyzeSignature Ǩ��, 2026-08-09, �ſ�
     * g_IoaSignatureHuntingEnabled): 9 ��ǩ���쳣 �� RiskScore �� Aggregate �ж���
     * CertVerify �����֤������ (��Ч��/IsSelfSigned/��ָ��/WHQL)�� */
    if (g_IoaSignatureHuntingEnabled) {
        IoaSigHunt_AnalyzeSignature(FilePath, Result, &Result->SignatureHunt);
    }

    IocScan_Aggregate(Result);

    /* �������� (SS FileReputation Ǩ��): ��� Reputation �ֶ�, ���� FinalVerdict */
    IocScan_ReputationScore(Result);

    printf("[IocScanner] File scan: %S �� verdict=%d conf=%lu\n",
           FilePath, Result->FinalVerdict, Result->FinalConfidence);
    return STATUS_SUCCESS;
}

NTSTATUS
IocScanner_ScanFile(
    _In_    PCWSTR              FilePath,
    _Out_   IOC_SCAN_RESULT*    Result
    )
/*++
Routine Description:
    文件静态 IOC 扫描（无 PE_INFO 提示，内部以 NULL 传递）。
    需传递构建期 PE_INFO 几何以复用解析的调用方请用
    IocScanner_ScanFileWithHint（ImageAnalyzer 深度流水线）。
--*/
{
    return IocScanner_ScanFileWithHint(FilePath, NULL, Result);
}

NTSTATUS
IocScanner_ScanCmdline(
    _In_    PCWSTR              CmdLine,
    _Out_   IOC_SCAN_RESULT*    Result
    )
/*++
Routine Description:
    ���������ַ���ִ�� IOC ģʽƥ�䡣

Arguments:
    CmdLine �� �������ַ�����
    Result  �� ���ɨ������

Return Value:
    NTSTATUS��
--*/
{
    if (!Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    if (CmdLine && CmdLine[0]) {
        IocScan_Cmdline(CmdLine, Result);
        IocScan_Aggregate(Result);

        /* �������� (SS FileReputation Ǩ��): ��� Reputation �ֶ� */
        IocScan_ReputationScore(Result);
    }
    return STATUS_SUCCESS;
}

/*  IocScanner_ScanProcess ��ɾ����2026-08-15��ImageAnalyzer ͳһ��ˮ�߻�����
 *  ���̽ڵ㾲̬���������� IOC/ImageAnalyzer/ImageAnalyzer(exePath, cmdline, &r)
 *  ��IocEngine.c IocObserveProcess ���ã���ԭ��ϣ��ѯ/Cmdline/�������߼���
 *  ImageAnalyzer Tier1/Tier2/Tier3 �е���ģ�鼶������ WKD_MODULE ΪȨ�������� */


/**************************************************/
/*       �ڹ�ϣ / �ӳٵ������ (������, ���� SS)      */
/**************************************************/

BOOLEAN
IocScan_ComputeSectionHashes(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ IOC_SECTION_HASH*       Hashes,
    _In_  ULONG                   MaxHashes,
    _Out_ PULONG                  Count
    )
/*++
Routine Description:
    ��ڼ��� SHA256 (���� SS ComputeSectionHashes/ParseSections �ڹ�ϣ)��
    ������: wkd �� section-hash ��¡���ѷ� (�ع����� #20 �ж�), ��δ����ɱ/����Ԥ����
    �� DoS: ���ڹ�ϣ ��16MB �ſء�

Arguments:
    Ctx      - ���������� (Reader ��������)��
    Hashes   - ����ڹ�ϣ���顣
    MaxHashes- ����������
    Count    - �����Ч��ϣ����

Return Value:
    TRUE=����һ���ڹ�ϣ�ɹ���
--*/
{
    ULONG i;

    if (Ctx == NULL || !Ctx->Parsed || Hashes == NULL || Count == NULL) {
        if (Count) *Count = 0;
        return FALSE;
    }
    *Count = 0;

    for (i = 0; i < Ctx->Info.NumberOfSections && *Count < MaxHashes; i++) {
        const PE_SECTION* sec = &Ctx->Info.Sections[i];
        DEF_SHA256_HASH hash;

        if (sec->SizeOfRawData == 0 || sec->PointerToRawData == 0) continue;

        {
            SIZE_T dataLen = sec->SizeOfRawData;
            if (dataLen > (16u * 1024 * 1024)) dataLen = 16u * 1024 * 1024;
            if (dataLen >= 1) {
                BYTE* buf = (BYTE*)malloc(dataLen);
                if (buf) {
                    if (WpeReadBytesAtOffset(Ctx, sec->PointerToRawData, buf, dataLen) &&
                        IocScanner_ComputeBufferSha256(buf, (ULONG)dataLen, &hash)) {
                        IOC_SECTION_HASH* out = &Hashes[*Count];
                        RtlZeroMemory(out, sizeof(*out));
                        strncpy_s(out->Name, sizeof(out->Name), sec->Name, _TRUNCATE);
                        memcpy(out->Sha256, hash.Data, sizeof(out->Sha256));
                        out->HasSha256 = TRUE;
                        (*Count)++;
                    }
                    free(buf);
                }
            }
        }
    }
    return (*Count > 0);
}


/**************************************************/
/*    FileHasher �������� (SS FileHasher.cpp)       */
/*  ������: �����渲��, δ������ˮ��               */
/*  ��ע: ���� SS <file>:<line>, <������ԭ��>       */
/**************************************************/

#pragma warning(push)
#pragma warning(disable:4505)   /* δ���õľֲ����� (��������) */

/* -- Ӳ�����ټ�� (SS FileHasher.cpp DetectHardwareCapabilities L536-558) ------
 * ������: BCrypt �ײ����Զ�ʹ��Ӳ��ָ��, CPUID ��ⴿ�����ֽ�湦�ܡ� */
static const LONG g_IocTISeverityWeights[4] = { -90, -70, -50, 0 };

/* -- ��в�鱨�������� (SS CheckThreatIntelligence L1694-1773, ������) -------
 * ����: TI ƥ������ �� ���ض�Ȩ���ۼ� (Critical-90/High-70/Medium-50)��
 * ������ԭ��: ��ṹ�� TI feed Դ, wkd ��ǰ�� ioc_hashes �����ǹ�ϣά�ȡ� */
static LONG
IocScan_ThreatIntelScore(
    _In_ PWKD_THREAT_INTEL_MATCH Matches,
    _In_ ULONG                    Count
    )
{
    LONG score = 0;
    ULONG i;
    if (!Matches) return 0;
    for (i = 0; i < Count; i++) {
        if (_stricmp(Matches[i].Severity, "Critical") == 0) score += g_IocTISeverityWeights[0];
        else if (_stricmp(Matches[i].Severity, "High") == 0) score += g_IocTISeverityWeights[1];
        else if (_stricmp(Matches[i].Severity, "Medium") == 0) score += g_IocTISeverityWeights[2];
    }
    if (score > 100) score = 100;
    if (score < -100) score = -100;
    return score;
}

/* -- �ƶ������ṹ (SS CloudReputation L353-371, ������) ---------------------
 * ����: ML ���� + �����ж� + �����/���塣
 * ������ԭ��: wkd ���ƺ��; SS ��Դ�� PerformCloudQuery ������ no-op�� */
typedef struct _WKD_CLOUD_REPUTATION {
    BOOLEAN QuerySuccessful;
    ULONG   MlScore;            /* 0-1000 (SS double 0-1) */
    ULONG   MlConfidence;
    CHAR    MlModel[32];
    ULONG   CommunityClean;
    ULONG   CommunitySuspicious;
    ULONG   CommunityMalicious;
    CHAR    Category[64];
    CHAR    FamilyName[64];
    CHAR    DetectionNames[8][64];   /* ���� SS CloudReputation.detectionNames L368 */
    ULONG   DetectionNameCount;
    ULONG   QueryLatencyMs;
} WKD_CLOUD_REPUTATION, *PWKD_CLOUD_REPUTATION;

/* -- ����ͨ�Լ�� (SS CheckCloudConnectivity L2235-2267, ������) ------------
 * ����: �˵� HTTPS У�� + API Key �����ԡ�
 * ������ԭ��: wkd ���ƺ�ˡ� */
static BOOLEAN
IocScan_CheckCloudConnectivity(
    _In_ PCWSTR Endpoint,
    _In_ PCSTR  ApiKey
    )
{
    if (!Endpoint || Endpoint[0] == L'\0') return FALSE;
    if (_wcsnicmp(Endpoint, L"https://", 8) != 0) return FALSE;
    if (!ApiKey || ApiKey[0] == '\0') return FALSE;
    return TRUE;
}

/* -- �ƶ�������ѯ (SS QueryCloudReputation L1775-1842, ������) --------------
 * ����: ML ������ֵ (SS 0.8/0.5/0.2) + ��������ռ���ж���
 * ������ԭ��: ���ƺ��, PerformCloudQuery ��ʧ�ܡ� */
static BOOLEAN
IocScan_QueryCloud(
    _In_    PWKD_CLOUD_REPUTATION Cloud,
    _Inout_ PLONG                 Score
    )
{
    ULONG total;
    if (!Cloud || !Score) return FALSE;
    if (!Cloud->QuerySuccessful) return FALSE;

    if (Cloud->MlScore > 800) {            /* SS mlScore > 0.8 �� -80 */
        *Score -= 80;
    } else if (Cloud->MlScore > 500) {     /* SS > 0.5 �� -40 */
        *Score -= 40;
    } else if (Cloud->MlScore < 200) {     /* SS < 0.2 �� +30 */
        *Score += 30;
    }

    total = Cloud->CommunityClean + Cloud->CommunitySuspicious + Cloud->CommunityMalicious;
    if (total > 0 && (Cloud->CommunityMalicious * 100 / total) > 50) {
        *Score -= 30;
    }
    return TRUE;
}

/* -- �ļ��ϱ� (SS SubmitForAnalysis/SubmitMetadata L1009-1096, ������) -------
 * ����: δ֪�ļ��ύ�ƶ˷���/Ԫ�����ϱ���
 * ������ԭ��: ���ƺ��; SS ��Դ���Ϊ��־ռλ�� */
static BOOLEAN
IocScan_SubmitForAnalysis(
    _In_ PCWSTR FilePath,
    _In_ PCWSTR Endpoint
    )
{
    UNREFERENCED_PARAMETER(FilePath);
    UNREFERENCED_PARAMETER(Endpoint);
    return FALSE;
}

static BOOLEAN
IocScan_SubmitMetadata(
    _In_ PCWSTR FilePath,
    _In_ PCWSTR Endpoint
    )
{
    UNREFERENCED_PARAMETER(FilePath);
    UNREFERENCED_PARAMETER(Endpoint);
    return FALSE;
}

/* -- ��/©���ϱ� (SS ReportFalsePositive/ReportFalseNegative L1098-1152, ������) */
static BOOLEAN
IocScan_ReportFalsePositive(
    _In_ PCSTR Sha256,
    _In_ PCSTR Reason
    )
{
    UNREFERENCED_PARAMETER(Sha256);
    UNREFERENCED_PARAMETER(Reason);
    return FALSE;
}

static BOOLEAN
IocScan_ReportFalseNegative(
    _In_ PCSTR Sha256,
    _In_ PCSTR ThreatName
    )
{
    UNREFERENCED_PARAMETER(Sha256);
    UNREFERENCED_PARAMETER(ThreatName);
    return FALSE;
}

/* -- ��Ϊ���������� (SS BehavioralContext L325-347, ������) -----------------
 * ����: ִ����ʷ/C2/���� I/O/ϵͳ�ļ��޸ġ�
 * ������ԭ��: ��Ϊ�ںϹ� VerdictEngine (E6 ��λ); wkd IoaC2Detect/
 *   IoaRansomwareDetect �Ѹ����źŲɼ�, ���������� SS Ȩ�����塣 */
typedef struct _WKD_BEHAVIORAL_REP {
    ULONG   ExecutionCount;
    ULONG   CleanExecutions;
    ULONG   SuspiciousExecutions;
    BOOLEAN HasC2Communication;
    BOOLEAN HasRansomwareBehavior;
    BOOLEAN ModifiesSystemFiles;
    BOOLEAN CreatesExecutables;
} WKD_BEHAVIORAL_REP, *PWKD_BEHAVIORAL_REP;

/* -- ��Ϊ����Ȩ�� (SS AnalyzeBehavior L1844-2046, ������) -------------------
 * Ȩ��: C2 -40 / ���� -50 / �ɾ���ʷ(>10 �� 0 ����) +20 / ϵͳ�ļ� -15 / ��ִ�� -10 */
static LONG
IocScan_BehaviorScore(
    _In_ PWKD_BEHAVIORAL_REP B
    )
{
    LONG score = 0;
    if (!B) return 0;
    if (B->HasC2Communication) score -= 40;
    if (B->HasRansomwareBehavior) score -= 50;
    if (B->CleanExecutions > 10 && B->SuspiciousExecutions == 0) score += 20;
    if (B->ModifiesSystemFiles) score -= 15;
    if (B->CreatesExecutables) score -= 10;
    if (score > 100) score = 100;
    if (score < -100) score = -100;
    return score;
}

/* -- �������� (SS FileReputationConfig L448-477, ������) --------------------
 * ������: Default/Offline/HighSecurity (���� SS L2434-2483)��
 * ������: wkd ������ֵ��ǰ������ IocScan_LevelFromScore, ���û���������� */
typedef enum _WKD_REP_MODE {
    WkdRepMode_LocalOnly = 0,
    WkdRepMode_CloudEnabled,
    WkdRepMode_Comprehensive
} WKD_REP_MODE;

typedef struct _WKD_FILE_REPUTATION_CONFIG {
    ULONG   MaxCacheEntries;
    ULONG   CacheTtlHours;
    LONG    MalwareThreshold;       /* SS Ĭ�� -70, HighSecurity -50 */
    LONG    SuspiciousThreshold;    /* SS Ĭ�� -30, HighSecurity -20 */
    LONG    TrustedThreshold;       /* SS Ĭ�� 70, HighSecurity 80 */
    ULONG   DefaultMode;
    BOOLEAN AllowOfflineMode;
    BOOLEAN EnableBehavioralAnalysis;
    BOOLEAN TrackFileHistory;
} WKD_FILE_REPUTATION_CONFIG, *PWKD_FILE_REPUTATION_CONFIG;

static VOID
IocScan_ConfigDefault(
    _Out_ PWKD_FILE_REPUTATION_CONFIG Cfg
    )
{
    if (!Cfg) return;
    Cfg->DefaultMode = WkdRepMode_LocalOnly;
    Cfg->MaxCacheEntries = 1000000;
    Cfg->CacheTtlHours = 24;
    Cfg->MalwareThreshold = -70;
    Cfg->SuspiciousThreshold = -30;
    Cfg->TrustedThreshold = 70;
    Cfg->AllowOfflineMode = TRUE;
    Cfg->EnableBehavioralAnalysis = TRUE;
    Cfg->TrackFileHistory = TRUE;
}

static VOID
IocScan_ConfigOffline(
    _Out_ PWKD_FILE_REPUTATION_CONFIG Cfg
    )
{
    if (!Cfg) return;
    IocScan_ConfigDefault(Cfg);
    Cfg->DefaultMode = WkdRepMode_LocalOnly;
    Cfg->MaxCacheEntries = 500000;
    Cfg->CacheTtlHours = 48;
    Cfg->EnableBehavioralAnalysis = FALSE;
}

static VOID
IocScan_ConfigHighSecurity(
    _Out_ PWKD_FILE_REPUTATION_CONFIG Cfg
    )
{
    if (!Cfg) return;
    Cfg->DefaultMode = WkdRepMode_Comprehensive;
    Cfg->MaxCacheEntries = 2000000;
    Cfg->CacheTtlHours = 12;
    Cfg->MalwareThreshold = -50;
    Cfg->SuspiciousThreshold = -20;
    Cfg->TrustedThreshold = 80;
    Cfg->AllowOfflineMode = FALSE;
    Cfg->EnableBehavioralAnalysis = TRUE;
    Cfg->TrackFileHistory = TRUE;
}

/* -- ������������ (SS PreloadCache/SaveCache L1158-1352, ������) ------------
 * ����: ������Ŀ�־û� (SS JSON ��) + Ͷ������ (������ hash �� key һ����У��)��
 * ������ԭ��: wkd ɨ�軺��Ϊ�ڴ� LRU (ScanManager g_ScanCache); �־û���
 *   StorageEngine file_reputation ������ (StPersistFileReputation)��
 *   �˴��Լ����ı��и�ʽռλ������, ��ʵ�־û��� SQLite�� */
typedef struct _WKD_REP_CACHE_ROW {
    CHAR Sha256Hex[65];
    LONG Score;
    ULONG Level;
    ULONG Confidence;
    CHAR ThreatName[64];
} WKD_REP_CACHE_ROW, *PWKD_REP_CACHE_ROW;

#define WKD_REP_CACHE_MAX_ROWS   4096

static ULONG
IocScan_CacheSaveRows(
    _In_  PCWSTR             FilePath,
    _In_  PWKD_REP_CACHE_ROW Rows,
    _In_  ULONG              Count
    )
{
    FILE* fp;
    ULONG i;
    if (!FilePath || !Rows) return 0;
    if (_wfopen_s(&fp, FilePath, L"w") != 0 || !fp) return 0;
    for (i = 0; i < Count; i++) {
        fprintf(fp, "%s|%ld|%lu|%lu|%s\n",
                Rows[i].Sha256Hex, Rows[i].Score, Rows[i].Level,
                Rows[i].Confidence, Rows[i].ThreatName);
    }
    fclose(fp);
    return Count;
}

static ULONG
IocScan_CacheLoadRows(
    _In_  PCWSTR             FilePath,
    _Out_ PWKD_REP_CACHE_ROW Rows,
    _In_  ULONG              MaxRows
    )
{
    FILE* fp;
    ULONG loaded = 0;
    if (!FilePath || !Rows) return 0;
    if (_wfopen_s(&fp, FilePath, L"r") != 0 || !fp) return 0;
    while (loaded < MaxRows && loaded < WKD_REP_CACHE_MAX_ROWS) {
        char line[512];
        if (fgets(line, sizeof(line), fp) == NULL) break;
        /* ����: sha256|score|level|conf|threat (SS JSON ����ı������) */
        if (sscanf_s(line, "%64[0-9a-fA-F]|%ld|%lu|%lu|%63[^|\n]",
                     Rows[loaded].Sha256Hex, (unsigned int)65,
                     &Rows[loaded].Score, &Rows[loaded].Level,
                     &Rows[loaded].Confidence,
                     Rows[loaded].ThreatName, (unsigned int)64) == 5) {
            /* Ͷ������: У�� sha256 ǡΪ 64 Сд hex (���� SS GetFromCache L2125,
               ���۸Ļ����ļ�ע������ key/��в��) */
            if (strlen(Rows[loaded].Sha256Hex) != 64) continue;
            loaded++;
        }
    }
    fclose(fp);
    return loaded;
}

/* -- ��֪��ǩ���߱� (SS GetCertificateReputation ��ǩ���߷�֧ L873-886)
 * ����: ���û�ǩ���� thumbprint ������, ���� signerReputation=-50 �ҵȼ�������
 * 2026-08 �Ѽ���: IocScan_ClassifySigner ���Ȳ���������������Դ = ����Ա
 *   ��̬��� / �鱨 feed (��ǰԤ���ձ�); untrusted ����ͬʱ�� cert_reputation
 *   �� (StUpsertCertReputation IsTrusted=FALSE) ����븲�ǡ� */
static CHAR g_IocBadSigners[32][64];   /* Ԥ���ձ�: SHA1 thumbprint hex Сд */

static BOOLEAN
IocScan_IsKnownBadSigner(
    _In_ PCSTR Thumbprint
    )
{
    ULONG i;
    if (!Thumbprint || Thumbprint[0] == '\0') return FALSE;
    for (i = 0; i < RTL_NUMBER_OF(g_IocBadSigners); i++) {
        if (g_IocBadSigners[i][0] == '\0') break;
        if (_stricmp(Thumbprint, g_IocBadSigners[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* -- ��ϣ��ʽУ�� (SS IsValidSha256Hex/Sha1Hex/Md5Hex L170-204, ������) ------
 * ����: �ϸ� hex ����/�ַ�У�� (���ǹ淶����ϣ��Ⱦ����/���)��
 * ������ԭ��: wkd ��ϣ���� BCrypt ������ת hex (UtHexEncode) ��Ȼ�Ϸ�;
 *   ���� API ���У���� StUpsertIocHash ���ȼ�鸲�ǡ� */
static BOOLEAN
IocScan_IsValidHex(
    _In_ PCSTR   S,
    _In_ SIZE_T  Len
    )
{
    SIZE_T i;
    if (!S || strnlen(S, Len + 1) != Len) return FALSE;
    for (i = 0; i < Len; i++) {
        if (!((S[i] >= '0' && S[i] <= '9') ||
              (S[i] >= 'a' && S[i] <= 'f') ||
              (S[i] >= 'A' && S[i] <= 'F'))) return FALSE;
    }
    return TRUE;
}

static BOOLEAN
IocScan_IsValidSha256Hex(_In_ PCSTR S) { return IocScan_IsValidHex(S, 64); }
static BOOLEAN
IocScan_IsValidSha1Hex(_In_ PCSTR S)   { return IocScan_IsValidHex(S, 40); }
static BOOLEAN
IocScan_IsValidMd5Hex(_In_ PCSTR S)    { return IocScan_IsValidHex(S, 32); }

/* -- ��ϣ��һ�� + �̹�ϣ (SS NormalizeHash L209-220/ShortHash L263-266, ������)
 * ����: Сд��һ�� + ��־��ض̹�ϣ (ǰ 16 hex)��
 * ������ԭ��: wkd UtHexEncode �Ѳ�Сд hex, Сд��һ���ɵ�������֤�� */
static VOID
IocScan_NormalizeHash(
    _In_  PCSTR In,
    _Out_ PCHAR Out,
    _In_  ULONG OutCch
    )
{
    ULONG i, o = 0;
    if (!In || !Out || OutCch == 0) return;
    for (i = 0; In[i] && (o + 1) < OutCch; i++) {
        CHAR c = In[i];
        if (c >= 'A' && c <= 'F') c = (CHAR)(c - 'A' + 'a');
        Out[o++] = c;
    }
    Out[o] = '\0';
}

static VOID
IocScan_ShortHash(
    _In_  PCSTR In,
    _Out_ PCHAR Out,
    _In_  ULONG OutCch       /* �� 17 */
    )
{
    if (!In || !Out || OutCch == 0) return;
    strncpy_s(Out, OutCch, In, 16);
    Out[OutCch - 1] = '\0';
}

/* -- ������� (SS CachePolicy L229-234 + CacheResult L2141-2209, ������) -----
 * ����: ����ѡ�������̲��� (NoCache/Positive/Negative/All, ���� SS
 *   CachePositive ֻ���氲ȫ/����, CacheNegative ֻ�������)��
 * ������ԭ��: wkd g_ScanCache ����������ɨ���� (CacheAll ����), ���Ի����ӡ� */
typedef enum _WKD_REP_CACHE_POLICY {
    WkdRepCache_NoCache = 0,
    WkdRepCache_CachePositive,
    WkdRepCache_CacheNegative,
    WkdRepCache_CacheAll
} WKD_REP_CACHE_POLICY;

static BOOLEAN
IocScan_ShouldCacheResult(
    _In_ WKD_REP_CACHE_POLICY Policy,
    _In_ PIOC_SCAN_RESULT     Result
    )
{
    if (!Result) return FALSE;
    switch (Policy) {
    case WkdRepCache_NoCache: return FALSE;
    case WkdRepCache_CachePositive:
        return (Result->Reputation.Level == WkdRep_Trusted ||
                Result->Reputation.Level == WkdRep_MicrosoftSigned ||
                Result->Reputation.Level == WkdRep_KnownSafe);
    case WkdRepCache_CacheNegative:
        return (Result->Reputation.Level == WkdRep_KnownMalware ||
                Result->Reputation.Level == WkdRep_HighlyMalicious);
    case WkdRepCache_CacheAll:
    default:
        return TRUE;
    }
}

/* -- �����Բ��� + �ӳ�ͳ�� (SS MAX_CLOUD_RETRIES/CLOUD_RETRY_DELAY_MS L123-124
 *    + UpdateCloudLatency L2315-2325, ������)
 * ����: �Ʋ�ѯ�������� 2 + ���Լ�� 500ms + �ӳٹ���ƽ�� (9:1 EMA)��
 * ������ԭ��: ���ƺ�� (PerformCloudQuery ��ʧ��), SS ��Դ����Ϊռλ�� */
#define WKD_REP_MAX_CLOUD_RETRIES    2
#define WKD_REP_CLOUD_RETRY_DELAY_MS 500

static VOID
IocScan_UpdateCloudLatency(
    _Inout_ volatile LONG64* Avg,
    _In_    ULONG            LatencyMs
    )
{
    LONG64 cur;
    if (!Avg) return;
    cur = *Avg;
    InterlockedExchange64(Avg, (LONG64)((cur * 9 + LatencyMs) / 10));
}

/* -- ֤�� SHA256 ָ�� (SS PE_sig_verf GetCertThumbprint L1556-1652, ������)
 * ����: BCrypt SHA256 �� cert DER ���� �� ��д hex (SS ��д; wkd Thumbprint Ϊ SHA1 Сд)��
 * ������ԭ��: wkd cert_reputation ����Ϊ SHA1 ָ�� (IocScan_ExtractCertDetails),
 *    SHA256 ָ�������ѷ�; ���������湩δ�� thumbprint Ǩ�ơ� */
static BOOLEAN
IocScan_GetCertThumbprintSha256(
    _In_  PCCERT_CONTEXT Cert,
    _Out_ PCHAR          Hex,   /* ��65 */
    _In_  ULONG          HexCch
    )
{
    DEF_SHA256_HASH digest;
    static const CHAR kHex[] = "0123456789ABCDEF";
    ULONG k;

    if (!Cert || !Cert->pbCertEncoded || Cert->cbCertEncoded == 0 ||
        !Hex || HexCch < 65) {
        return FALSE;
    }

    /* 统一走 BCrypUtils（BCrypt SHA-256 buffer 哈希, 2026-09-08 收敛） */
    if (!IocScanner_ComputeBufferSha256(Cert->pbCertEncoded,
                                        (ULONG)Cert->cbCertEncoded,
                                        &digest)) {
        return FALSE;
    }

    for (k = 0; k < DEF_SHA256_SIZE; k++) {
        Hex[k * 2] = kHex[(digest.Data[k] >> 4) & 0xF];
        Hex[k * 2 + 1] = kHex[digest.Data[k] & 0xF];
    }
    Hex[DEF_SHA256_SIZE * 2] = '\0';
    return TRUE;
}

/* -- �����ļ��ж� (SS LOW_PREVALENCE_THRESHOLD=100/HIGH=10000/
 *    RARE_FILE_PERCENTAGE=0.01 L118-120, ������)
 * ����: seen_count ������ֵ �� isRare (�����жȿ����ź�)��
 * ������ԭ��: wkd file_reputation.seen_count �ѳ־û� (StPersistFileReputation),
 *   isRare �ж�������� (WkdRep_LowPrevalence ö����Ԥ��)�� */
#define WKD_REP_HIGH_PREVALENCE_THRESHOLD 10000
#define WKD_REP_LOW_PREVALENCE_THRESHOLD  100

static BOOLEAN
IocScan_PrevalenceIsRare(
    _In_ ULONG SeenCount
    )
{
    return (SeenCount > 0 && SeenCount < WKD_REP_LOW_PREVALENCE_THRESHOLD);
}

/* -- ����ͳ�ƶ���ṹ + ���� (SS FileReputationStatistics L483-503 + Reset
 *    L2489-2502, ������)
 * ����: SS 12 ������������ռλ + Reset ���㡣
 * ������ԭ��: wkd ʵ��ͳ�ƹ� WKD_SCAN_MANAGER.RepStats (ScanManager.h),
 *   �˽ṹ���� SS ���������ռλ, �����ģ�������� */
typedef struct _WKD_REP_STATS_LOCAL {
    LONG64 TotalQueries;
    LONG64 LocalHits;
    LONG64 CloudQueries;
    LONG64 CacheHits;
    LONG64 CacheMisses;
    LONG64 MaliciousDetected;
    LONG64 SuspiciousDetected;
    LONG64 UnknownFiles;
    LONG64 TrustedFiles;
    LONG64 AverageLatencyUs;
    LONG64 MaxLatencyUs;
    LONG64 CloudFailures;
} WKD_REP_STATS_LOCAL, *PWKD_REP_STATS_LOCAL;

static VOID
IocScan_ResetReputationStats(
    _Inout_ PWKD_REP_STATS_LOCAL Stats
    )
{
    if (!Stats) return;
    Stats->TotalQueries = 0;
    Stats->LocalHits = 0;
    Stats->CloudQueries = 0;
    Stats->CacheHits = 0;
    Stats->CacheMisses = 0;
    Stats->MaliciousDetected = 0;
    Stats->SuspiciousDetected = 0;
    Stats->UnknownFiles = 0;
    Stats->TrustedFiles = 0;
    Stats->AverageLatencyUs = 0;
    Stats->MaxLatencyUs = 0;
    Stats->CloudFailures = 0;
}

/* -- MITRE ��עƴ�� (SS CheckThreatIntelligence mitreId �������� L1718-1721, ������)
 * ����: ���� TI ƥ��� MITRE ��������ƴ�ӡ�
 * ������ԭ��: wkd ThreatIntel �ṹ�� feed δ����, ƴ���� TI һ��Ԥ���� */
static VOID
IocScan_TiMergeMitre(
    _In_  PWKD_THREAT_INTEL_MATCH Matches,
    _In_  ULONG                   Count,
    _Out_ PCHAR                   Out,
    _In_  ULONG                   OutCch
    )
{
    ULONG i;
    ULONG o = 0;
    if (!Matches || !Out || OutCch == 0) return;
    for (i = 0; i < Count && (o + 1) < OutCch; i++) {
        ULONG k;
        if (Matches[i].MitreId[0] == '\0') continue;
        if (o > 0 && (o + 1) < OutCch) Out[o++] = ',';
        for (k = 0; Matches[i].MitreId[k] && (o + 1) < OutCch; k++) {
            Out[o++] = Matches[i].MitreId[k];
        }
    }
    Out[o] = '\0';
}

/* ========================================================================
 * 8. FileTypeAnalyzer �������� (SS FileTypeAnalyzer.cpp, 2026-08-06)
 *    MIME ӳ�� / �Զ���ǩ��ע���� JSON ����
 *    �����渲��, δ������ˮ��, ��ע SS �к� + ������ԭ��
 * ======================================================================== */


#pragma warning(pop)
