/**************************************************/
/*  WkDefender Agent �� ɨ����Ų� ScanManager ʵ��  */
/*  Ǩ���� ShadowStrike ScanEngine (���Ų�, �Ǽ��) */
/**************************************************/

#include "ScanManager.h"
#include "DirectoryMonitor.h"            /* Quick ?????��???? (DirectoryMonitor ??? 2026-08) */
#include "IOC/IocScanner.h"
#include "IOC/IocEngine.h"               /* extern g_IocEngine (IocEngine.c ����) */
#include "IOC/ImageAnalyzer/ImageAnalyzer.h" /* ͳһ���������ˮ�� (2026-08-15) */
#include "Common/Exempts/Exempts.h"      /* ͳһ�������� (Exempts �ع� #67, ��� IocFileWhitelist) */
#include "Common/Utils.h"
#include "FileLockManager.h"          /* ��̽���ſ� (FileLockManager Ǩ�� 2026-08) */

#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <tlhelp32.h>               /* ScanAllProcesses: Toolhelp ö�� */

/**************************************************/
/*               ȫ��ʵ��                           */
/**************************************************/

WKD_SCAN_MANAGER g_ScanManager;

/**************************************************/
/*               ���������Ŀ                       */
/**************************************************/

typedef struct _WKD_SCAN_CACHE_ENTRY {
    BOOLEAN         Active;
    CHAR            Sha256Hex[65];      /* Сд hex */
    IOC_SCAN_RESULT Result;
    FILETIME        Timestamp;
    FILETIME        FileModTime;        /* ����ʱ�ļ� LastWriteTime (SS mod-time ʧЧ) */
    ULONG           HitCount;
} WKD_SCAN_CACHE_ENTRY;

static WKD_SCAN_CACHE_ENTRY g_ScanCache[WKD_SCAN_CACHE_ENTRIES];

/* ��̽���ſ� (FileLockManager Ǩ�� 2026-08): �����뿪��, ���� g_Ioa*Enabled ������
 * �� TRUE �� ScanFileDirect �Ա����ļ�����ɨ�貢���� (�޸�ԭ SHA256 ʧ�ܾ�Ĭ
 * Unknown ȱ��: �����ļ��޷��ɿ���ȡ��ϣ, ��ʽ��Ϊ Unknown + LockedFiles ����)�� */
static BOOLEAN g_FlmScanGateEnabled = FALSE;

/**************************************************/
/*               �ڲ�����                           */
/**************************************************/

static VOID
ScanManager_HashToHex(
    _In_ PDEF_SHA256_HASH Hash,
    _Out_ PCHAR           Hex
    )
{
    static const CHAR hexChars[] = "0123456789abcdef";
    ULONG i;

    for (i = 0; i < 32; i++) {
        Hex[i * 2]     = hexChars[(Hash->Data[i] >> 4) & 0x0F];
        Hex[i * 2 + 1] = hexChars[Hash->Data[i] & 0x0F];
    }
    Hex[64] = '\0';
}

static BOOLEAN
ScanManager_CacheLookup(
    _In_ PCSTR Sha256Hex,
    _In_opt_ PCWSTR FilePath,       /* NULL=�ڴ�·��, ���� mod-time У�� */
    _Out_ PIOC_SCAN_RESULT Result
    )
{
    ULONG i;
    FILETIME now;

    GetSystemTimeAsFileTime(&now);
    for (i = 0; i < WKD_SCAN_CACHE_ENTRIES; i++) {
        if (!g_ScanCache[i].Active) continue;
        if (_strnicmp(g_ScanCache[i].Sha256Hex, Sha256Hex, 64) != 0) continue;

        /* TTL ��� */
        ULONGLONG nowUs  = (ULONGLONG)now.dwHighDateTime << 32 | now.dwLowDateTime;
        ULONGLONG tsUs   = (ULONGLONG)g_ScanCache[i].Timestamp.dwHighDateTime << 32 | g_ScanCache[i].Timestamp.dwLowDateTime;
        ULONGLONG ttlUs  = (ULONGLONG)WKD_SCAN_CACHE_TTL_MS * 10000;
        if (nowUs > tsUs && (nowUs - tsUs) > ttlUs) {
            g_ScanCache[i].Active = FALSE;
            continue;
        }

        /* mod-time У�� (SS FileHasher mod-time ʧЧ�����屸ע: wkd ���水����
           key, ͬ��ϣͬ����, ��У��Ϊ���ܸ������ౣ��) */
        if (FilePath) {
            WIN32_FILE_ATTRIBUTE_DATA attr;
            if (GetFileAttributesExW(FilePath, GetFileExInfoStandard, &attr)) {
                if (CompareFileTime(&attr.ftLastWriteTime, &g_ScanCache[i].FileModTime) != 0) {
                    g_ScanCache[i].Active = FALSE;
                    continue;
                }
            }
        }

        *Result = g_ScanCache[i].Result;
        g_ScanCache[i].Timestamp = now;
        g_ScanCache[i].HitCount++;
        InterlockedIncrement64(&g_ScanManager.CacheHits);
        return TRUE;
    }

    InterlockedIncrement64(&g_ScanManager.CacheMisses);
    return FALSE;
}

static VOID
ScanManager_CacheStore(
    _In_ PCSTR Sha256Hex,
    _In_opt_ PCWSTR FilePath,       /* NULL=�ڴ�·��, ����¼ mod-time */
    _In_ PIOC_SCAN_RESULT Result
    )
{
    ULONG i;
    ULONG lruIdx = (ULONG)-1;
    ULONGLONG lruTs = (ULONGLONG)-1;
    FILETIME now;
    ULONGLONG nowUs;

    GetSystemTimeAsFileTime(&now);
    nowUs = (ULONGLONG)now.dwHighDateTime << 32 | now.dwLowDateTime;

    /* �ҿ�λ�� LRU ��̭λ */
    for (i = 0; i < WKD_SCAN_CACHE_ENTRIES; i++) {
        ULONGLONG ts;
        if (!g_ScanCache[i].Active) { lruIdx = i; break; }
        ts = (ULONGLONG)g_ScanCache[i].Timestamp.dwHighDateTime << 32 | g_ScanCache[i].Timestamp.dwLowDateTime;
        if (ts < lruTs) { lruTs = ts; lruIdx = i; }
    }
    if (lruIdx == (ULONG)-1) return;

    memset(&g_ScanCache[lruIdx], 0, sizeof(g_ScanCache[lruIdx]));
    g_ScanCache[lruIdx].Active = TRUE;
    strncpy_s(g_ScanCache[lruIdx].Sha256Hex, sizeof(g_ScanCache[lruIdx].Sha256Hex), Sha256Hex, _TRUNCATE);
    g_ScanCache[lruIdx].Result = *Result;
    g_ScanCache[lruIdx].Timestamp = now;
    if (FilePath) {
        WIN32_FILE_ATTRIBUTE_DATA attr;
        if (GetFileAttributesExW(FilePath, GetFileExInfoStandard, &attr)) {
            g_ScanCache[lruIdx].FileModTime = attr.ftLastWriteTime;
        }
    }
}

/* ��ʽ��ս������ (���� SS FileHasher::ClearCache L1699-1703) */
VOID
ScanManager_ClearCache(
    VOID
    )
{
    ULONG i;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_CACHE_ENTRIES; i++) {
        g_ScanCache[i].Active = FALSE;
    }
    LeaveCriticalSection(&g_ScanManager.Lock);
}

/* ��ǰ������Ŀ�� (���� SS FileHasher::GetCacheSize L1711-1716) */
ULONG
ScanManager_GetCacheSize(
    VOID
    )
{
    ULONG i, count = 0;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_CACHE_ENTRIES; i++) {
        if (g_ScanCache[i].Active) count++;
    }
    LeaveCriticalSection(&g_ScanManager.Lock);
    return count;
}

/**************************************************/
/*               ��в�ж����ռ�                     */
/**************************************************/

static VOID
ScanManager_CollectThreat(
    _In_ PWKD_SCAN_JOB Job,
    _In_ PCWSTR        FilePath,
    _In_ PIOC_SCAN_RESULT Result
    )
{
    PWKD_SCAN_THREAT threat;
    ULONG idx;

    EnterCriticalSection(&Job->Lock);
    idx = (ULONG)Job->ThreatCount;
    if (idx >= WKD_SCAN_MAX_THREATS) {
        LeaveCriticalSection(&Job->Lock);
        return;
    }

    threat = &Job->Threats[idx];
    RtlZeroMemory(threat, sizeof(*threat));
    wcsncpy_s(threat->FilePath, MAX_PATH, FilePath, _TRUNCATE);

    if (Result->ThreatName[0]) {
        /* ���� SS GenerateThreatName ��� */
        CHAR narrow[64];
        size_t n = 0;
        if (MultiByteToWideChar(CP_UTF8, 0, Result->ThreatName, -1,
                                threat->ThreatName, 64) == 0) {
            /* ���� ASCII ֱ�� */
            for (n = 0; Result->ThreatName[n] && n < 63; n++) {
                threat->ThreatName[n] = (WCHAR)(UCHAR)Result->ThreatName[n];
            }
            threat->ThreatName[n] = L'\0';
        }
        UNREFERENCED_PARAMETER(narrow);
    } else {
        wcsncpy_s(threat->ThreatName, 64,
            (Result->FinalVerdict == DefIocVerdict_Malicious) ? L"Malware.Generic" : L"Threat.Suspicious",
            _TRUNCATE);
    }

    threat->Severity = (Result->FinalVerdict == DefIocVerdict_Malicious)
                       ? WkdThreatSev_High
                       : (Result->FinalConfidence >= 60 ? WkdThreatSev_Medium : WkdThreatSev_Low);
    threat->IsCleaned = FALSE;

    Job->ThreatCount = (LONG)(idx + 1);
    InterlockedIncrement(&Job->ThreatsFound);
    InterlockedIncrement64(&g_ScanManager.TotalThreats);
    LeaveCriticalSection(&Job->Lock);

    /* ����ص���slot �ѹ̶����ٱ�д�������ϱ� UI 0x6002�� */
    if (g_ScanManager.ThreatCb) {
        g_ScanManager.ThreatCb(Job->JobId, &Job->Threats[idx]);
    }
}

/**************************************************/
/*               ���ļ�ɨ����ˮ��                   */
/**************************************************/

NTSTATUS
ScanManager_ScanFileDirect(
    _In_ PCWSTR             FilePath,
    _Out_ PIOC_SCAN_RESULT  Result
    )
/*++
Routine Description:
    ���ļ�����ɨ�衣����:
      �ų� �� SHA256 �� ���� �� ������ �� IOC ��̬ɨ�� �� ����д�ء�
    YARA ���ɨ�費�ڱ�����·����IocYara_Enqueue �첽��ӣ���

Arguments:
    FilePath - �ļ�����·����
    Result   - ��� IOC ɨ������

Return Value:
    NTSTATUS��
--*/
{
    DEF_SHA256_HASH hash;
    CHAR hex[65];
    IOC_SCAN_RESULT scanResult;
    BOOLEAN maliciousHash = FALSE;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    /* 1. �ų����� */
    if (ScanManager_IsExcluded(FilePath)) {
        Result->FinalVerdict = DefIocVerdict_Clean;
        return STATUS_SUCCESS;
    }

    /* 2.5 ��̽�� (FileLockManager Ǩ�� 2026-08): �����ļ�����ɨ�� + ���ˡ�
     * �������ſ� g_FlmScanGateEnabled=FALSE����̽��Ϊ���� CreateFileW ̽��
     * (FileLockManager_IsFileLocked), ����������ֻ��ϵͳ�ļ� ACCESS_DENIED �󱨡� */
    if (g_FlmScanGateEnabled && FileLockManager_IsFileLocked(FilePath, NULL)) {
        InterlockedIncrement64(&g_ScanManager.LockedFiles);
        Result->FinalVerdict = DefIocVerdict_Unknown;
        return STATUS_SUCCESS;
    }

    /* 2. SHA256 */
    if (!IocScanner_ComputeFileSha256(FilePath, &hash)) {
        Result->FinalVerdict = DefIocVerdict_Unknown;
        return STATUS_SUCCESS;
    }
    ScanManager_HashToHex(&hash, hex);

    /* 3. ������� */
    if (ScanManager_CacheLookup(hex, FilePath, Result)) {
        return STATUS_SUCCESS;
    }

    /* 4. ������ FastPath��֤��/·��/��ϣ�� */
    if (ExemptsIsWhitelisted(FilePath, &hash, NULL)) {
        InterlockedIncrement64(&g_ScanManager.WhitelistHits);
        Result->FinalVerdict = DefIocVerdict_Clean;
        ScanManager_CacheStore(hex, FilePath, Result);
        return STATUS_SUCCESS;
    }

    /* 5. ��ϣ�����Ԥ�죨ioc_hashes�� */
    IocScanner_QueryHash(&hash, &maliciousHash);

    /* �鵵/�ĵ�/ý��ר��ɨ���� TODO �ѹ�λ��2026-08-15����
     * ԭλ�ڲ��� 5/6 ������� TODO��IocArchive_ScanFile / IocDocument_ScanFile /
     * IocMedia_ScanFile����ͳһ��ˮ��Ǩ���� ImageAnalyzer.c �� PE ��֧
     * ���ļ����ͷַ�������ߣ��ſ� g_Ioa*Enabled Ĭ�Ϲأ���
     * ��������ȫ���������� ImageAnalyzer.c "�� PE ר��ɨ��������" ע�͡� */

    /* 6. ͳһ���������ˮ�ߣ�ImageAnalyzer, 2026-08-15����
     *    PE �ļ���ģ�����WKD_MODULE �ļ���Ȩ������������ Done �� O(1) ���ã�
     *    ������ IocEngine_ScanFile/IocScanner_ScanFile ÿ·���ظ� SHA256/PE ��������
     *    �� PE���ĵ�/�ű�/�鵵��ImageAnalyzer �ڲ�ֱ����ȷ�������ģ�顣
     *    Tier3 ��ȷ����������ף�ÿΨһ�����һ�Σ������ IaMergeFileSignals
     *    �ϲ���ϣ��ѯ/����/�ļ������źš� */
    RtlZeroMemory(&scanResult, sizeof(scanResult));
    /* UNICODE_STRING �ֶ����� (·��ͨ�� <32K; �����ε���, ��ӵ��) */
    {
        UNICODE_STRING usPath;
        usPath.Buffer = (PWSTR)FilePath;
        usPath.Length = (USHORT)(lstrlenW(FilePath) * sizeof(WCHAR));
        usPath.MaximumLength = usPath.Length + sizeof(WCHAR);
        IocAnalyseImage(&usPath, NULL, &scanResult);
    }

    /* 7. ��ϣ���и����ж� */
    if (maliciousHash) {
        scanResult.HashChecked = TRUE;
        scanResult.HashVerdict = DefIocVerdict_Malicious;
        scanResult.FinalVerdict = DefIocVerdict_Malicious;
        scanResult.FinalConfidence = 100;
        if (scanResult.ThreatName[0] == '\0') {
            strncpy_s(scanResult.ThreatName, sizeof(scanResult.ThreatName),
                      "Hash.Malicious", _TRUNCATE);
        }
        InterlockedIncrement64(&g_ScanManager.RepStats.BlacklistHits);
    }

    /* �������� (SS FileReputation Ǩ�� 2026-08-06): ��ϣ���Ǻ�����,
     * ʹ Reputation �ֶη�ӳ�������ź� (IocScanner_ScanFile ������һ��,
     * �˴��ݵ�����, �� FinalVerdict ����һ��) */
    IocScan_ReputationScore(&scanResult);
    InterlockedIncrement64(&g_ScanManager.RepStats.ReputationChecks);

    *Result = scanResult;

    /* 8. ����д�� */
    ScanManager_CacheStore(hex, FilePath, Result);
    InterlockedIncrement64(&g_ScanManager.TotalScans);

    return STATUS_SUCCESS;
}

/**************************************************/
/*               �ų�����                           */
/**************************************************/

BOOLEAN
ScanManager_IsExcluded(
    _In_ PCWSTR Path
    )
{
    LONG i;
    LONG count;

    if (!Path) return FALSE;

    count = g_ScanManager.ExclusionCount;
    for (i = 0; i < count; i++) {
        PWKD_EXCLUSION_RULE rule = &g_ScanManager.Exclusions[i];
        if (!rule->Enabled) continue;

        switch (rule->Type) {
        case WkdExclType_PathPrefix:
            if (_wcsnicmp(Path, rule->Pattern, wcslen(rule->Pattern)) == 0) {
                return TRUE;
            }
            break;
        case WkdExclType_Extension: {
            PCWSTR dot = wcsrchr(Path, L'.');
            if (dot && _wcsicmp(dot, rule->Pattern) == 0) {
                return TRUE;
            }
            break;
        }
        case WkdExclType_ProcessName: {
            PCWSTR slash = wcsrchr(Path, L'\\');
            PCWSTR name = slash ? slash + 1 : Path;
            if (_wcsicmp(name, rule->Pattern) == 0) {
                return TRUE;
            }
            break;
        }
        default:
            break;
        }
    }
    return FALSE;
}

VOID
ScanManager_AddExclusion(
    _In_ PWKD_EXCLUSION_RULE Rule
    )
{
    LONG idx;

    if (!Rule) return;

    EnterCriticalSection(&g_ScanManager.Lock);
    idx = g_ScanManager.ExclusionCount;
    if (idx < WKD_SCAN_MAX_EXCLUSIONS) {
        g_ScanManager.Exclusions[idx] = *Rule;
        g_ScanManager.ExclusionCount = idx + 1;
    }
    LeaveCriticalSection(&g_ScanManager.Lock);
}

/**************************************************/
/*               Ŀ¼����                           */
/**************************************************/

static VOID
ScanManager_CountFilesRecursive(
    _In_ PCWSTR          Root,
    _In_ BOOLEAN         Recursive,
    _Inout_ PULONG       Count,
    _In_ ULONG           MaxCount
    )
{
    WCHAR pattern[MAX_PATH];
    WCHAR subPath[MAX_PATH];
    HANDLE find;
    WIN32_FIND_DATAW fd;
    ULONG cap = *Count;

    _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*", Root);
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.cFileName[0] == L'.') continue;

        _snwprintf_s(subPath, MAX_PATH, _TRUNCATE, L"%s\\%s", Root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (Recursive && cap < MaxCount) {
                ScanManager_CountFilesRecursive(subPath, Recursive, Count, MaxCount);
            }
        } else {
            cap = *Count;
            if (cap < MaxCount) {
                if (!ScanManager_IsExcluded(subPath)) {
                    (*Count)++;
                }
            }
        }
    } while (FindNextFileW(find, &fd));

    FindClose(find);
}

static VOID
ScanManager_ScanDirectory(
    _In_ PWKD_SCAN_JOB Job,
    _In_ PCWSTR        Root
    )
{
    WCHAR pattern[MAX_PATH];
    WCHAR subPath[MAX_PATH];
    HANDLE find;
    WIN32_FIND_DATAW fd;

    if (InterlockedCompareExchange((PLONG)&Job->State, 0, 0) != WkdScanState_Running) {
        return;
    }
    if (WaitForSingleObject(Job->CancelEvent, 0) == WAIT_OBJECT_0) {
        return;
    }

    _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*", Root);
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        IOC_SCAN_RESULT result;

        if (fd.cFileName[0] == L'.') continue;
        if (WaitForSingleObject(Job->CancelEvent, 0) == WAIT_OBJECT_0) break;

        /* ��ͣ���: ��ѯ�ȴ��ָ���ȡ�� */
        while (InterlockedCompareExchange((PLONG)&Job->Paused, 0, 0) != 0) {
            if (WaitForSingleObject(Job->CancelEvent, 0) == WAIT_OBJECT_0) break;
            Sleep(50);
        }
        if (WaitForSingleObject(Job->CancelEvent, 0) == WAIT_OBJECT_0) break;

        _snwprintf_s(subPath, MAX_PATH, _TRUNCATE, L"%s\\%s", Root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (Job->Recursive) {
                ScanManager_ScanDirectory(Job, subPath);
            }
        } else {
            if (ScanManager_IsExcluded(subPath)) continue;

            /* ���ļ�ɨ�� */
            ScanManager_ScanFileDirect(subPath, &result);

            InterlockedIncrement(&Job->FilesScanned);
            LONG scanned = Job->FilesScanned;
            LONG total = Job->TotalFiles;
            if (total > 0) {
                LONG pct = (LONG)((ULONGLONG)scanned * 100 / total);
                if (pct > 100) pct = 100;
                InterlockedExchange(&Job->Progress, pct);
            }

            /* ��в�ռ� */
            if (result.FinalVerdict >= DefIocVerdict_Suspicious) {
                ScanManager_CollectThreat(Job, subPath, &result);
            }

            /* ���Ȼص� */
            if (g_ScanManager.ProgressCb) {
                g_ScanManager.ProgressCb(Job->JobId,
                    (ULONG)Job->Progress,
                    (ULONG)Job->FilesScanned,
                    (ULONG)Job->ThreatsFound);
            }
        }
    } while (FindNextFileW(find, &fd));

    FindClose(find);
}

/**************************************************/
/*               ɨ���߳�                           */
/**************************************************/

static DWORD WINAPI
ScanManager_ScanThread(
    _In_ LPVOID Param
    )
{
    PWKD_SCAN_JOB job = (PWKD_SCAN_JOB)Param;
    WCHAR roots[WKD_DIR_MAX_QUICK_ROOTS][DEF_MAX_PATH];
    ULONG rootCount = 0;
    ULONG ri;
    ULONG total = 0;
    LONG state;

    /* ȷ��ɨ��� (Quick = �ؼ�Ŀ¼���, ���൥��) */
    switch (job->Type) {
    case WkdScanType_Quick:
        /* DirectoryMonitor_GetQuickScanRoots: System/User/Startup/Downloads/Temp �ۺ�
         * (DirectoryMonitor Ǩ�� 2026-08, ����ԭ�� C:\Windows �Ĺؼ�Ŀ¼ɨ��ȱ��) */
        if (NT_SUCCESS(DirectoryMonitor_GetQuickScanRoots(
                roots, WKD_DIR_MAX_QUICK_ROOTS, &rootCount)) && rootCount > 0) {
            break;
        }
        /* ����: ·������ʧ�� �� ����ֻɨ Windows */
        wcsncpy_s(roots[0], DEF_MAX_PATH, L"C:\\Windows", _TRUNCATE);
        rootCount = 1;
        break;
    case WkdScanType_Full:
        wcsncpy_s(roots[0], DEF_MAX_PATH, L"C:\\", _TRUNCATE);
        rootCount = 1;
        break;
    default:
        wcsncpy_s(roots[0], DEF_MAX_PATH,
                  job->RootPath[0] ? job->RootPath : L"C:\\", _TRUNCATE);
        rootCount = 1;
        break;
    }

    /* Ԥͳ���ļ�����������׼ȷ�� */
    for (ri = 0; ri < rootCount; ri++) {
        if (WaitForSingleObject(job->CancelEvent, 0) == WAIT_OBJECT_0) break;
        ScanManager_CountFilesRecursive(roots[ri], job->Recursive, &total, 100000);
    }
    InterlockedExchange(&job->TotalFiles, (LONG)total);

    /* ִ��ɨ�� (���˳�����, ȡ������;�˳�) */
    for (ri = 0; ri < rootCount; ri++) {
        if (WaitForSingleObject(job->CancelEvent, 0) == WAIT_OBJECT_0) break;
        ScanManager_ScanDirectory(job, roots[ri]);
    }
    GetSystemTimeAsFileTime(&job->EndTime);

    /* ����״̬ */
    state = WaitForSingleObject(job->CancelEvent, 0) == WAIT_OBJECT_0
            ? WkdScanState_Cancelled
            : WkdScanState_Completed;
    InterlockedExchange(&job->State, state);
    InterlockedExchange(&job->Progress, 100);

    if (state == WkdScanState_Completed && g_ScanManager.CompleteCb) {
        g_ScanManager.CompleteCb(job->JobId, (ULONG)job->ThreatsFound);
    }

    CloseHandle(job->CancelEvent);
    job->CancelEvent = NULL;
    CloseHandle(job->Thread);
    job->Thread = NULL;

    return 0;
}

/**************************************************/
/*               �������                           */
/**************************************************/

NTSTATUS
ScanManager_StartScan(
    _In_ WKD_SCAN_TYPE  Type,
    _In_opt_ PCWSTR     Path,
    _Out_ PULONG        JobId
    )
{
    PWKD_SCAN_JOB job = NULL;
    ULONG i;
    static ULONG s_NextJobId = 1;
    HANDLE cancelEvent;

    if (!g_ScanManager.Initialized || !JobId) return STATUS_INVALID_PARAMETER;

    cancelEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!cancelEvent) return STATUS_INSUFFICIENT_RESOURCES;

    EnterCriticalSection(&g_ScanManager.Lock);

    /* �ҿ�������� */
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        if (g_ScanManager.Jobs[i].State == WkdScanState_Idle ||
            g_ScanManager.Jobs[i].State == WkdScanState_Completed) {
            job = &g_ScanManager.Jobs[i];
            break;
        }
    }

    if (!job) {
        LeaveCriticalSection(&g_ScanManager.Lock);
        CloseHandle(cancelEvent);
        return STATUS_TOO_MANY_OPENED_FILES;
    }

    /* ��ʼ������ */
    if (job->Thread) { CloseHandle(job->Thread); job->Thread = NULL; }
    RtlZeroMemory(job->Threats, sizeof(job->Threats));
    job->JobId = s_NextJobId++;
    job->Type = Type;
    job->Recursive = TRUE;
    wcsncpy_s(job->RootPath, MAX_PATH, Path ? Path : L"", _TRUNCATE);
    job->State = WkdScanState_Queued;
    job->Progress = 0;
    job->FilesScanned = 0;
    job->TotalFiles = 0;
    job->ThreatsFound = 0;
    job->ThreatCount = 0;
    job->Paused = 0;
    job->CancelEvent = cancelEvent;
    GetSystemTimeAsFileTime(&job->StartTime);
    job->EndTime = job->StartTime;

    *JobId = job->JobId;

    /* �����߳� */
    job->Thread = CreateThread(NULL, 0, ScanManager_ScanThread, job, 0, NULL);
    if (!job->Thread) {
        job->State = WkdScanState_Failed;
        job->CancelEvent = NULL;
        CloseHandle(cancelEvent);
        LeaveCriticalSection(&g_ScanManager.Lock);
        return STATUS_UNSUCCESSFUL;
    }
    InterlockedExchange(&job->State, WkdScanState_Running);

    LeaveCriticalSection(&g_ScanManager.Lock);

    return STATUS_SUCCESS;
}

NTSTATUS
ScanManager_CancelScan(
    _In_ ULONG JobId
    )
{
    ULONG i;

    if (!g_ScanManager.Initialized) return STATUS_INVALID_DEVICE_STATE;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        PWKD_SCAN_JOB job = &g_ScanManager.Jobs[i];
        if (job->JobId == JobId && job->State == WkdScanState_Running) {
            if (job->CancelEvent) {
                SetEvent(job->CancelEvent);
            }
            LeaveCriticalSection(&g_ScanManager.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ScanManager.Lock);

    return STATUS_NOT_FOUND;
}

NTSTATUS
ScanManager_GetScanState(
    _In_ ULONG      JobId,
    _Out_ PULONG    State
    )
{
    ULONG i;

    if (!State) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        if (g_ScanManager.Jobs[i].JobId == JobId) {
            *State = (ULONG)g_ScanManager.Jobs[i].State;
            LeaveCriticalSection(&g_ScanManager.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ScanManager.Lock);

    return STATUS_NOT_FOUND;
}

NTSTATUS
ScanManager_GetScanProgress(
    _In_ ULONG          JobId,
    _Out_opt_ PULONG    Progress,
    _Out_opt_ PULONG    Files,
    _Out_opt_ PULONG    Threats
    )
{
    ULONG i;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        PWKD_SCAN_JOB job = &g_ScanManager.Jobs[i];
        if (job->JobId == JobId) {
            if (Progress) *Progress = (ULONG)job->Progress;
            if (Files)    *Files    = (ULONG)job->FilesScanned;
            if (Threats)  *Threats  = (ULONG)job->ThreatsFound;
            LeaveCriticalSection(&g_ScanManager.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ScanManager.Lock);

    return STATUS_NOT_FOUND;
}

NTSTATUS
ScanManager_GetScanThreats(
    _In_ ULONG              JobId,
    _Out_ PWKD_SCAN_THREAT* Threats,
    _Out_ PULONG            Count
    )
{
    ULONG i;

    if (!Threats || !Count) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        PWKD_SCAN_JOB job = &g_ScanManager.Jobs[i];
        if (job->JobId == JobId) {
            *Threats = job->Threats;
            *Count = (ULONG)job->ThreatCount;
            LeaveCriticalSection(&g_ScanManager.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ScanManager.Lock);

    return STATUS_NOT_FOUND;
}

/**************************************************/
/*               ���� TTL ��ɨ�߳�                  */
/**************************************************/

static DWORD WINAPI
ScanManager_CacheCleanupThread(
    _In_ LPVOID Param
    )
{
    PWKD_SCAN_MANAGER mgr = (PWKD_SCAN_MANAGER)Param;
    FILETIME now;
    ULONGLONG nowUs;

    while (WaitForSingleObject(mgr->CacheCleanupEvent, WKD_SCAN_CACHE_TTL_MS) != WAIT_OBJECT_0) {
        ULONG i;
        GetSystemTimeAsFileTime(&now);
        nowUs = (ULONGLONG)now.dwHighDateTime << 32 | now.dwLowDateTime;

        for (i = 0; i < WKD_SCAN_CACHE_ENTRIES; i++) {
            ULONGLONG ts;
            if (!g_ScanCache[i].Active) continue;
            ts = (ULONGLONG)g_ScanCache[i].Timestamp.dwHighDateTime << 32 | g_ScanCache[i].Timestamp.dwLowDateTime;
            if (nowUs > ts && (nowUs - ts) > (ULONGLONG)WKD_SCAN_CACHE_TTL_MS * 10000) {
                g_ScanCache[i].Active = FALSE;
            }
        }
    }
    return 0;
}

/**************************************************/
/*               ��ʼ�� / ����                      */
/**************************************************/

NTSTATUS
ScanManager_Initialize(
    VOID
    )
{
    if (g_ScanManager.Initialized) {
        return STATUS_SUCCESS;
    }

    memset(&g_ScanManager, 0, sizeof(g_ScanManager));
    memset(g_ScanCache, 0, sizeof(g_ScanCache));

    InitializeCriticalSection(&g_ScanManager.Lock);
    for (ULONG i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        InitializeCriticalSection(&g_ScanManager.Jobs[i].Lock);
        g_ScanManager.Jobs[i].State = WkdScanState_Idle;
    }

    g_ScanManager.CacheCleanupEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_ScanManager.CacheCleanupEvent) {
        g_ScanManager.CacheCleanupThread = CreateThread(
            NULL, 0, ScanManager_CacheCleanupThread, &g_ScanManager, 0, NULL);
    }

    /* Exempts ͳһ���������� main.c ExemptsInitialize �������ع� #67��ԭ IocFileWhitelist_Initialize �Ƴ��� */

    g_ScanManager.Initialized = TRUE;
    printf("[ScanManager] Initialized\n");

    return STATUS_SUCCESS;
}

VOID
ScanManager_Cleanup(
    VOID
    )
{
    ULONG i;

    if (!g_ScanManager.Initialized) return;

    if (g_ScanManager.CacheCleanupEvent) {
        SetEvent(g_ScanManager.CacheCleanupEvent);
        if (g_ScanManager.CacheCleanupThread) {
            WaitForSingleObject(g_ScanManager.CacheCleanupThread, 2000);
            CloseHandle(g_ScanManager.CacheCleanupThread);
        }
        CloseHandle(g_ScanManager.CacheCleanupEvent);
    }

    /* ȡ�����ȴ����������� */
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        PWKD_SCAN_JOB job = &g_ScanManager.Jobs[i];
        if (job->State == WkdScanState_Running) {
            if (job->CancelEvent) SetEvent(job->CancelEvent);
            if (job->Thread) {
                WaitForSingleObject(job->Thread, 3000);
                CloseHandle(job->Thread);
                job->Thread = NULL;
            }
        }
        DeleteCriticalSection(&job->Lock);
    }

    DeleteCriticalSection(&g_ScanManager.Lock);
    memset(&g_ScanManager, 0, sizeof(g_ScanManager));
    printf("[ScanManager] Cleanup\n");
}

/**************************************************/
/*               �ص�����                           */
/**************************************************/

VOID
ScanManager_SetCallbacks(
    _In_opt_ WKD_SCAN_PROGRESS_CB ProgressCb,
    _In_opt_ WKD_SCAN_COMPLETE_CB CompleteCb
    )
{
    EnterCriticalSection(&g_ScanManager.Lock);
    g_ScanManager.ProgressCb = ProgressCb;
    g_ScanManager.CompleteCb = CompleteCb;
    LeaveCriticalSection(&g_ScanManager.Lock);
}

VOID
ScanManager_SetThreatCallback(
    _In_opt_ WKD_SCAN_THREAT_CB ThreatCb
    )
{
    EnterCriticalSection(&g_ScanManager.Lock);
    g_ScanManager.ThreatCb = ThreatCb;
    LeaveCriticalSection(&g_ScanManager.Lock);
}

/**************************************************/
/*               ������ɨ�� (SS ScanBatch)          */
/**************************************************/

static VOID
ScanManager_FillThreat(
    _Out_ PWKD_SCAN_THREAT Threat,
    _In_ PCWSTR            FilePath,
    _In_ PIOC_SCAN_RESULT  Result
    )
{
    RtlZeroMemory(Threat, sizeof(*Threat));
    wcsncpy_s(Threat->FilePath, MAX_PATH, FilePath, _TRUNCATE);

    if (Result->ThreatName[0]) {
        MultiByteToWideChar(CP_UTF8, 0, Result->ThreatName, -1,
                            Threat->ThreatName, 64);
    } else {
        wcsncpy_s(Threat->ThreatName, 64,
            (Result->FinalVerdict == DefIocVerdict_Malicious)
                ? L"Malware.Generic" : L"Threat.Suspicious", _TRUNCATE);
    }
    Threat->Severity = (Result->FinalVerdict == DefIocVerdict_Malicious)
                       ? WkdThreatSev_High
                       : (Result->FinalConfidence >= 60 ? WkdThreatSev_Medium : WkdThreatSev_Low);
    Threat->IsCleaned = FALSE;
}

NTSTATUS
ScanManager_ScanBatch(
    _In_ PCWSTR*            FilePaths,
    _In_ ULONG              Count,
    _Out_ PWKD_SCAN_THREAT  Threats,
    _Out_ PULONG            ThreatCount
    )
{
    ULONG i;
    ULONG n = 0;

    if (!FilePaths || !Threats || !ThreatCount) return STATUS_INVALID_PARAMETER;
    *ThreatCount = 0;

    for (i = 0; i < Count; i++) {
        IOC_SCAN_RESULT r;
        if (n >= WKD_SCAN_MAX_THREATS) break;
        if (!FilePaths[i]) continue;

        ScanManager_ScanFileDirect(FilePaths[i], &r);
        InterlockedIncrement(&g_ScanManager.FilesScanned);

        if (r.FinalVerdict >= DefIocVerdict_Suspicious) {
            ScanManager_FillThreat(&Threats[n], FilePaths[i], &r);
            n++;
        }
    }
    *ThreatCount = n;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               ������ͣ/�ָ�                      */
/**************************************************/

NTSTATUS
ScanManager_PauseScan(
    _In_ ULONG              JobId
    )
{
    ULONG i;

    if (!g_ScanManager.Initialized) return STATUS_INVALID_DEVICE_STATE;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        PWKD_SCAN_JOB job = &g_ScanManager.Jobs[i];
        if (job->JobId == JobId && job->State == WkdScanState_Running) {
            InterlockedExchange((PLONG)&job->Paused, 1);
            InterlockedExchange(&job->State, WkdScanState_Paused);
            LeaveCriticalSection(&g_ScanManager.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ScanManager.Lock);
    return STATUS_NOT_FOUND;
}

NTSTATUS
ScanManager_ResumeScan(
    _In_ ULONG              JobId
    )
{
    ULONG i;

    if (!g_ScanManager.Initialized) return STATUS_INVALID_DEVICE_STATE;

    EnterCriticalSection(&g_ScanManager.Lock);
    for (i = 0; i < WKD_SCAN_MAX_JOBS; i++) {
        PWKD_SCAN_JOB job = &g_ScanManager.Jobs[i];
        if (job->JobId == JobId && job->State == WkdScanState_Paused) {
            InterlockedExchange((PLONG)&job->Paused, 0);
            InterlockedExchange(&job->State, WkdScanState_Running);
            LeaveCriticalSection(&g_ScanManager.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ScanManager.Lock);
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*               �ڴ滺��ɨ�� (SS ScanMemory)       */
/**************************************************/

NTSTATUS
ScanManager_ScanMemoryBuffer(
    _In_ const BYTE*        Buf,
    _In_ ULONG              Len,
    _Out_ PIOC_SCAN_RESULT  Result
    )
{
    DEF_SHA256_HASH hash;
    CHAR hex[65];
    BOOLEAN malicious = FALSE;

    if (!Buf || !Result || Len == 0) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    if (!IocScanner_ComputeBufferSha256(Buf, Len, &hash)) {
        Result->FinalVerdict = DefIocVerdict_Unknown;
        return STATUS_SUCCESS;
    }
    ScanManager_HashToHex(&hash, hex);

    if (ScanManager_CacheLookup(hex, NULL, Result)) return STATUS_SUCCESS;

    IocScanner_QueryHash(&hash, &malicious);
    if (malicious) {
        Result->HashChecked = TRUE;
        Result->HashVerdict = DefIocVerdict_Malicious;
        Result->FinalVerdict = DefIocVerdict_Malicious;
        Result->FinalConfidence = 100;
        strncpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Hash.Malicious", _TRUNCATE);
    } else {
        Result->FinalVerdict = DefIocVerdict_Clean;
    }

    ScanManager_CacheStore(hex, NULL, Result);
    InterlockedIncrement64(&g_ScanManager.TotalScans);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               ����ɨ�� (SS ScanProcess)          */
/**************************************************/

NTSTATUS
ScanManager_ScanProcess(
    _In_ ULONG              Pid,
    _Out_ PIOC_SCAN_RESULT  Result
    )
{
    HANDLE h;
    WCHAR path[MAX_PATH];
    DWORD size = MAX_PATH;

    if (!Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    if (Pid == 0 || Pid == 4) return STATUS_SUCCESS;

    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!h) return STATUS_NOT_FOUND;

    if (QueryFullProcessImageNameW(h, 0, path, &size)) {
        ScanManager_ScanFileDirect(path, Result);
    } else {
        Result->FinalVerdict = DefIocVerdict_Unknown;
    }
    CloseHandle(h);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               ȫ����ö��ɨ��                     */
/**************************************************/

NTSTATUS
ScanManager_ScanAllProcesses(
    _Out_ ULONG*            Pids,
    _In_ ULONG              MaxCount,
    _Out_ PULONG            Count
    )
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    ULONG n = 0;

    if (!Pids || !Count || MaxCount == 0) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (n < MaxCount) Pids[n++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    *Count = n;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               ����Ԥ�� (SS WarmCache)            */
/**************************************************/

VOID
ScanManager_WarmCache(
    _In_ PCWSTR*            Paths,
    _In_ ULONG              Count
    )
{
    ULONG i;

    if (!Paths || !g_ScanManager.Initialized) return;
    for (i = 0; i < Count; i++) {
        IOC_SCAN_RESULT r;
        if (Paths[i]) ScanManager_ScanFileDirect(Paths[i], &r);
    }
}

/**************************************************/
/*               �����Բ� (SS SelfTest)             */
/**************************************************/

BOOLEAN
ScanManager_SelfTest(
    VOID
    )
{
    IOC_SCAN_RESULT tr, got;
    WKD_EXCLUSION_RULE rule;
    static const char testHash[] =
        "0000000000000000000000000000000000000000000000000000000000000000";

    if (!g_ScanManager.Initialized) return FALSE;

    /* 1. �����ȡ */
    RtlZeroMemory(&tr, sizeof(tr));
    tr.FinalVerdict = DefIocVerdict_Clean;
    ScanManager_CacheStore(testHash, NULL, &tr);
    if (!ScanManager_CacheLookup(testHash, NULL, &got)) return FALSE;

    /* 2. �ų����� */
    RtlZeroMemory(&rule, sizeof(rule));
    rule.Type = WkdExclType_ProcessName;
    wcsncpy_s(rule.Pattern, MAX_PATH, L"selftest_excl.tmp", _TRUNCATE);
    rule.Enabled = TRUE;
    ScanManager_AddExclusion(&rule);
    if (!ScanManager_IsExcluded(L"C:\\selftest\\selftest_excl.tmp")) return FALSE;
    InterlockedExchange(&g_ScanManager.ExclusionCount, 0);

    return TRUE;
}

/**************************************************/
/*   �����첽/�ص��������� (SS FileReputation)       */
/*  �����渲��, δ������ˮ�� (ScanJob �Ѹ�������)    */
/**************************************************/

/* �첽����ص� (SS ReputationCallback ����, ������) */
typedef VOID (*WKD_REP_CALLBACK)(_In_ PCWSTR FilePath, _In_ PIOC_SCAN_RESULT Result);

/* �������� (SS MAX_CONCURRENT_ASYNC_CHECKS=64, ������) */
#define WKD_REP_MAX_ASYNC_CHECKS  64

#pragma warning(push)
#pragma warning(disable:4505)

/* -- �첽������� (SS CheckFileAsync/CheckFilesAsync L577-646, ������) -----
 * ����: ���ļ��첽������� + �������� + ���Źرա�
 * ������ԭ��: wkd ScanManager 4 �� ScanJob ״̬���Ѹ�������ɨ��; ���ļ�
 *   ͬ������ ScanFileDirect �������¼��������� (�첽�����̰߳�װͬ��)�� */
static NTSTATUS
ScanManager_ReputationAsync(
    _In_ PCWSTR FilePath
    )
{
    IOC_SCAN_RESULT r;
    if (!FilePath) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(&r, sizeof(r));
    return ScanManager_ScanFileDirect(FilePath, &r);
}

/* -- Unknown �ļ��ص�ע��� (SS RegisterUnknownFileCallback L1358-1379, ������)
 * ����: Unknown �ȼ��ļ�֪ͨ���� (�ص� ID ����)��
 * ������ԭ��: wkd �澯�ַ��� ALPC ���� (VerdictEngine �� UI ֪ͨ), �ص�ע���
 *   �Ǳ�Ҫ; Unknown �ȼ����������� RepStats.UnknownFiles ά�ȡ� */
static ULONG
ScanManager_RegisterUnknownCallback(
    _In_opt_ WKD_REP_CALLBACK Callback
    )
{
    UNREFERENCED_PARAMETER(Callback);
    return 1;
}

#pragma warning(pop)
