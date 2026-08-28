/**************************************************/
/*  WkDefender IOA — 持久化行为检测实现             */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdatePersistenceScore (BehaviorAnalyzer.cpp     */
/*  L1034-1149) + IsPersistenceRegistryPath          */
/*  (L2779-2808)。功能重实现, 非源码复制。           */
/*                                                  */
/*  死代码: 无调用者, 未接入 IoaObserve 流水线。      */
/**************************************************/

#include "IoaPersistenceDetect.h"
#include "../DefendTypes.h"

#include <wchar.h>
#include <ctype.h>

/**************************************************/
/*           内部辅助函数 (文件内静态)                */
/**************************************************/

static
BOOLEAN
IoaPersist_IsPersistencePath(
    _In_ PCWSTR KeyPath
    )
/*++
Routine Description:
    判断注册表路径是否命中持久化位置库 (大小写不敏感子串匹配)。

Arguments:
    KeyPath — 注册表完整路径。

Return Value:
    TRUE 持久化位置 / FALSE 否。
--*/
{
    WCHAR lower[DEF_MAX_PATH];
    size_t len;

    if (!KeyPath || !KeyPath[0]) return FALSE;

    len = wcslen(KeyPath);
    if (len >= DEF_MAX_PATH) return FALSE;

    for (size_t i = 0; i < len; i++) {
        lower[i] = (WCHAR)towlower(KeyPath[i]);
    }
    lower[len] = L'\0';

    for (ULONG i = 0; i < WKD_PERSIST_PATH_COUNT; i++) {
        if (wcsstr(lower, g_WkdPersistencePaths[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
IoaPersist_ContainsSubstr(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR Substr
    )
/*++
Routine Description:
    大小写不敏感子串包含判断 (IFEO/AppInit 分级加分用)。

Arguments:
    KeyPath — 注册表完整路径。
    Substr  — 待匹配子串。

Return Value:
    TRUE 包含 / FALSE 否。
--*/
{
    WCHAR lower[DEF_MAX_PATH];
    WCHAR subLower[64];
    size_t len, subLen;

    if (!KeyPath || !Substr) return FALSE;

    len = wcslen(KeyPath);
    subLen = wcslen(Substr);
    if (len >= DEF_MAX_PATH || subLen >= 64) return FALSE;

    for (size_t i = 0; i < len; i++) lower[i] = (WCHAR)towlower(KeyPath[i]);
    lower[len] = L'\0';
    for (size_t i = 0; i < subLen; i++) subLower[i] = (WCHAR)towlower(Substr[i]);
    subLower[subLen] = L'\0';

    return wcsstr(lower, subLower) != NULL;
}

/*
 * 文件系统持久化路径判定（对标 SS PreSetInfo g_SensitivePaths 持久化部分，
 *   依赖驱动文件事件带路径 + 扩展名）：
 *     ① 启动文件夹 (\Startup\) — 用户/全局 Startup 目录写入，强信号
 *     ② ntuser.dat — 用户配置篡改
 *     ③ DLL/驱动写入系统目录 (\System32\ / SysWOW64\ / drivers\) — 植入信号
 */
static
BOOLEAN
IoaPersist_IsFilePersistPath(
    _In_opt_ PCWSTR TargetPath,
    _In_opt_ PCWSTR FileExtension
    )
{
    if (!TargetPath || !TargetPath[0]) {
        return FALSE;
    }

    /* 启动文件夹（AppData\...\Startup + ProgramData\...\Startup） */
    if (IoaPersist_ContainsSubstr(TargetPath, L"\\startup\\")) {
        return TRUE;
    }
    /* 用户配置文件 */
    if (IoaPersist_ContainsSubstr(TargetPath, L"ntuser.dat")) {
        return TRUE;
    }
    /* DLL/驱动植入系统目录 */
    if (FileExtension && FileExtension[0] != L'\0') {
        if (_wcsicmp(FileExtension, L".dll") == 0 ||
            _wcsicmp(FileExtension, L".sys") == 0) {
            if (IoaPersist_ContainsSubstr(TargetPath, L"\\windows\\system32\\") ||
                IoaPersist_ContainsSubstr(TargetPath, L"\\windows\\syswow64\\")) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaPersistence_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    )
/*++
Routine Description:
    持久化行为评分。依据事件类型分支累计 State 计数器,
    返回得分增量, 命中时置位 PERSISTENCE 检测标志。

Arguments:
    State — 进程级行为状态 (读写)。
    Evt   — 归一化行为事件视图 (只读)。

Return Value:
    本次事件得分增量 [0,100]。
--*/
{
    ULONG scoreAdd = 0;

    if (!State || !Evt) return 0;

    switch (Evt->Type) {
        case WKD_EVT_REG_SET_VALUE:
        case WKD_EVT_REG_CREATE_KEY: {
            if (IoaPersist_IsPersistencePath(Evt->TargetPath)) {
                State->PersistenceHits++;
                scoreAdd += WKD_PERSIST_RUNKEY_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_PERSISTENCE;

                /* IFEO 劫持尤为可疑 */
                if (IoaPersist_ContainsSubstr(Evt->TargetPath,
                        WKD_PERSIST_IFEO_SUBSTR)) {
                    scoreAdd += WKD_PERSIST_IFEO_SCORE;
                }
                /* AppInit DLLs */
                if (IoaPersist_ContainsSubstr(Evt->TargetPath,
                        WKD_PERSIST_APPINIT_SUBSTR)) {
                    scoreAdd += WKD_PERSIST_APPINIT_SCORE;
                }
            }
            break;
        }

        case WKD_EVT_TASK_CREATE: {
            State->TaskCreates++;
            scoreAdd += WKD_PERSIST_TASK_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
            break;
        }

        case WKD_EVT_SERVICE_INSTALL: {
            State->ServiceInstalls++;
            scoreAdd += WKD_PERSIST_SERVICE_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
            break;
        }

        case WKD_EVT_WMI_SUBSCRIPTION: {
            State->WmiSubscriptions++;
            scoreAdd += WKD_PERSIST_WMI_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
            break;
        }

        case WKD_EVT_BOOT_CONFIG_MODIFY: {
            State->BootConfigModifies++;
            scoreAdd += WKD_PERSIST_BOOT_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
            break;
        }

        /* 文件系统持久化（对标 SS PreSetInfo 持久化部分 + 驱动文件事件补源 0x1301/0x1302）：
         * 启动文件夹写入 / ntuser.dat 篡改 / DLL·驱动植入系统目录 */
        case WKD_EVT_FILE_WRITE:
        case WKD_EVT_FILE_CREATE: {
            if (IoaPersist_IsFilePersistPath(Evt->TargetPath, Evt->FileExtension)) {
                State->PersistenceHits++;
                if (IoaPersist_ContainsSubstr(Evt->TargetPath, L"\\startup\\")) {
                    scoreAdd += WKD_PERSIST_FILE_STARTUP_SCORE;
                } else if (IoaPersist_ContainsSubstr(Evt->TargetPath, L"ntuser.dat")) {
                    scoreAdd += WKD_PERSIST_FILE_PROFILE_SCORE;
                } else {
                    scoreAdd += WKD_PERSIST_FILE_SYSDIR_SCORE;
                }
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
            }
            break;
        }

        default:
            break;
    }

    if (scoreAdd > 0) {
        /* 并发安全重构 2026-08-23：饱和累加保 [0,100] 上限原子发布 */
        { LONG old, nw; do { old = State->MaliceScore; nw = min(old + scoreAdd, 100); }
          while (InterlockedCompareExchange(&State->MaliceScore, nw, old) != old); }
    }
    return min(scoreAdd, 100);
}

/**************************************************/
/*           目录级投放判定 (DirectoryMonitor 融合)  */
/**************************************************/

ULONG
IoaPersistence_CheckDirectoryDrop(
    _In_ PCWSTR DirPath,
    _In_ PCWSTR FileName,
    _In_opt_ PCWSTR FileExtension
    )
/*++
Routine Description:
    目录级持久化投放判定 (死代码, DirectoryMonitor 迁移 2026-08)。
    RDCW 目录事件无进程上下文, 无法进 WKD_BEHAVIOR_EVENT 进程级评分链;
    本入口按监控目录路径 + 新条目文件名判定持久化投放, 返回评分增量,
    供目录监控回调消费构造 NULL-NodeId 告警。复用 IoaPersist_IsFilePersistPath
    判定 (启动夹/ntuser.dat/系统目录 DLL·SYS 植入)。

Arguments:
    DirPath      — 监控目录路径 (RDCW 事件 Path)。
    FileName     — 新条目文件名。
    FileExtension— 扩展名 (含前导点, 可空)。

Return Value:
    本次投放评分增量 [0,100] (0 = 非持久化投放)。
--*/
{
    WCHAR fullPath[DEF_MAX_PATH + 512];
    size_t dl;
    ULONG scoreAdd = 0;

    if (!DirPath || !DirPath[0] || !FileName || !FileName[0]) {
        return 0;
    }

    dl = wcslen(DirPath);
    if (dl >= DEF_MAX_PATH) return 0;
    if (wcslen(FileName) >= 512) return 0;

    wcscpy_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), DirPath);
    if (dl > 0 && fullPath[dl - 1] != L'\\' && fullPath[dl - 1] != L'/') {
        wcscat_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), L"\\");
    }
    wcscat_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), FileName);

    if (IoaPersist_IsFilePersistPath(fullPath, FileExtension)) {
        if (IoaPersist_ContainsSubstr(fullPath, L"\\startup\\")) {
            scoreAdd = WKD_PERSIST_FILE_STARTUP_SCORE;
        } else if (IoaPersist_ContainsSubstr(fullPath, L"ntuser.dat")) {
            scoreAdd = WKD_PERSIST_FILE_PROFILE_SCORE;
        } else {
            scoreAdd = WKD_PERSIST_FILE_SYSDIR_SCORE;
        }
    }

    return min(scoreAdd, 100);
}
