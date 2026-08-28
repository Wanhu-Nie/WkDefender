/**************************************************/
/*  WkDefender IOA — 勒索软件行为检测实现            */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateRansomwareScore (BehaviorAnalyzer.cpp      */
/*  L790-921) + IsRansomNotePattern (L2740-2777)。   */
/*  功能重实现, 非源码复制。                         */
/*                                                  */
/*  接线 (2026-08 FBE 迁移): IoaObserve 阶段4.9c     */
/*  已调用 (门控 g_IoaFileBehaviorAnalyzerEnabled,   */
/*  默认 FALSE 关闭)。高熵分支依赖驱动 minifilter    */
/*  补 FileEntropy。                                 */
/**************************************************/

#include "IoaRansomwareDetect.h"
#include "../DefendTypes.h"

#include <wchar.h>
#include <ctype.h>

/**************************************************/
/*           内部辅助函数 (文件内静态)                */
/**************************************************/

static
BOOLEAN
IoaRansom_IsRansomExtension(
    _In_ PCWSTR Extension
    )
/*++
Routine Description:
    判断文件扩展名是否命中勒索扩展名知识库 (大小写不敏感)。

Arguments:
    Extension — 扩展名字符串 (含前导点, 如 L".djvu")。

Return Value:
    TRUE 命中 / FALSE 未命中。
--*/
{
    WCHAR lower[32];
    size_t len;

    if (!Extension || !Extension[0]) return FALSE;

    len = wcslen(Extension);
    if (len >= 32) return FALSE;

    for (size_t i = 0; i < len; i++) {
        lower[i] = (WCHAR)towlower(Extension[i]);
    }
    lower[len] = L'\0';

    for (ULONG i = 0; i < WKD_RANSOM_EXT_COUNT; i++) {
        if (_wcsicmp(lower, g_WkdRansomExtensions[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
IoaRansom_IsRansomNote(
    _In_ PCWSTR TargetPath
    )
/*++
Routine Description:
    判断路径文件名是否命中勒索信模式 (对齐 SS IsRansomNotePattern)。

Arguments:
    TargetPath — 文件完整路径。

Return Value:
    TRUE 勒索信 / FALSE 否。
--*/
{
    WCHAR lower[DEF_MAX_PATH];
    WCHAR filename[DEF_MAX_PATH];
    const WCHAR* lastSlash;
    size_t len;

    if (!TargetPath || !TargetPath[0]) return FALSE;

    len = wcslen(TargetPath);
    if (len >= DEF_MAX_PATH) return FALSE;

    for (size_t i = 0; i < len; i++) {
        lower[i] = (WCHAR)towlower(TargetPath[i]);
    }
    lower[len] = L'\0';

    lastSlash = wcsrchr(lower, L'\\');
    wcscpy_s(filename, DEF_MAX_PATH,
             (lastSlash != NULL) ? (lastSlash + 1) : lower);

    for (ULONG i = 0; i < WKD_RANSOM_NOTE_COUNT; i++) {
        if (wcsstr(filename, g_WkdRansomNotePatterns[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * 双扩展名伪装判定（对齐 SS PostWrite PwpCheckDoubleExtension，T1036）：
 *   路径尾部命中 19 条双扩展名模式（invoice.pdf.exe 经典模式）。
 */
static
BOOLEAN
IoaRansom_IsDoubleExtension(
    _In_ PCWSTR TargetPath
    )
{
    WCHAR lower[DEF_MAX_PATH];
    size_t len;

    if (!TargetPath || !TargetPath[0]) {
        return FALSE;
    }

    len = wcslen(TargetPath);
    if (len >= DEF_MAX_PATH) {
        return FALSE;
    }

    for (size_t i = 0; i < len; i++) {
        lower[i] = (WCHAR)towlower(TargetPath[i]);
    }
    lower[len] = L'\0';

    for (ULONG i = 0; i < WKD_RANSOM_DOUBLEEXT_COUNT; i++) {
        size_t patLen = wcslen(g_WkdRansomDoubleExtensions[i]);
        if (patLen <= len &&
            _wcsicmp(lower + len - patLen, g_WkdRansomDoubleExtensions[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaRansomware_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    )
/*++
Routine Description:
    勒索软件行为评分。依据事件类型分支累计 State 计数器,
    返回得分增量, 达阈值时置位 DetectionFlags。

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
        case WKD_EVT_FILE_WRITE:
        case WKD_EVT_FILE_CREATE: {
            /* 高熵写检测 */
            if (Evt->FileEntropy >= WKD_RANSOM_ENTROPY_Q16) {
                State->HighEntropyWrites++;
                scoreAdd += WKD_RANSOM_WRITE_SCORE;
                if (State->HighEntropyWrites >= WKD_RANSOM_FILE_THRESHOLD) {
                    scoreAdd += WKD_RANSOM_ENC_BONUS;
                    State->DetectionFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
                }
            }

            /* Canary 蜜罐触碰 */
            if (Evt->IsCanary) {
                State->CanaryTouched++;
                scoreAdd += WKD_RANSOM_CANARY_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
            }

            /* 勒索信创建 */
            if (IoaRansom_IsRansomNote(Evt->TargetPath)) {
                State->RansomNoteHits++;
                scoreAdd += WKD_RANSOM_NOTE_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
            }

            /* 双扩展名伪装 (对齐 SS PostWrite g_DoubleExtensions, T1036) */
            if (IoaRansom_IsDoubleExtension(Evt->TargetPath)) {
                scoreAdd += WKD_RANSOM_DOUBLEEXT_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_MASQUERADE;
            }

            /* 文件修改速率 (对齐 SS RANSOMWARE_RATE_THRESHOLD) */
            if (State->LastFileEventTime.QuadPart != 0) {
                LARGE_INTEGER now;
                LONGLONG elapsedMs;
                GetSystemTimeAsFileTime((PFILETIME)&now);
                elapsedMs = (now.QuadPart - State->LastFileEventTime.QuadPart) / 10000;
                if (elapsedMs > 0) {
                    double rate = 1000.0 / (double)elapsedMs;
                    if (rate > (double)WKD_RANSOM_RATE_THRESHOLD) {
                        scoreAdd += WKD_RANSOM_RATE_SCORE;
                    }
                }
            }
            GetSystemTimeAsFileTime((PFILETIME)&State->LastFileEventTime);
            break;
        }

        case WKD_EVT_FILE_RENAME: {
            State->FileRenames++;
            if (IoaRansom_IsRansomExtension(Evt->FileExtension)) {
                State->ExtensionChanges++;
                scoreAdd += WKD_RANSOM_RENAME_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
            }
            break;
        }

        case WKD_EVT_FILE_DELETE: {
            State->FilesDeleted++;
            if (State->FilesDeleted > WKD_RANSOM_FILE_THRESHOLD) {
                scoreAdd += WKD_RANSOM_MASSDELETE_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_DELETE;
            }
            break;
        }

        case WKD_EVT_SHADOW_COPY_DELETE: {
            State->ShadowCopyOps++;
            scoreAdd += WKD_RANSOM_SHADOW_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_SHADOW;
            break;
        }

        default:
            break;
    }

    if (scoreAdd > 0) {
        /* 并发安全重构 2026-08-23：饱和累加依赖旧值，用饱和 CAS 循环
         * 保 [0,100] 上限契约 + 原子发布。 */
        LONG old, nw;
        do {
            old = State->MaliceScore;
            nw = min(old + scoreAdd, 100);
        } while (InterlockedCompareExchange(&State->MaliceScore, nw, old) != old);
    }
    return min(scoreAdd, 100);
}

/**************************************************/
/*           目录级批量变化判定 (DirectoryMonitor 融合) */
/**************************************************/

ULONG
IoaRansomware_CheckDirectoryActivity(
    _Inout_ PWKD_DIR_RANSOM_STATE State,
    _In_    BOOLEAN  IsRename,
    _In_    BOOLEAN  IsDelete,
    _In_opt_ PCWSTR  FileName
    )
/*++
Routine Description:
    目录级批量变化判定 (死代码, DirectoryMonitor 迁移 2026-08)。
    RDCW 目录事件无进程上下文, 无法进 WKD_BEHAVIOR_EVENT 进程级评分链;
    本入口按目录级 rename/delete 批量变化判定 (勒索扩展名重命名 +
    大量删除), 返回评分增量供目录监控回调消费构造 NULL-NodeId 告警。
    复用 g_WkdRansomExtensions / WKD_RANSOM_RENAME_SCORE /
    WKD_RANSOM_MASSDELETE_SCORE 常量。

Arguments:
    State    — 目录级聚合状态 (读写计数器)。
    IsRename — 本次事件是否重命名。
    IsDelete — 本次事件是否删除。
    FileName — 变化的文件名 (勒索扩展名判定, 可空)。

Return Value:
    本次事件评分增量 [0,100]。
--*/
{
    ULONG scoreAdd = 0;

    if (!State) return 0;

    if (IsRename) {
        State->RenameCount++;
        if (FileName && FileName[0]) {
            PCWSTR dot = wcsrchr(FileName, L'.');
            if (dot && IoaRansom_IsRansomExtension(dot)) {
                State->RansomRenameHits++;
                scoreAdd += WKD_RANSOM_RENAME_SCORE;
            }
        }
    }

    if (IsDelete) {
        State->DeleteCount++;
        if (State->DeleteCount > WKD_RANSOM_FILE_THRESHOLD) {
            scoreAdd += WKD_RANSOM_MASSDELETE_SCORE;
        }
    }

    return min(scoreAdd, 100);
}
