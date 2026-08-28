/**************************************************/
/*  WkDefender IOA — 勒索软件行为检测                */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateRansomwareScore (BehaviorAnalyzer.cpp      */
/*  L790-921) + 知识库 (L181-194/L225-230)。          */
/*  功能重实现, 非源码复制。                          */
/*                                                  */
/*  接线 (2026-08 FBE 迁移): 已由 IoaObserve 阶段    */
/*  4.9c 调用 (IoaEngine.c), 默认门控                */
/*  g_IoaFileBehaviorAnalyzerEnabled=FALSE 关闭。    */
/*  高熵分支依赖驱动 minifilter 补 FileEntropy       */
/*  (当前 FileEntropy=0 不触发); 勒索扩展名变更/     */
/*  大量删除/勒索信/Canary 分支有效。                */
/*                                                  */
/*  目录级入口 (2026-08 DirectoryMonitor 迁移):      */
/*  IoaRansomware_CheckDirectoryActivity — RDCW 目录 */
/*  事件无 PID 无法进进程级评分, 本入口按目录级      */
/*  rename/delete 批量变化判定 (勒索扩展名重命名/    */
/*  大量删除), 死代码待 main.c 回调接线激活。        */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    高熵写 3/次, >=50次 +20 (T1486)                */
/*    Canary 触碰 +50, 勒索信 +60, 速率>10/s +5      */
/*    扩展名变更 +8 (T1486), 大量删除 +5 (T1485)     */
/*    卷影副本删除 +40 (T1490)                       */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_FILE_CREATE         200
#define WKD_EVT_FILE_WRITE          203
#define WKD_EVT_FILE_RENAME         205
#define WKD_EVT_FILE_DELETE         204
#define WKD_EVT_SHADOW_COPY_DELETE  804

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_RANSOM_FILE_THRESHOLD   50      /* SS RANSOMWARE_FILE_THRESHOLD */
#define WKD_RANSOM_RATE_THRESHOLD   10      /* SS RANSOMWARE_RATE_THRESHOLD (文件/秒) */
#define WKD_RANSOM_ENTROPY_Q16      491520  /* 7.5 << 16 (SS ENCRYPTION_ENTROPY_THRESHOLD) */

#define WKD_RANSOM_WRITE_SCORE      3       /* 单次高熵写 */
#define WKD_RANSOM_ENC_BONUS        20      /* 高熵写达阈值追加 */
#define WKD_RANSOM_CANARY_SCORE     50      /* SS CANARY_FILE_SCORE */
#define WKD_RANSOM_NOTE_SCORE       60      /* SS RANSOM_NOTE_SCORE */
#define WKD_RANSOM_RATE_SCORE       5       /* 文件修改速率超阈值 */
#define WKD_RANSOM_RENAME_SCORE     8       /* 勒索扩展名重命名 */
#define WKD_RANSOM_MASSDELETE_SCORE 5       /* 大量删除 */
#define WKD_RANSOM_SHADOW_SCORE     40      /* SS SHADOW_COPY_DELETE_SCORE */
#define WKD_RANSOM_DOUBLEEXT_SCORE  80      /* SS PostWrite 双扩展名 +80 (T1036) */

/**************************************************/
/*   勒索扩展名知识库 (SS BehaviorAnalyzer L181-194) */
/**************************************************/

static const PCWSTR g_WkdRansomExtensions[] = {
    L".encrypted", L".locked",  L".crypto",  L".crypt",   L".locky",
    L".cerber",    L".zepto",   L".thor",    L".aesir",   L".osiris",
    L".zzzzz",     L".micro",   L".mp3",     L".vvv",     L".ccc",
    L".abc",       L".xxx",     L".ttt",     L".ecc",     L".ezz",
    L".aaa",       L".xtbl",    L".crysis",  L".cryp1",   L".crypz",
    L".wallet",    L".petya",   L".golden",  L".dharma",  L".arena",
    L".bip",       L".combo",   L".gamma",   L".hese",    L".gero",
    L".mado",      L".peta",    L".pedro",   L".nesa",    L".coot",
    L".derp",      L".meka",    L".toec",    L".mosk",    L".lotep",
    L".grod",      L".nols",    L".werd",    L".bora",    L".reco",
    L".kuub",      L".mmnn",    L".ooss",    L".noos",    L".karl",
    L".shadow",    L".djvu",    L".stop",    L".puma",
};
#define WKD_RANSOM_EXT_COUNT \
    (sizeof(g_WkdRansomExtensions) / sizeof(g_WkdRansomExtensions[0]))

/**************************************************/
/*   勒索信模式知识库 (SS L225-230 + IsRansomNote    */
/*   静态数组 L2751-2758, 合并去重)                 */
/**************************************************/

static const PCWSTR g_WkdRansomNotePatterns[] = {
    L"readme",               L"_readme",
    L"how_to_decrypt",       L"how_to_recover",
    L"restore_files",        L"decrypt_instructions",
    L"help_decrypt",         L"payment",
    L"ransom",               L"your_files",
    L"recovery_key",         L"important_read_me",
    L"attention",            L"warning",
    L"decrypt_info",         L"#decrypt",
    L"recover_files",        L"all_files_encrypted",
};
#define WKD_RANSOM_NOTE_COUNT \
    (sizeof(g_WkdRansomNotePatterns) / sizeof(g_WkdRansomNotePatterns[0]))

/**************************************************/
/*   双扩展名伪装知识库 (SS PostWrite              */
/*   g_DoubleExtensions 19 条, T1036)              */
/**************************************************/

static const PCWSTR g_WkdRansomDoubleExtensions[] = {
    L".pdf.exe", L".doc.exe", L".docx.exe", L".xls.exe", L".xlsx.exe",
    L".jpg.exe", L".png.exe", L".txt.exe", L".zip.exe", L".mp3.exe",
    L".mp4.exe", L".avi.exe", L".pdf.scr", L".doc.scr", L".jpg.scr",
    L".pdf.js",  L".doc.js",  L".pdf.vbs", L".doc.vbs",
};
#define WKD_RANSOM_DOUBLEEXT_COUNT \
    (sizeof(g_WkdRansomDoubleExtensions) / sizeof(g_WkdRansomDoubleExtensions[0]))

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaRansomware_UpdateScore — 勒索软件行为评分。
 *
 * 依据事件类型分支累计 State 计数器, 返回得分增量, 并在
 * 达阈值时置位 State->DetectionFlags 对应 DEF_BEHAVIOR_FLAG。
 * 接线: IoaObserve 阶段4.9c (门控 g_IoaFileBehaviorAnalyzerEnabled)。
 *
 * 参数:
 *   State — 进程级行为状态 (读写计数器/检测标志)。
 *   Evt   — 归一化行为事件视图 (只读)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaRansomware_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    );

/**************************************************/
/*   目录级批量变化判定 (DirectoryMonitor 迁移)      */
/**************************************************/

/*
 * 目录级勒索聚合状态 (RDCW 事件无进程上下文, 按目录维度聚合)。
 * 由目录监控回调持有 (main.c OnDirectoryEvent), 每个监控目录一份。
 * WindowStart 预留窗口化 (当前仅累计计数, 死代码标注)。
 */
typedef struct _WKD_DIR_RANSOM_STATE {
    ULONG         RenameCount;      /* 时间窗内重命名数 */
    ULONG         DeleteCount;      /* 时间窗内删除数 */
    ULONG         RansomRenameHits; /* 勒索扩展名重命名命中 */
    LARGE_INTEGER WindowStart;      /* 窗口起点 (预留) */
} WKD_DIR_RANSOM_STATE, *PWKD_DIR_RANSOM_STATE;

/*
 * IoaRansomware_CheckDirectoryActivity — 目录级批量变化判定 (死代码)。
 *
 * RDCW 目录事件无进程上下文, 无法进 WKD_BEHAVIOR_EVENT 进程级评分链。
 * 本入口按目录级 rename/delete 批量变化判定:
 *   Rename 且文件名命中 g_WkdRansomExtensions → WKD_RANSOM_RENAME_SCORE(8)
 *   Delete 累计 > WKD_RANSOM_FILE_THRESHOLD(50) → WKD_RANSOM_MASSDELETE_SCORE(5)
 * 返回评分增量, 供目录监控回调消费构造 NULL-NodeId 告警。
 *
 * 死代码: 待 DirectoryMonitor 回调接线激活 (g_IoaDirectoryMonitorEnabled)。
 *
 * 参数:
 *   State    - 目录级聚合状态 (读写计数器)。
 *   IsRename - 本次事件是否重命名。
 *   IsDelete - 本次事件是否删除。
 *   FileName - 变化的文件名 (勒索扩展名判定, 可空)。
 *
 * 返回值: 本次事件评分增量 [0,100]。
 */
ULONG
IoaRansomware_CheckDirectoryActivity(
    _Inout_ PWKD_DIR_RANSOM_STATE State,
    _In_    BOOLEAN  IsRename,
    _In_    BOOLEAN  IsDelete,
    _In_opt_ PCWSTR  FileName
    );
