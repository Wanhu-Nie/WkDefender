/**************************************************/
/*  WkDefender IOA — 持久化行为检测 (死代码)         */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdatePersistenceScore (BehaviorAnalyzer.cpp     */
/*  L1034-1149) + 持久化路径库 (L196-212,           */
/*  IsPersistenceRegistryPath L2779-2808)。          */
/*  功能重实现, 非源码复制。                          */
/*                                                  */
/*  死代码: 依赖驱动注册表事件源未激活,               */
/*  检测逻辑完整但不接入流水线。                      */
/*  待接通: 驱动补 CmRegisterCallback 后激活。        */
/*                                                  */
/*  目录级入口 (2026-08 DirectoryMonitor 迁移):      */
/*  IoaPersistence_CheckDirectoryDrop — RDCW 目录    */
/*  事件无 PID 无法进进程级评分, 本入口按目录路径+   */
/*  文件名判定持久化投放 (启动夹/ntuser.dat/系统目录  */
/*  DLL 植入), 死代码待 main.c 回调接线激活。         */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    Run键 +30 (T1547.001), IFEO +15 (T1546.012)    */
/*    AppInit +10 (T1546.010), 任务 +35 (T1053.005)  */
/*    服务 +40 (T1543.003), WMI +45 (T1546.003)      */
/*    启动配置 +50 (T1542)                           */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_REG_SET_VALUE       302     /* RegistrySetValue */
#define WKD_EVT_REG_CREATE_KEY      300     /* RegistryCreateKey */
#define WKD_EVT_TASK_CREATE         550     /* TaskCreate */
#define WKD_EVT_SERVICE_INSTALL     500     /* ServiceInstall */
#define WKD_EVT_WMI_SUBSCRIPTION    601     /* WMISubscription */
#define WKD_EVT_BOOT_CONFIG_MODIFY  805     /* BootConfigModify */
/* 文件系统事件 (对齐 SS BehaviorEventType, 同 IoaRansomwareDetect.h) */
#define WKD_EVT_FILE_CREATE         200     /* FileCreate */
#define WKD_EVT_FILE_WRITE          203     /* FileWrite */
#define WKD_EVT_FILE_RENAME         205     /* FileRename */

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_PERSIST_RUNKEY_SCORE    30      /* SS REG_RUN_KEY_SCORE */
#define WKD_PERSIST_IFEO_SCORE      15      /* IFEO 追加 */
#define WKD_PERSIST_APPINIT_SCORE   10      /* AppInit 追加 */
#define WKD_PERSIST_TASK_SCORE      35      /* SS SCHEDULED_TASK_SCORE */
#define WKD_PERSIST_SERVICE_SCORE   40      /* SS SERVICE_INSTALL_SCORE */
#define WKD_PERSIST_WMI_SCORE       45      /* SS WMI_PERSISTENCE_SCORE */
#define WKD_PERSIST_BOOT_SCORE      50      /* SS BOOT_CONFIG_SCORE */

/**************************************************/
/*   持久化注册表路径库 (SS L196-212, 完整路径)      */
/*   检测用大小写不敏感 wcsstr 匹配                  */
/**************************************************/

static const PCWSTR g_WkdPersistencePaths[] = {
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
    L"SYSTEM\\CurrentControlSet\\Services",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"SOFTWARE\\Classes\\CLSID",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    L"SOFTWARE\\Classes\\CLSID",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
};
#define WKD_PERSIST_PATH_COUNT \
    (sizeof(g_WkdPersistencePaths) / sizeof(g_WkdPersistencePaths[0]))

/**************************************************/
/*   特殊子串 (IFEO / AppInit 分级加分)             */
/**************************************************/

#define WKD_PERSIST_IFEO_SUBSTR     L"Image File Execution Options"
#define WKD_PERSIST_APPINIT_SUBSTR  L"AppInit_DLLs"

/**************************************************/
/*   文件系统持久化分值 (对标 SS PreSetInfo 敏感文件  */
/*   持久化部分: Startup/DLL 植入/ntuser.dat)         */
/**************************************************/

#define WKD_PERSIST_FILE_STARTUP_SCORE  35  /* 启动文件夹写入 */
#define WKD_PERSIST_FILE_SYSDIR_SCORE   30  /* DLL/驱动植入系统目录 */
#define WKD_PERSIST_FILE_PROFILE_SCORE  25  /* ntuser.dat 配置篡改 */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaPersistence_UpdateScore — 持久化行为评分 (死代码)。
 *
 * 依据事件类型分支累计 State 计数器, 返回得分增量, 并在
 * 命中时置位 State->DetectionFlags 的 DEF_BEHAVIOR_FLAG_PERSISTENCE。
 *
 * 参数:
 *   State — 进程级行为状态 (读写计数器/检测标志)。
 *   Evt   — 归一化行为事件视图 (只读)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaPersistence_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    );

/*
 * IoaPersistence_CheckDirectoryDrop — 目录级持久化投放判定 (死代码)。
 *
 * RDCW 目录事件无进程上下文, 无法进 WKD_BEHAVIOR_EVENT 进程级评分链。
 * 本入口按"监控目录路径 + 新条目文件名"判定持久化投放, 返回评分增量,
 * 供目录监控回调 (main.c OnDirectoryEvent) 消费构造 NULL-NodeId 告警。
 * 复用 IoaPersist_IsFilePersistPath 判定逻辑:
 *   ① \startup\                 → WKD_PERSIST_FILE_STARTUP_SCORE(35)
 *   ② ntuser.dat                → WKD_PERSIST_FILE_PROFILE_SCORE(25)
 *   ③ System32/SysWOW64 DLL/SYS → WKD_PERSIST_FILE_SYSDIR_SCORE(30)
 *
 * 死代码: 待 DirectoryMonitor 回调接线激活 (g_IoaDirectoryMonitorEnabled)。
 *
 * 参数:
 *   DirPath      - 监控目录路径 (RDCW 事件 Path)。
 *   FileName     - 新条目文件名。
 *   FileExtension- 扩展名 (含前导点, 可空)。
 *
 * 返回值: 本次投放评分增量 [0,100] (0 = 非持久化投放)。
 */
ULONG
IoaPersistence_CheckDirectoryDrop(
    _In_ PCWSTR DirPath,
    _In_ PCWSTR FileName,
    _In_opt_ PCWSTR FileExtension
    );
