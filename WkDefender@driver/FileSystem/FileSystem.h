/**************************************************/
/*                                                    */
/*  WkDefender 文件系统子系统——内部私有头              */
/*                                                    */
/*  【架构定位】仅供 FileSystem 目录内模块             */
/*  （FileSystem.c 编排器 + 11 个能力模块 .c，含        */
/*  2026-10 提取的 PreSetInformation/PreCreate/PreWrite）包含。 */
/*  FileSystem 目录之外的任何模块禁止 include 本头，    */
/*  一律走 Include\FileSystem.h（对外公共头）。          */
/*                                                    */
/*  本头内容：                                         */
/*    1. include 对外公共头（编排器服务、能力模块       */
/*       API 声明、外部可见类型、薄层导出）             */
/*    2. FileSystem 目录内独享的内部数据结构            */
/*       （模块内部表结构/评分阈值/死代码接口）          */
/*                                                    */
/*  分层约定（2026-09-13）：                            */
/*    Include\FileSystem.h          对外公共头         */
/*    FileSystem\FileSystem.h       内部私有头(本文件)  */
/*    FileSystem\FileSystem.c       编排器             */
/*    FileSystem\*.c                分析能力模块        */
/*    Callbacks\FileSystemNotification.{c,h} 薄层      */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#ifndef _WC_FILESYSTEM_INTERNAL_H_
#define _WC_FILESYSTEM_INTERNAL_H_

#pragma once

#include <ntddk.h>
#include <fltkernel.h>
#include <ntifs.h>

#include "../Include/FileSystem.h"  /* 对外公共头：生命周期 + 能力模块 API + 外部类型 */

/* ============================================================================
 * 一、ProcessFileContext：评分阈值常量（内部）
 *    对外仅暴露 WKD_PFCP_OP 与三个入口（已入公共头）
 * ========================================================================== */

#define WKD_PFCP_MAX_CONTEXTS       256
#define WKD_PFCP_WINDOW_100NS       (1000LL * 10000LL)      /* 1 秒滚动窗口 */
#define WKD_PFCP_CONTEXT_TTL_100NS  (300LL * 1000LL * 10000LL) /* 5 分钟槽 TTL */
#define WKD_PFCP_CLEANUP_INTERVAL_MS 60000                  /* PeriodicTimer 上限 60s */

/* 勒索评分阈值（FSC_RANSOMWARE_*_THRESHOLD） */
#define WKD_PFCP_RENAME_THRESHOLD            40
#define WKD_PFCP_EXT_CHANGE_THRESHOLD        25
#define WKD_PFCP_DELETE_THRESHOLD            40
#define WKD_PFCP_MODIFY_THRESHOLD            60
#define WKD_PFCP_TOTAL_RENAME_THRESHOLD      100
#define WKD_PFCP_TOTAL_EXT_CHANGE_THRESHOLD  50

/* 分值（FscpDetectRansomwareBehavior 40/35/30/20/15/25/20） */
#define WKD_PFCP_SCORE_MASS_RENAME           40
#define WKD_PFCP_SCORE_EXT_CHANGE            35
#define WKD_PFCP_SCORE_MASS_DELETE           30
#define WKD_PFCP_SCORE_TOTAL_RENAME          20
#define WKD_PFCP_SCORE_TOTAL_EXT_CHANGE      15
#define WKD_PFCP_SCORE_COMBO_RENAME_EXT      25
#define WKD_PFCP_SCORE_MASS_MODIFY           20
#define WKD_PFCP_RANSOMWARE_THRESHOLD        70

/* ============================================================================
 * 二、FileBackupEngine：内部结构（对外仅暴露函数与 FBE_* 枚举/常量）
 * ========================================================================== */

/* 逐进程追踪器 */
typedef struct _FBE_PROCESS_TRACKER {
    LIST_ENTRY Link;                /* 进程桶链 */
    HANDLE ProcessId;

    LIST_ENTRY BackupEntries;       /* FBE_BACKUP_ENTRY.ProcessLink 链表 */
    volatile LONG EntryCount;
    EX_PUSH_LOCK Lock;

    volatile LONG64 TotalBytesBackedUp;
    volatile LONG64 FilesBackedUp;
    volatile LONG64 FilesRolledBack;
} FBE_PROCESS_TRACKER, *PFBE_PROCESS_TRACKER;

/* 全局统计（死代码：无消费方，接口保留） */
typedef struct _FBE_STATISTICS {
    volatile LONG64 TotalBackupRequests;
    volatile LONG64 BackupsCreated;
    volatile LONG64 BackupsSkippedDuplicate;
    volatile LONG64 BackupsSkippedSize;
    volatile LONG64 BackupsSkippedExtension;
    volatile LONG64 BackupsFailed;
    volatile LONG64 TotalBytesBackedUp;
    volatile LONG64 TotalBytesRolledBack;
    volatile LONG64 RollbackRequests;
    volatile LONG64 RollbacksSucceeded;
    volatile LONG64 RollbacksFailed;
    volatile LONG64 RollbackFilesRestored;
    volatile LONG64 EntriesEvicted;
    volatile LONG64 CurrentBackupDiskUsage;
    volatile LONG64 PeakBackupDiskUsage;
} FBE_STATISTICS, *PFBE_STATISTICS;

/* 运行配置 */
typedef struct _FBE_CONFIG {
    LONGLONG MaxTotalBackupSize;
    LONGLONG MaxSingleFileSize;
    ULONG MaxEntriesPerProcess;
    BOOLEAN EnableWriteBackup;
    BOOLEAN EnableRenameBackup;
    BOOLEAN EnableDeleteBackup;
    BOOLEAN EnableTruncateBackup;
} FBE_CONFIG, *PFBE_CONFIG;

/* 死代码：wkd 无查询流水线/UI 消费方，接口保留对齐 SS。 */
_IRQL_requires_max_(APC_LEVEL)
VOID
FbeGetStatistics(
    _Out_ PFBE_STATISTICS Statistics
    );

/* 死代码：同上。 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
FbeHasBackups(
    _In_ HANDLE ProcessId
    );

/* ============================================================================
 * 三、PostWrite：进程活动槽（内部）
 *    对外仅暴露函数与 WKD_PWC_FILE_TRACKER/WRITE_CONTEXT（已入公共头）
 * ========================================================================== */

/*++
 * WKD_PWC_PROCESS_ACTIVITY
 *   进程级写活动跟踪（静态槽数组；全局 ActivityLock 保护结构化字段，
 *   计数器走 Interlocked 原子）。PW_PROCESS_ACTIVITY。
 *--*/
typedef struct _WKD_PWC_PROCESS_ACTIVITY {
    HANDLE ProcessId;
    volatile LONG WriteCount;
    volatile LONG UniqueFileCount;
    volatile LONG HighEntropyWrites;
    volatile LONG SuspicionScore;        /* 衰减后分数（告警依据） */
    volatile LONG RawScore;              /* 衰减前累积（上限 500） */
    LARGE_INTEGER FirstWriteTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER WindowStart;
    LARGE_INTEGER LastScoreUpdate;
    BOOLEAN IsRateLimited;
    BOOLEAN IsFlagged;                   /* 已触发告警（单次语义） */
    BOOLEAN IsActive;
    UINT8 Reserved[5];

    WKD_PWC_FILE_TRACKER TrackedFiles[WKD_PWC_MAX_TRACKED_FILES_PER_PROCESS];
    ULONG TrackedFileCount;
    ULONG Reserved2;
} WKD_PWC_PROCESS_ACTIVITY, *PWKD_PWC_PROCESS_ACTIVITY;

/* ============================================================================
 * 四、USBDeviceControl：规则条目与卷追踪（内部）
 *    对外仅暴露策略/类/配置/统计（已入公共头）
 * ========================================================================== */

/* 设备规则条目（UDC_DEVICE_RULE） */
typedef struct _WKD_UDC_DEVICE_RULE {

    LIST_ENTRY          Link;

    /* 匹配条件（0 = 通配） */
    USHORT              VendorId;
    USHORT              ProductId;
    WCHAR               SerialNumber[WKD_UDC_SERIAL_MAX_LENGTH];
    USHORT              SerialNumberLength;     /* 0 = 匹配任意序列号 */

    /* 设备类过滤（Unknown = 匹配任意类） */
    WKD_UDC_DEVICE_CLASS DeviceClass;

    /* 应用策略 */
    WKD_UDC_DEVICE_POLICY Policy;

    /* 规则元数据 */
    LARGE_INTEGER       CreatedTime;
    ULONG               RuleId;

} WKD_UDC_DEVICE_RULE, *PWKD_UDC_DEVICE_RULE;

/* 已追踪卷（UDC_TRACKED_VOLUME） */
typedef struct _WKD_UDC_TRACKED_VOLUME {

    LIST_ENTRY          Link;

    /* 卷标识 */
    UNICODE_STRING      VolumeName;
    WCHAR               VolumeNameBuffer[260];
    ULONG               VolumeSerial;

    /* 设备信息 */
    USHORT              VendorId;
    USHORT              ProductId;
    WCHAR               SerialNumber[WKD_UDC_SERIAL_MAX_LENGTH];
    WKD_UDC_DEVICE_CLASS DeviceClass;

    /* 有效策略 */
    WKD_UDC_DEVICE_POLICY EffectivePolicy;

    /* 追踪 */
    LARGE_INTEGER       MountTime;
    PFLT_INSTANCE       Instance;       /* 该卷上的 minifilter 实例 */
    volatile LONG       WriteAttempts;
    volatile LONG       WriteBlocked;
    volatile LONG       FilesAccessed;

} WKD_UDC_TRACKED_VOLUME, *PWKD_UDC_TRACKED_VOLUME;

/* ============================================================================
 * 五、PreSetInformation：SetInformation 前置回调流水线（2026-10 提取）
 *    能力模块文件 FileSystem\PreSetInformation.c（迁移自薄层 FsPreSetInformationNotifyCallback
 *    段）。模块无 FileSystem 目录内私有结构/阈值需共享——两个导出函数
 *    （FsPreSetInformationNotifyCallback/FspIsBackupDirPath）声明均在公共头 Include\FileSystem.h
 *    十一分区；内部常量 WKD_FS_MAX_RENAME_BUFFER_SIZE 为文件内私有。
 * ========================================================================== */

/* ============================================================================
 * 六、PreCreate：Create 前置回调流水线（2026-10 提取，与 PreSetInformation 同批）
 *    能力模块文件 FileSystem\PreCreate.c（迁移自薄层 CbpPreCreateNotifyCallback
 *    段，补齐 SS ShadowStrikePreCreate 语义）。模块无 FileSystem 目录内
 *    私有结构/阈值需共享——主回调 FsPreCreateNotifyCallback 声明在公共头
 *    Include\FileSystem.h 十二分区；本地评分阈值（WKD_PC_BLOCK_THREAT_SCORE=75 /
 *    WKD_PC_ALERT_THREAT_SCORE=50）与访问模式辅助（PcpIs*）均为文件内私有。
 * ========================================================================== */

/* ============================================================================
 * 七、PreWrite：Write 前置回调流水线（2026-10 提取，与 PreCreate/PreSetInformation
 *    同批）
 *    能力模块文件 FileSystem\PreWrite.c（迁移自薄层 FspPreWrite 段）。模块无
 *    FileSystem 目录内私有结构/阈值需共享——主回调 FsPreWriteNotifyCallback
 *    声明在公共头 Include\FileSystem.h 十三分区；文件对象 ID 查询辅助
 *    FspQueryFileId（原薄层 WkdFspQueryFileId）为文件内 static。
 * ========================================================================== */

#endif /* _WC_FILESYSTEM_INTERNAL_H_ */