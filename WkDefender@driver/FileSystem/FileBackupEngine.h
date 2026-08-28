/**************************************************/
/*  WkDefender 文件备份/回滚引擎（勒索 CoW）         */
/**************************************************/

#pragma once

#include <fltKernel.h>
#include <ntifs.h>

/*++
 * 模块职责：
 *   本模块实现勒索软件 Copy-on-First-Write 备份/回滚引擎，迁移自 ShadowStrike
 *   FileBackupEngine.{c,h}（重功能实现非源码复制，按功能融合进 wkd）。
 *   PreWrite/PreSetInformation 回调先备份原始文件，勒索判定后按进程回滚，
 *   进程正常退出时丢弃备份。
 *
 *   对齐 SS 行号标注：各函数注释引用 SS FileBackupEngine.c 对应行号。
 *
 * 迁移裁剪/死代码说明：
 *   - FbeGetStatistics/FbeHasBackups：死代码，wkd 无查询流水线/UI 消费方，
 *     接口保留对齐 SS 公共 API 面。
 *   - 备份目录名由 SS 的 ShadowStrikeBackup 改为 WkdBackup。
 *   - 容量上限沿用 SS 默认（全局 10GB / 单文件 100MB / 单进程 4096 条 / 总 65536）。
 *--*/

/* ============================================================================
 * 池标签
 * ========================================================================== */
#define WKD_FBE_POOL_TAG            'eBFK'  /* KFBe - 通用 */
#define WKD_FBE_ENTRY_POOL_TAG      'nBFK'  /* KFBn - Backup Entry */
#define WKD_FBE_IO_POOL_TAG         'iBFK'  /* KFBi - I/O Buffer */
#define WKD_FBE_ROLLBACK_POOL_TAG   'rBFK'  /* KFBr - Rollback */
#define WKD_FBE_PATH_POOL_TAG       'pBFK'  /* KFBp - 路径缓冲（死代码：对齐 SS FBE_PATH_POOL_TAG，
                                               SS 亦未使用——路径缓冲内嵌 FBE_BACKUP_ENTRY，无独立分配） */

/* ============================================================================
 * 配置常量（沿用 SS FBE 默认值）
 * ========================================================================== */
#define FBE_MAX_BACKUP_SIZE_DEFAULT     ((LONGLONG)10 * 1024 * 1024 * 1024)  /* 10 GB 全局 */
#define FBE_MAX_SINGLE_FILE_SIZE        ((LONGLONG)100 * 1024 * 1024)        /* 100 MB 单文件 */
#define FBE_MAX_TRACKED_PROCESSES       1024
#define FBE_MAX_ENTRIES_PER_PROCESS     4096
#define FBE_MAX_TOTAL_ENTRIES           65536
#define FBE_HASH_BUCKET_COUNT           256
#define FBE_IO_BUFFER_SIZE              (64 * 1024)     /* 64 KB 拷贝缓冲 */
#define FBE_BACKUP_DIR_NAME             L"\\WkdBackup"
#define FBE_MAX_PATH_LENGTH             300             /* 字符，覆盖 99.9% 实际路径 */
#define FBE_BACKUP_PATH_LENGTH          128             /* 字符，备份路径短且确定 */

/**************************************************/
/*                      枚举类型                   */
/**************************************************/

/* 备份条目状态机：Free→Pending→Valid→RolledBack/Evicted/Failed */
typedef enum _FBE_ENTRY_STATE {
    FbeEntryState_Free = 0,
    FbeEntryState_Pending,          /* 备份进行中 */
    FbeEntryState_Valid,            /* 备份完成，可回滚 */
    FbeEntryState_RolledBack,       /* 已回滚 */
    FbeEntryState_Evicted,          /* LRU 淘汰 */
    FbeEntryState_Failed            /* 备份失败 */
} FBE_ENTRY_STATE;

/* 备份操作类型 */
typedef enum _FBE_OPERATION_TYPE {
    FbeOp_Write = 0,                /* IRP_MJ_WRITE 修改 */
    FbeOp_Rename,                   /* FileRenameInformation */
    FbeOp_Delete,                   /* FileDispositionInformation */
    FbeOp_Truncate,                 /* FileEndOfFileInformation（仅监控不备份，SS 语义） */
    FbeOp_SetAllocation             /* FileAllocationInformation（死代码，SS 亦未接线） */
} FBE_OPERATION_TYPE;

/* 回滚结果 */
typedef enum _FBE_ROLLBACK_RESULT {
    FbeRollback_Success = 0,
    FbeRollback_PartialSuccess,     /* 部分文件已恢复 */
    FbeRollback_NoBackupsFound,
    FbeRollback_IOError,
    FbeRollback_ShuttingDown,
    FbeRollback_InvalidProcess
} FBE_ROLLBACK_RESULT;

/**************************************************/
/*                      结构体声明                 */
/**************************************************/

/* 备份条目：三链表嵌入 + 状态机 + 内嵌路径缓冲 */
typedef struct _FBE_BACKUP_ENTRY {
    LIST_ENTRY ProcessLink;         /* 逐进程链表 */
    LIST_ENTRY HashLink;            /* 哈希桶链 */
    LIST_ENTRY LruLink;             /* 全局 LRU 链 */

    volatile LONG State;            /* FBE_ENTRY_STATE（原子访问） */

    HANDLE ProcessId;               /* 归属进程 */
    FBE_OPERATION_TYPE OperationType;
    LARGE_INTEGER Timestamp;        /* 备份创建时间 */

    UNICODE_STRING OriginalPath;    /* 原始完整路径 */
    WCHAR OriginalPathBuffer[FBE_MAX_PATH_LENGTH];
    LARGE_INTEGER OriginalFileSize;

    UNICODE_STRING BackupPath;      /* 备份路径（短而确定） */
    WCHAR BackupPathBuffer[FBE_BACKUP_PATH_LENGTH];
    LARGE_INTEGER BackupFileSize;

    ULONG VolumeSerial;
} FBE_BACKUP_ENTRY, *PFBE_BACKUP_ENTRY;

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

#define STATUS_FBE_SKIP     ((NTSTATUS)0xE0FB0001L)

/**************************************************/
/*                      函数声明                   */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbeInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
FbeShutdown(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreWriteBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreSetInfoBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName,
    _In_ FBE_OPERATION_TYPE OpType
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
FBE_ROLLBACK_RESULT
FbeRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
FbeCommitProcess(
    _In_ HANDLE ProcessId
    );

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
