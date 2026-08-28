/**************************************************/
/*  PreAcquireSection 代码执行映射检测（驱动侧接口） */
/*  迁移自 SS PreAcquireSection.c（重功能实现）      */
/*                                                  */
/*  活代码：WkdPasInitialize/Shutdown/ProcessMapping */
/*  供 Filter.c FspPreAcquireSection 回调壳调用。    */
/*  检测内核在 PreAcquireSection.c 内聚。            */
/**************************************************/

#pragma once

#include <fltKernel.h>
#include <ntifs.h>

/**************************************************/
/*                      常量定义                   */
/**************************************************/

/* 执行保护掩码（文件轨回调快速跳过） */
#define PAS_EXECUTE_PROTECTION_MASK     (PAGE_EXECUTE | PAGE_EXECUTE_READ | \
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

/* 映射分类标志（对齐 SS PAS_MAP_FLAG_* 16 位） */
#define PAS_MAP_FLAG_EXECUTABLE         0x00000001
#define PAS_MAP_FLAG_IMAGE              0x00000002
#define PAS_MAP_FLAG_WRITABLE           0x00000004
#define PAS_MAP_FLAG_CROSS_PROCESS      0x00000008
#define PAS_MAP_FLAG_UNSIGNED           0x00000010
#define PAS_MAP_FLAG_PACKED             0x00000020
#define PAS_MAP_FLAG_SUSPICIOUS_PATH    0x00000040
#define PAS_MAP_FLAG_TEMP_LOCATION      0x00000080
#define PAS_MAP_FLAG_NETWORK            0x00000100
#define PAS_MAP_FLAG_REMOVABLE          0x00000200
#define PAS_MAP_FLAG_ADS                0x00000400
#define PAS_MAP_FLAG_BLOCKED            0x00000800
#define PAS_MAP_FLAG_HOLLOWING_SUSPECT  0x00001000
#define PAS_MAP_FLAG_REFLECTIVE_SUSPECT 0x00002000
#define PAS_MAP_FLAG_EARLY_PROCESS      0x00004000
#define PAS_MAP_FLAG_SUSPENDED_THREAD   0x00008000

/* 行为标志（对齐 SS PAS_BEHAVIOR_* 8 位） */
#define PAS_BEHAVIOR_RAPID_MAPPING      0x00000001
#define PAS_BEHAVIOR_CROSS_PROCESS      0x00000002
#define PAS_BEHAVIOR_UNSIGNED_EXEC      0x00000004
#define PAS_BEHAVIOR_TEMP_EXEC          0x00000008
#define PAS_BEHAVIOR_MULTIPLE_TARGETS   0x00000010
#define PAS_BEHAVIOR_SELF_MODIFICATION  0x00000020
#define PAS_BEHAVIOR_HOLLOWING          0x00000040
#define PAS_BEHAVIOR_REFLECTIVE         0x00000080

/* 评分阈值（对齐 SS PAS_SUSPICION_* / MinBlockScore=85） */
#define PAS_SUSPICION_LOW_DEFAULT       15
#define PAS_SUSPICION_MEDIUM_DEFAULT    30
#define PAS_SUSPICION_HIGH_DEFAULT      65
#define PAS_SUSPICION_CRITICAL_DEFAULT  85
#define PAS_MIN_BLOCK_SCORE             PAS_SUSPICION_CRITICAL_DEFAULT
#define PAS_ANOMALY_THRESHOLD_DEFAULT   10
#define PAS_HOLLOWING_EARLY_WINDOW_MS   5000

/**************************************************/
/*                      结构体声明                 */
/**************************************************/

/* 单次可执行映射输入（Filter.c 回调壳 → WkdPasProcessMapping）。
 * PreMappedFlags 由回调壳把 B2 路径分析结果（WKD_FS_PATH_*）与卷类型
 * 判定预映射为 PAS_MAP_FLAG_* 增量（两宏集合分处不同文件，避免跨文件
 * 宏依赖）。 */
typedef struct _WKD_PAS_INPUT {
    HANDLE           ProcessId;       /* 映射发起进程 */
    ULONG            PageProtection;  /* 请求保护（含 SEC_IMAGE 位） */
    PCUNICODE_STRING FileName;        /* 映射文件路径（CACHE_ONLY 已查，可空） */
    ULONG            PathScore;       /* B2 路径分析分数（0-100，WkdFspCalcPathFlagScore） */
    ULONG            PreMappedFlags;  /* 预映射的 PAS_MAP_FLAG_* 增量 */
} WKD_PAS_INPUT, *PWKD_PAS_INPUT;

/**************************************************/
/*                      函数声明                   */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPasInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPasShutdown(
    VOID
    );

/* 处理一次可执行映射：更新进程画像、行为检测、评分融合。
 * 输出 Score（0-100，PAS 基础分 + B2 路径分封顶 +40）与
 * MappingFlags（PAS_MAP_FLAG_* 位图）。
 * 阻断决策由回调壳依据 Score 与 WKD_PAS_CONFIG.EnableBlocking 执行。 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPasProcessMapping(
    _In_ PWKD_PAS_INPUT Input,
    _Out_opt_ PULONG Score,
    _Out_opt_ PULONG MappingFlags
    );

/* 状态/配置/统计访问器（Filter.c 回调壳不直接触碰 .c 内 static 全局）。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasIsActive(
    VOID
    );

/* Score 是否达到事件上送门槛（Config.SuspicionMedium） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasShouldReport(
    _In_ ULONG Score
    );

/* Score 是否达到阻断门槛（Config.EnableBlocking && Score>=MinBlockScore） */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPasShouldBlock(
    _In_ ULONG Score
    );

/* 统计计数（回调壳触发的三类结果） */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteSelfProtectBlock(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteBlocked(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPasNoteAllowed(
    VOID
    );
