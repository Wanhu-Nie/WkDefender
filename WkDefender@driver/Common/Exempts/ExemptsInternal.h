/**************************************************/
/*  WkDefender — 排除子系统内部接口                 */
/*                                                   */
/*  私有头文件：仅 Exempts 子系统的 4 个 .c 编译单元  */
/*  包含。集中定义 EXEMPT_ENGINE 全局结构体与各组件  */
/*  上下文，实现"门面集中持有各组件状态 + 全局 rundown */
/*  保护"。外部模块只依赖 Exempts.h（门面接口）。     */
/*                                                   */
/*  职责划分:                                        */
/*    Exempts.c          — 门面/管理引擎（唯一对外） */
/*    ExemptsManager.c   — 纯存储仓库（四表规则）    */
/*    ExemptPid.c        — PID 信任状态 + 判定逻辑   */
/*    ExemptPath.c       — 无状态路径算法            */
/**************************************************/

#ifndef WKD_EXEMPT_INTERNAL_H
#define WKD_EXEMPT_INTERNAL_H

#include "Exempts.h"

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "../Utils.h"
#include "../HashMap.h"                     /* WKD_HASH_MAP（PathHashMap 存储） */

/* ============================================================================
 * 内部常量
 * ============================================================================ */

/* 子系统状态机（集中于 EXEMPT_ENGINE.State，组件不再各自持有） */
#define EXEMPT_STATE_UNINITIALIZED   0
#define EXEMPT_STATE_INITIALIZING     1
#define EXEMPT_STATE_READY            2
#define EXEMPT_STATE_SHUTTING_DOWN    3

/* 过期清理周期（门面自建 60s 线程） */
#define EXEMPT_CLEANUP_INTERVAL_MS    60000

/* 规则存储上限 */
#define EXEMPT_MAX_PATH_EXCLUSIONS         256     /* 最大路径排除条数 */
#define EXEMPT_MAX_EXTENSION_EXCLUSIONS    64      /* 最大扩展名排除条数 */
#define EXEMPT_MAX_PROCESS_EXCLUSIONS      128     /* 最大进程名排除条数 */
#define EXEMPT_MAX_PID_EXCLUSIONS          64      /* 最大 PID 排除条数 */
#define EXEMPT_MAX_PATH_LENGTH   520     /* 排除路径最大长度（字符数） */
#define EXEMPT_MAX_EXTENSION_LENGTH        16      /* 扩展名最大长度（不含点） */
#define EXEMPT_MAX_PROCESS_NAME_LENGTH     260     /* 进程名最大长度 */

/* 规则哈希桶（迁移到 WKD_HASH_MAP 后仅保留桶数配置） */
#define EXEMPT_EXTENSION_HASH_BUCKETS      32      /* 扩展名哈希桶数 */
#define EXEMPT_PROCESS_HASH_BUCKETS        64      /* 进程名哈希桶数 */
#define EXEMPT_PID_HASH_BUCKETS            64      /* PID 哈希桶数 */

/* TrustedPID 引擎 */
#define EXEMPT_PID_BITMAP_LIMIT            65536   /* 位图覆盖 PID 上限 */
#define EXEMPT_PID_BITMAP_ULONGS           (EXEMPT_PID_BITMAP_LIMIT / 32)
#define EXEMPT_PID_HASH_BUCKETS            256     /* 高 PID 哈希桶数 */
#define EXEMPT_MAX_INHERIT_DEPTH           8       /* 父继承最大深度 */

/* ============================================================================
 * 池标签
 * ============================================================================ */

#define EXEMPT_POOL_TAG_ENTRY              'eExW'  /* 排除条目 */
#define EXEMPT_POOL_TAG_PROCESS            'rExW'  /* 进程引擎（位图/哈希条目） */

/* ============================================================================
 * 规则条目结构体（#pragma pack(8) 内）
 * ============================================================================ */

#pragma pack(push, 8)

// 路径排除条目 — 归一化后的路径前缀及匹配元数据
// 存储于 PathHashMap（Common\HashMap.c），Value 持有本条目指针。
// RefCount 引用计数：1 = 在表中；查询/枚举命中时 +1（HashMap Reference），
// 查询方用完必须 ExemptpPathDereference 归还（归零释放）。
typedef struct _EXEMPT_PATH {
    PUNICODE_STRING Path;
    ULONG Flags;                    // 排除标志（EXEMPT_FLAG_*）
    ULONG Reserved;
    volatile ULONG RefCount;        // 引用计数（初始 1 = 在表中）
    volatile ULONG HitCount;        // 命中计数
    LARGE_INTEGER CreateTime;       // 创建时间
    LARGE_INTEGER ExpireTime;       // 过期时间（0=永不过期）
} EXEMPT_PATH, *PEXEMPT_PATH;

// 扩展名排除条目 — 存储于 ExtensionHashMap（key=归一化小写扩展名）
typedef struct _EXEMPT_EXTENSION_EXCLUSION {
    WCHAR Extension[EXEMPT_MAX_EXTENSION_LENGTH];  // 扩展名（不含点，小写）
    USHORT ExtensionLength;                         // 扩展名长度
    UINT8 Flags;
    UINT8 Reserved;
    volatile LONG RefCount;         // 引用计数（0=游离，1=表中，查询命中 +1）
    volatile LONG HitCount;
} EXEMPT_EXTENSION_EXCLUSION, *PEXEMPT_EXTENSION_EXCLUSION;

// 进程名排除条目 — 存储于 ProcessHashMap（key=归一化小写进程名）
typedef struct _EXEMPT_PROCESS_EXCLUSION {
    WCHAR ProcessName[EXEMPT_MAX_PROCESS_NAME_LENGTH]; // 进程名（小写）
    USHORT NameLength;
    UINT8 Flags;
    UINT8 Reserved;
    volatile LONG RefCount;         // 引用计数
    volatile LONG HitCount;
} EXEMPT_PROCESS_EXCLUSION, *PEXEMPT_PROCESS_EXCLUSION;

// PID 排除条目 — 存储于 PidHashMap（key=8 字节 HANDLE）
typedef struct _EXEMPT_PID_EXCLUSION {
    HANDLE ProcessId;
    UINT8 Flags;
    UINT8 Reserved;
    volatile LONG RefCount;         // 引用计数
    volatile LONG HitCount;
    LARGE_INTEGER ExpireTime;           // 0 = 进程退出前有效
} EXEMPT_PID_EXCLUSION, *PEXEMPT_PID_EXCLUSION;

#pragma pack(pop)

/* ============================================================================
 * 排除管理器（纯存储仓库）
 *   — 四表规则数据统一存储于 WKD_HASH_MAP（读共享/写独占）
 *   — 不再持有 rundown / 状态机 / 清理线程（这些归 EXEMPT_ENGINE）
 * ============================================================================ */

typedef struct _EXEMPT_MANAGER {
    WKD_HASH_MAP PathHashMap;       // key=归一化小写路径（去尾斜杠），value=PEXEMPT_PATH
    WKD_HASH_MAP ExtensionHashMap;  // key=归一化小写扩展名，value=PEXEMPT_EXTENSION_EXCLUSION
    WKD_HASH_MAP ProcessHashMap;    // key=归一化小写进程名，value=PEXEMPT_PROCESS_EXCLUSION
    WKD_HASH_MAP PidHashMap;        // key=8 字节 HANDLE，value=PEXEMPT_PID_EXCLUSION
} EXEMPT_MANAGER, *PEXEMPT_MANAGER;

/* ============================================================================
 * TrustedPID 引擎（信任状态 + 判定逻辑）
 *   — 位图/哈希集存储 + 创建播种/父继承/热查询/终止清理逻辑
 *   — 只做逻辑，不维护规则表（规则表在 ExemptsManager）
 * ============================================================================ */

typedef struct _EXEMPT_PID_ENTRY {
    LIST_ENTRY ListEntry;           /* 哈希桶链 */
    HANDLE ProcessId;               /* 进程 ID */
    HANDLE ParentProcessId;         /* 父 PID */
    EXEMPT_REASON Reason;          /* 排除原因 */
    UINT8 InheritanceDepth;         /* 继承深度 */
    BOOLEAN InheritToChildren;      /* 是否向子进程传播 */
    BOOLEAN Permanent;              /* 不可自动移除 */
    UINT8 Reserved[3];
} EXEMPT_PID_ENTRY, *PEXEMPT_PID_ENTRY;

typedef struct _EXEMPT_PID_BUCKET {
    LIST_ENTRY ListHead;
    LONG EntryCount;
} EXEMPT_PID_BUCKET, *PEXEMPT_PID_BUCKET;

typedef struct _EXEMPT_PID_CONTEXT {
    PULONG TrustedBitmap;           /* 全部可信 PID（无锁原子读） */
    PULONG InheritBitmap;           /* 可继承信任 PID（无锁原子读） */
    PUCHAR InheritDepthMap;         /* 低 PID 继承深度表（每 PID 1 字节） */

    EXEMPT_PID_BUCKET HashBuckets[EXEMPT_PID_HASH_BUCKETS];
    EX_PUSH_LOCK HashLock;

    volatile LONG ActiveRecords;     /* 近似可信 PID 计数 */
    BOOLEAN EnableInheritance;      /* 继承开关 */
    UINT8 Reserved[3];
} EXEMPT_PID_CONTEXT, *PEXEMPT_PID_CONTEXT;

/* ============================================================================
 * 子系统全局结构体（门面 Exempts.c 持有唯一实例）
 *   集中记录各组件状态 + 全局 rundown 保护 + 清理线程。
 * ============================================================================ */

typedef struct _EXEMPT_ENGINE {
    volatile LONG State;            /* 子系统状态机（EXEMPT_STATE_*） */
    BOOLEAN Enabled;                /* 启用标志 */
    EX_RUNDOWN_REF RundownRef;      /* 全局关闭排空保护 */

    EXEMPT_MANAGER Manager;        /* 内嵌存储仓库（四表规则） */
    EXEMPT_PID_CONTEXT PidContext;      /* 内嵌 TrustedPID 引擎 */

    HANDLE CleanupThread;           /* 门面自建 60s 清理线程句柄 */
    KEVENT CleanupStopEvent;        /* 清理线程停止事件 */
} EXEMPT_ENGINE, *PEXEMPT_ENGINE;

/* ============================================================================
 * 组件函数原型（全部参数化 PEXEMPT_ENGINE，由门面持有并传入）
 * ============================================================================ */

//---------------------------------------------------------------------------
// ExemptsManager.c — 纯存储仓库
//---------------------------------------------------------------------------

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CopInitializeExemptMgr(
    _Inout_ PEXEMPT_ENGINE Engine
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrShutdown(
    _Inout_ PEXEMPT_ENGINE Engine
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
CopCheckPathExempted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_opt_ PCUNICODE_STRING Extension
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
CopCheckProcessExemptedByIdOrName(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ProcessName
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CopAddExemptedPath(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags,
    _In_ ULONG TTLSeconds
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsMgrAddExtensionExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsMgrAddProcessExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsMgrAddPidExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_opt_ ULONG TTLSeconds
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemovePathExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Path
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemoveExtensionExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Extension
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemoveProcessExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING ProcessName
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemovePidExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrClearExclusions(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ EXEMPT_RULE_TYPE Type
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CoLoadDefaultExempts(
    _In_ PEXEMPT_ENGINE Engine
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrCleanupExpired(
    _In_ PEXEMPT_ENGINE Engine
    );

// 进程退出回收：移除 PID 表中 ExpireTime==0（TTL=0，"进程退出前有效"）的条目
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrReapPidOnExit(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

//---------------------------------------------------------------------------
// ExemptPid.c — TrustedPID 引擎（信任状态 + 判定逻辑）
//---------------------------------------------------------------------------

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CopInitializeExemptPid(
    _Inout_ PEXEMPT_ENGINE Engine
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptPidShutdown(
    _Inout_ PEXEMPT_ENGINE Engine
    );

// 进程创建播种判定（路径排除 → 进程名排除 → 父继承），命中写可信位图
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
CopExemptCreatedProcessInternal(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptPidOnProcessTerminate(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

// 热路径可信查询（门面持全局 rundown 后调用，内部无锁/轻锁）
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ExemptPidIsTrusted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

// 手动置可信（门面 AddPidExclusion 成功后的同步播种，不参与继承）
_IRQL_requires_max_(APC_LEVEL)
VOID
ExemptPidMarkTrusted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

//---------------------------------------------------------------------------
// ExemptPath.c — 无状态路径算法（纯函数，零全局状态）
//---------------------------------------------------------------------------

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ExemptpMatchPathPattern(
    _In_ PCUNICODE_STRING FilePath,
    _In_ PCUNICODE_STRING Pattern,
    _In_ UINT8 Flags
    );

#endif // WKD_EXEMPT_INTERNAL_H
