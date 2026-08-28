#pragma once

#include <ntifs.h>

#include "../Common/Constants.h"        /* AE_THREAT_SEVERITY */
#include "../Common/HashMap.h"          /* WKD_HASH_MAP */

/**************************************************/
/*                 AppControl 配置常量              */
/**************************************************/

#define IOC_AC_HASH_SIZE             32    /* SHA-256 */
#define IOC_AC_MAX_PATH_LENGTH       520
#define IOC_AC_HASH_BUCKET_COUNT     256
#define IOC_AC_MAX_HASH_RULES        8192
#define IOC_AC_MAX_PATH_RULES        512
#define IOC_AC_MAX_PATH_WALK         IOC_AC_MAX_PATH_RULES

#define IOC_AC_POOL_TAG              'cAcI'
#define IOC_AC_RULE_POOL_TAG         'rAcI'

/**************************************************/
/*                    枚举声明                     */
/**************************************************/

typedef enum _IOC_AC_POLICY_MODE {
    AcMode_Audit = 0,       /* 记录违规，不阻断 */
    AcMode_Enforce,         /* 阻断未授权执行（fail-closed，EDR 默认不启用） */
    AcMode_Learning         /* 自动学习白名单（默认关闭，自动洗白风险） */
} IOC_AC_POLICY_MODE;

typedef enum _IOC_AC_VERDICT {
    AcVerdict_Allow = 0,    /* 允许执行 */
    AcVerdict_Block,        /* 拒绝执行 */
    AcVerdict_Audit,        /* 记录违规但放行 */
    AcVerdict_Unknown       /* 无规则命中（默认策略决定） */
} IOC_AC_VERDICT;

typedef enum _IOC_AC_RULE_TYPE {
    AcRule_HashAllow = 0,
    AcRule_HashBlock,
    AcRule_PathAllow,
    AcRule_PathBlock
    /* Signer 规则：SS 仅声明枚举未实现，本迁移舍弃 */
} IOC_AC_RULE_TYPE;

/**************************************************/
/*                   结构体声明                    */
/**************************************************/

typedef struct _IOC_AC_PATH_RULE {
    LIST_ENTRY Link;
    IOC_AC_RULE_TYPE RuleType;
    UNICODE_STRING PathPrefix;
    WCHAR PathBuffer[IOC_AC_MAX_PATH_LENGTH];
    ULONG RuleId;
} IOC_AC_PATH_RULE, * PIOC_AC_PATH_RULE;

typedef struct _IOC_AC_STATISTICS {
    volatile LONG64 ExecutionsChecked;
    volatile LONG64 ExecutionsAllowed;
    volatile LONG64 ExecutionsBlocked;
    volatile LONG64 ExecutionsAudited;
    volatile LONG64 ImagesChecked;
    volatile LONG64 ImagesBlocked;
    volatile LONG64 RulesLearned;
    volatile LONG64 HashLookups;
    volatile LONG64 PathLookups;
} IOC_AC_STATISTICS, * PIOC_AC_STATISTICS;

/**************************************************/
/*                   函数声明                     */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAppControlInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocAppControlShutdown(
    VOID
    );

/* 模块门控 — 默认关闭；启用后进程创建/镜像判定接线生效 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocAcEnabled(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAcSetEnabled(
    _In_ BOOLEAN Enable
    );

/*
 * 进程创建执行判定（对齐 SS AcCheckProcessExecution）：
 * 哈希→路径规则→内置信任路径→默认策略。
 * 命中 AcVerdict_Block 时调用方应设置
 * CreateInfo->CreationStatus = STATUS_ACCESS_DENIED 阻断创建。
 */
_IRQL_requires_(PASSIVE_LEVEL)
IOC_AC_VERDICT
IocAppControlCheckProcessExecution(
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ const UCHAR* ImageHash,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId
    );

/*
 * 镜像加载判定（对齐 SS AcCheckImageLoad，通知型）：
 * 仅路径规则 + 信任路径，命中 Block 由调用方加分上报，无法阻断加载。
 */
_IRQL_requires_(PASSIVE_LEVEL)
IOC_AC_VERDICT
IocAppControlCheckImageLoad(
    _In_ PCUNICODE_STRING ImagePath,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IocAppControlGetStatistics(
    _Out_ PIOC_AC_STATISTICS Statistics
    );

/*
 * 策略/规则管理 — Agent 推送通道（调用点第二阶段接入）。
 * 当前阶段功能面就绪，无调用者。
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAppControlSetPolicyMode(
    _In_ IOC_AC_POLICY_MODE Mode
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAppControlAddHashRule(
    _In_ const UCHAR* Hash,
    _In_ IOC_AC_RULE_TYPE RuleType
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAppControlAddPathRule(
    _In_ PCUNICODE_STRING Prefix,
    _In_ IOC_AC_RULE_TYPE RuleType
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAppControlRemoveHashRule(
    _In_ const UCHAR* Hash
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAppControlRemovePathRule(
    _In_ PCUNICODE_STRING Prefix
    );
