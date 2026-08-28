/**************************************************/
/*  WkDefender — 排除(Exempts)子系统公共接口          */
/*                                                   */
/*  本头文件是排除子系统的唯一对外接口。外部模块      */
/*  （ScanManager / DirectoryMonitor / IoaEngine /   */
/*  IoaInjectionClassifier / main）只依赖本头，       */
/*  不接触内部组件结构。                              */
/*                                                   */
/*  架构: 仿照驱动侧 WkDefender@driver\Common\Exempts */
/*  的门面模式重建 agent 侧白名单能力。               */
/*                                                   */
/*  职责划分:                                        */
/*    Exempts.c          — 门面/管理引擎（唯一对外） */
/*    ExemptsManager.c   — 纯存储仓库（规则表）      */
/*    ExemptHash.c       — 哈希判定逻辑             */
/*    ExemptPath.c       — 无状态路径算法            */
/*    ExemptCert.c       — 证书/发布者判定（委托     */
/*                         Signature 子系统）        */
/*    ExemptPush.c       — 系统组件采集 + ALPC 推送  */
/*    ExemptInjection.c  — 注入场景豁免              */
/*    ExemptProcess.c    — 进程身份豁免（无镜像假进程）*/
/*  内部组件结构/原型见 ExemptsInternal.h（私有头）。 */
/*                                                   */
/*  统一命名为 Exempts（豁免/排除），废弃 Whitelist    */
/*  命名。agent 侧为权威规则源，经 ALPC 0x3105 增量   */
/*  推送驱动侧 Exempts（Path 规则；驱动侧不消费       */
/*  TrustedHash，用户决策 2026-08-14）。              */
/*  2026-08-14 重构，见档案 #67。                     */
/**************************************************/

#ifndef WKD_AGENT_EXEMPTS_H
#define WKD_AGENT_EXEMPTS_H

#include <windows.h>
#include "../../IOC/IocTypes.h"          /* DEF_SHA256_HASH / IOC_SCAN_RESULT */

/* PWKD_PROCESS 前向声明：避免 include Process/ProcessTypes.h 引入进程域完整
 * 定义。完整类型由 ExemptInjection.c 自行 include。 */
struct _WKD_PROCESS;

/**************************************************/
/*                  枚举类型                        */
/**************************************************/

/* 排除规则类型（文件维度四维） */
typedef enum _EXEMPT_RULE_TYPE {
    ExemptRule_Hash = 0,        /* 文件哈希（SHA256） */
    ExemptRule_Path = 1,        /* 路径模式 */
    ExemptRule_Certificate = 2, /* 证书指纹 */
    ExemptRule_Publisher = 3,   /* 发布者名 */
    ExemptRule_MaxValue
} EXEMPT_RULE_TYPE;

/* 排除规则标志 */
typedef enum _EXEMPT_FLAGS {
    EXEMPT_FLAG_NONE      = 0x00, /* 无特殊标志 */
    EXEMPT_FLAG_CASE_SENS = 0x01, /* 大小写敏感（默认不敏感） */
    EXEMPT_FLAG_RECURSIVE = 0x02, /* 路径递归子目录 */
    EXEMPT_FLAG_TEMPORARY = 0x04, /* 临时排除（自动过期） */
    EXEMPT_FLAG_SYSTEM    = 0x08  /* 系统排除（不可移除） */
} EXEMPT_FLAGS;

/* 路径匹配模式（吸收 SS PathMatchMode） */
typedef enum _EXEMPT_PATH_MODE {
    ExemptMode_Exact = 0,       /* 完全相等 */
    ExemptMode_Prefix = 1,      /* 前缀（组件边界） */
    ExemptMode_Suffix = 2,      /* 后缀 */
    ExemptMode_Contains = 3,    /* 包含 */
    ExemptMode_Glob = 4,        /* 通配符（* ?） */
    ExemptMode_MaxValue
} EXEMPT_PATH_MODE;

/* 排除评估判决 */
typedef enum _EXEMPT_VERDICT {
    ExemptVerdict_Trusted = 0,  /* 豁免（放行） */
    ExemptVerdict_NotTrusted,   /* 不豁免 */
} EXEMPT_VERDICT;

/* 排除匹配原因 */
typedef enum _EXEMPT_REASON {
    ExemptReason_None = 0,          /* 未匹配任何排除 */
    ExemptReason_HashMatch,         /* 哈希规则命中 */
    ExemptReason_CertMatch,         /* 证书规则/微软签名命中 */
    ExemptReason_PublisherMatch,    /* 发布者规则命中 */
    ExemptReason_PathMatch,         /* 路径规则命中 */
    ExemptReason_MaxValue
} EXEMPT_REASON;
typedef EXEMPT_REASON *PEXEMPT_REASON;

/**************************************************/
/*                  常量                            */
/**************************************************/

#define EXEMPT_MAX_PATTERN      520     /* 路径模式最大长度（字符，对齐驱动 EXEMPT_MAX_PATH_LENGTH） */
#define EXEMPT_MAX_DESCRIPTION  128     /* 描述最大长度 */
#define EXEMPT_HASH_SIZE        32      /* SHA256 字节数 */

/**************************************************/
/*                  规则结构                        */
/**************************************************/

/* 统一规则载体（四维共用一个结构，Type 区分） */
typedef struct _EXEMPT_RULE {
    UINT64 RuleId;              /* 唯一 ID（持久化主键） */
    UINT8  Type;                /* EXEMPT_RULE_TYPE */
    UINT8  Reason;              /* EXEMPT_REASON（命中归因） */
    UINT8  MatchMode;           /* EXEMPT_PATH_MODE */
    UINT8  Flags;               /* EXEMPT_FLAG_* */
    UINT8  HashAlgorithm;       /* 0=未知 1=SHA256 */
    UINT8  HashLength;          /* 有效哈希字节数 */
    UINT8  HashData[EXEMPT_HASH_SIZE]; /* 哈希二进制（SHA256） */
    UINT32 PolicyId;            /* 关联策略 ID */
    UINT64 CreatedTime;         /* FILETIME 100ns */
    UINT64 ModifiedTime;        /* FILETIME 100ns */
    UINT64 ExpirationTime;      /* 0=永不过期 */
    ULONG  HitCount;            /* 命中计数 */
    WCHAR  Pattern[EXEMPT_MAX_PATTERN];     /* 路径模式/证书指纹hex/发布者名 */
    WCHAR  Description[EXEMPT_MAX_DESCRIPTION];
} EXEMPT_RULE, *PEXEMPT_RULE;

/**************************************************/
/*              函数声明 — 门面（Exempts.c）        */
/*                唯一对外接口                       */
/**************************************************/

/*---------------------------------------------------------------------------
 * 生命周期
 *---------------------------------------------------------------------------*/

/* 初始化排除子系统：加载 SQLite 规则 → 建内存表 → READY */
NTSTATUS
ExemptsInitialize(
    VOID
    );

VOID
ExemptsCleanup(
    VOID
    );

/*---------------------------------------------------------------------------
 * 统一豁免判定（唯一判定入口，对齐 SS 信任层级 Hash>Cert>Publisher>Path）
 *---------------------------------------------------------------------------*/

/*++
Routine Description:
    统一豁免判定。信任层级（对齐 SS IsWhitelisted）：
        Hash > Certificate > Publisher > Path，首匹配胜。
    - 哈希层：Sha256 命中哈希规则 → Trusted(HashMatch)
    - 证书层：微软签名（内置信任）或证书指纹规则 → Trusted(CertMatch)
    - 发布者层：发布者规则 → Trusted(PublisherMatch)
    - 路径层：路径规则（含模式匹配） → Trusted(PathMatch)

Arguments:
    FilePath - 文件完整路径（可空，路径层跳过）。
    Sha256   - 文件 SHA256（可空，哈希层跳过）。
    Result   - 已扫描的 IOC 结果（含证书字段）。NULL 时内部补做
               证书验证（IocVerifySignature）。
    Reason   - 可选输出命中原因。

Return Value:
    ExemptVerdict_Trusted / ExemptVerdict_NotTrusted。
--*/
EXEMPT_VERDICT
ExemptsEvaluate(
    _In_opt_ PCWSTR             FilePath,
    _In_opt_ PDEF_SHA256_HASH   Sha256,
    _In_opt_ PIOC_SCAN_RESULT   Result,
    _Out_opt_ PEXEMPT_REASON    Reason
    );

/* 兼容旧调用：BOOL 版（= ExemptsEvaluate == Trusted） */
BOOLEAN
ExemptsIsWhitelisted(
    _In_ PCWSTR             FilePath,
    _In_opt_ PDEF_SHA256_HASH Hash,
    _In_opt_ PIOC_SCAN_RESULT Result
    );

/*---------------------------------------------------------------------------
 * 哈希规则（ExemptHash）
 *---------------------------------------------------------------------------*/

NTSTATUS
ExemptsAddHash(
    _In_ PDEF_SHA256_HASH   Hash,
    _In_opt_ PCWSTR         Description
    );

NTSTATUS
ExemptsRemoveHash(
    _In_ PDEF_SHA256_HASH   Hash
    );

BOOLEAN
ExemptsIsHashWhitelisted(
    _In_ PDEF_SHA256_HASH   Hash
    );

/*---------------------------------------------------------------------------
 * 路径规则（ExemptPath）
 *---------------------------------------------------------------------------*/

NTSTATUS
ExemptsAddPath(
    _In_ PCWSTR             Path,
    _In_ EXEMPT_PATH_MODE   Mode,
    _In_opt_ PCWSTR         Description
    );

NTSTATUS
ExemptsRemovePath(
    _In_ PCWSTR             Path,
    _In_ EXEMPT_PATH_MODE   Mode
    );

BOOLEAN
ExemptsIsPathWhitelisted(
    _In_ PCWSTR             Path,
    _In_ EXEMPT_PATH_MODE   Mode,
    _Out_opt_ PEXEMPT_REASON Reason
    );

/*---------------------------------------------------------------------------
 * 证书/发布者规则（ExemptCert）
 *---------------------------------------------------------------------------*/

NTSTATUS
ExemptsAddCertificate(
    _In_ PCWSTR             Thumbprint,     /* SHA1 指纹 hex（小写无冒号） */
    _In_opt_ PCWSTR         Description
    );

NTSTATUS
ExemptsRemoveCertificate(
    _In_ PCWSTR             Thumbprint
    );

NTSTATUS
ExemptsAddPublisher(
    _In_ PCWSTR             Publisher,
    _In_opt_ PCWSTR         Description
    );

NTSTATUS
ExemptsRemovePublisher(
    _In_ PCWSTR             Publisher
    );

/*---------------------------------------------------------------------------
 * 注入场景豁免（ExemptInjection，合并 IocInjectionWhitelist）
 *---------------------------------------------------------------------------*/

/* 进程对名称级白名单预过滤（仅名称匹配，不豁免） */
BOOLEAN
ExemptsInjectionIsPairWhitelisted(
    _In_ PCWSTR             SourceName,
    _In_opt_ PCWSTR         TargetName
    );

/* 注入豁免完整判定（三步：进程对+受保护目录+签名 / 微软签名+非LOLBin+受保护目录） */
BOOLEAN
ExemptsShouldWhitelistInjection(
    _In_ struct _WKD_PROCESS*  SrcNode,
    _In_ struct _WKD_PROCESS*  TgtNode
    );

/*---------------------------------------------------------------------------
 * 进程身份豁免（ExemptProcess，2026-08-20）
 *---------------------------------------------------------------------------*/

/*++
Routine Description:
    判定进程名是否为"无镜像内核假进程"（System / Registry /
    Secure System / Memory Compression）。

    用途：ProcessCreate 前置快速通道。这些内核假进程没有真实可执行
    文件，深度静态分析（PE 解析/哈希/证书）无输入意义，且伪路径会
    触发无效磁盘 IO、污染分析信号与统计。

    安全边界（红线，改动名单前必读）：
      - 只允许收录"无镜像内核假进程"。System/Registry 等名字在
        PsQueryFullProcessImageFileName 语义下用户态进程无法伪装，
        豁免无绕过面。
      - 严禁扩展为通用进程名豁免：svchost.exe/lsass.exe 等有真实
        文件的进程按名豁免可被改名伪装绕过（对齐 process_manager.c
        禁杀名单"系统目录 + 文件名"双条件防伪装设计）。
      - 有文件的进程豁免必须走 ExemptsEvaluate（文件四维）：
        本判定只覆盖进程身份维度，二者互补（身份在前、文件在后）。

Arguments:
    ProcessName - 进程文件名（ImageFileName->Buffer，可空）。

Return Value:
    TRUE = 无镜像内核假进程（豁免）；FALSE = 非假进程 / 空输入。
--*/
BOOLEAN
CoExemptPseudoSystemProcess(
    _In_opt_ PCWSTR ProcessName
    );

/*---------------------------------------------------------------------------
 * 规则管理（通用）
 *---------------------------------------------------------------------------*/

/* 清空指定类型规则（ExemptRule_MaxValue=全部） */
VOID
ExemptsClearRules(
    _In_ EXEMPT_RULE_TYPE   Type
    );

/* 枚举全部规则（快照，调用方 UtHeapFree 释放） */
NTSTATUS
ExemptsGetRules(
    _Out_ PEXEMPT_RULE*     OutRules,
    _Out_ PULONG            Count
    );

/* 当前规则总数 */
UINT64
ExemptsGetRuleCount(
    VOID
    );

/*---------------------------------------------------------------------------
 * 系统组件采集 + ALPC 推送（ExemptPush，合并 IocWhitelistPush）
 *---------------------------------------------------------------------------*/

/* 采集核心系统组件哈希写入规则库（供 PushAll 前调用） */
NTSTATUS
ExemptsCollectSystemHashes(
    VOID
    );

/* 全量推送：采集系统哈希（agent 本地）→ 枚举 Path 规则 → ALPC 0x3105 增量推送驱动 */
NTSTATUS
ExemptsPushAll(
    VOID
    );

#endif /* WKD_AGENT_EXEMPTS_H */
