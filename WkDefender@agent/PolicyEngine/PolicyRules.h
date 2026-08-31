/**************************************************/
/*  WkDefender PolicyEngine — 内置检测规则          */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

typedef struct _POLICY_RULE {
    WCHAR               Name[128];
    WCHAR               Description[512];
    DEF_THREAT_SEVERITY MinSeverity;
    ULONG               MinScore;
    ULONG               RequiredFlags;
    ULONG               AnyFlags;
    WCHAR               MitreId[16];
    BOOLEAN             Enabled;
    ULONG               ThrottleSeconds;
} POLICY_RULE, *PPOLICY_RULE;

/**************************************************/
/*       运行时检测规则 (ThreatDetector 迁移)         */
/*                                                  */
/*  融合 POLICY_RULE + SS DetectionRule (hpp        */
/*  L1176-1229): 事件类型/进程模式/路径模式/命令行   */
/*  模式 + ScoreContribution/IsAtomic/Sequence超时。 */
/*  评估逻辑默认关闭 (PolicyEngine.EnableRuntimeRules */
/*  = FALSE), 注册表 API 为活代码。                  */
/**************************************************/

#define WKD_RULE_ID_LEN         64
#define WKD_RULE_PATTERN_LEN    256

/**************************************************/
/*       运行时规则条件模型 (RuleEngine 迁移, 2026-08)  */
/*                                                  */
/*  融合自 ShadowStrike PhantomSensor Behavioral/    */
/*  RuleEngine.{c,h}: 多条件 AND 组合 + 优先级首个   */
/*  命中 + 动作绑定 + 规则级统计。重功能实现非复制。   */
/*                                                  */
/*  结构映射 (对齐 RuleEngine.h):                    */
/*    WKD_CONDITION_TYPE    ← RE_CONDITION_TYPE     */
/*    WKD_OPERATOR          ← RE_OPERATOR           */
/*    WKD_RULE_ACTION       ← RE_ACTION_TYPE        */
/*    WKD_CONDITION         ← RE_CONDITION          */
/*    WKD_RULE_ACTION_DESC  ← RE_ACTION             */
/*    WKD_COMPILED_CONDITION← RE_COMPILED_CONDITION */
/*                                                  */
/*  与便捷字段 (EventType/ProcessPattern/...) 并存:   */
/*    ConditionCount>0 → 条件组合评估; =0 → 便捷字段   */
/*    (既有规则语义零改动)。                         */
/*                                                  */
/*  ※死代码条件: FileHash/RegistryPath/NetworkAddress/ */
/*    Domain/MitreTechnique — 评估上下文对应字段恒     */
/*    NULL (事件源未接 IOA), 条件自然不命中; InList     */
/*    编译期拒绝 (对齐 SS RepCompileRule L1755-1757);  */
/*    Custom 恒 FALSE (对齐 SS L2188-2195 无 handler)。 */
/**************************************************/

#define WKD_RULE_MAX_CONDITIONS    16      /* 对齐 RE_MAX_CONDITIONS */
#define WKD_RULE_MAX_ACTIONS       8       /* 对齐 RE_MAX_ACTIONS */
#define WKD_RULE_MAX_VALUE_LEN     255     /* 对齐 RE_MAX_VALUE_LEN */
#define WKD_RULE_ACTION_PARAM_LEN  128

/* 条件类型 (对齐 SS RE_CONDITION_TYPE, RuleEngine.h L70-85) */
typedef enum _WKD_CONDITION_TYPE {
    WkdCond_ProcessName = 0,
    WkdCond_ParentName,
    WkdCond_CommandLine,
    WkdCond_FilePath,
    WkdCond_FileHash,           /* ※死代码: 上下文无哈希源, ioc_hashes/IocMatcher 已覆盖 */
    WkdCond_RegistryPath,       /* ※死代码: 注册表载荷未接 IOA */
    WkdCond_NetworkAddress,     /* ※死代码: 网络事件源未接通 */
    WkdCond_Domain,             /* ※死代码: 同上 */
    WkdCond_ThreatScore,
    WkdCond_MitreTechnique,     /* ※死代码: 单事件上下文无 MITRE 标注 (T3Tactic 在 PairContext) */
    WkdCond_BehaviorFlag,
    WkdCond_TimeOfDay,
    WkdCond_Custom,             /* ※死代码: 无运行时 handler, 恒 FALSE (对齐 SS) */
    WkdCond_MaxValue
} WKD_CONDITION_TYPE;

/* 操作符 (对齐 SS RE_OPERATOR, RuleEngine.h L90-101) */
typedef enum _WKD_OPERATOR {
    WkdOp_Equals = 0,
    WkdOp_NotEquals,
    WkdOp_Contains,
    WkdOp_StartsWith,
    WkdOp_EndsWith,
    WkdOp_Wildcard,             /* 显式通配 */
    WkdOp_GreaterThan,
    WkdOp_LessThan,
    WkdOp_InList,               /* ※死代码: 编译期拒绝 (对齐 SS STATUS_NOT_SUPPORTED) */
    WkdOp_MaxValue
} WKD_OPERATOR;

/* 动作类型 (对齐 SS RE_ACTION_TYPE, RuleEngine.h L106-117; 处置出口= VerdictEngine) */
typedef enum _WKD_RULE_ACTION {
    WkdRuleAction_None = 0,     /* 显式无动作 */
    WkdRuleAction_Allow,        /* 免告警免加分 (白名单语义, 不做驱动放行穿透) */
    WkdRuleAction_Block,        /* → WKD_VERDICT{RecommendedAction=Block} */
    WkdRuleAction_Quarantine,   /* → WKD_VERDICT{RecommendedAction=Quarantine} */
    WkdRuleAction_Terminate,    /* → WKD_VERDICT{RecommendedAction=Terminate} */
    WkdRuleAction_Alert,        /* → IOA_ALERT 入队 (DefDetSrc_Rule) */
    WkdRuleAction_Log,          /* → 打印/log_manager */
    WkdRuleAction_Investigate,  /* ※死代码: 无对应处置语义, 降级 Alert */
    WkdRuleAction_Custom,       /* ※死代码: 无 handler, 按 None */
    WkdRuleAction_MaxValue
} WKD_RULE_ACTION;

/* 条件结构 (对齐 SS RE_CONDITION, RuleEngine.h L122-128) */
typedef struct _WKD_CONDITION {
    WKD_CONDITION_TYPE Type;
    WKD_OPERATOR       Operator;
    WCHAR              Value[WKD_RULE_MAX_VALUE_LEN + 1];
    BOOLEAN            Negate;             /* NOT 条件 */
    UCHAR              Reserved[3];
} WKD_CONDITION, *PWKD_CONDITION;
typedef const WKD_CONDITION *PCWKD_CONDITION;

/* 动作结构 (对齐 SS RE_ACTION, RuleEngine.h L133-136) */
typedef struct _WKD_RULE_ACTION_DESC {
    WKD_RULE_ACTION Type;
    WCHAR           Parameter[WKD_RULE_ACTION_PARAM_LEN];
} WKD_RULE_ACTION_DESC, *PWKD_RULE_ACTION_DESC;

/* 编译缓存 (对齐 SS RE_COMPILED_CONDITION, RuleEngine.c L75-107; 用户态简化, 无预哈希) */
typedef struct _WKD_COMPILED_CONDITION {
    BOOLEAN IsCompiled;
    ULONG   PatternLen;         /* 字符串条件 WCHAR 长度 */
    ULONG   NumericValue;       /* 数值条件预解析 */
    ULONG   TimeStartMinute;    /* 时间段 "HH:MM-HH:MM" 预解析 */
    ULONG   TimeEndMinute;
    UCHAR   FileHash[32];       /* 哈希条件 hex→bytes (死代码条件) */
} WKD_COMPILED_CONDITION, *PWKD_COMPILED_CONDITION;
typedef const WKD_COMPILED_CONDITION *PCWKD_COMPILED_CONDITION;

typedef struct _WKD_DETECTION_RULE {
    WCHAR               RuleId[WKD_RULE_ID_LEN];
    WCHAR               Name[128];
    WCHAR               Description[512];
    BOOLEAN             Enabled;
    DEF_THREAT_SEVERITY Severity;           /* 规则严重级 */
    DEF_THREAT_CATEGORY Category;           /* 规则威胁类别 */
    ULONG               ScoreContribution;  /* 命中加分 [0,100] */
    ULONG               MinScore;           /* 最低评分门槛 (融合 POLICY_RULE) */
    ULONG               RequiredFlags;      /* 行为标志全含 */
    ULONG               AnyFlags;           /* 行为标志任一 */
    ULONG               EventType;          /* 匹配的事件类型 (WKD_EVENT_TYPE, 0=任意) */
    WCHAR               ProcessPattern[WKD_RULE_PATTERN_LEN];    /* 进程名通配 (L"*" 全部) */
    WCHAR               TargetPattern[WKD_RULE_PATTERN_LEN];     /* 目标路径通配 */
    WCHAR               CommandLinePattern[WKD_RULE_PATTERN_LEN];/* 命令行子串 */
    WCHAR               MitreId[16];
    BOOLEAN             IsAtomic;           /* TRUE=单事件; FALSE=序列 (评估未实现) */
    ULONG               SequenceTimeoutMs;  /* 序列超时 */
    LARGE_INTEGER       LastMatchTime;      /* 运行时: 最近命中 */

    /* ── RuleEngine 迁移 (2026-08): 多条件 AND 组合模型 ──
     * ConditionCount>0 走条件组合评估; =0 回退便捷字段 (既有路径)。
     * CompiledConditions 在 AddRule 时由 Policy_CompileRule 填充,
     * GetRules 输出时清零 (对齐 SS ReGetRule 清 ListEntry, RuleEngine.c L1314-1315)。 */
    WKD_CONDITION        Conditions[WKD_RULE_MAX_CONDITIONS];
    ULONG                ConditionCount;
    WKD_RULE_ACTION_DESC Actions[WKD_RULE_MAX_ACTIONS];
    ULONG                ActionCount;
    ULONG                Priority;           /* 低=高优先级 (对齐 SS RE_RULE.Priority) */
    BOOLEAN              StopProcessing;     /* 命中后停止评估后续规则 (对齐 SS) */
    WKD_COMPILED_CONDITION CompiledConditions[WKD_RULE_MAX_CONDITIONS];
    ULONG                CompiledConditionCount;
    BOOLEAN              IsCompiled;
    volatile LONG64      EvaluationCount;    /* 规则级统计 (对齐 SS RE_RULE.EvaluationCount) */
    volatile LONG64      MatchCount;         /* 规则级统计 (对齐 SS RE_RULE.MatchCount) */
} WKD_DETECTION_RULE, *PWKD_DETECTION_RULE;

#define POLICY_RUNTIME_RULES_MAX  64

static const POLICY_RULE g_BuiltinRules[] = {
    { L"CriticalScore",           L"Score >= 200",                      DefThreatSeverity_Critical, 200, 0, 0, L"",                1, 60 },
    { L"HighScoreWithInjection",  L"Score>=100 AND injection",          DefThreatSeverity_High,      100, DEF_BEHAVIOR_FLAG_INJECTION, 0, L"T1055",   1, 120 },
    { L"HollowingDetected",       L"Process hollowing",                 DefThreatSeverity_Critical,  0,   DEF_BEHAVIOR_FLAG_HOLLOWING, 0, L"T1055.012", 1, 60 },
    { L"LolbinWithChain",         L"LOLBin + suspicious chain, score>=60", DefThreatSeverity_High,   60,  DEF_BEHAVIOR_FLAG_LOLBIN, DEF_BEHAVIOR_FLAG_SUSPICIOUS_CHAIN, L"T1218", 1, 120 },
    { L"CredentialDumping",       L"LSASS memory read, score>=70",      DefThreatSeverity_Critical,  70,  DEF_BEHAVIOR_FLAG_MEMORY_READ_REMOTE, 0, L"T1003.001", 1, 60 },
    { L"PrivilegeEscalation",     L"Token manipulation, score>=80",     DefThreatSeverity_High,      80,  DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE, 0, L"T1134", 1, 120 },
    { L"SuspiciousPowerShell",    L"Encoded PowerShell, score>=50",     DefThreatSeverity_Medium,    50,  DEF_BEHAVIOR_FLAG_POWERSHELL_ENCODED, 0, L"T1059.001", 1, 180 },
    { L"CrossSessionInjection",   L"Cross-session injection",           DefThreatSeverity_High,      0,   DEF_BEHAVIOR_FLAG_CROSS_SESSION | DEF_BEHAVIOR_FLAG_INJECTION, 0, L"T1564.004", 1, 120 },
    { L"PpidSpoofWithElevation",  L"PPID spoof + elevation",            DefThreatSeverity_High,      0,   DEF_BEHAVIOR_FLAG_PPID_SPOOF | DEF_BEHAVIOR_FLAG_ELEVATED, 0, L"T1055.012", 1, 120 },
    { L"DownloaderActivity",      L"Downloader behavior, score>=60",    DefThreatSeverity_Medium,    60,  DEF_BEHAVIOR_FLAG_DOWNLOADER, 0, L"T1105", 1, 180 },
    { L"RemoteThreadForeign",     L"Remote thread in foreign proc, score>=50", DefThreatSeverity_Medium, 50, DEF_BEHAVIOR_FLAG_REMOTE_THREAD, 0, L"T1055.001", 1, 180 },
    { L"ReflectiveLoad",          L"Reflective DLL loading",            DefThreatSeverity_High,      0,   DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD, 0, L"T1620", 1, 60 },

    /* ── 注入规则补充 (死代码: 待驱动补 NtQueueApcThread/SetContext/
     *   Suspend/Resume/MapViewOfSection syscall case 后激活) ── */
    { L"ApcInjection",            L"APC injection",                     DefThreatSeverity_High,      0,   DEF_BEHAVIOR_FLAG_APC_INJECTION, 0, L"T1055.004", 1, 120 },
    { L"ThreadContextHijack",     L"Thread context hijacking",          DefThreatSeverity_High,      0,   DEF_BEHAVIOR_FLAG_SET_CONTEXT, 0, L"T1055.012", 1, 120 },
    { L"SectionMapInjection",     L"Section map remote injection",      DefThreatSeverity_High,      0,   DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE, 0, L"T1055.002", 1, 120 },
};
#define BUILTIN_RULE_COUNT (sizeof(g_BuiltinRules) / sizeof(g_BuiltinRules[0]))

/**************************************************/
/*       序列规则 (ShadowStrike PatternMatcher 迁移)  */
/*                                                  */
/*  实现 WKD_DETECTION_RULE.IsAtomic=FALSE 的        */
/*  序列分支: 事件序列行为模式匹配。                  */
/*                                                  */
/*  迁移自 SS PhantomSensor Behavioral/              */
/*  PatternMatcher.c — PM_PATTERN (数据驱动模式) /   */
/*  PM_EVENT_CONSTRAINT (单步约束) /                 */
/*  PM_MATCH_STATE_INTERNAL (匹配状态)。             */
/*  重功能实现, 非源码复制。                         */
/*                                                  */
/*  ※死代码开关: EnableSequenceRules=FALSE 默认不    */
/*    评估 (对齐 EnableRuntimeRules)。注册 API 为活   */
/*    代码 (可经 ALPC/UI 调用)。                    */
/*                                                  */
/*  与 Tier2 FSM 的关系:                            */
/*    FSM    = 编译期硬编码 6 种已知攻击模式 (边序列)  */
/*    序列规则 = 运行时数据驱动规则 (边类型 + 通配符 +  */
/*    时序窗口 + Optional/Terminal + 部分匹配), 运营   */
/*    可部署, 与 FSM 互补。                          */
/**************************************************/

#define WKD_SEQ_MAX_STEPS                  12      /* 对齐 FSM_STATE_MAX=12 (PM 为 32) */
#define WKD_SEQ_MAX_RULES                  64      /* 对齐 POLICY_RUNTIME_RULES_MAX */
#define WKD_SEQ_STATE_HASH_BUCKETS         4096    /* 对齐 FSM_STATE_HASH_BUCKETS */
#define WKD_SEQ_MAX_STATES_PER_PAIR        64      /* 对齐 PM_MAX_STATES_PER_PROCESS=100, 按对收紧 */
#define WKD_SEQ_MAX_WILDCARD_ITERATIONS    10000   /* 对齐 PM_MAX_WILDCARD_ITERATIONS, 防 ReDoS */
#define WKD_SEQ_PATTERN_LEN                 1024    /* 序列规则模式/文本最大长度 (wcsnlen 上界) */
#define WKD_SEQ_VALUE_LEN                  128     /* 对齐 PM_MAX_VALUE_PATTERN_LENGTH=128 */

/* 序列规则单步约束 (对齐 PM_EVENT_CONSTRAINT) */
typedef struct _WKD_SEQUENCE_STEP {
    IOA_GRAPH_EDGE_TYPE EdgeType;                   /* 触发边类型 (DefEdge_*, 0=任意) */
    WCHAR   ProcessPattern[WKD_RULE_PATTERN_LEN];   /* 源进程名通配 (L"*"=全部) */
    WCHAR   PathPattern[WKD_RULE_PATTERN_LEN];      /* 目标路径/镜像通配 */
    WCHAR   ValuePattern[WKD_SEQ_VALUE_LEN];        /* 事件值通配 (注册表值/参数串) */
    ULONG   MaxTimeFromPrevious;                    /* 距上一步最大间隔 ms (0=不限) */
    ULONG   MinTimeFromPrevious;                    /* 距上一步最小间隔 ms (0=不限) */
    BOOLEAN Optional;                               /* 可选步: 未出现不阻塞推进 */
    BOOLEAN Terminal;                               /* 匹配即完成 (部分命中也出告警) */
} WKD_SEQUENCE_STEP, *PWKD_SEQUENCE_STEP;

/* 序列规则定义 (对齐 PM_PATTERN + 融合 WKD_DETECTION_RULE 元数据) */
typedef struct _WKD_SEQUENCE_RULE {
    /* 元数据 (对齐 WKD_DETECTION_RULE 风格) */
    WCHAR               RuleId[WKD_RULE_ID_LEN];
    WCHAR               Name[128];
    WCHAR               Description[512];
    BOOLEAN             Enabled;
    DEF_THREAT_SEVERITY Severity;
    DEF_THREAT_CATEGORY Category;
    ULONG               ScoreContribution;          /* 命中加分 [0,100] */
    WCHAR               MitreId[16];

    /* 事件序列 (对齐 PM_PATTERN.Events) */
    WKD_SEQUENCE_STEP   Steps[WKD_SEQ_MAX_STEPS];
    ULONG               StepCount;

    /* 匹配设置 */
    BOOLEAN             RequireExactOrder;          /* TRUE=严格按序 (对齐 PM) */
    ULONG               SequenceTimeoutMs;          /* 整链硬超时 ms (0=不限; 补 FSM 缺陷) */
    ULONG               MinMatchedEvents;           /* 部分匹配门槛 (0=全部必需步) */

    /* 运行时 (锁内维护) */
    ULONG64             FirstStepEdgeMask;          /* 预计算 Steps[0].EdgeType 位图, 首步预过滤 */
    volatile LONG64     MatchCount;
    LARGE_INTEGER       LastMatchTime;
} WKD_SEQUENCE_RULE, *PWKD_SEQUENCE_RULE;

/* 序列匹配状态 (对齐 PM_MATCH_STATE_INTERNAL) */
typedef struct _WKD_SEQ_MATCH_STATE {
    /* 键 (哈希输入: DJB(SourceNodeId||TargetNodeId||RuleIndex)) */
    GUID    SourceNodeId;
    GUID    TargetNodeId;
    ULONG   RuleIndex;                              /* Rules[] 索引 */

    /* 逐事件追踪 (对齐 PM_MATCH_STATE_INTERNAL) */
    BOOLEAN         EventMatched[WKD_SEQ_MAX_STEPS];
    LARGE_INTEGER   EventTimes[WKD_SEQ_MAX_STEPS];
    ULONG           EventMatchOrder[WKD_SEQ_MAX_STEPS];
    ULONG           NextMatchOrder;
    ULONG           CurrentStep;                    /* 下一期望步索引 */
    ULONG           MatchedEvents;
    LARGE_INTEGER   FirstEventTime;
    LARGE_INTEGER   LastEventTime;

    /* 完成状态 */
    BOOLEAN         IsComplete;
    BOOLEAN         IsStale;                        /* 硬超时已过, 等待清理 */
    BOOLEAN         IsRemoved;                      /* 已从进程对链表移除, 等待引用归零 */
    BOOLEAN         AlertSent;                      /* 保证只告警一次 */
    ULONG           ConfidenceScore;                /* [0,100]: MatchedEvents*100/StepCount */

    /* 生命周期 */
    LIST_ENTRY      HashLink;                       /* 引擎 StateHashBuckets[] */
    LIST_ENTRY      PairLink;                       /* 链入 PairCtx->SeqMatchHead */
    volatile LONG   RefCount;
} WKD_SEQ_MATCH_STATE, *PWKD_SEQ_MATCH_STATE;
