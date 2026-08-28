/**************************************************/
/*  WkDefender Agent — 公共基础类型定义              */
/*  供 IOC / IOA / PolicyEngine / Storage 共用     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <stdio.h>
#include <ntstatus.h>
#include <rpc.h>

/**************************************************/
/*  兼容回退: PCUCHAR 定义于 ntdef.h (内核头),       */
/*  用户态包含链不含 ntdef.h, 此处安全补全。         */
/**************************************************/
#ifndef PCUCHAR
typedef CONST UCHAR *PCUCHAR;
#endif

/**************************************************/
/*               统一堆函数接口                      */
/**************************************************/
#include "Common/Utils.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(p) ((void)(p))
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/**************************************************/
/*               基础常量                           */
/**************************************************/

#define DEF_MAX_PATH                    256
#define DEF_MAX_COMMAND_LINE            4096
#define DEF_MAX_IMAGE_NAME              256
#define DEF_SHA256_SIZE                 32

#define DEF_PROCESS_HASH_BUCKETS        1021
#define DEF_GRAPH_NODE_HASH_BUCKETS     4099

#define DEF_HOT_CACHE_MAX_ENTRIES       8192
#define DEF_HOT_CACHE_TTL_MS            (1000 * 60 * 60)

#define DEF_EDGE_MAX_EVENT_IDS          16
#define DEF_PATH_MAX_DEPTH              32
#define DEF_SUBGRAPH_MAX_NODES          256

/**************************************************/
/*               链表操作宏 (用户态)                */
/**************************************************/

#ifndef InitializeListHead
#define InitializeListHead(ListHead) \
    ((ListHead)->Flink = (ListHead)->Blink = (ListHead))
#endif

#ifndef InsertHeadList
#define InsertHeadList(ListHead, Entry) do { \
    PLIST_ENTRY _flink = (ListHead)->Flink;   \
    (Entry)->Flink = _flink;                  \
    (Entry)->Blink = (ListHead);              \
    _flink->Blink = (Entry);                  \
    (ListHead)->Flink = (Entry);              \
} while (0)
#endif

#ifndef IsListEmpty
#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))
#endif

#ifndef InsertTailList
#define InsertTailList(ListHead, Entry) do { \
    PLIST_ENTRY _blink = (ListHead)->Blink;   \
    (Entry)->Flink = (ListHead);              \
    (Entry)->Blink = _blink;                  \
    _blink->Flink = (Entry);                  \
    (ListHead)->Blink = (Entry);              \
} while (0)
#endif

#ifndef RemoveEntryList
#define RemoveEntryList(Entry) do { \
    PLIST_ENTRY _flink = (Entry)->Flink; \
    PLIST_ENTRY _blink = (Entry)->Blink; \
    _flink->Blink = _blink; \
    _blink->Flink = _flink; \
    (Entry)->Flink = (Entry)->Blink = NULL; \
} while (0)
#endif

#ifndef RemoveHeadList
#define RemoveHeadList(ListHead) \
    ((ListHead)->Flink != (ListHead) ? \
     ((ListHead)->Flink->Blink = (ListHead)->Blink, \
      (ListHead)->Blink->Flink = (ListHead)->Flink, \
      (ListHead)->Flink) : (ListHead))
#endif



/**************************************************/
/*               GUID 辅助                         */
/**************************************************/

#define DEF_NGUID                    { 0,0,0,{0,0,0,0,0,0,0,0} }
#define DefIsNullNodeId(id)                 \
    ((id).Data1 == 0 && (id).Data2 == 0 &&  \
     (id).Data3 == 0 && (id).Data4[0] == 0)
#define WkdCreateGuid(guid)                    CoCreateGuid(guid)
#define WkdCopyGuid(dst, src)               memcpy((dst), (src), sizeof(GUID))
#define DefGuidEqual(a, b)                  (memcmp((a), (b), sizeof(GUID)) == 0)

/**************************************************/
/*               NodeId / ProcessId 初始化          */
/*  用于将驱动原始数据（PID）转换为 IOA 引擎所需的  */
/*  GUID NodeId 和 DEF_PROCESS_ID 结构化标识        */
/**************************************************/

FORCEINLINE
VOID
DefInitNodeId(
    _Out_ GUID* Id,
    _In_ ULONG Pid,
    _In_ LONGLONG CreateTime
    )
/*++
    从 PID 创建确定性 GUID。
    适用于线程事件等未经过 Genealogy 的路径，
    让 IOA 引擎后续可以通过 Data1 匹配到进程节点。
--*/
{
    Id->Data1 = Pid;
    Id->Data2 = 0;
    Id->Data3 = 0;
    Id->Data4[0] = 0;
    Id->Data4[1] = 0;
    Id->Data4[2] = 0;
    Id->Data4[3] = 0;
    Id->Data4[4] = 0;
    Id->Data4[5] = 0;
    Id->Data4[6] = 0;
    Id->Data4[7] = 0;
    UNREFERENCED_PARAMETER(CreateTime);
}

/**************************************************/
/*                   结束                           */
/**************************************************/
/**************************************************/

typedef struct _DEF_SHA256_HASH {
    UCHAR Data[DEF_SHA256_SIZE];
} DEF_SHA256_HASH, *PDEF_SHA256_HASH;

/**************************************************/
/*               节点类型                           */
/**************************************************/

typedef enum _DEF_NODE_TYPE {
    DefNode_Unknown         = 0,
    DefNode_Process         = 1,
    DefNode_File            = 2,
    DefNode_Registry        = 3,
    DefNode_Network         = 4,
    DefNode_Thread          = 5,
    DefNode_MemoryRegion    = 6,
    DefNode_Max
} DEF_NODE_TYPE, *PDEF_NODE_TYPE;

/**************************************************/
/*               边类型                             */
/**************************************************/

typedef enum _IOA_GRAPH_EDGE_TYPE {
    DefEdge_Unknown         = 0,
    DefEdge_Creates         = 1,
    DefEdge_Terminates      = 2,
    DefEdge_WritesTo        = 10,
    DefEdge_ReadsFrom       = 11,
    DefEdge_Executes        = 12,
    DefEdge_Opens           = 13,
    DefEdge_InjectsInto     = 20,
    DefEdge_Hollows         = 21,
    DefEdge_ReflectiveLoad  = 22,
    DefEdge_Sideloads       = 23,
    DefEdge_ConnectsTo      = 30,
    DefEdge_ListensOn       = 31,
    DefEdge_DnsQueries      = 32,
    DefEdge_Modifies        = 40,
    DefEdge_Allocates       = 41,
    DefEdge_Protects        = 42,
    DefEdge_Impersonates    = 43,
    DefEdge_AssociatedWith  = 50,
    DefEdge_Max
} IOA_GRAPH_EDGE_TYPE, *PIOA_GRAPH_EDGE_TYPE;

/**************************************************/
/*               事件分类                           */
/**************************************************/

typedef enum _DEF_EVENT_CLASS {
    DefEventClass_Unknown   = 0,
    DefEventClass_IOC       = 1,
    DefEventClass_IOA       = 2,
    DefEventClass_System    = 3,
} DEF_EVENT_CLASS, *PDEF_EVENT_CLASS;

/**************************************************/
/*               IOC 来源                          */
/**************************************************/

typedef enum _DEF_IOC_SOURCE {
    DefIocSrc_None          = 0,
    DefIocSrc_FileHash      = 1,
    DefIocSrc_CertBlacklist = 2,
    DefIocSrc_YaraRule      = 3,
    DefIocSrc_SigmaRule     = 4,
    DefIocSrc_IpReputation  = 5,
    DefIocSrc_Max
} DEF_IOC_SOURCE, *PDEF_IOC_SOURCE;

/**************************************************/
/*               IOC 判定                          */
/**************************************************/

typedef enum _DEF_IOC_VERDICT {
    DefIocVerdict_Unknown   = 0,
    DefIocVerdict_Clean     = 1,
    DefIocVerdict_Suspicious= 2,
    DefIocVerdict_Malicious = 3,
} DEF_IOC_VERDICT, *PDEF_IOC_VERDICT;

/**************************************************/
/*               威胁严重度                         */
/**************************************************/

typedef enum _DEF_THREAT_SEVERITY {
    DefThreatSeverity_None      = 0,
    DefThreatSeverity_Low       = 1,
    DefThreatSeverity_Medium    = 2,
    DefThreatSeverity_High      = 3,
    DefThreatSeverity_Critical  = 4,
} DEF_THREAT_SEVERITY, *PDEF_THREAT_SEVERITY;

/**************************************************/
/*               行为标志位                         */
/**************************************************/

#define DEF_BEHAVIOR_FLAG_PPID_SPOOF           0x00000001
#define DEF_BEHAVIOR_FLAG_CROSS_SESSION        0x00000002
#define DEF_BEHAVIOR_FLAG_ELEVATED             0x00000004
#define DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE      0x00000008
#define DEF_BEHAVIOR_FLAG_INJECTION            0x00000010
#define DEF_BEHAVIOR_FLAG_HOLLOWING            0x00000020
#define DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD      0x00000040
#define DEF_BEHAVIOR_FLAG_LOLBIN               0x00000080
#define DEF_BEHAVIOR_FLAG_POWERSHELL_ENCODED   0x00000100
#define DEF_BEHAVIOR_FLAG_DOWNLOADER           0x00000200
#define DEF_BEHAVIOR_FLAG_DLL_SIDE_LOAD        0x00000400
#define DEF_BEHAVIOR_FLAG_PATH_HIJACK          0x00000800
#define DEF_BEHAVIOR_FLAG_REMOTE_THREAD        0x00001000
#define DEF_BEHAVIOR_FLAG_APC_INJECTION        0x00002000
#define DEF_BEHAVIOR_FLAG_SET_CONTEXT          0x00004000
#define DEF_BEHAVIOR_FLAG_MEMORY_READ_REMOTE   0x00008000
#define DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE   0x00010000
#define DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE     0x00020000
#define DEF_BEHAVIOR_FLAG_PROCESS_OPEN         0x00040000
#define DEF_BEHAVIOR_FLAG_SUSPICIOUS_CHAIN     0x00080000

/*
 * 行为标志语义分类掩码。
 *
 * 商业 EDR 的核心洞察：进程的行为标志分为两类 —
 *   1. 进程固有属性（诞生即确定，不依赖交互对象）→ 归属 ProcessNode
 *   2. 进程对交互行为（"对谁做了什么"）→ 归属 ProcessPairContext
 *
 * 将交互行为打在进程全局标志上会导致跨交互语义污染：
 *   进程A打开lsass → SrcNode标记PROCESS_OPEN → 进程A连接Office365也被污染。
 * 对标 CrowdStrike Falcon / SentinelOne，行为归因的最小粒度是进程交互边。
 */
#define DEF_BEHAVIOR_MASK_PROCESS_INTRINSIC (     \
    DEF_BEHAVIOR_FLAG_PPID_SPOOF            |     \
    DEF_BEHAVIOR_FLAG_CROSS_SESSION         |     \
    DEF_BEHAVIOR_FLAG_ELEVATED              |     \
    DEF_BEHAVIOR_FLAG_LOLBIN                |     \
    DEF_BEHAVIOR_FLAG_POWERSHELL_ENCODED    |     \
    DEF_BEHAVIOR_FLAG_DOWNLOADER            |     \
    DEF_BEHAVIOR_FLAG_DLL_SIDE_LOAD         |     \
    DEF_BEHAVIOR_FLAG_PATH_HIJACK           |     \
    DEF_BEHAVIOR_FLAG_SUSPICIOUS_CHAIN        )

#define DEF_BEHAVIOR_MASK_PAIR_INTERACTION (      \
    DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE       |     \
    DEF_BEHAVIOR_FLAG_INJECTION             |     \
    DEF_BEHAVIOR_FLAG_HOLLOWING             |     \
    DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD       |     \
    DEF_BEHAVIOR_FLAG_REMOTE_THREAD         |     \
    DEF_BEHAVIOR_FLAG_APC_INJECTION         |     \
    DEF_BEHAVIOR_FLAG_SET_CONTEXT           |     \
    DEF_BEHAVIOR_FLAG_MEMORY_READ_REMOTE    |     \
    DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE    |     \
    DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE      |     \
    DEF_BEHAVIOR_FLAG_PROCESS_OPEN            )

C_ASSERT((DEF_BEHAVIOR_MASK_PROCESS_INTRINSIC &
          DEF_BEHAVIOR_MASK_PAIR_INTERACTION) == 0);
C_ASSERT((DEF_BEHAVIOR_MASK_PROCESS_INTRINSIC |
          DEF_BEHAVIOR_MASK_PAIR_INTERACTION) == 0x000FFFFF);

/**************************************************/
/*     行为标志位扩展 — 新检测类别 (死代码预留)      */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer 8 大引擎    */
/*  (Ransomware/Persistence/C2/Evasion/Exfil/       */
/*   Lateral/Credential/Masquerade)。               */
/*                                                  */
/*  死代码: 检测引擎 (Ioa*Detect) 未接入流水线,      */
/*  此标志为接入阶段 PolicyRules / 告警预留。         */
/*  不加入上方 PROCESS_INTRINSIC / PAIR_INTERACTION  */
/*  掩码, 避免破坏现有 C_ASSERT 语义分类断言。       */
/**************************************************/

#define DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC       0x00100000   /* 勒索加密 T1486 */
#define DEF_BEHAVIOR_FLAG_RANSOMWARE_DELETE    0x00200000   /* 勒索批量删除 T1485 */
#define DEF_BEHAVIOR_FLAG_RANSOMWARE_SHADOW    0x00400000   /* 卷影副本删除 T1490 */
#define DEF_BEHAVIOR_FLAG_PERSISTENCE          0x00800000   /* 注册表/服务/任务持久化 T1547.001 */
#define DEF_BEHAVIOR_FLAG_C2_COMMUNICATION     0x01000000   /* C2 通信 T1071.001 */
#define DEF_BEHAVIOR_FLAG_EXFILTRATION         0x02000000   /* 数据外渗 T1048.003 */
#define DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT     0x04000000   /* 横向移动 T1021.002 */
#define DEF_BEHAVIOR_FLAG_EVASION              0x08000000   /* 防御规避 T1070.001 */
#define DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET    0x10000000   /* 凭据目标进程被打开 T1003.001 */
#define DEF_BEHAVIOR_FLAG_MASQUERADE           0x20000000   /* 进程伪装(脚本父+Temp) T1036 */
#define DEF_BEHAVIOR_FLAG_TXF_CREATE           0x40000000   /* 事务化进程创建 (Doppelgang T1055.013, 死代码) */
#define DEF_BEHAVIOR_FLAG_AMSI_BYPASS          0x80000000   /* AMSI 绕过补丁 T1562.001 (AmsiBypassDetector, 2026-08-05) */

/**************************************************/
/*               进程状态                           */
/**************************************************/

typedef enum _DEF_PROCESS_STATUS {
    DefProcessStatus_Running    = 0x0001,
    DefProcessStatus_Terminated = 0x0002,
    DefProcessStatus_Isolated   = 0x0008,
    DefProcessStatus_Threat     = 0x0040,
} DEF_PROCESS_STATUS, *PDEF_PROCESS_STATUS;

/**************************************************/
/*           因果图边描述符（环形缓冲区条目）        */
/**************************************************/

#define GRAPH_RING_BUFFER_SIZE      4096        /* 必须是 2 的幂 */
#define GRAPH_RING_BUFFER_MASK      (GRAPH_RING_BUFFER_SIZE - 1)

typedef enum _GRAPH_LAYER_DECISION {
    GraphLayer_Hot  = 0,    /* Layer 0: 必须进图 — 进程创建/退出/FSM活跃/高威胁 */
    GraphLayer_Warm = 1,    /* Layer 1: 条件进图 — 关键进程访问/跨进程内存操作 */
    GraphLayer_Cold = 2,    /* Layer 2: 暂存延迟 — 待后续事件评估后回补或淘汰 */
    GraphLayer_Skip = 3,    /* Layer 3: 不进图 — 系统进程间通信/自操作/归档 */
} GRAPH_LAYER_DECISION, *PGRAPH_LAYER_DECISION;

typedef struct _GRAPH_EDGE_DESCRIPTOR {
    GUID                EdgeId;             /* 16 bytes — 边全局唯一ID */
    GUID                SrcNodeId;          /* 16 bytes */
    GUID                TgtNodeId;          /* 16 bytes */
    IOA_GRAPH_EDGE_TYPE       EdgeType;           /* 4 bytes */
    DEF_EVENT_CLASS     EventClass;         /* 4 bytes */
    ULONG               BehaviorFlags;      /* 4 bytes */
    ULONG               Confidence;         /* 4 bytes */
    LARGE_INTEGER       Timestamp;          /* 8 bytes — 事件时间戳 */
} GRAPH_EDGE_DESCRIPTOR, *PGRAPH_EDGE_DESCRIPTOR;

C_ASSERT(sizeof(GRAPH_EDGE_DESCRIPTOR) == 72);

/**************************************************/
/*           FSM 攻击分类（粗粒度）                   */
/*           Tier2 只做粗判，精确 MITRE 由 Tier3 负责  */
/**************************************************/

typedef enum _FSM_ATTACK_CLASS {
    FsmClass_None               = 0,
    FsmClass_ProcessInjection   = 1,   /* 进程注入类 (T1055.001/.002/.004/.012, T1620) */
    FsmClass_ProcessHollowing   = 2,   /* 进程挖空类 (T1055.012) */
    FsmClass_CredentialAccess   = 3,   /* 凭据访问类 (T1003.001/.002/.003) */
    FsmClass_DefenseEvasion     = 4,   /* 防御规避类 */
    FsmClass_Persistence        = 5,   /* 持久化类 (T1574.002 等) */
    FsmClass_LateralMovement    = 6,   /* 横向移动类 */
    FsmClass_Collection         = 7,   /* 数据收集类 */
    FsmClass_CommandAndControl  = 8,   /* C2 通信类 */
    FsmClass_Max
} FSM_ATTACK_CLASS, *PFSM_ATTACK_CLASS;

/**************************************************/
/*           DFA+FSM 攻击模式定义                   */
/*                                                  */
/*  注意：当前使用固定数组 Steps[FSM_STATE_MAX]。   */
/*  未来进化方向为邻接表/有向图，支持分支路径和      */
/*  可选步骤。迁移时 Tier3 应通过 FsmPatternId +    */
/*  全局注册表查询模式的完整 DAG 结构。              */
/**************************************************/

#define FSM_PATTERN_COUNT           6       /* 预定义 6 种攻击模式 (含 ThreadHijacking) */
#define FSM_STATE_MAX               12      /* 每种模式最多 12 个状态 (为邻接表预留) */
#define FSM_PATTERN_NAME_MAX        32
#define CONCRETE_EDGE_MAX_NODES     128     /* 每聚合边最大具体边节点数 */

/* 单步状态转移定义 (精简 — 仅检查边类型 + 威胁增量 + 超时) */
typedef struct _FSM_STATE_TRANSITION {
    IOA_GRAPH_EDGE_TYPE TriggerEdge;            /* 触发此步进所需的边类型 */
    ULONG               ThreatIncrement;        /* 本步贡献的威胁增量 (步骤越深贡献越大) */
    ULONG               TimeoutMs;              /* 本步最大允许间隔 (毫秒, 用于衰减计算, 0=不限) */
} FSM_STATE_TRANSITION, *PFSM_STATE_TRANSITION;

/* 完整攻击模式定义 */
typedef struct _FSM_PATTERN_TEMPLATE {
    WCHAR               Name[FSM_PATTERN_NAME_MAX];     /* 模式名称 (调试用) */
    FSM_ATTACK_CLASS    FsmClass;                       /* 粗粒度攻击分类 (Tier2 判定) */
    ULONG               StateCount;                     /* 状态总数 (含 S0 初始态) */
    FSM_STATE_TRANSITION Steps[FSM_STATE_MAX];          /* Steps[i] = Si → S{i+1} */
    BOOLEAN             AcceptStates[FSM_STATE_MAX];    /* 哪些状态是接受态 */
    ULONG               AcceptThreshold;                /* 接受态威胁得分阈值 */
    ULONG               TotalTimeoutMs;                 /* 整条链的总超时窗口 */
} FSM_PATTERN_TEMPLATE, *PFSM_PATTERN_TEMPLATE;

/**************************************************/
/*           FSM 状态包装聚合边                     */
/**************************************************/

/*
 * FSM_PATTERN_STATE — 聚合边的上层包装（数组元素）。
 *
 * 层级: FSM_PATTERN → States[0..EdgeCount-1] → FSM_PATTERN_STATE → 聚合边
 *
 * 每个 FSM_PATTERN_STATE 包装一条聚合边，记录边类型引用键和触发时间信息。
 * 聚合边统计快照 (OccurrenceCount/ActiveCount/Confidence) 不在此冗余存储，
 * Tier2/Tier3 按需通过 (SrcProcessNodeId, TgtProcessNodeId, EdgeType) 三元组
 * 查找聚合边哈希表获取。
 */
typedef struct _FSM_PATTERN_STATE {
    IOA_GRAPH_EDGE_TYPE EdgeType;         /* 聚合边引用键（供 Tier2/3 回查聚合边表） */
    LARGE_INTEGER       TriggerTime;      /* 具体边触发时间戳 */
    GUID                TriggerEdgeId;    /* 预生成边GUID (→因果图/IOA_CONCRETE_EDGE) */
    GUID                TriggerEventId;   /* 原始事件GUID (→cg_events.event_id, 供Tier3反查) */
} FSM_PATTERN_STATE, *PFSM_PATTERN_STATE;

/**************************************************/
/*           聚合边具体边记录 (FSM 多路归并数据源)      */
/*                                                  */
/*  生命周期:                                        */
/*    出生: 事件到达 → EdgeAgg_InsertConcrete 尾插    */
/*    休眠: Tier1 60s 窗口过期 → Active=FALSE    */
/*    死亡: 因果图边淘汰 → EdgeAgg_OnGraphEdgeEvicted */
/*                                                  */
/*  链表内按时间基本有序 (尾插), 归并时跳过 Active=0   */
/*  的节点。                                         */
/**************************************************/

typedef struct _IOA_CONCRETE_EDGE {
    GUID                EdgeId;         /* 与事件共享 GUID */
    LARGE_INTEGER       Timestamp;      /* 事件时间戳 */
    IOA_GRAPH_EDGE_TYPE EdgeType;
    LIST_ENTRY          Link;           /* 链入聚合边的 EdgesHead */
    BOOLEAN             Active;         /* Tier1 窗口内是否存活 */
} IOA_CONCRETE_EDGE, *PIOA_CONCRETE_EDGE;

/**************************************************/
/*           FSM 证据包（从同步路径传出）           */
/**************************************************/

/*
 * IOA_FSM_EVIDENCE — 精简版 (2026-07 重构)
 *
 * States[] 数组已移除。Tier3 通过 PatternIndex 查询 Patterns[].Steps[]
 * 获取边类型序列，然后从聚合边表自行做因果倒推确定具体边。
 *
 * Tier2 内部的 FSM_PATTERN_STATE 仍保留，用于 FSM 推进时的
 * ThreatScore 衰减计算和步骤超时判定，但不再跨层传递给 Tier3。
 */
typedef struct _IOA_FSM_EVIDENCE {
    FSM_ATTACK_CLASS    FsmClass;            /* 粗粒度攻击分类 (Tier2 判定) */
    GUID                SrcProcessNodeId;
    GUID                TgtProcessNodeId;
    ULONG               PatternIndex;        /* 模式模板索引 (供 Tier3 查 Patterns[].Steps[]) */
    ULONG               CurrentStep;         /* 已推进到的步数 (1-based) */
    ULONG               ThreatScore;         /* 已含衰减的威胁得分 */
    LARGE_INTEGER       StartTime;
    LARGE_INTEGER       LastStepTime;
} IOA_FSM_EVIDENCE, *PIOA_FSM_EVIDENCE;

/**************************************************/
/*         InteractionBitmap — 统一位图 (128位)     */
/*                                                  */
/*  设计原则:                                       */
/*    低64位 = 数据层 (客观事实, 事件到达无条件设置)   */
/*    高64位 = 语义层 (由 T1Evaluate 从数据层推导)    */
/*                                                  */
/*  PairCtx 不再持有独立的 PairBehaviorFlags /       */
/*  ActiveEdgeTypeMask——统一由此位图承载。            */
/**************************************************/

#define INTERACTION_BITMAP_SIZE     16      /* 128位 = 16字节 */

typedef struct _INTERACTION_BITMAP {
    UCHAR           Bits[INTERACTION_BITMAP_SIZE];   /* 低64=数据层, 高64=语义层 */
} INTERACTION_BITMAP, *PINTERACTION_BITMAP;

/**************************************************/
/*         位图操作宏                                */
/**************************************************/

/* 数据层 (bit 0-63, 字节 0-7) */
#define BM_IS_DATA_SET(bm, edgeType) \
    (((bm)->Bits[(ULONG)(edgeType) / 8] >> ((ULONG)(edgeType) % 8)) & 1)

#define BM_DATA_SET(bm, edgeType) \
    ((bm)->Bits[(ULONG)(edgeType) / 8] |= (UCHAR)(1 << ((ULONG)(edgeType) % 8)))

/* 语义层 (bit 64-127, 字节 8-15) — 偏移 64 位 = 字节 8 */
#define BM_SEM_OFFSET               8

#define BM_SEM_SET(bm, semIdx) \
    ((bm)->Bits[BM_SEM_OFFSET + (semIdx) / 8] |= (UCHAR)(1 << ((semIdx) % 8)))

#define BM_SEM_TEST(bm, semIdx) \
    (((bm)->Bits[BM_SEM_OFFSET + (semIdx) / 8] >> ((semIdx) % 8)) & 1)

/* 获取层位图的 ULONG64 视图 (用于批量 popcount/交集) */
#define BM_DATA_U64(bm)     (*(ULONG64*)&(bm)->Bits[0])
#define BM_SEM_U64(bm)      (*(ULONG64*)&(bm)->Bits[BM_SEM_OFFSET])

/* 清零语义层 (每次 IoaCollectFeatures 开头调用) */
#define BM_SEM_CLEAR(bm)    (*(ULONG64*)&(bm)->Bits[BM_SEM_OFFSET] = 0)

/**************************************************/
/*         数据层位定义                              */
/*         直接使用 IOA_GRAPH_EDGE_TYPE 枚举值作索引  */
/*         已由 C_ASSERT 验证 DefEdge_Max < 64      */
/**************************************************/

C_ASSERT(DefEdge_Max < 64);

/**************************************************/
/*         语义层位定义 (bit 64-127, 字节 8-15)      */
/*         索引 = 位偏移 - 64 (字节 8 内偏移)        */
/**************************************************/

/* ── Layer 1: 低级语义 (bit 64-79, 索引 0-15) ── */
#define BM_SEM_INJECTION_PRIMITIVE     0   /* 注入原语: Opens+WritesTo */
#define BM_SEM_SHELLCODE_SETUP         1   /* Shellcode准备: Allocates+WritesTo+Protects */
#define BM_SEM_REMOTE_THREAD           2   /* 远程线程: InjectsInto */
#define BM_SEM_TOKEN_PRIMITIVE         3   /* Token原语: Impersonates */
#define BM_SEM_MEMORY_READ_REMOTE      4   /* 远程内存读取: ReadFrom */
#define BM_SEM_PROCESS_OPEN            5   /* 进程打开: Opens(目标系统进程) */
#define BM_SEM_HOLLOWING_PRIMITIVE     6   /* 镂空原语: Hollows */
#define BM_SEM_SUSPICIOUS_CHAIN        7   /* 可疑链: Creates+特殊标志 */
#define BM_SEM_SECTION_MAP_REMOTE      8   /* 远程内存映射: 驱动侧标记 */

/* ── Layer 2: 高级语义 (bit 80-95, 索引 16-31) ── */
#define BM_SEM_DLL_INJECTION           16  /* DLL注入: INJECTION_PRIMITIVE + REMOTE_THREAD */
#define BM_SEM_APC_INJECTION           17  /* APC注入: INJECTION_PRIMITIVE + APC标志 */
#define BM_SEM_PROCESS_HOLLOWING       18  /* 进程镂空: SHELLCODE_SETUP + HOLLOWING_PRIMITIVE */
#define BM_SEM_CREDENTIAL_DUMPING      19  /* 凭证窃取: PROCESS_OPEN + MEMORY_READ_REMOTE */
#define BM_SEM_TOKEN_MANIPULATE         20  /* Token操纵: TOKEN_PRIMITIVE + PRIVILEGE_ABUSE */
#define BM_SEM_DLL_SIDE_LOADING        21  /* DLL侧加载: Sideloads + 路径标志 */
#define BM_SEM_THREAD_HIJACK           22  /* 线程劫持: PROCESS_OPEN + AssociatedWith */
#define BM_SEM_REFLECTIVE_LOAD         23  /* 反射加载: ReflectiveLoad */
#define BM_SEM_ATOM_BOMBING            24  /* 原子炸弹: QueueApc(命中原子检索API) + 可疑原子 T1055.009 */

/* ── Layer 2 语义掩码 (Policy 用) ── */
#define BM_MASK_L2_SEMANTIC  ( \
    (1ULL << BM_SEM_DLL_INJECTION)       | \
    (1ULL << BM_SEM_APC_INJECTION)       | \
    (1ULL << BM_SEM_PROCESS_HOLLOWING)   | \
    (1ULL << BM_SEM_CREDENTIAL_DUMPING)  | \
    (1ULL << BM_SEM_TOKEN_MANIPULATE)     | \
    (1ULL << BM_SEM_DLL_SIDE_LOADING)    | \
    (1ULL << BM_SEM_THREAD_HIJACK)       | \
    (1ULL << BM_SEM_REFLECTIVE_LOAD)     | \
    (1ULL << BM_SEM_ATOM_BOMBING)          )

/**************************************************/
/*         T1 语义进化规则                          */
/*                                                  */
/*  规则描述"什么条件触发什么语义位"。                */
/*  Priority 控制执行顺序:                           */
/*    1 = 低级语义 (从数据层推导)                     */
/*    2 = 高级语义 (从低级语义+数据层推导)             */
/*    3 = 进程固有标志 (从事件标志推导)                */
/**************************************************/

#define T1_EVOLUTION_RULE_MAX   64

typedef struct _T1_EVOLUTION_RULE {
    /* ── 按大小降序排列，消除 alignment padding ── */
    /* 8 字节字段 (指针 / ULONG64) */
    PCWSTR  Name;                       /* 仅日志用，不含 MITRE ID (8 bytes) */
    ULONG64 DataRequired;               /* 数据层必须已有这些位 (8 bytes) */
    ULONG64 DataOptional;               /* 数据层可选位池 (8 bytes) */
    ULONG64 SemanticRequired;           /* 语义层必须已有这些位 (8 bytes) */
    ULONG64 EventFlagMatch;             /* 当前事件必须携带的标志 (8 bytes) */

    /* ── 动作 ── */
    union {
        ULONG64 SemanticSet;            /* 设置的语义层位 (若 SemanticSetLayer=1) */
        ULONG64 DataSet;                /* 强制设置的数据层位 (若 SemanticSetLayer=0) */
        ULONG64 ProcFlagSet;            /* 设置的进程固有标志位 (若 SemanticSetLayer=2) */
    };                                  /* 8 bytes */

    /* 4 字节字段 */
    ULONG   DataOptionalMin;            /* 可选位至少命中 N 个 (4 bytes) */

    /* 1 字节字段 (紧凑排列) */
    UCHAR   Priority;                   /* 1=低级语义, 2=高级语义, 3=进程固有 */
    UCHAR   EventEdgeMatch;             /* 当前事件的边类型 (0=不要求) */
    BOOLEAN TgtMustBeSystem;            /* 目标必须是系统进程 */
    UCHAR   SrcIntegrityMax;            /* 源进程完整性上限 (0=不限) */
    UCHAR   SemanticSetLayer;           /* 0=数据层, 1=语义层, 2=传给调用者(进程固有) */

    /* 填充到 64 字节 */
    UCHAR   Reserved[7];

    /*
     * 布局验证 (x64):
     *   0-7   Name                    = 8
     *   8-15  DataRequired            = 8
     *   16-23 DataOptional            = 8
     *   24-31 SemanticRequired        = 8
     *   32-39 EventFlagMatch          = 8
     *   40-47 union { ... }           = 8
     *   48-51 DataOptionalMin         = 4
     *   52    Priority                = 1
     *   53    EventEdgeMatch          = 1
     *   54    TgtMustBeSystem         = 1
     *   55    SrcIntegrityMax         = 1
     *   56    SemanticSetLayer        = 1
     *   57-63 Reserved[7]             = 7
     *   ──────────────────────────────────
     *   Total: 64 bytes ✓
     */
} T1_EVOLUTION_RULE, *PT1_EVOLUTION_RULE;

/**************************************************/
/*         简化攻击模板 (供 Scorer_EvalTemplate)      */
/*                                                  */
/*  仅描述"什么位图组合构成什么攻击"，不含 MITRE ID。  */
/*  MITRE 映射归 Tier3 IoaMitreMapper 负责。         */
/**************************************************/

typedef struct _ATTACK_TEMPLATE {
    PCWSTR      Name;                   /* 仅日志用 */
    ULONG64     RequiredDataMask;       /* 数据层必须匹配的位掩码 */
    ULONG64     RequiredSemMask;        /* 语义层必须匹配的位掩码 */
    ULONG       MinCoveragePct;         /* 最低覆盖率阈值 [0,100] */
    ULONG       BaseScore;              /* 完全匹配基础分 [0,100] */
} ATTACK_TEMPLATE, *PATTACK_TEMPLATE;

/**************************************************/
/*       威胁判定枚举 (ThreatDetector 迁移)          */
/*       多引擎融合 Verdict 层的支撑枚举             */
/*       语义对齐 ShadowStrike ThreatDetector.hpp   */
/**************************************************/

/*
 * 威胁类别 — 战术/攻击类别维度，对齐 FSM_ATTACK_CLASS 的
 * 8 类攻击类别 + 家族兜底类别 (Ransomware/Malware/Exploit)。
 * 推断优先: T3Tactic.ConfirmedClass → FsmClass 映射；
 * 回退: 检测名子串 (ransom→Ransomware 等, 对齐 SS InferCategory)。
 */
typedef enum _DEF_THREAT_CATEGORY {
    DefThreatCat_None                = 0,
    DefThreatCat_ProcessInjection    = 1,   /* T1055.x (FsmClass_ProcessInjection) */
    DefThreatCat_ProcessHollowing    = 2,   /* T1055.012 (FsmClass_ProcessHollowing) */
    DefThreatCat_CredentialAccess    = 3,   /* T1003 (FsmClass_CredentialAccess) */
    DefThreatCat_DefenseEvasion      = 4,   /* (FsmClass_DefenseEvasion) */
    DefThreatCat_Persistence         = 5,   /* T1547 (FsmClass_Persistence) */
    DefThreatCat_LateralMovement     = 6,   /* (FsmClass_LateralMovement) */
    DefThreatCat_Collection          = 7,   /* (FsmClass_Collection) */
    DefThreatCat_CommandAndControl   = 8,   /* (FsmClass_CommandAndControl) */
    DefThreatCat_Ransomware          = 9,   /* 家族兜底 (IoaRansomwareDetect) */
    DefThreatCat_Malware             = 10,  /* 通用恶意软件兜底 (Trojan/Worm/Virus/Rootkit 等) */
    DefThreatCat_Exploit             = 11,  /* 零日/exploit 原语 */
    DefThreatCat_SuspiciousBehavior  = 12,  /* 行为异常但未定型 */
    DefThreatCat_PolicyViolation     = 13,  /* 策略违规 (非恶意) */
    DefThreatCat_Max
} DEF_THREAT_CATEGORY, *PDEF_THREAT_CATEGORY;

/*
 * 置信度级别 — 五级置信度。
 * 由多引擎一致率推导 (对齐 SS AggregateEngineDetections 的
 * agreement ratio: ≥0.9 Confirmed / ≥0.7 High / ≥0.5 Medium / else Low)。
 */
typedef enum _DEF_CONFIDENCE_LEVEL {
    DefConfidence_Unknown    = 0,
    DefConfidence_Low        = 1,
    DefConfidence_Medium     = 2,
    DefConfidence_High       = 3,
    DefConfidence_Confirmed  = 4,
} DEF_CONFIDENCE_LEVEL, *PDEF_CONFIDENCE_LEVEL;

/*
 * 响应动作 — 统一处置动作 (对齐 SS ResponseAction, 剔除 Log/Remediate/
 * Rollback 冗余项)。由 Verdict 严重度映射推荐, 由响应分发执行。
 */
typedef enum _DEF_RESPONSE_ACTION {
    DefRespAction_None        = 0,
    DefRespAction_Alert       = 1,   /* 仅告警 */
    DefRespAction_Block       = 2,   /* 同步阻断 (阶段7 联动) */
    DefRespAction_Quarantine  = 3,   /* 隔离文件 */
    DefRespAction_Terminate   = 4,   /* 终止进程 (处置引擎) */
    DefRespAction_Isolate     = 5,   /* 隔离进程 */
    DefRespAction_Rollback    = 6,   /* 回滚进程文件 (FBE 迁移 2026-08, 死代码预留:
                                        自动回滚闭环待勒索检测链路打通, 当前由 UI 0x1007 指令驱动) */
} DEF_RESPONSE_ACTION, *PDEF_RESPONSE_ACTION;

/*
 * 检测源 — 多引擎检测来源标识。
 * 独立枚举 (不复用 DEF_IOC_SOURCE, 那是 IOC 子类型)，
 * 用于 Verdict 的 PrimarySource 与多引擎权重融合。
 */
typedef enum _DEF_DETECTION_SOURCE {
    DefDetSrc_None       = 0,
    DefDetSrc_IOC        = 1,   /* IOC 引擎 (哈希/证书/YARA/启发式) */
    DefDetSrc_IOA_Tier1  = 2,   /* T1 单事件规则/语义进化 */
    DefDetSrc_IOA_Tier2  = 3,   /* T2 FSM/回溯 */
    DefDetSrc_IOA_Tier3  = 4,   /* T3 因果倒推/攻击链 */
    DefDetSrc_Behavior   = 5,   /* 行为检测器 (MaliceScore) ※死代码源 */
    DefDetSrc_Scan       = 6,   /* 文件/内存扫描 (ScanManager) */
    DefDetSrc_Rule       = 7,   /* 运行时规则 */
    DefDetSrc_Cluster    = 8,   /* 可疑集群检测 (SS 进程关系图迁移, 死代码) */
    DefDetSrc_Max
} DEF_DETECTION_SOURCE, *PDEF_DETECTION_SOURCE;

/**************************************************/
/*         堆喷检测类型 (HeapSpray 迁移)            */
/*                                                  */
/*  迁移自 ShadowStrike HeapSpray.h (2026-08-07),   */
/*  按功能融合重实现非复制。                          */
/*                                                  */
/*  死代码: 消费方为 IoaHeapSprayDetect (agent 聚合) */
/*  + 驱动侧预判 (TsIndicator_Injection_HeapSpray),  */
/*  流水线未接入。                                   */
/**************************************************/

typedef enum _WKD_HEAP_SPRAY_TYPE {
    WkdHeapSpray_Unknown        = 0,
    WkdHeapSpray_NopSled,               /* 经典 NOP sled 喷 (SS HsSprayType_NopSled) */
    WkdHeapSpray_HeapFeng,              /* 堆风水 (SS 枚举声明, 分类不产出) */
    WkdHeapSpray_JitSpray,              /* JIT 编译喷 (SS HsSprayType_JitSpray) */
    WkdHeapSpray_ArraySpray,            /* JS 数组喷 (SS 枚举声明, 分类不产出) */
    WkdHeapSpray_StringSpray,           /* 字符串喷 (SS HsSprayType_StringSpray) */
    WkdHeapSpray_TypedArraySpray,       /* TypedArray 喷 (SS 枚举声明, 分类不产出) */
    WkdHeapSpray_ObjectSpray,           /* 对象/vtable 指针喷 (SS HsSprayType_ObjectSpray) */
    WkdHeapSpray_WasmSpray,             /* WebAssembly 喷 (SS 枚举声明, 分类不产出) */
} WKD_HEAP_SPRAY_TYPE, *PWKD_HEAP_SPRAY_TYPE;

/*
 * 检测标志 (对齐 SS HS_DETECTION_FLAGS, 位序一致)。
 */
#define WKD_HSF_NONE                0x00000000
#define WKD_HSF_HIGH_ALLOC_RATE     0x00000001   /* 高分配率 (HsFlag_HighAllocationRate) */
#define WKD_HSF_REPEATED_PATTERN    0x00000002   /* 重复模式 (HsFlag_RepeatedPattern) */
#define WKD_HSF_SUSPICIOUS_SIZE     0x00000004   /* 可疑大小 (HsFlag_SuspiciousSize) */
#define WKD_HSF_EXECUTABLE_ALLOC    0x00000008   /* 可执行分配 (HsFlag_ExecutableAlloc) */
#define WKD_HSF_ALIGNED_ADDRESSES   0x00000010   /* 对齐地址 (HsFlag_AlignedAddresses) */
#define WKD_HSF_LARGE_CONTIGUOUS    0x00000020   /* 大块连续 (HsFlag_LargeContiguous) */
#define WKD_HSF_SHELLCODE_PATTERN   0x00000040   /* 壳码模式 (HsFlag_ShellcodePattern) */
#define WKD_HSF_JIT_PATTERN         0x00000080   /* JIT 模式 (HsFlag_JitPattern) */

/*
 * 堆喷分析结果 (对齐 SS HS_SPRAY_RESULT)。
 * 值语义, 栈返回, 无需释放 (SS 池分配 + HsFreeResult 在 wkd 废弃)。
 */
typedef struct _WKD_HEAP_SPRAY_RESULT {
    BOOLEAN             SprayDetected;          /* 对齐 SS SprayDetected */
    WKD_HEAP_SPRAY_TYPE Type;                   /* 对齐 SS Type */
    ULONG               Flags;                  /* 对齐 SS Flags (WKD_HSF_*) */
    ULONG               ConfidenceScore;        /* 对齐 SS ConfidenceScore [0,1000] */
    ULONG               ProcessId;              /* 对齐 SS ProcessId */
    ULONG               AllocationCount;        /* 对齐 SS AllocationCount */
    ULONG64             TotalSize;              /* 对齐 SS TotalSize */
    ULONG64             AverageSize;            /* 对齐 SS AverageSize */
    ULONG               AllocationsPerSecond;   /* 对齐 SS AllocationsPerSecond */
    UCHAR               DominantPattern[64];    /* 对齐 SS DominantPattern */
    ULONG               DominantPatternSize;    /* 对齐 SS DominantPatternSize */
    ULONG               PatternRepetitions;     /* 对齐 SS PatternRepetitions */
    ULONG               UniquePatterns;         /* 对齐 SS UniquePatterns */
    ULONG               AlignedCount;           /* 对齐 SS AlignedCount (页对齐) */
    ULONG_PTR           LowestAddress;          /* 对齐 SS LowestAddress */
    ULONG_PTR           HighestAddress;         /* 对齐 SS HighestAddress */
    SIZE_T              AddressSpan;            /* 对齐 SS AddressSpan (Highest - Lowest) */
    LARGE_INTEGER       FirstAllocation;        /* 对齐 SS FirstAllocation */
    LARGE_INTEGER       LastAllocation;         /* 对齐 SS LastAllocation */
    ULONG               DurationMs;             /* 对齐 SS DurationMs */
} WKD_HEAP_SPRAY_RESULT, *PWKD_HEAP_SPRAY_RESULT;
