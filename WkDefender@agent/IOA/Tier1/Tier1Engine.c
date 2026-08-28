/**************************************************/
/*  WkDefender — Tier 1 语义进化引擎实现              */
/*                                                    */
/*  核心:                                              */
/*    - 数据层无条件写入 (事件到达 → 位图 OR)            */
/*    - 语义多轮进化 (Priority 1→2→3, 低级→高级)       */
/*    - 特征采集 (速率/谱系, IoaCollectFeatures)        */
/*    - RecentEdgeMask 窗口衰减                         */
/**************************************************/

#include "Tier1Engine.h"
#include "../IoaEngine.h"
#include "../../Process/ProcessTree.h"
#include "../IoaProcessPair.h"
#include "../IoaEdgeAggregate.h"
#include <string.h>

/**************************************************/
/*               内部辅助: 镜像名匹配                */
/**************************************************/

static
BOOLEAN
T1MatchImageFileName(
    _In_opt_ PUNICODE_STRING Image,
    _In_     PCWSTR          SubString
    )
/*++
Routine Description:
    大小写不敏感检查镜像名是否包含指定子串。
--*/
{
    PWCHAR baseName;
    PWCHAR p;

    if (!Image || !Image->Buffer || !SubString) return FALSE;

    baseName = Image->Buffer;
    p = baseName + (Image->Length / sizeof(WCHAR));

    for (; p > baseName; p--) {
        if (*p == L'\\' || *p == L'/') { p++; break; }
    }

    return (wcsstr(p, SubString) != NULL);
}

/**************************************************/
/*         内部: T1CollectRateFeatures              */
/**************************************************/

static
VOID
T1CollectRateFeatures(
    _In_opt_ PWKD_PROCESS SrcNode,
    _In_opt_ PWKD_PROCESS TgtNode,
    _Out_   PT1_PAIR_FEATURE   Feature
    )
/*++
Routine Description:
    采集进程对的速率统计数据（纯数据，不作评分）。
--*/
{
    PLIST_ENTRY entry;
    ULONG activeTargets = 0;
    ULONG activeSources = 0;
    ULONG activeOutEdges = 0;
    ULONG activeInEdges  = 0;
    PAE_PROCESS_PAIR pc;

    RtlZeroMemory(Feature, sizeof(T1_PAIR_FEATURE));

    /* 链头锁原则 (2026-08-25): Out/InPairListHead 遍历持节点
     * PairLinksLock 共享; 只读统计, 锁内即取即算不缓存指针。 */
    if (SrcNode && SrcNode->OutPairCount > 0) {
        AcquireSRWLockShared(&SrcNode->PairLinksLock);
        entry = SrcNode->OutPairListHead.Flink;
        while (entry != &SrcNode->OutPairListHead) {
            pc = CONTAINING_RECORD(entry, AE_PROCESS_PAIR, SourceProcessLinks);
            if (pc->ActiveEventCount > 0) {
                activeTargets++;
                activeOutEdges += pc->ActiveEventCount;
            }
            entry = entry->Flink;
        }
        ReleaseSRWLockShared(&SrcNode->PairLinksLock);
    }

    if (TgtNode && TgtNode->InPairCount > 0) {
        AcquireSRWLockShared(&TgtNode->PairLinksLock);
        entry = TgtNode->InPairListHead.Flink;
        while (entry != &TgtNode->InPairListHead) {
            pc = CONTAINING_RECORD(entry, AE_PROCESS_PAIR, TargetProcessLinks);
            if (pc->ActiveEventCount > 0) {
                activeSources++;
                activeInEdges += pc->ActiveEventCount;
            }
            entry = entry->Flink;
        }
        ReleaseSRWLockShared(&TgtNode->PairLinksLock);
    }

    Feature->ActiveOutTargets = activeTargets;
    Feature->ActiveInSources  = activeSources;
    Feature->ActiveOutEdges   = activeOutEdges;
    Feature->ActiveInEdges    = activeInEdges;
}

/**************************************************/
/*         内部: T1CollectGenealogyFlags            */
/**************************************************/

static
VOID
T1CollectGenealogyFlags(
    _In_opt_ PWKD_PROCESS SrcNode,
    _In_opt_ PWKD_PROCESS TgtNode,
    _Out_   PT1_PAIR_FEATURE   Feature
    )
/*++
Routine Description:
    从进程节点的固有属性中提取谱系标志。
--*/
{
    ULONG srcFlags = 0;
    ULONG tgtFlags = 0;

    if (SrcNode) {
        if (SrcNode->BehaviorFlags & DEF_BEHAVIOR_FLAG_PPID_SPOOF)
            srcFlags |= T1_GFLAG_PPID_SPOOF;
        if (SrcNode->BehaviorFlags & DEF_BEHAVIOR_FLAG_CROSS_SESSION)
            srcFlags |= T1_GFLAG_CROSS_SESSION;
        if (SrcNode->BehaviorFlags & DEF_BEHAVIOR_FLAG_ELEVATED)
            srcFlags |= T1_GFLAG_ELEVATED;

        if (DefIsNullNodeId(SrcNode->ParentNodeId) && SrcNode->TreeDepth == 0)
            srcFlags |= T1_GFLAG_ORPHAN;

        if (SrcNode->TreeDepth > 3)
            srcFlags |= T1_GFLAG_DEEP_TREE;

        if (SrcNode->Parent &&
            SrcNode->Parent->IsSystemProcess &&
            !SrcNode->IsSystemProcess)
            srcFlags |= T1_GFLAG_SYSTEM_PARENT;

        Feature->SrcIsSystemProcess = SrcNode->IsSystemProcess;
        Feature->SrcIntegrityLevel  = SrcNode->IntegrityLevel;
    }

    if (TgtNode) {
        if (TgtNode->BehaviorFlags & DEF_BEHAVIOR_FLAG_PPID_SPOOF)
            tgtFlags |= T1_GFLAG_PPID_SPOOF;
        if (TgtNode->BehaviorFlags & DEF_BEHAVIOR_FLAG_CROSS_SESSION)
            tgtFlags |= T1_GFLAG_CROSS_SESSION;
        if (TgtNode->BehaviorFlags & DEF_BEHAVIOR_FLAG_ELEVATED)
            tgtFlags |= T1_GFLAG_ELEVATED;

        if (DefIsNullNodeId(TgtNode->ParentNodeId) && TgtNode->TreeDepth == 0)
            tgtFlags |= T1_GFLAG_ORPHAN;

        if (TgtNode->TreeDepth > 3)
            tgtFlags |= T1_GFLAG_DEEP_TREE;

        if (TgtNode->Parent &&
            TgtNode->Parent->IsSystemProcess &&
            !TgtNode->IsSystemProcess)
            tgtFlags |= T1_GFLAG_SYSTEM_PARENT;

        Feature->TgtIsSystemProcess = TgtNode->IsSystemProcess;
        Feature->TgtIntegrityLevel  = TgtNode->IntegrityLevel;
    }

    Feature->SrcGenealogyFlags = srcFlags;
    Feature->TgtGenealogyFlags = tgtFlags;
}

/**************************************************/
/*          数据层位掩码工具宏                       */
/**************************************************/

/* 边类型 → 数据层 bit */
#define T1_DATA_BIT(e)  (1ULL << (ULONGLONG)(e))

/**************************************************/
/*          语义进化规则表 (20 条)                   */
/*          Priority 1 = 低级语义                   */
/*          Priority 2 = 高级语义                   */
/*          Priority 3 = 进程固有标志                */
/**************************************************/

static const T1_EVOLUTION_RULE g_EvolutionRules[] = {

    /*
     * ═══════════════════════════════════════════════════════════
     * Priority 1 — 低级语义 (从数据层直接推导)
     * ═══════════════════════════════════════════════════════════
     */

    /* R1: 注入原语 — Opens + WritesTo (Allocates 可选)
     *     覆盖: Classic DLL注入 / APC注入 / 线程劫持 的第一步 */
    {
        L"InjectionPrimitive",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_Opens) | T1_DATA_BIT(DefEdge_WritesTo),
        .DataOptional        = T1_DATA_BIT(DefEdge_Allocates),
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_INJECTION_PRIMITIVE),
    },

    /* R2: Shellcode 准备 — Allocates + WritesTo + Protects (三者缺一不可)
     *     覆盖: 进程镂空 / Shellcode加载 的内存准备阶段 */
    {
        L"ShellcodeSetup",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_Allocates) |
                               T1_DATA_BIT(DefEdge_WritesTo)  |
                               T1_DATA_BIT(DefEdge_Protects),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_SHELLCODE_SETUP),
    },

    /* R3: 远程线程 — 当前事件为 InjectsInto */
    {
        L"RemoteThread",
        .Priority            = 1,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = (UCHAR)DefEdge_InjectsInto,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_REMOTE_THREAD),
    },

    /* R4: Token 原语 — Impersonates */
    {
        L"TokenPrimitive",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_Impersonates),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_TOKEN_PRIMITIVE),
    },

    /* R5: 远程内存读取 — ReadFrom (目标=系统进程) */
    {
        L"RemoteMemoryRead",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_ReadsFrom),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = TRUE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_MEMORY_READ_REMOTE),
    },

    /* R6: 进程打开 (目标=系统进程) */
    {
        L"ProcessOpenSystem",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_Opens),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = TRUE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_PROCESS_OPEN),
    },

    /* R7: 镂空原语 — Hollows */
    {
        L"HollowingPrimitive",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_Hollows),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_HOLLOWING_PRIMITIVE),
    },

    /* R8: 可疑链 — Creates + 当前事件携带可疑标志 */
    {
        L"SuspiciousChain",
        .Priority            = 1,
        .DataRequired        = T1_DATA_BIT(DefEdge_Creates),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_SUSPICIOUS_CHAIN |
                               DEF_BEHAVIOR_FLAG_PPID_SPOOF       |
                               DEF_BEHAVIOR_FLAG_DOWNLOADER,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_SUSPICIOUS_CHAIN),
    },

    /* R9: 远程内存映射 — SectionMap */
    {
        L"SectionMapRemote",
        .Priority            = 1,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_SECTION_MAP_REMOTE),
    },

    /*
     * ═══════════════════════════════════════════════════════════
     * Priority 2 — 高级语义 (从低级语义+数据层推导)
     * ═══════════════════════════════════════════════════════════
     */

    /* R10: DLL 注入 = 注入原语 + 远程线程 */
    {
        L"DllInjection",
        .Priority            = 2,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = (1ULL << BM_SEM_INJECTION_PRIMITIVE) |
                               (1ULL << BM_SEM_REMOTE_THREAD),
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_DLL_INJECTION),
    },

    /* R11: APC 注入 = 注入原语 + APC标志 */
    {
        L"ApcInjection",
        .Priority            = 2,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = (1ULL << BM_SEM_INJECTION_PRIMITIVE),
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_APC_INJECTION |
                               DEF_BEHAVIOR_FLAG_SET_CONTEXT,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_APC_INJECTION),
    },

    /* R12: 进程镂空 = Shellcode准备 + 镂空原语 */
    {
        L"ProcessHollowing",
        .Priority            = 2,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = (1ULL << BM_SEM_SHELLCODE_SETUP) |
                               (1ULL << BM_SEM_HOLLOWING_PRIMITIVE),
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_PROCESS_HOLLOWING),
    },

    /* R13: 凭证窃取 = 进程打开 + 远程内存读取 (目标=系统进程) */
    {
        L"CredentialDumping",
        .Priority            = 2,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = (1ULL << BM_SEM_PROCESS_OPEN) |
                               (1ULL << BM_SEM_MEMORY_READ_REMOTE),
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = TRUE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_CREDENTIAL_DUMPING),
    },

    /* R14: Token 操纵 = Token原语 + 特权滥用标志 */
    {
        L"TokenManipulation",
        .Priority            = 2,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = (1ULL << BM_SEM_TOKEN_PRIMITIVE),
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE |
                               DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_TOKEN_MANIPULATE),
    },

    /* R15: DLL 侧加载 = Sideloads 数据位 + 侧加载标志 */
    {
        L"DllSideLoading",
        .Priority            = 2,
        .DataRequired        = T1_DATA_BIT(DefEdge_Sideloads),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_DLL_SIDE_LOAD,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_DLL_SIDE_LOADING),
    },

    /* R16: 线程劫持 = 进程打开 + Allocates + AssociatedWith */
    {
        L"ThreadHijack",
        .Priority            = 2,
        .DataRequired        = T1_DATA_BIT(DefEdge_Allocates) |
                               T1_DATA_BIT(DefEdge_AssociatedWith),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = (1ULL << BM_SEM_PROCESS_OPEN),
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_THREAD_HIJACK),
    },

    /* R17: 反射加载 = ReflectiveLoad 数据位 */
    {
        L"ReflectiveLoad",
        .Priority            = 2,
        .DataRequired        = T1_DATA_BIT(DefEdge_ReflectiveLoad),
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = 0,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 1,
        .SemanticSet         = (1ULL << BM_SEM_REFLECTIVE_LOAD),
    },

    /*
     * ═══════════════════════════════════════════════════════════
     * Priority 3 — 进程固有标志 (写入 SrcNode->BehaviorFlags)
     * ═══════════════════════════════════════════════════════════
     */

    /* R18: PPID 欺骗 */
    {
        L"PpidSpoof",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_PPID_SPOOF,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_PPID_SPOOF,
    },

    /* R19: 跨会话 */
    {
        L"CrossSession",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_CROSS_SESSION,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_CROSS_SESSION,
    },

    /* R20: 提权 */
    {
        L"Elevated",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_ELEVATED,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_ELEVATED,
    },

    /* R21: LOLBin */
    {
        L"LolBin",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_LOLBIN,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_LOLBIN,
    },

    /* R22: PowerShell 编码 */
    {
        L"PowerShellEncoded",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_POWERSHELL_ENCODED,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_POWERSHELL_ENCODED,
    },

    /* R23: Downloader */
    {
        L"Downloader",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_DOWNLOADER,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_DOWNLOADER,
    },

    /* R24: 路径劫持 */
    {
        L"PathHijack",
        .Priority            = 3,
        .DataRequired        = 0,
        .DataOptional        = 0,
        .DataOptionalMin     = 0,
        .SemanticRequired    = 0,
        .EventEdgeMatch      = 0,
        .EventFlagMatch      = DEF_BEHAVIOR_FLAG_PATH_HIJACK,
        .TgtMustBeSystem     = FALSE,
        .SrcIntegrityMax     = 0,
        .SemanticSetLayer    = 2,
        .ProcFlagSet         = DEF_BEHAVIOR_FLAG_PATH_HIJACK,
    },

    /* 哨兵 */
    { NULL, 0, 0, 0, 0, 0, 0, 0, FALSE, 0, {0}, 0, {0} }
};

#define T1_RULE_COUNT  ((ULONG)(sizeof(g_EvolutionRules) / sizeof(g_EvolutionRules[0]) - 1))

/**************************************************/
/*         内部: 单条规则匹配检查                    */
/**************************************************/

static
BOOLEAN
T1CheckRule(
    _In_ const T1_EVOLUTION_RULE*   Rule,
    _In_ ULONG64                    DataDword,
    _In_ ULONG64                    SemDword,
    _In_ IOA_GRAPH_EDGE_TYPE        EdgeType,
    _In_ PWKD_EVENT_HEADER          Event,
    _In_opt_ PWKD_PROCESS      SrcNode,
    _In_opt_ PWKD_PROCESS      TgtNode
    )
/*++
Routine Description:
    检查一条进化规则的所有条件是否满足。

    条件检查顺序 (短路):
      1. 数据层必需位 (DataRequired ? DataDword)
      2. 数据层可选位 (popcount(DataOptional ∩ DataDword) >= DataOptionalMin)
      3. 语义层必需位 (SemanticRequired ? SemDword)
      4. 当前事件边类型 (EventEdgeMatch)
      5. 当前事件标志 (EventFlagMatch)
      6. 系统进程目标 (TgtMustBeSystem)
      7. 源完整性上限 (SrcIntegrityMax)

Arguments:
    Rule      — 进化规则。
    DataDword — 数据层 ULONG64 (InteractionBitmap.Bits[0..7])。
    SemDword  — 语义层 ULONG64 (InteractionBitmap.Bits[8..15])。
    EdgeType  — 当前事件的边类型。
    Event     — 当前事件。
    SrcNode   — 源进程节点。
    TgtNode   — 目标进程节点。

Return Value:
    TRUE=条件满足, FALSE=不满足。
--*/
{
    /* 1. 数据层必需位 */
    if (Rule->DataRequired &&
        (DataDword & Rule->DataRequired) != Rule->DataRequired) {
        return FALSE;
    }

    /* 2. 数据层可选位 */
    if (Rule->DataOptional && Rule->DataOptionalMin > 0) {
        ULONG hit = 0;
        ULONG64 mask = Rule->DataOptional;
        /* 快速 popcount 匹配位数 */
        ULONG64 intersection = DataDword & mask;
        while (intersection) {
            hit++;
            intersection &= (intersection - 1);  /* 清除最低位 */
        }
        if (hit < Rule->DataOptionalMin) return FALSE;
    }

    /* 3. 语义层必需位 */
    if (Rule->SemanticRequired &&
        (SemDword & Rule->SemanticRequired) != Rule->SemanticRequired) {
        return FALSE;
    }

    /* 4. 当前事件边类型 */
    if (Rule->EventEdgeMatch != 0 &&
        (UCHAR)EdgeType != Rule->EventEdgeMatch) {
        return FALSE;
    }

    /* 5. 当前事件标志 */
    if (Rule->EventFlagMatch &&
        !(Event->BehaviorFlags & (ULONG)Rule->EventFlagMatch)) {
        return FALSE;
    }

    /* 6. 目标必须是系统进程 */
    if (Rule->TgtMustBeSystem &&
        (!TgtNode || !TgtNode->IsSystemProcess)) {
        return FALSE;
    }

    /* 7. 源进程完整性上限 */
    if (Rule->SrcIntegrityMax > 0 &&
        SrcNode && SrcNode->IntegrityLevel > Rule->SrcIntegrityMax) {
        return FALSE;
    }

    return TRUE;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
T1Initialize(
    PIOA_TIER1_ENGINE* Out,
    PIOA_PERSIST_QUEUE PersistQueue
    )
/*++
Routine Description:
    初始化 Tier 1 语义进化引擎。
--*/
{
    PIOA_TIER1_ENGINE e;

    e = UtHeapAlloc(sizeof(IOA_TIER1_ENGINE));
    if (!e) return STATUS_NO_MEMORY;

    RtlZeroMemory(e, sizeof(IOA_TIER1_ENGINE));
    e->PersistQueue = PersistQueue;

    InitializeCriticalSection(&e->Lock);
    e->Initialized = TRUE;

    printf("[Tier1Engine] Initialized: %u evolution rules "
           "(semantic evolution engine)\n", T1_RULE_COUNT);

    *Out = e;
    return STATUS_SUCCESS;
}

VOID
T1Cleanup(
    PIOA_TIER1_ENGINE Engine
    )
/*++
Routine Description:
    清理 Tier 1 引擎。
--*/
{
    if (!Engine || !Engine->Initialized) return;

    printf("[Tier1Engine] Cleanup: evals=%lld hits=%lld features=%lld\n",
           Engine->TotalEvaluations, Engine->RuleHits, Engine->FeatureCollects);

    DeleteCriticalSection(&Engine->Lock);
    UtHeapFree(Engine);
}

/**************************************************/
/*         特征采集入口 — IoaCollectFeatures        */
/**************************************************/

NTSTATUS
IoaCollectFeatures(
    _In_    PIOA_TIER1_ENGINE         Engine,
    _Inout_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_PROCESS         SrcNode,
    _In_opt_ PWKD_PROCESS         TgtNode,
    _In_    LARGE_INTEGER              Now
    )
/*++
Routine Description:
    Tier1 纯特征采集入口。

    改动:
      - 语义层不再镜像 PairBehaviorFlags (已移除)
      - 语义层 popcount 从 InteractionBitmap 快照获取
      - ActiveEdgeTypeCount 由 __popcnt64 从数据层动态计算 (不再缓存)

Arguments:
    Engine      — Tier 1 引擎实例。
    PairCtx     — 当前进程对上下文 (T1Feature 写入目标)。
    SrcNode     — 源进程节点 (可 NULL)。
    TgtNode     — 目标进程节点 (可 NULL)。
    Now         — 当前时间戳。
--*/
{
    PT1_PAIR_FEATURE f;

    if (!Engine || !PairCtx) return STATUS_INVALID_PARAMETER;

    f = &PairCtx->T1Feature;

    /* ── 0. 语义层清零 — T1Evaluate 将从头重新推导 ── */
    BM_SEM_CLEAR(&PairCtx->InteractionBitmap);

    /* ── 1. 速率统计 ── */
    T1CollectRateFeatures(SrcNode, TgtNode, f);

    /* ── 2. 谱系标志提取 ── */
    T1CollectGenealogyFlags(SrcNode, TgtNode, f);

    /* ── 3. 活跃事件总数 ── */
    f->PairEventCount = PairCtx->ActiveEventCount;

    /* ── 4. RecentEdgeMask 窗口衰减 (纯数据维护) ── */
    {
        ULONG64 rebuiltMask = 0;
        ULONG64 checkBit = 1;
        LONGLONG age, nowMs = Now.QuadPart / 10000LL;

        for (ULONG e = 0; e < 64; e++) {
            if (f->RecentEdgeMask & checkBit) {
                age = nowMs -
                    (f->EdgeLastSeen[e].QuadPart / 10000LL);
                if (age <= 60000 && age >= 0) {
                    rebuiltMask |= checkBit;
                }
            }
            checkBit <<= 1;
        }
        f->RecentEdgeMask = rebuiltMask;
    }

    /* ── 5. 版本递增 ── */
    f->Version++;
    f->LastUpdate = Now;

    Engine->FeatureCollects++;

    /* 调试输出 */
    if (Engine->FeatureCollects <= 5 ||
        f->ActiveOutTargets >= 3 ||
        f->ActiveInSources >= 2 ||
        f->SrcGenealogyFlags != 0) {
        ULONG64 dataWord = BM_DATA_U64(&PairCtx->InteractionBitmap);
        ULONG64 semWord  = BM_SEM_U64(&PairCtx->InteractionBitmap);
        printf("[Tier1Engine] CollectFeatures(%lld): "
               "OutTgts=%lu InSrcs=%lu "
               "DataWord=0x%llx SemWord=0x%llx "
               "SrcGen=0x%lx TgtGen=0x%lx "
               "RuleHit=%lu v%lu\n",
               Engine->FeatureCollects,
               f->ActiveOutTargets, f->ActiveInSources,
               dataWord, semWord,
               f->SrcGenealogyFlags, f->TgtGenealogyFlags,
               f->RuleHitCount, f->Version);
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*           语义进化引擎 — T1Evaluate              */
/**************************************************/

BOOLEAN
T1Evaluate(
    _In_    PIOA_TIER1_ENGINE            Engine,
    _In_    IOA_GRAPH_EDGE_TYPE          EdgeType,
    _In_    PWKD_EVENT_HEADER            Event,
    _Inout_opt_ PWKD_PROCESS         SrcNode,
    _In_opt_ PWKD_PROCESS           TgtNode,
    _Inout_ PAE_PROCESS_PAIR    PairCtx
    )
/*++
Routine Description:
    语义进化引擎 — 数据层无条件写入 + 多轮语义推导。

    阶段1: 数据层无条件写入。
           事件边类型 → BM_DATA_SET(InteractionBitmap, edgeType)。
           不可跳过, 不可条件化。

    阶段2: 多轮语义进化。
           按 Priority 1→2→3 依次执行规则表,
           每条规则检查当前位图状态 → 命中则设置语义位。
           同轮内可能触发多条规则 (不再一击即止)。

           语义层在 IoaCollectFeatures 开头已被清零,
           本次调用基于当前数据层快照重新推导。

    进程固有标志 (Priority=3) 规则返回时要设置的标志,
    直接写入 SrcNode->BehaviorFlags。

Arguments:
    Engine    — Tier 1 引擎实例。
    EdgeType  — 当前事件的边类型。
    Event     — 当前事件 (仅用于 EventFlagMatch 检查)。
    SrcNode   — 源进程节点 (可 NULL, 用于进程固有标志回写)。
    TgtNode   — 目标进程节点 (可 NULL, 用于 TgtMustBeSystem)。
    PairCtx   — 进程对上下文 (读写 InteractionBitmap)。

Return Value:
    TRUE = 至少一条规则命中 (语义层有新位被设置)。
--*/
{
    ULONG64 dataDword;
    ULONG64 semDword;
    ULONG64 prevSemDword;
    ULONG hitCount = 0;
    ULONG procFlags = 0;
    BOOLEAN hit = FALSE;

    if (!Engine || !Event || !PairCtx) return FALSE;

    /* ═══════════════════════════════════════════════╗
       ║  阶段1: 数据层无条件写入                      ║
       ║  事件边类型 → 位图 OR (不可跳过)              ║
       ╚══════════════════════════════════════════════╝ */
    if (EdgeType > DefEdge_Unknown && EdgeType < DefEdge_Max) {
        BM_DATA_SET(&PairCtx->InteractionBitmap, EdgeType);
    }

    /* 读取当前位图快照 */
    dataDword = BM_DATA_U64(&PairCtx->InteractionBitmap);
    semDword  = BM_SEM_U64(&PairCtx->InteractionBitmap);
    prevSemDword = semDword;

    EnterCriticalSection(&Engine->Lock);

    /* ═══════════════════════════════════════════════╗
       ║  阶段2: 多轮语义进化                          ║
       ║  Priority 1 → 2 → 3 依次执行                 ║
       ╚══════════════════════════════════════════════╝ */
    for (UCHAR priority = 1; priority <= 3; priority++) {
        for (ULONG r = 0; g_EvolutionRules[r].Name; r++) {
            const T1_EVOLUTION_RULE* rule = &g_EvolutionRules[r];

            if (rule->Priority != priority) continue;

            /* 若语义层已置位 → 跳过 (幂等) */
            if (rule->SemanticSetLayer == 1 &&
                (semDword & rule->SemanticSet)) {
                continue;
            }
            if (rule->SemanticSetLayer == 0 &&
                (dataDword & rule->DataSet)) {
                continue;
            }

            /* 条件检查 */
            if (!T1CheckRule(rule, dataDword, semDword,
                             EdgeType, Event, SrcNode, TgtNode)) {
                continue;
            }

            /* ── 命中: 执行动作 ── */
            Engine->RuleHits++;
            hitCount++;
            hit = TRUE;

            switch (rule->SemanticSetLayer) {
            case 1:
                /* 语义层 */
                *(ULONG64*)&PairCtx->InteractionBitmap.Bits[BM_SEM_OFFSET]
                    |= rule->SemanticSet;
                semDword = BM_SEM_U64(&PairCtx->InteractionBitmap);
                printf("[Tier1Engine] SEM HIT: %S (P%u) "
                       "DataWord=0x%llx SemWord=0x%llx\n",
                       rule->Name, rule->Priority, dataDword, semDword);
                break;

            case 2:
                /* 进程固有标志 → 累加, 退出锁后统一写入 SrcNode */
                procFlags |= (ULONG)(rule->ProcFlagSet);
                printf("[Tier1Engine] PROC HIT: %S (P%u) Flags=0x%lx\n",
                       rule->Name, rule->Priority, (ULONG)rule->ProcFlagSet);
                break;

            case 0:
                /* 数据层强制设置 (罕见: 事件标志直接映射) */
                *(ULONG64*)&PairCtx->InteractionBitmap.Bits[0]
                    |= rule->DataSet;
                dataDword = BM_DATA_U64(&PairCtx->InteractionBitmap);
                break;
            }
        }
    }

    LeaveCriticalSection(&Engine->Lock);

    /* ═══════════════════════════════════════════════╗
       ║  阶段3: 进程固有标志回写                      ║
       ║  Priority=3 规则累加结果写入 SrcNode           ║
       ╚══════════════════════════════════════════════╝ */
    if (procFlags && SrcNode) {
        InterlockedOr(&SrcNode->BehaviorFlags, procFlags);
    }

    /* ── 更新 T1Feature 统计 ── */
    if (PairCtx) {
        PairCtx->T1Feature.RuleHitCount = hitCount;
        PairCtx->T1Feature.SemanticPopcount =
            (ULONG)__popcnt64(BM_SEM_U64(&PairCtx->InteractionBitmap));
    }

    Engine->TotalEvaluations++;
    return hit;
}
