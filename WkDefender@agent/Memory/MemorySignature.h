/**************************************************/
/*  WkDefender 内存签名 — 机制 B 核心 (纯 C YARA 解析器 + AC) */
/**************************************************/

/*
 * 职责：
 *   机制 B（自研，不依赖 libyara）：把 YARA 规则的 hex/text 字符串模式解析为
 *   字节序列 + 掩码，构建 Aho-Corasick 自动机，在进程内存缓冲上做多模式精确匹配。
 *   用于回路 B（镜像加载 → agent 进程内存 YARA），与机制 A（libyara 文件扫描）
 *   并列、数据源同源（均来自 Storage 的 yara_rules 表，D7 决策）。
 *
 * 参考 PhantomSensor（DEC-07 选 1，直接参考）：
 *   src/PhantomCore/PatternStore/PatternStore.cpp
 *     - PatternCompiler::CompilePattern（行 110）：YARA 模式 → (bytes, mask)
 *     - ImportFromYaraFile（行 1660）：YARA 文本 → 提取 strings/meta → 编译
 *     - BuildAutomaton（行 2383）：构建匹配结构
 *   src/PhantomCore/PatternStore/PatternIndex.cpp
 *     - AddPattern / Search / SearchContext::Feed：Trie/AC 逐字节 child→failure→output
 *
 * 简化边界（计划行 313-315、385，DEC-07 选 1 仍遵守"重新设计格式不要照搬"）：
 *   - 仅 hex 精确匹配 + ?? 通配（AC + 通配子边），通配命中后按 mask 回扫校验。
 *   - [min-max] 跳转：取下限，展开为下限个通配字节（不展开多条模式）。
 *   - (a-b) 字节范围：取下限字节。
 *   - 范围外（代码内标注）：SIMD/AVX2、Boyer-Moore、Regex(/.../)、序列化落盘
 *     （TrieNodeBinary mmap，§0.3-A 明确反对照搬）、多命名空间/include、流式分块。
 */

#pragma once

#include <windows.h>
#include <stdint.h>

/* 模式编译上限（DoS 防护；对齐 SS MemoryScanner MS_MAX_PATTERN_SIZE=1024。
 * 上移至 .h 供 MemoryScan.c overlap 跨边界计算复用（SS MED-1 fix）） */
#define MS_MAX_PATTERN_BYTES       2048

/* 威胁级（与机制 A 的 IocYara_ThreatLevelToScore 映射一致） */
typedef enum _MS_THREAT_LEVEL {
    MsThreat_Info = 0,
    MsThreat_Low = 1,
    MsThreat_Medium = 2,
    MsThreat_High = 3,
    MsThreat_Critical = 4
} MS_THREAT_LEVEL, *PMS_THREAT_LEVEL;

/* 单条模式 */
typedef struct _MS_PATTERN {
    BYTE*  Bytes;          /* 编译后字节序列，长度=Length */
    BYTE*  Mask;           /* 掩码：0xFF=精确 0x00=通配，长度=Length */
    UINT   Length;         /* 模式长度（字节） */
    UINT   PatternId;      /* 全局唯一 ID（自增，1-based） */
    CHAR*  RuleName;       /* "RuleName.$var"，可 NULL */
    INT    ThreatLevel;    /* MS_THREAT_LEVEL */
    BOOLEAN Disabled;      /* 临时禁用（MsPatternIndexSetEnabled, 对齐 SS MsPatternFlag_Disabled, 搜索跳过） */
    BOOLEAN Removed;       /* 逻辑删除（MsPatternIndexRemovePattern, 永久, 搜索跳过 + SetEnabled 拒绝恢复） */
} MS_PATTERN, *PMS_PATTERN;

/* AC Trie 节点（内存指针版，替代 TrieNodeBinary mmap 序列化） */
typedef struct _MS_AC_NODE {
    struct _MS_AC_NODE* Child[256];      /* 精确字节转移（NULL=无） */
    struct _MS_AC_NODE* WildcardChild;   /* 通配转移（?? / [min-max] 下限展开） */
    struct _MS_AC_NODE* Failure;         /* 失配指针（NULL=指向根） */
    UINT*  OutputPatternIds;             /* 该节点完成的模式 ID 数组 */
    UINT   OutputCount;                  /* OutputPatternIds 元素数 */
} MS_AC_NODE, *PMS_AC_NODE;

/* 自动机索引 */
typedef struct _MS_PATTERN_INDEX {
    MS_AC_NODE*  Root;           /* 根节点 */
    MS_PATTERN* Patterns;        /* 模式数组，下标=PatternId-1 */
    UINT         PatternCount;   /* 已添加模式数 */
    UINT         PatternCapacity;
    UINT         NextPatternId;  /* 下一分配 ID（从 1 起） */
    BOOLEAN      Built;          /* 失配链是否已构建 */
} MS_PATTERN_INDEX, *PMS_PATTERN_INDEX;

/* 命中回调 */
typedef VOID (CALLBACK* MS_MATCH_CALLBACK)(
    _In_ UINT PatternId,
    _In_ SIZE_T HitOffset,
    _In_ PMS_PATTERN Pattern);

/*====================================================================*/
/*  接口                                                */
/*====================================================================*/

/*++
 * MsPatternIndexCreate / Destroy
 *   创建/递归销毁自动机（含 Trie 全部节点 + Patterns 数组 + 每模式 Bytes/Mask/RuleName）。
 *--*/
PMS_PATTERN_INDEX MsPatternIndexCreate(VOID);
VOID MsPatternIndexDestroy(_In_ PMS_PATTERN_INDEX Index);

/*++
 * MsCompilePattern
 *   把单条 YARA 字符串段（hex 文本或文本串）编译为 (Bytes, Mask)。
 *   调用者负责释放 *OutBytes / *OutMask（用 MsFreePatternBuffer）。
 *   支持：hex 精确、?? 通配、(a-b) 下限、[min-max] 下限展开通配、文本串转 hex；
 *        正则 /.../ 返回 FALSE（范围外，跳过）。
 *   返回 TRUE 表示成功且 Length>0。
 *--*/
BOOL MsCompilePattern(
    _In_  LPCSTR PatternStr,
    _Out_ BYTE** OutBytes,
    _Out_ BYTE** OutMask,
    _Out_ UINT*  OutLength);

VOID MsFreePatternBuffer(_In_ BYTE* Bytes, _In_ BYTE* Mask);

/*++
 * MsPatternIndexAddPattern
 *   添加一条已编译模式到 Trie（不构建失配链，Built 保持 FALSE）。
 *--*/
BOOL MsPatternIndexAddPattern(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ BYTE*  Bytes,
    _In_ BYTE*  Mask,
    _In_ UINT   Length,
    _In_opt_ LPCSTR RuleName,
    _In_ INT    ThreatLevel);

/*++
 * MsPatternIndexBuild
 *   添加全部完成后调用一次：标准 BFS 构建失败链。
 *--*/
BOOL MsPatternIndexBuild(_In_ PMS_PATTERN_INDEX Index);

/*++
 * MsPatternIndexSearch
 *   在内存缓冲中搜索所有模式，命中经 Callback 上报（hitOffset 为缓冲内绝对偏移）。
 *   通配感知：AC 按精确字节 + WildcardChild 走边；最终命中按 mask 回扫二次校验。
 *--*/
BOOL MsPatternIndexSearch(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ const BYTE* Buffer,
    _In_ SIZE_T Size,
    _In_ MS_MATCH_CALLBACK Callback);

/*++
 * MsPatternIndexSetEnabled / MsPatternIndexRemovePattern
 *   模式运行时管理（对齐 SS MemoryScanner MsEnablePattern L1296-1338 /
 *   MsRemovePattern L1196-1292）。
 *   ※ 死代码: wkd 以 yara_rules 表为唯一源（MsImportFromYaraRules 一次性构建），
 *     运行时规则更新走 DB + 整体重建；单条 API 供未来运行时规则管理接线。
 *--*/
BOOL MsPatternIndexSetEnabled(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ UINT PatternId,
    _In_ BOOLEAN Enable);

BOOL MsPatternIndexRemovePattern(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ UINT PatternId);

/*++
 * ShadowStrike MemoryScanner 签名引擎对比（2026-08，MemoryMonitor 迁移批次）：
 *   SS MemoryScanner.c 三类签名引擎与本模块覆盖情况：
 *     - Wildcard（SS MspWildcardSearch L2528）→ 已覆盖：MsCompilePattern 的
 *       "??" 通配编译为 mask=0x00 + AC WildcardChild 走边 + mask 回扫二次校验，
 *       与 SS 掩码滑动窗口语义等价（功能等价，实现更强）。
 *     - BMH（SS MspBuildBMHTable/MspSearchBMH）→ 不迁移：单模式快速搜索属
 *       性能优化（O(n/m)），AC 自动机已覆盖单/多模式匹配功能面，agent 用户态
 *       无性能瓶颈，冗余不迁移。
 *     - MultiPart（SS 分段签名：2-4 段带偏移/哈希校验）→ 不迁移：wkd 签名源
 *       为 YARA 规则（SQLite yara_rules），不含分段偏移+哈希校验语义，无数据源，
 *       死代码标注。
 *   补记（2026-08-07 MemoryScanner.c 全量对比）：
 *     - AC 失败链 output（SS HIGH-6 fix L2830-2860 后缀匹配）→ 已覆盖：
 *       MsPatternIndexSearch 运行时沿失败链遍历收集 output（L566-589），
 *       与 SS build 期 output 合并 + 运行时失败链遍历双保险功能等价。
 *     - Regex/Signature(多段)/Entropy/API 模式类型 → SS 仅枚举定义无搜索实现
 *       （grep 验证 MspMultiPartSearch 不存在），纸面枚举；wkd 单类型已覆盖
 *       全部实际生效类型（Exact+Wildcard）。
 *     - WholeWord/AtStart/AtEnd/Negated/Critical flags → SS 搜索循环仅实际使用
 *       Disabled/CaseSensitive，其余纸面，wkd 无此需求。
 *     - 运行时管理 API（SetEnabled/RemovePattern）→ 本次死代码补迁（见上）。
 *--*/

/*++
 * MsImportFromYaraRules
 *   从 SQLite yara_rules 表（enabled=1）逐条取 rule_text → 解析 → 编译 → 加入 Index。
 *   db 为已打开的 sqlite3 句柄（通常传 WkdStorageEngine.WarmDb，与机制 A 同源）。
 *   返回成功导入的规则数（0 表示无规则，非致命）。
 *   参考 ImportFromYaraFile（行 1660）的状态机解析，但数据源改为 DB 而非文件。
 *--*/
UINT MsImportFromYaraRules(
    _In_ void* Db,                /* sqlite3* */
    _In_ PMS_PATTERN_INDEX Index);
