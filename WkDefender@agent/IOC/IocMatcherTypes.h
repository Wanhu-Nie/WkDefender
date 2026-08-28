/**************************************************/
/*  WkDefender IOC Matcher — 类型与常量定义           */
/*  移植自 ShadowStrike PhantomSensor IOCMatcher     */
/*  用户态适配版 (2026-07-22)                        */
/*                                                   */
/*  实时 IOC 匹配引擎的类型定义。                      */
/*  布隆过滤器 + 域名/IP/通配符匹配 + 过期管理。       */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               IOC 匹配模式                        */
/**************************************************/

typedef enum _IOC_MATCH_MODE {
    IocMatchMode_Exact = 0,         // 精确匹配
    IocMatchMode_Wildcard,           // 通配符 (*, ?)
    IocMatchMode_Regex,              // 正则表达式（对齐 SS 枚举，SS 亦未实现，仅预留）
    IocMatchMode_CIDR,               // CIDR 网段 (192.168.0.0/16)
    IocMatchMode_Subdomain,          // 子域名 (*.example.com)
    IocMatchMode_MaxValue
} IOC_MATCH_MODE, *PIOC_MATCH_MODE;

/**************************************************/
/*               IOC 类型枚举                        */
/**************************************************/
/*
 * 与 IocTypes.h 的 DEF_IOC_VERDICT 互补。
 * 这里是匹配目标的"种类"，不是判定结果。
 */

typedef enum _IOC_MATCH_TYPE {
    IocType_Unknown = 0,
    IocType_FileHash_MD5,
    IocType_FileHash_SHA1,
    IocType_FileHash_SHA256,
    IocType_FilePath,
    IocType_FileName,
    IocType_Registry,
    IocType_Mutex,
    IocType_IPAddress,
    IocType_Domain,
    IocType_URL,
    IocType_EmailAddress,
    IocType_ProcessName,
    IocType_CommandLine,
    IocType_JA3,
    IocType_YARA,                        /* 对齐 SS 枚举；YARA 判定由 IocYaraScanner 承担，此处仅预留 */
    IocType_Custom,
    IocType_MaxValue
} IOC_MATCH_TYPE, *PIOC_MATCH_TYPE;

/**************************************************/
/*               IOC 严重级别                        */
/**************************************************/

typedef enum _IOC_SEVERITY {
    IocSeverity_Unknown = 0,
    IocSeverity_Info,
    IocSeverity_Low,
    IocSeverity_Medium,
    IocSeverity_High,
    IocSeverity_Critical,
    IocSeverity_MaxValue
} IOC_SEVERITY, *PIOC_SEVERITY;

/**************************************************/
/*               常量                               */
/**************************************************/

#define IOC_MAX_VALUE_LENGTH            512     // IOC 值最大长度（含 null）
#define IOC_MAX_DESCRIPTION_LENGTH      256     // IOC 描述最大长度
#define IOC_MAX_THREAT_NAME_LENGTH      64      // 威胁名最大长度
#define IOC_MAX_SOURCE_LENGTH           64      // IOC 来源标识长度

#define IOC_DEFAULT_HASH_BUCKETS        4096    // 全局哈希桶数
#define IOC_MAX_IOCS_DEFAULT            1000000 // 默认 IOC 数量上限

/* 类型专用哈希桶数 */
#define IOC_HASH_BUCKETS_MD5            4096
#define IOC_HASH_BUCKETS_SHA1           4096
#define IOC_HASH_BUCKETS_SHA256         8192
#define IOC_HASH_BUCKETS_DOMAIN         2048
#define IOC_HASH_BUCKETS_IP             1024
#define IOC_HASH_BUCKETS_OTHER          512

/* 布隆过滤器 */
#define IOC_BLOOM_FILTER_SIZE          (1024 * 1024)   // 1MB
#define IOC_BLOOM_HASH_COUNT           7                // 每值哈希函数数
#define IOC_BLOOM_SEED_1               0x811C9DC5ULL    // FNV-1a 种子1
#define IOC_BLOOM_SEED_2               0xC96C5795D7870F42ULL  // 种子2

/* 哈希长度（十六进制串长度） */
#define IOC_MD5_HEX_LENGTH             32
#define IOC_SHA1_HEX_LENGTH            40
#define IOC_SHA256_HEX_LENGTH          64

/* 清理 */
#define IOC_CLEANUP_INTERVAL_MS        300000  // 5 分钟

/* 引用计数状态 */
#define IOC_REFCOUNT_DELETED           (-1)
#define IOC_REFCOUNT_INITIAL           1

/**************************************************/
/*               IOC 输入结构                        */
/**************************************************/

typedef struct _IOC_MATCH_INPUT {
    IOC_MATCH_TYPE  Type;
    IOC_SEVERITY    Severity;

    /* IOC 值（null-terminated，长度已校验） */
    CHAR            Value[IOC_MAX_VALUE_LENGTH];
    SIZE_T          ValueLength;

    /* 元数据 */
    CHAR            Description[IOC_MAX_DESCRIPTION_LENGTH];
    CHAR            ThreatName[IOC_MAX_THREAT_NAME_LENGTH];
    CHAR            Source[IOC_MAX_SOURCE_LENGTH];
    LARGE_INTEGER   Expiry;             // 过期时间（0=永不过期）

    /* 匹配选项 */
    BOOLEAN         CaseSensitive;
    IOC_MATCH_MODE  MatchMode;
} IOC_MATCH_INPUT, *PIOC_MATCH_INPUT;

/**************************************************/
/*               匹配结果结构                        */
/**************************************************/

typedef struct _IOC_MATCH_RESULT {
    IOC_MATCH_TYPE  Type;
    IOC_SEVERITY    Severity;
    ULONG64         IOCId;

    /* 注意：以下字段均为值拷贝，无内部指针 */
    CHAR            IOCValue[IOC_MAX_VALUE_LENGTH];        // 匹配到的 IOC 值
    CHAR            ThreatName[IOC_MAX_THREAT_NAME_LENGTH];
    CHAR            Description[IOC_MAX_DESCRIPTION_LENGTH];
    CHAR            MatchedValue[IOC_MAX_VALUE_LENGTH];    // 被匹配的值

    HANDLE          ProcessId;
    LARGE_INTEGER   MatchTime;
} IOC_MATCH_RESULT, *PIOC_MATCH_RESULT;

/**************************************************/
/*               匹配回调                            */
/**************************************************/

typedef VOID
(*IOC_MATCH_CALLBACK)(
    _In_ PIOC_MATCH_RESULT  MatchData,
    _In_opt_ PVOID          Context
    );

/**************************************************/
/*               引擎统计                           */
/**************************************************/

typedef struct _IOC_MATCHER_STATS {
    volatile LONG64 IOCsLoaded;
    volatile LONG64 IOCsExpired;
    volatile LONG64 MatchesFound;
    volatile LONG64 QueriesPerformed;
    volatile LONG64 BloomFilterHits;
    volatile LONG64 BloomFilterMisses;
    LARGE_INTEGER   StartTime;
} IOC_MATCHER_STATS, *PIOC_MATCHER_STATS;

/**************************************************/
/*               引擎配置                           */
/**************************************************/

typedef struct _IOC_MATCHER_CONFIG {
    BOOLEAN         EnableBloomFilter;
    BOOLEAN         EnableExpiration;
    BOOLEAN         EnableStatistics;
    ULONG           DefaultExpiryHours;
    ULONG           MaxIOCs;
    ULONG           HashBucketCount;
} IOC_MATCHER_CONFIG, *PIOC_MATCHER_CONFIG;

#define IOC_MATCHER_DEFAULT_CONFIG                          \
    {                                                       \
        TRUE,   /* EnableBloomFilter */                     \
        TRUE,   /* EnableExpiration */                      \
        TRUE,   /* EnableStatistics */                      \
        24 * 7, /* DefaultExpiryHours = 7 days */           \
        IOC_MAX_IOCS_DEFAULT,                               \
        IOC_DEFAULT_HASH_BUCKETS                            \
    }
