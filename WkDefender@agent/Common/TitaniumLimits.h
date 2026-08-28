/**************************************************/
/*  WkDefender TitaniumLimits — 资源上限常量集中定义 */
/*  参考 PhantomSensor YaraTitaniumLimits           */
/*  （YaraRuleStore.hpp:89-123）                    */
/**************************************************/

/*
 * 设计决策：所有资源上限集中在此头，各模块 #include 后引用同名宏。
 * 避免上限散落在多个 .c/.h 文件中导致维护不一致。
 */

#pragma once

/*====================================================================*/
/*  扫描与缓冲上限                                                    */
/*====================================================================*/

/* 单次 YARA 扫描缓冲最大大小（超过直接失败，防 DoS） */
#define WKD_MAX_SCAN_BUFFER_SIZE          (500ULL * 1024 * 1024)  /* 500MB */

/* 单文件最大扫描大小（超过跳过，防大文件 mmap OOM） */
#define WKD_MAX_FILE_SIZE                 (100ULL * 1024 * 1024)  /* 100MB */

/* YARA 扫描超时秒数（yr_rules_scan_mem timeout 参数） */
#define WKD_YARA_SCAN_TIMEOUT_SEC         30

/*====================================================================*/
/*  规则源与编译上限                                                  */
/*====================================================================*/

/* 单规则源文本最大长度（编译前截断，防 YARA 解析指数爆炸） */
#define WKD_MAX_RULE_SOURCE_SIZE          (10ULL * 1024 * 1024)   /* 10MB */

/* 单 YARA 规则文件最大大小 */
#define WKD_MAX_RULE_FILE_SIZE            (50ULL * 1024 * 1024)   /* 50MB */

/* 编译后的规则 BLOB 最大大小 */
#define WKD_MAX_COMPILED_RULES_SIZE       (500ULL * 1024 * 1024)  /* 500MB */

/*====================================================================*/
/*  名称与元数据上限（参考 YARA 标准 + PhantomSensor 设置）            */
/*====================================================================*/

#define WKD_MAX_RULE_NAME_LENGTH          256
#define WKD_MAX_NAMESPACE_LENGTH          128
#define WKD_MAX_TAGS_PER_RULE             100
#define WKD_MAX_TAG_LENGTH                64
#define WKD_MAX_META_ITEMS                100
#define WKD_MAX_META_VALUE_LENGTH         4096
#define WKD_MAX_PATH_LENGTH               32767

/*====================================================================*/
/*  匹配上限（双重 DoS 防护：每规则上限 + 总上限 CALLBACK_ABORT）     */
/*====================================================================*/

/* 单规则在单次扫描中的最大命中数（超限后该规则打标截断） */
#define WKD_YARA_MAX_MATCHES_PER_RULE     100

/* 单次扫描总命中数上限（超限 CALLBACK_ABORT 中止扫描） */
#define WKD_YARA_MAX_TOTAL_MATCHES        10000

/*====================================================================*/
/*  文件导入与仓库上限                                                */
/*====================================================================*/

/* YARA 规则仓库目录最大文件数（防 FindYaraFiles DoS） */
#define WKD_MAX_YARA_FILES_IN_REPO        100000

/* 递归导入/扫描的最大深度 */
#define WKD_MAX_RECURSION_DEPTH           20

/* 目录扫描超时（秒） */
#define WKD_DIRECTORY_SCAN_TIMEOUT_SEC    300

/*====================================================================*/
/*  线程与并发上限                                                    */
/*====================================================================*/

/* YARA 扫描器消息队列最大挂起任务数 */
#define WKD_YARA_QUEUE_MAX_PENDING        512

/* 批处理单批最大条目数 */
#define WKD_MAX_BATCH_SIZE                1000000

/*====================================================================*/
/*  锁层次声明（所有模块遵循此获取顺序，防死锁）                       */
/*====================================================================*/

/*
 *  锁层次（从高到低获取顺序，反序释放）：
 *    Level 1: g_YaraLock (SRWLOCK)     — 保护 g_YaraRules 指针生命周期
 *    Level 2: g_YaraScanLock (SRWLOCK) — 串行化 yr_rules_scan_mem
 *    Level 3: SQLite 内部锁            — sqlite3_mutex 自动管理
 *
 *  获取规则：必须按 Level 1 → 2 → 3 顺序获取，不可以逆序。
 *  例如：扫描路径先持 g_YaraLock Shared → 再持 g_YaraScanLock Exclusive
 *        重载路径先持 g_YaraLock Exclusive → 不持 g_YaraScanLock
 *        SQLite 写入在 Release 前两层锁之后进行（锁外执行）。
 */
