/**************************************************/
/*  WkDefender IOC Matcher — 实时 IOC 匹配引擎       */
/*  移植自 ShadowStrike PhantomSensor IOCMatcher     */
/*                                                   */
/*  功能：                                            */
/*  - 布隆过滤器快速否定（哈希/域名/IP 的 O(1) 预检）*/
/*  - 域名子域名/IP CIDR/通配符匹配                   */
/*  - IOC 引用计数 + 关闭闸门（卸载安全）              */
/*  - IOC 过期自动清理                                */
/*  - CSV 批量加载                                    */
/*                                                   */
/*  与现有 IocScanner 的关系：                         */
/*  - IocScanner = 进程创建时的静态分析扫描器           */
/*  - IocMatcher = 热路径实时 IOC 判定引擎             */
/*  两者互为补充，不替代。                             */
/**************************************************/

#pragma once

#include "IocMatcherTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************/
/*               生命周期                           */
/**************************************************/

/**
 * @brief 初始化 IOC Matcher 引擎。
 *
 * @param Config  可选配置（NULL 使用默认值）
 * @return STATUS_SUCCESS 或错误码
 *
 * @irql PASSIVE_LEVEL（用户态无 IRQL 约束，仅为接口对齐保留注释）
 */
NTSTATUS
IocMatcher_Initialize(
    _In_opt_ PIOC_MATCHER_CONFIG Config
    );

/**
 * @brief 关闭 IOC Matcher 引擎。
 *
 * 等所有 in-flight 调用完成后释放资源。
 * 调用后引擎句柄不再有效。
 */
VOID
IocMatcher_Shutdown(
    VOID
    );

/**************************************************/
/*               IOC 管理                           */
/**************************************************/

/**
 * @brief 加载一条 IOC。
 *
 * @param IOC   IOC 数据（调用者可释放）
 * @return STATUS_SUCCESS 或错误码
 */
NTSTATUS
IocMatcher_LoadIOC(
    _In_ PIOC_MATCH_INPUT IOC
    );

/**
 * @brief 从缓冲区批量加载 IOC（CSV 或行格式）。
 *
 * @param Buffer        包含 IOC 数据的缓冲区
 * @param Size          缓冲区大小（字节）
 * @param LoadedCount   可选：接收加载成功的 IOC 数
 * @param ErrorCount    可选：接收解析失败的条数
 * @return STATUS_SUCCESS 或错误码
 */
NTSTATUS
IocMatcher_LoadFromBuffer(
    _In_ PVOID      Buffer,
    _In_ SIZE_T     Size,
    _Out_opt_ PULONG LoadedCount,
    _Out_opt_ PULONG ErrorCount
    );

/**
 * @brief 按 ID 移除一条 IOC。
 */
NTSTATUS
IocMatcher_RemoveIOC(
    _In_ ULONG64 IOCId
    );

/**
 * @brief 手动触发过期 IOC 清理。
 */
NTSTATUS
IocMatcher_CleanupExpired(
    VOID
    );

/**************************************************/
/*               核心匹配 API                       */
/**************************************************/

/**
 * @brief 匹配字符串值。
 *
 * @param Type          IOC 类型
 * @param Value         被匹配的值（null-terminated）
 * @param ValueLength   值长度（不含 null）
 * @param Result        输出匹配结果（调用者分配）
 * @return STATUS_SUCCESS 命中 / STATUS_NOT_FOUND 未命中
 */
NTSTATUS
IocMatcher_Match(
    _In_ IOC_MATCH_TYPE     Type,
    _In_reads_z_(ValueLength + 1) PCSTR Value,
    _In_ SIZE_T             ValueLength,
    _Out_ PIOC_MATCH_RESULT Result
    );

/**
 * @brief 匹配二进制哈希值（自动转十六进制串）。
 *
 * @param Hash          二进制哈希数据
 * @param HashLength    哈希长度（字节）
 * @param HashType      哈希类型（MD5/SHA1/SHA256）
 * @param Result        输出匹配结果
 * @return STATUS_SUCCESS 命中 / STATUS_NOT_FOUND 未命中
 */
NTSTATUS
IocMatcher_MatchHash(
    _In_reads_bytes_(HashLength) PCUCHAR Hash,
    _In_ SIZE_T             HashLength,
    _In_ IOC_MATCH_TYPE     HashType,
    _Out_ PIOC_MATCH_RESULT Result
    );

/**
 * @brief 布隆过滤器快速检查——O(1) 否定。
 *
 * 返回 FALSE 表示"值一定不存在"（可直接跳过精确查询）。
 * 返回 TRUE  表示"可能存在"（需要进一步精确匹配）。
 *
 * @param Type  IOC 类型（仅精确匹配型如 Hash/JA3/Mutex 有效）
 * @param Data  数据
 * @param Length 长度
 * @return FALSE = 一定不存在, TRUE = 可能存在
 */
BOOLEAN
IocMatcher_BloomCheck(
    _In_ IOC_MATCH_TYPE     Type,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T             Length
    );

/**************************************************/
/*               回调注册                           */
/**************************************************/

/**
 * @brief 注册匹配回调。
 *
 * 仅一个回调可注册。新注册原子替换旧注册。
 * 传入 NULL 可取消注册。
 */
NTSTATUS
IocMatcher_RegisterCallback(
    _In_opt_ IOC_MATCH_CALLBACK Callback,
    _In_opt_ PVOID              Context
    );

/**************************************************/
/*               统计查询                           */
/**************************************************/

/**
 * @brief 获取引擎统计快照。
 */
NTSTATUS
IocMatcher_GetStatistics(
    _Out_ PIOC_MATCHER_STATS Stats
    );

/**
 * @brief 获取当前 IOC 数量。
 */
LONG
IocMatcher_GetIOCCount(
    VOID
    );

#ifdef __cplusplus
}
#endif
