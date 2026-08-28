/**************************************************/
/*  WkDefender IOC Matcher — 匹配函数               */
/*  移植自 ShadowStrike PhantomSensor IOCMatcher     */
/*                                                   */
/*  通配符匹配 / 域名子域名 / IPv4 CIDR               */
/*  所有函数均为 PASSIVE_LEVEL 安全（用户态无限制）     */
/**************************************************/

#pragma once

#include "IocMatcherTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 通配符匹配（支持 * 和 ?）。
 *
 * - * 匹配零个或多个任意字符
 * - ? 匹配恰好一个任意字符
 * - 大小写不敏感由 CaseSensitive 控制
 *
 * @param Pattern       模式串
 * @param PatternLength 模式串长度
 * @param String        被匹配串
 * @param StringLength  被匹配串长度
 * @param CaseSensitive TRUE=大小写敏感
 * @return TRUE=匹配
 */
BOOLEAN
IompMatchWildcard(
    _In_z_ PCSTR     Pattern,
    _In_ SIZE_T      PatternLength,
    _In_z_ PCSTR     String,
    _In_ SIZE_T      StringLength,
    _In_ BOOLEAN     CaseSensitive
    );

/**
 * @brief 域名匹配（支持 *.example.com 子域名通配）。
 *
 * 模式 "*.example.com" 可匹配 "sub.example.com" 和 "example.com"。
 * 模式 "example.com" 只精确匹配 "example.com"。
 */
BOOLEAN
IompMatchDomain(
    _In_z_ PCSTR     Pattern,
    _In_ SIZE_T      PatternLength,
    _In_z_ PCSTR     Domain,
    _In_ SIZE_T      DomainLength
    );

/**
 * @brief IP 地址匹配（支持 CIDR 和通配符）。
 *
 * - "192.168.0.0/16" 匹配 192.168.x.x
 * - "10.0.0.0/8" 匹配 10.x.x.x
 * - "192.168.1.*" 通配符匹配
 * - "192.168.1.1" 精确匹配
 */
BOOLEAN
IompMatchIPAddress(
    _In_z_ PCSTR     Pattern,
    _In_ SIZE_T      PatternLength,
    _In_z_ PCSTR     IPAddress,
    _In_ SIZE_T      IPLength
    );

/**
 * @brief 解析 IPv4 地址字符串。
 *
 * @param String  "192.168.1.1[/24]" 格式
 * @param Length  字符串长度
 * @param IP      输出 32-bit 网络字节序 IP
 * @param CIDR    输出 CIDR 前缀长度（未指定默认为 32）
 * @return TRUE=解析成功
 */
BOOLEAN
IompParseIPv4Address(
    _In_z_ PCSTR     String,
    _In_ SIZE_T      Length,
    _Out_ PULONG     IP,
    _Out_opt_ PULONG CIDR
    );

#ifdef __cplusplus
}
#endif
