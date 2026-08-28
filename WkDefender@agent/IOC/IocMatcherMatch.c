/**************************************************/
/*  WkDefender IOC Matcher — 匹配函数实现            */
/*  移植自 ShadowStrike PhantomSensor IOCMatcher     */
/*                                                   */
/*  通配符匹配 / 域名子域名 / IPv4 CIDR               */
/**************************************************/

#include "IocMatcherMatch.h"
#include <string.h>
#include <assert.h>

/**************************************************/
/*               通配符匹配                         */
/**************************************************/

BOOLEAN
IompMatchWildcard(
    _In_z_ PCSTR     Pattern,
    _In_ SIZE_T      PatternLength,
    _In_z_ PCSTR     String,
    _In_ SIZE_T      StringLength,
    _In_ BOOLEAN     CaseSensitive
    )
{
    PCSTR p = Pattern;
    PCSTR s = String;
    PCSTR pEnd = Pattern + PatternLength;
    PCSTR sEnd = String + StringLength;
    PCSTR starP = NULL;
    PCSTR starS = NULL;

    if (Pattern == NULL || PatternLength == 0) return FALSE;
    if (String == NULL) return FALSE;

    while (s < sEnd) {
        if (p >= pEnd) {
            if (starP != NULL) {
                p = starP + 1;
                s = ++starS;
                if (starS >= sEnd) return FALSE;
                continue;
            }
            return FALSE;
        }

        CHAR pc = *p;
        CHAR sc = *s;

        if (!CaseSensitive) {
            if (pc >= 'A' && pc <= 'Z') pc = pc + ('a' - 'A');
            if (sc >= 'A' && sc <= 'Z') sc = sc + ('a' - 'A');
        }

        if (*p == '*') {
            starP = p++;
            starS = s;
        } else if (*p == '?' || pc == sc) {
            p++;
            s++;
        } else if (starP != NULL) {
            p = starP + 1;
            s = ++starS;
            if (starS >= sEnd) break;
        } else {
            return FALSE;
        }
    }

    /* 跳过模式串尾部剩余 * */
    while (p < pEnd && *p == '*') p++;

    return (p >= pEnd);
}

/**************************************************/
/*               域名匹配                           */
/**************************************************/

/*
 * 模式 "*.example.com"：
 *   - 匹配 "sub.example.com"（子域名匹配）
 *   - 匹配 "example.com"（根域名匹配）
 * 模式 "example.com"：
 *   - 只精确匹配 "example.com"
 *   - 不匹配 "sub.example.com"
 */
BOOLEAN
IompMatchDomain(
    _In_z_ PCSTR     Pattern,
    _In_ SIZE_T      PatternLength,
    _In_z_ PCSTR     Domain,
    _In_ SIZE_T      DomainLength
    )
{
    PCSTR patternStart;
    SIZE_T patternLen;
    BOOLEAN wildcardStart = FALSE;

    if (Pattern == NULL || Domain == NULL ||
        PatternLength == 0 || DomainLength == 0) {
        return FALSE;
    }

    patternStart = Pattern;
    patternLen = PatternLength;

    /* 检查 *. 前缀 */
    if (patternLen >= 2 && Pattern[0] == '*' && Pattern[1] == '.') {
        wildcardStart = TRUE;
        patternStart = Pattern + 2;
        patternLen -= 2;
    }

    if (patternLen == 0) return FALSE;
    if (DomainLength < patternLen) return FALSE;

    /* 精确匹配 */
    if (DomainLength == patternLen) {
        return (_strnicmp(patternStart, Domain, patternLen) == 0);
    }

    /* 子域名匹配：域以模式结尾，且前置有 '.' */
    if (DomainLength > patternLen && wildcardStart) {
        SIZE_T offset = DomainLength - patternLen;
        if (Domain[offset - 1] != '.') return FALSE;
        return (_strnicmp(patternStart, Domain + offset, patternLen) == 0);
    }

    return FALSE;
}

/**************************************************/
/*               IPv4 地址解析                     */
/**************************************************/

BOOLEAN
IompParseIPv4Address(
    _In_z_ PCSTR     String,
    _In_ SIZE_T      Length,
    _Out_ PULONG     IP,
    _Out_opt_ PULONG CIDR
    )
{
    ULONG octets[4] = { 0 };
    ULONG octetIdx = 0;
    ULONG currentValue = 0;
    SIZE_T i;
    BOOLEAN hasCIDR = FALSE;
    ULONG cidrValue = 0;

    *IP = 0;
    if (CIDR != NULL) *CIDR = 32;

    if (String == NULL || Length == 0) return FALSE;

    for (i = 0; i < Length; i++) {
        CHAR c = String[i];

        if (c >= '0' && c <= '9') {
            if (hasCIDR) {
                cidrValue = cidrValue * 10 + (c - '0');
                if (cidrValue > 32) return FALSE;
            } else {
                currentValue = currentValue * 10 + (c - '0');
                if (currentValue > 255) return FALSE;
            }
        } else if (c == '.' && !hasCIDR) {
            if (octetIdx >= 3) return FALSE;
            octets[octetIdx++] = currentValue;
            currentValue = 0;
        } else if (c == '/' && !hasCIDR) {
            if (octetIdx != 3) return FALSE;
            octets[octetIdx] = currentValue;
            hasCIDR = TRUE;
            cidrValue = 0;
        } else {
            return FALSE;
        }
    }

    if (hasCIDR) {
        if (CIDR != NULL) *CIDR = cidrValue;
    } else {
        if (octetIdx != 3) return FALSE;
        octets[3] = currentValue;
        if (octets[3] > 255) return FALSE;
    }

    *IP = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return TRUE;
}

/**************************************************/
/*               IP 地址匹配                        */
/**************************************************/

BOOLEAN
IompMatchIPAddress(
    _In_z_ PCSTR     Pattern,
    _In_ SIZE_T      PatternLength,
    _In_z_ PCSTR     IPAddress,
    _In_ SIZE_T      IPLength
    )
{
    ULONG patternIP, ip;
    ULONG patternCIDR, cidr;
    ULONG mask;
    SIZE_T i;
    BOOLEAN hasWildcard = FALSE;

    if (Pattern == NULL || IPAddress == NULL ||
        PatternLength == 0 || IPLength == 0) {
        return FALSE;
    }

    /* 检查通配符 */
    for (i = 0; i < PatternLength; i++) {
        if (Pattern[i] == '*') {
            hasWildcard = TRUE;
            break;
        }
    }

    if (hasWildcard) {
        return IompMatchWildcard(Pattern, PatternLength,
                                  IPAddress, IPLength, TRUE);
    }

    /* CIDR 匹配 */
    if (!IompParseIPv4Address(Pattern, PatternLength, &patternIP, &patternCIDR))
        return FALSE;
    if (!IompParseIPv4Address(IPAddress, IPLength, &ip, &cidr))
        return FALSE;

    if (patternCIDR == 0)
        mask = 0;
    else if (patternCIDR >= 32)
        mask = 0xFFFFFFFF;
    else
        mask = 0xFFFFFFFF << (32 - patternCIDR);

    return ((patternIP & mask) == (ip & mask));
}
