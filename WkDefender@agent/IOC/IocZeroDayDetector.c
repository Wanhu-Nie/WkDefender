/**************************************************/
/*  WkDefender IOC 引擎 — exploit 原语检测实现      */
/**************************************************/

#include "IocZeroDayDetector.h"

#include <string.h>
#include <math.h>
#include <ntstatus.h>

#include "../IOA/Tier1/T1ShellcodeDetect.h"  /* IocDetectShellcode 复用 (HeapSpray 迁移 2026-08) */

#define WKD_ZD_MIN_NOP_SLED      16
#define WKD_ZD_SHELLCODE_ENT_MIN 5.5f
#define WKD_ZD_SHELLCODE_ENT_MAX 7.5f

/**************************************************/
/*               内部辅助                           */
/**************************************************/

static double
IocZd_Entropy(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    double freq[256] = { 0 };
    double ent = 0.0;
    SIZE_T i;

    if (Len == 0) return 0.0;
    for (i = 0; i < Len; i++) freq[Buf[i]]++;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / (double)Len;
            ent -= p * log(p) / log(2.0);
        }
    }
    return ent;
}

/**************************************************/
/*               NOP sled 检测                     */
/**************************************************/

BOOLEAN
IocZeroDay_IsNopSled(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_opt_ PULONG SledLen
    )
{
    SIZE_T consecutive = 0;
    SIZE_T bestRun = 0;
    SIZE_T i;

    if (!Buf || Len < WKD_ZD_MIN_NOP_SLED) return FALSE;
    if (SledLen) *SledLen = 0;

    for (i = 0; i < Len; i++) {
        /* NOP (90) + NOP 族单字节寄存器互换 (90-97) */
        if (Buf[i] >= 0x90 && Buf[i] <= 0x97) {
            consecutive++;
            if (consecutive > bestRun) bestRun = consecutive;
        } else {
            consecutive = 0;
        }
    }

    if (bestRun >= WKD_ZD_MIN_NOP_SLED) {
        if (SledLen) *SledLen = (ULONG)bestRun;
        return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*               GetPC 技巧检测                    */
/**************************************************/

BOOLEAN
IocZeroDay_HasGetPC(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    SIZE_T i;

    if (!Buf || Len < 6) return FALSE;

    for (i = 0; i + 5 < Len; i++) {
        /* CALL $+5 / POP reg: E8 00 00 00 00 58-5F */
        if (Buf[i] == 0xE8 && Buf[i + 1] == 0x00 && Buf[i + 2] == 0x00 &&
            Buf[i + 3] == 0x00 && Buf[i + 4] == 0x00 &&
            Buf[i + 5] >= 0x58 && Buf[i + 5] <= 0x5F) {
            return TRUE;
        }
        /* FNSTENV [ESP-0Ch]: D9 74 24 F4 */
        if (i + 3 < Len && Buf[i] == 0xD9 && Buf[i + 1] == 0x74 &&
            Buf[i + 2] == 0x24 && Buf[i + 3] == 0xF4) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*               堆喷模式检测                      */
/**************************************************/

static BOOLEAN
IocZd_IsSprayValue(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _In_ ULONG       Value
    )
{
    SIZE_T count = 0;
    SIZE_T i;

    for (i = 0; i + 3 < Len; i += 4) {
        if (memcmp(Buf + i, &Value, 4) == 0) {
            count++;
            if (count >= 4) return TRUE;   /* 至少 4 次重复 */
        }
    }
    return FALSE;
}

BOOLEAN
IocZeroDay_IsHeapSprayPattern(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_opt_ PULONG Value
    )
{
    /* 对齐 SS HspIsKnownSprayPattern DWORD 表 + wkd 原有 0x0E0E0E0E:
     *   SS: {0x0C0C0C0C, 0x0D0D0D0D, 0x0A0A0A0A, 0x41414141, 0x42424242,
     *        0x90909090, 0x04040404, 0x06060606, 0x07070707, 0x08080808} */
    static const ULONG sprayValues[] = {
        0x0C0C0C0C, 0x0D0D0D0D, 0x0E0E0E0E, 0x0A0A0A0A,
        0x41414141, 0x42424242, 0x90909090,
        0x04040404, 0x06060606, 0x07070707, 0x08080808,
    };
    ULONG i;

    if (!Buf || Len < 64) return FALSE;

    for (i = 0; i < (ULONG)(sizeof(sprayValues) / sizeof(sprayValues[0])); i++) {
        if (IocZd_IsSprayValue(Buf, Len, sprayValues[i])) {
            if (Value) *Value = sprayValues[i];
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*               解码 stub 检测                    */
/*  GetPC + XOR 解密循环组合 (简化)               */
/**************************************************/

static BOOLEAN
IocZd_HasDecoderStub(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    SIZE_T i;

    if (!IocZeroDay_HasGetPC(Buf, Len)) return FALSE;

    for (i = 0; i + 2 < Len; i++) {
        /* XOR [reg], imm8/reg 组合 */
        if ((Buf[i] == 0x80 && (Buf[i + 1] & 0x38) == 0x30) ||
            Buf[i] == 0x30 || Buf[i] == 0x31) {
            /* 附近循环跳转 */
            SIZE_T j;
            SIZE_T end = (i + 10 < Len) ? i + 10 : Len;
            for (j = i + 1; j < end; j++) {
                if (Buf[j] == 0xE2 || Buf[j] == 0x75) return TRUE;
            }
        }
    }
    return FALSE;
}

/**************************************************/
/*               ROP gadget 模式检测               */
/*  pop-ret (58-5F C3) / xchg esp (87 E0 C3)      */
/**************************************************/

static ULONG
IocZd_CountRopGadgets(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    ULONG count = 0;
    SIZE_T i;

    for (i = 0; i + 1 < Len; i++) {
        if ((Buf[i] >= 0x58 && Buf[i] <= 0x5F) && Buf[i + 1] == 0xC3) {
            count++;   /* pop reg; ret */
        }
        if (i + 2 < Len && Buf[i] == 0x87 && Buf[i + 1] == 0xE0 &&
            Buf[i + 2] == 0xC3) {
            count++;   /* xchg eax, esp; ret */
        }
    }
    return count;
}

/**************************************************/
/*               网络签名扫描                      */
/**************************************************/

static ULONG
IocZd_CountNetworkIndicators(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    static const char* netSigs[] = {
        "ws2_32", "wininet", "WinHttpOpen",
        "InternetOpen", "HttpSendReq",
    };
    ULONG count = 0;
    ULONG s;

    for (s = 0; s < (ULONG)(sizeof(netSigs) / sizeof(netSigs[0])); s++) {
        SIZE_T slen = strlen(netSigs[s]);
        SIZE_T i;
        if (slen == 0 || Len < slen) continue;
        for (i = 0; i + slen <= Len; i++) {
            if (memcmp(Buf + i, netSigs[s], slen) == 0) { count++; break; }
        }
    }
    return count;
}

/**************************************************/
/*               完整分析                          */
/**************************************************/

NTSTATUS
IocZeroDay_AnalyzeBuffer(
    _In_ const BYTE*        Buf,
    _In_ SIZE_T             Len,
    _Out_ PWKD_ZERO_DAY_RESULT Result
    )
{
    ULONG nopLen = 0;
    ULONG sprayValue = 0;
    int score = 0;

    if (!Buf || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    if (Len == 0) return STATUS_SUCCESS;

    Result->Entropy = IocZd_Entropy(Buf, Len);

    if (IocZeroDay_IsNopSled(Buf, Len, &nopLen)) {
        Result->HasNopSled = TRUE;
        Result->NopSledLength = nopLen;
        score += 25;
    }
    if (IocZeroDay_HasGetPC(Buf, Len)) {
        Result->HasGetPC = TRUE;
        score += 35;
    }
    if (IocZd_HasDecoderStub(Buf, Len)) {
        Result->HasDecoderStub = TRUE;
        Result->IsEncoded = TRUE;
        score += 40;
    }
    if (IocZeroDay_IsHeapSprayPattern(Buf, Len, &sprayValue)) {
        Result->IsHeapSpray = TRUE;
        Result->HeapSprayValue = sprayValue;
        score += 30;
    }
    if (Result->Entropy >= WKD_ZD_SHELLCODE_ENT_MIN &&
        Result->Entropy <= WKD_ZD_SHELLCODE_ENT_MAX) {
        score += 15;
    }

    Result->NetworkIndicators = IocZd_CountNetworkIndicators(Buf, Len);
    if (Result->NetworkIndicators > 0) score += 20;

    Result->RopGadgetCount = IocZd_CountRopGadgets(Buf, Len);
    if (Result->RopGadgetCount >= 5) score += 30;

    Result->Score = (score > 100) ? 100 : (ULONG)score;

    if (score >= 50) {
        Result->Detected = TRUE;
        if (Result->IsHeapSpray) {
            strcpy_s(Result->Description, sizeof(Result->Description), "Heap spray pattern");
        } else if (Result->HasDecoderStub) {
            strcpy_s(Result->Description, sizeof(Result->Description), "Encoded shellcode (decoder stub)");
        } else if (Result->HasGetPC) {
            strcpy_s(Result->Description, sizeof(Result->Description), "GetPC shellcode");
        } else {
            strcpy_s(Result->Description, sizeof(Result->Description), "Shellcode indicators");
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*   堆喷内容分析 (HeapSpray 迁移 2026-08)          */
/*                                                  */
/*  对齐 ShadowStrike HeapSpray.c 内容模式函数,      */
/*  按功能融合重实现非复制。                          */
/*  死代码: 供 IoaHeapSprayDetect 聚合消费,          */
/*  流水线未接入。                                   */
/**************************************************/

ULONG
IocZeroDay_CalculateRepetitionScore(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
/*++
Routine Description:
    重复度评分 — 主字节频率 (0-40) + 最长游程 (0-30) + 低多样性 (0-30)。
    对齐 SS HspCalculateRepetitionScore (HeapSpray.c L1931-2009)。
    评分越高说明内容越重复 (堆喷越可疑)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    重复度评分 [0,100]。
--*/
{
    ULONG byteCounts[256] = { 0 };
    ULONG maxCount = 0;
    ULONG runLength = 0;
    ULONG maxRunLength = 0;
    UCHAR lastByte = 0;
    ULONG i;
    ULONG score = 0;
    ULONG uniqueBytes = 0;

    if (!Buf || Len == 0) {
        return 0;
    }

    for (i = 0; i < Len; i++) {
        byteCounts[Buf[i]]++;

        if (i == 0 || Buf[i] == lastByte) {
            runLength++;
        } else {
            if (runLength > maxRunLength) {
                maxRunLength = runLength;
            }
            runLength = 1;
        }
        lastByte = Buf[i];
    }

    if (runLength > maxRunLength) {
        maxRunLength = runLength;
    }

    for (i = 0; i < 256; i++) {
        if (byteCounts[i] > maxCount) {
            maxCount = byteCounts[i];
        }
        if (byteCounts[i] > 0) {
            uniqueBytes++;
        }
    }

    /* 主字节频率 (0-40) */
    score += (maxCount * 40) / (ULONG)Len;

    /* 最长游程 (0-30) */
    score += (maxRunLength * 30) / (ULONG)Len;

    /* 低字节多样性 (0-30): 越少不同字节越高 */
    if (uniqueBytes < 16) {
        score += 30 - (uniqueBytes * 2);
    }

    return (score > 100) ? 100 : score;
}

BOOLEAN
IocZeroDay_ContainsNopSled(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
/*++
Routine Description:
    NOP 等价字节连续滑道检测。0x90/0x0C/0x0D/0x0A 视为 NOP 等价
    (0x0C0C/0x0D0D/0x0A0A 为常见堆喷着陆垫字节), 连续 ≥16 判定。
    对齐 SS HspContainsNopSled (HeapSpray.c L2466-2503)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    TRUE = 存在 NOP sled。
--*/
{
    ULONG consecutiveNops = 0;
    ULONG i;

    if (!Buf || Len == 0) {
        return FALSE;
    }

    for (i = 0; i < Len; i++) {
        if (Buf[i] == 0x90 || Buf[i] == 0x0C ||
            Buf[i] == 0x0D || Buf[i] == 0x0A) {
            consecutiveNops++;
        } else {
            consecutiveNops = 0;
        }

        if (consecutiveNops >= 16) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
IocZeroDay_IsKnownSprayPattern(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
/*++
Routine Description:
    已知堆喷模式 — 重复 DWORD 值表 (0x0C0C0C0C 等 11 值) 任一命中,
    或任意单字节 ≥90% 重复 (256 字节样本 90%+ 同一字节即喷样)。
    对齐 SS HspIsKnownSprayPattern (HeapSpray.c L2403-2460)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    TRUE = 命中已知堆喷模式。
--*/
{
    static const ULONG sprayValues[] = {
        0x0C0C0C0C, 0x0D0D0D0D, 0x0A0A0A0A,
        0x41414141, 0x42424242, 0x90909090,
        0x04040404, 0x06060606, 0x07070707, 0x08080808,
    };
    ULONG i;

    if (!Buf || Len < 4) {
        return FALSE;
    }

    for (i = 0; i + 3 < Len; i += 4) {
        ULONG dword;
        RtlCopyMemory(&dword, &Buf[i], sizeof(ULONG));
        if (dword == sprayValues[0] || dword == sprayValues[1] ||
            dword == sprayValues[2] || dword == sprayValues[3] ||
            dword == sprayValues[4] || dword == sprayValues[5] ||
            dword == sprayValues[6] || dword == sprayValues[7] ||
            dword == sprayValues[8] || dword == sprayValues[9]) {
            return TRUE;
        }
    }

    if (Len >= 16) {
        ULONG counts[256] = { 0 };
        for (i = 0; i < Len; i++) {
            counts[Buf[i]]++;
        }
        for (i = 0; i < 256; i++) {
            if (counts[i] * 100 / (ULONG)Len >= 90) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

WKD_HEAP_SPRAY_TYPE
IocZeroDay_DetectSprayType(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
/*++
Routine Description:
    堆喷类型分类。判定顺序 (对齐 SS HspDetectSprayType L2015-2154):
      NOP sled (>80% NOP/0x0C/0x0D) → JIT (0x3C909090 DWORD 掩码) →
      StringSpray (可打印 ASCII >90%) → BSTR (长度前缀 Unicode) →
      ObjectSpray (≥80% 字节呈现用户态指针)。
    HeapFeng/Array/TypedArray/Wasm 类型 SS 分类器本身不产出,
    枚举值保留兼容, 本函数不返回。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    WKD_HEAP_SPRAY_TYPE 分类结果。
--*/
{
    ULONG i;
    ULONG nopCount = 0;
    ULONG slide0CCount = 0;
    ULONG slide0DCount = 0;
    BOOLEAN hasJitPattern = FALSE;

    if (!Buf || Len < 4) {
        return WkdHeapSpray_Unknown;
    }

    for (i = 0; i < Len; i++) {
        if (Buf[i] == 0x90) {
            nopCount++;
        }
        if (Buf[i] == 0x0C) {
            slide0CCount++;
        }
        if (Buf[i] == 0x0D) {
            slide0DCount++;
        }
    }

    for (i = 0; i + 3 < Len; i += 4) {
        ULONG dword;
        RtlCopyMemory(&dword, &Buf[i], sizeof(ULONG));
        if ((dword & 0x00FFFFFF) == (0x3C909090 & 0x00FFFFFF)) {
            hasJitPattern = TRUE;
        }
    }

    if (nopCount > Len * 80 / 100) {
        return WkdHeapSpray_NopSled;
    }

    if (slide0CCount > Len * 80 / 100 ||
        slide0DCount > Len * 80 / 100) {
        return WkdHeapSpray_NopSled;
    }

    if (hasJitPattern) {
        return WkdHeapSpray_JitSpray;
    }

    {
        ULONG printableCount = 0;
        for (i = 0; i < Len; i++) {
            if (Buf[i] >= 0x20 && Buf[i] < 0x7F) {
                printableCount++;
            }
        }
        if (printableCount > Len * 90 / 100) {
            return WkdHeapSpray_StringSpray;
        }
    }

    /* BSTR 长度前缀 Unicode 字符串 (SS L2102-2127) */
    if (Len >= 8) {
        ULONG potentialLength;
        RtlCopyMemory(&potentialLength, Buf, sizeof(ULONG));
        if (potentialLength > 0 && potentialLength < 0x10000 &&
            potentialLength >= (Len - sizeof(ULONG)) / 2) {
            ULONG unicodeHits = 0;
            ULONG k;
            for (k = 4; k + 1 < Len; k += 2) {
                if (Buf[k] >= 0x20 && Buf[k] < 0x7F &&
                    Buf[k + 1] == 0x00) {
                    unicodeHits++;
                }
            }
            if (unicodeHits > (Len - 4) / 4) {
                return WkdHeapSpray_StringSpray;
            }
        }
    }

    /* Object spray — vtable 指针启发式 (SS L2136-2151) */
    {
        ULONG ptrCount = 0;
        if (Len >= sizeof(PVOID)) {
            for (i = 0; i + sizeof(PVOID) <= Len; i += sizeof(PVOID)) {
                ULONG_PTR ptr;
                RtlCopyMemory(&ptr, &Buf[i], sizeof(ULONG_PTR));
                if (ptr > 0x10000 && ptr <= WKD_HS_MAX_USER_ADDRESS) {
                    ptrCount++;
                }
            }
            if (ptrCount > (Len / sizeof(PVOID)) * 80 / 100) {
                return WkdHeapSpray_ObjectSpray;
            }
        }
    }

    return WkdHeapSpray_Unknown;
}

BOOLEAN
IocZeroDay_ContainsShellcodeSignatures(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
/*++
Routine Description:
    壳码签名检测。GetPC / API-hash / 直接 syscall 特征位复用
    IocDetectShellcode (活代码, 避免重复实现); 再补 SS 独有
    6 模式: JMP ESP / CALL ESP / PUSH ESP RET / FS:[0x30] /
    GS:[0x60] / x64 syscall stub / ROR-13 API hash。
    对齐 SS HspContainsShellcodeSignatures (HeapSpray.c L2509-2642)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    TRUE = 存在壳码签名。
--*/
{
    ULONG i;
    ULONG t1flags;

    if (!Buf || Len < 4) {
        return FALSE;
    }

    /* 复用 IocDetectShellcode: GETPC / APIHASH / SYSCALL (Size ≤256 安全) */
    t1flags = IocDetectShellcode(Buf, (ULONG)Len, FALSE);
    if (t1flags & (T1_SC_GETPC | T1_SC_APIHASH | T1_SC_SYSCALL)) {
        return TRUE;
    }

    for (i = 0; i + 1 < Len; i++) {
        /* GetPC (E8 00 00 00 00, 不要求 POP 跟随, SS L2536-2543) */
        if (i + 4 < Len &&
            Buf[i] == 0xE8 && Buf[i + 1] == 0x00 &&
            Buf[i + 2] == 0x00 && Buf[i + 3] == 0x00 &&
            Buf[i + 4] == 0x00) {
            return TRUE;
        }

        /* JMP ESP (FF E4) */
        if (Buf[i] == 0xFF && Buf[i + 1] == 0xE4) {
            return TRUE;
        }

        /* CALL ESP (FF D4) */
        if (Buf[i] == 0xFF && Buf[i + 1] == 0xD4) {
            return TRUE;
        }

        /* PUSH ESP; RET (54 C3) */
        if (Buf[i] == 0x54 && Buf[i + 1] == 0xC3) {
            return TRUE;
        }

        /* XOR decoder stub (SS L2570-2583): XOR reg,reg + 附近 loop/jmp) */
        if ((Buf[i] >= 0x30 && Buf[i] <= 0x33) &&
            (Buf[i + 1] & 0xC0) == 0xC0) {
            ULONG j;
            ULONG end = ((i + 20) < Len) ? ((ULONG)i + 20) : (ULONG)Len - 1;
            for (j = i + 2; j < end; j++) {
                if (Buf[j] == 0xE2 || Buf[j] == 0xEB ||
                    Buf[j] == 0x75 || Buf[j] == 0x74) {
                    return TRUE;
                }
            }
        }

        /* FS:[0x30] PEB 访问 (32 位壳码, 64 A1 30 00 00 00) */
        if (i + 5 < Len &&
            Buf[i] == 0x64 && Buf[i + 1] == 0xA1 &&
            Buf[i + 2] == 0x30 && Buf[i + 3] == 0x00 &&
            Buf[i + 4] == 0x00 && Buf[i + 5] == 0x00) {
            return TRUE;
        }

        /* GS:[0x60] PEB 访问 (64 位壳码, 65 48 8B 04 25 60 ...) */
        if (i + 8 < Len &&
            Buf[i] == 0x65 && Buf[i + 1] == 0x48 &&
            Buf[i + 2] == 0x8B && Buf[i + 3] == 0x04 &&
            Buf[i + 4] == 0x25 && Buf[i + 5] == 0x60) {
            return TRUE;
        }

        /* x64 syscall stub (4C 8B D1 B8 XX XX XX XX 0F 05, 直接 syscall 绕过 ntdll 钩子) */
        if (i + 9 < Len &&
            Buf[i] == 0x4C && Buf[i + 1] == 0x8B &&
            Buf[i + 2] == 0xD1 && Buf[i + 3] == 0xB8 &&
            Buf[i + 8] == 0x0F && Buf[i + 9] == 0x05) {
            return TRUE;
        }

        /* API hash ROR-13 解析 stub (C1 CA 0D) */
        if (i + 2 < Len &&
            Buf[i] == 0xC1 && Buf[i + 1] == 0xCA &&
            Buf[i + 2] == 0x0D) {
            return TRUE;
        }
    }

    return FALSE;
}
