/**************************************************/
/*  WkDefender IOC 引擎 — 多态/变形检测实现        */
/**************************************************/

#include "IocPolymorphicDetector.h"
#include "IocScanner.h"   /* IocScanner_ComputeFuzzyHash/CompareFuzzyHash (SS FuzzyHasher CTPH) */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <ntstatus.h>

/**************************************************/
/*               内部辅助                           */
/**************************************************/

static double
IocPoly_Entropy(
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
/*               XOR 解密循环检测                   */
/*  对齐 SS DetectXORLoop:                         */
/*   XOR byte ptr [reg+off], imm8  (80 /6)         */
/*   XOR dword ptr [reg+off], imm32 (81 /6)        */
/*   XOR [reg], reg                (30/31)         */
/*   后随循环跳转 E2 (loop) / 75 (jne)             */
/**************************************************/

BOOLEAN
IocPoly_DetectXorLoop(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ PULONG      LoopOff
    )
{
    SIZE_T i;

    if (!Buf || !LoopOff || Len < 8) return FALSE;
    *LoopOff = 0;

    for (i = 0; i + 4 < Len; i++) {
        BOOLEAN isXor = FALSE;

        /* XOR [mem], reg/imm 的 ModRM /6 (reg 字段 = 110b) */
        if ((Buf[i] == 0x80 || Buf[i] == 0x81) && (Buf[i + 1] & 0x38) == 0x30) {
            isXor = TRUE;
        } else if (Buf[i] == 0x30 || Buf[i] == 0x31) {
            /* XOR r/m8, r8 (30) / XOR r/m32, r32 (31) */
            isXor = TRUE;
        }

        if (isXor) {
            /* 附近寻找循环跳转: LOOP (E2), JNE (75) */
            SIZE_T j;
            SIZE_T lookEnd = (i + 10 < Len) ? i + 10 : Len;
            for (j = i + 1; j < lookEnd; j++) {
                if (Buf[j] == 0xE2 || Buf[j] == 0x75) {
                    *LoopOff = (ULONG)i;
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/**************************************************/
/*               引擎签名检测                       */
/*  对齐 SS DetectEngineInternal (部分)            */
/**************************************************/

static WKD_POLY_ENGINE
IocPoly_DetectEngine(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    /* NED: PUSH reg(0x50-0x57) + MOV reg, imm32 (B8+rd) + XOR [reg], key (30/31) */
    SIZE_T i;
    for (i = 0; i + 8 < Len; i++) {
        if (Buf[i] >= 0x50 && Buf[i] <= 0x57 &&          /* PUSH reg */
            Buf[i + 1] >= 0xB8 && Buf[i + 1] <= 0xBF &&  /* MOV reg, imm32 */
            (Buf[i + 6] == 0x30 || Buf[i + 6] == 0x31)) { /* XOR [reg], reg */
            return WkdPolyEngine_NED;
        }
    }
    return WkdPolyEngine_Unknown;
}

/**************************************************/
/*       模糊哈希 (SS FuzzyHasher CTPH)            */
/*  委托 IocScanner 真 CTPH 引擎                   */
/**************************************************/

NTSTATUS
IocPoly_ComputeFuzzyHash(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ CHAR*       Out,
    _In_  ULONG       OutSize
    )
{
    INT rc;

    if (!Buf || !Out || OutSize < 128) return STATUS_INVALID_PARAMETER;

    rc = IocScanner_ComputeFuzzyHash(Buf, Len, Out, OutSize);
    if (rc != 0) {
        Out[0] = '\0';
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

#pragma warning(push)
#pragma warning(disable:4505)   /* 未引用的局部函数 (死代码) */
/* 编辑距离 (Levenshtein, 死代码: 伪 CTPH 已由真 CTPH 委托取代, 不再被消费) */
static ULONG
IocPoly_EditDistance(
    _In_ PCSTR A,
    _In_ PCSTR B
    )
{
    SIZE_T la = strlen(A), lb = strlen(B);
    ULONG* dp;
    SIZE_T i, j;
    ULONG result;

    if (la == 0) return (ULONG)lb;
    if (lb == 0) return (ULONG)la;

    dp = (ULONG*)calloc((la + 1) * (lb + 1), sizeof(ULONG));
    if (!dp) return (ULONG)(la > lb ? la : lb);

    for (i = 0; i <= la; i++) dp[i * (lb + 1)] = (ULONG)i;
    for (j = 0; j <= lb; j++) dp[j] = (ULONG)j;

    for (i = 1; i <= la; i++) {
        for (j = 1; j <= lb; j++) {
            ULONG cost = (A[i - 1] == B[j - 1]) ? 0 : 1;
            ULONG del = dp[(i - 1) * (lb + 1) + j] + 1;
            ULONG ins = dp[i * (lb + 1) + (j - 1)] + 1;
            ULONG sub = dp[(i - 1) * (lb + 1) + (j - 1)] + cost;
            ULONG m = del < ins ? del : ins;
            dp[i * (lb + 1) + j] = m < sub ? m : sub;
        }
    }
    result = dp[la * (lb + 1) + lb];
    free(dp);
    return result;
}
#pragma warning(pop)

ULONG
IocPoly_CompareFuzzyHash(
    _In_ PCSTR Hash1,
    _In_ PCSTR Hash2
    )
{
    INT score;

    if (!Hash1 || !Hash2) return 0;
    score = IocScanner_CompareFuzzyHash(Hash1, Hash2);
    if (score < 0) return 0;
    return (ULONG)score;
}

/**************************************************/
/*               快速预检                           */
/**************************************************/

BOOLEAN
IocPoly_IsPotentiallyPolymorphic(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    ULONG nopCount = 0;
    ULONG checkLen;
    ULONG loopOff = 0;
    SIZE_T i;

    if (!Buf || Len < 32) return FALSE;

    /* 熵 >= 6.5 */
    if (IocPoly_Entropy(Buf, Len) >= 6.5) return TRUE;

    /* NOP 占比 > 15% (前 256 字节) */
    checkLen = (Len < 256) ? (ULONG)Len : 256;
    for (i = 0; i < checkLen; i++) {
        if (Buf[i] == 0x90) nopCount++;
    }
    if (nopCount * 100 / checkLen > 15) return TRUE;

    /* XOR 循环 */
    if (IocPoly_DetectXorLoop(Buf, Len, &loopOff)) return TRUE;

    return FALSE;
}

/**************************************************/
/*               完整分析                           */
/**************************************************/

NTSTATUS
IocPoly_AnalyzeBuffer(
    _In_ const BYTE*     Buf,
    _In_ SIZE_T          Len,
    _Out_ PWKD_POLY_RESULT Result
    )
{
    ULONG loopOff = 0;
    ULONG nopCount = 0;
    ULONG checkLen;
    ULONG confidence = 0;
    SIZE_T i;

    if (!Buf || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    if (Len < 32) return STATUS_SUCCESS;

    Result->Entropy = IocPoly_Entropy(Buf, Len);

    /* NOP 比例 */
    checkLen = (Len < 256) ? (ULONG)Len : 256;
    for (i = 0; i < checkLen; i++) {
        if (Buf[i] == 0x90) nopCount++;
    }
    Result->NopRatio = nopCount * 100 / checkLen;

    /* XOR 解密循环 */
    if (IocPoly_DetectXorLoop(Buf, Len, &loopOff)) {
        Result->HasXorLoop = TRUE;
        Result->XorLoopOffset = loopOff;
        confidence += 45;
    }

    /* 引擎签名 */
    Result->EngineType = IocPoly_DetectEngine(Buf, Len);
    if (Result->EngineType != WkdPolyEngine_Unknown) {
        confidence += 60;
    }

    /* 变形迹象: 高熵 + 大量短循环 */
    if (Result->Entropy >= 6.5) {
        confidence += 30;
    }
    if (Result->NopRatio > 15) {
        confidence += 20;
    }

    /* 模糊哈希 */
    IocPoly_ComputeFuzzyHash(Buf, Len, Result->FuzzyHash, sizeof(Result->FuzzyHash));

    Result->IsPolymorphic = (confidence >= 50);
    Result->Confidence = (confidence > 100) ? 100 : confidence;

    return STATUS_SUCCESS;
}
