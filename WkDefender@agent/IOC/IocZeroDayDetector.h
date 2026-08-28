/**************************************************/
/*  WkDefender IOC 引擎 — exploit 原语检测          */
/*  迁移自 ShadowStrike ZeroDayDetector (Stage 9)   */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  依赖缺失:                                       */
/*   - Capstone 反汇编 (完整 ROP 链/gadget 库)      */
/*   - PatternStore CVE 库 → 模式表内建            */
/**************************************************/

#pragma once

#include <windows.h>
#include "../DefendTypes.h"   /* WKD_HEAP_SPRAY_TYPE (HeapSpray 迁移 2026-08) */

/* x64 用户态地址上限 (对齐 SS MM_HIGHEST_USER_ADDRESS, 堆喷内容分析用) */
#define WKD_HS_MAX_USER_ADDRESS     ((ULONG_PTR)0x00007FFFFFFEFFFFULL)

/**************************************************/
/*               结构体声明                         */
/**************************************************/

typedef struct _WKD_ZERO_DAY_RESULT {
    BOOLEAN Detected;
    ULONG   Score;              /* 0-100 */
    CHAR    Description[128];

    BOOLEAN HasNopSled;
    ULONG   NopSledLength;
    BOOLEAN HasGetPC;
    BOOLEAN HasDecoderStub;
    BOOLEAN IsEncoded;
    BOOLEAN IsHeapSpray;
    ULONG   HeapSprayValue;

    double  Entropy;
    ULONG   NetworkIndicators;
    ULONG   RopGadgetCount;
} WKD_ZERO_DAY_RESULT, *PWKD_ZERO_DAY_RESULT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    检测连续 NOP sled (0x90-0x97)，长度阈值 16。

Arguments:
    Buf     - 数据缓冲。
    Len     - 长度。
    SledLen - 输出最长 NOP 串长度。

Return Value:
    TRUE = 存在 NOP sled。
--*/
BOOLEAN
IocZeroDay_IsNopSled(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_opt_ PULONG SledLen
    );

/*++
Routine Description:
    检测 GetPC 技巧 (E8 00 00 00 00 + POP reg / FNSTENV [ESP-0Ch])。

Arguments:
    Buf - 数据缓冲。
    Len - 长度。

Return Value:
    TRUE = 存在 GetPC。
--*/
BOOLEAN
IocZeroDay_HasGetPC(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );

/*++
Routine Description:
    检测堆喷模式 (重复的 0x0C0C0C0C 等值)。

Arguments:
    Buf   - 数据缓冲。
    Len   - 长度。
    Value - 输出检测到的堆喷值。

Return Value:
    TRUE = 疑似堆喷。
--*/
BOOLEAN
IocZeroDay_IsHeapSprayPattern(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_opt_ PULONG Value
    );

/*++
Routine Description:
    exploit 原语完整分析 (死代码主入口，未接入流水线)。
    NOP sled / GetPC / 解码 stub / 堆喷 / 熵 / 网络签名 / ROP gadget 模式，
    综合评分 >=50 判定 (对齐 SS DetectShellcodeInternal)。

Arguments:
    Buf    - 数据缓冲。
    Len    - 长度。
    Result - 输出分析结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocZeroDay_AnalyzeBuffer(
    _In_ const BYTE*        Buf,
    _In_ SIZE_T             Len,
    _Out_ PWKD_ZERO_DAY_RESULT Result
    );

/*++
Routine Description:
    堆喷内容分析 — 重复度评分 (0-100)。
    对齐 SS HspCalculateRepetitionScore (HeapSpray.c L1931-2009):
    主字节频率×40 + 最长游程×30 + 低多样性×30, cap 100。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    重复度评分 [0,100]。
--*/
ULONG
IocZeroDay_CalculateRepetitionScore(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );

/*++
Routine Description:
    NOP 等价字节连续滑道检测 (0x90/0x0C/0x0D/0x0A, ≥16 连续)。
    对齐 SS HspContainsNopSled (HeapSpray.c L2466-2503)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    TRUE = 存在 NOP sled。
--*/
BOOLEAN
IocZeroDay_ContainsNopSled(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );

/*++
Routine Description:
    已知堆喷模式检测 — 重复 DWORD 值表 (0x0C0C0C0C 等 11 值)
    + 任意单字节 ≥90% 重复。
    对齐 SS HspIsKnownSprayPattern (HeapSpray.c L2403-2460)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    TRUE = 命中已知堆喷模式。
--*/
BOOLEAN
IocZeroDay_IsKnownSprayPattern(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );

/*++
Routine Description:
    堆喷类型分类 — NopSled / JIT / StringSpray / BSTR / ObjectSpray。
    对齐 SS HspDetectSprayType (HeapSpray.c L2015-2154)。
    HeapFeng/Array/TypedArray/Wasm 类型 SS 分类器本身不产出,
    枚举值保留兼容, 本函数不返回。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    WKD_HEAP_SPRAY_TYPE 分类结果。
--*/
WKD_HEAP_SPRAY_TYPE
IocZeroDay_DetectSprayType(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );

/*++
Routine Description:
    壳码签名检测 — GetPC / API-hash / 直接 syscall 复用
    IocDetectShellcode; 补 SS 独有 6 模式 (JMP ESP / CALL ESP /
    PUSH ESP RET / FS:[0x30] / GS:[0x60] / x64 syscall stub / ROR-13)。
    对齐 SS HspContainsShellcodeSignatures (HeapSpray.c L2509-2642)。

Arguments:
    Buf - 内容缓冲。
    Len - 长度。

Return Value:
    TRUE = 存在壳码签名。
--*/
BOOLEAN
IocZeroDay_ContainsShellcodeSignatures(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );
