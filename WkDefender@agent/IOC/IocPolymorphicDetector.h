/**************************************************/
/*  WkDefender IOC 引擎 — 多态/变形检测 + 模糊哈希  */
/*  迁移自 ShadowStrike PolymorphicDetector +        */
/*  FuzzyHasher (Stage 6)                           */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  依赖缺失:                                       */
/*   - Capstone 反汇编 (指令替换/代码规范化)        */
/*   - TLSH 库 → TLSH 计算未集成 (SS 亦未实现)      */
/*  模糊哈希: 真 CTPH (SS FuzzyHasher) 已实现,       */
/*   委托 IocScanner_ComputeFuzzyHash/CompareFuzzyHash */
/**************************************************/

#pragma once

#include <windows.h>

/**************************************************/
/*               多态引擎类型                       */
/*  对齐 SS PolyEngineType                         */
/**************************************************/

typedef enum _WKD_POLY_ENGINE {
    WkdPolyEngine_Unknown = 0,
    WkdPolyEngine_MtE,              /* Mutation Engine */
    WkdPolyEngine_NED,              /* NuKE Encryption Device */
    WkdPolyEngine_DAME,             /* Dark Angel's Multiple Encryptor */
    WkdPolyEngine_VCL,              /* Virus Creation Lab */
    WkdPolyEngine_SMEG,
    WkdPolyEngine_TPE,
    WkdPolyEngine_Custom,
} WKD_POLY_ENGINE;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

typedef struct _WKD_POLY_RESULT {
    BOOLEAN             IsPolymorphic;
    ULONG               Confidence;      /* 0-100 */
    WKD_POLY_ENGINE     EngineType;
    BOOLEAN             HasXorLoop;
    ULONG               XorLoopOffset;
    BOOLEAN             IsMetamorphic;
    double              Entropy;
    ULONG               NopRatio;        /* NOP 占比 x100 (如 15=15%) */
    ULONG               AnalysisTimeMs;

    /* 模糊哈希 (CTPH "blockSize:sig1:sig2" 最大 109+1, 对齐 SS kMaxResultLength=148) */
    CHAR                FuzzyHash[128];
} WKD_POLY_RESULT, *PWKD_POLY_RESULT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    快速预检代码是否可能为多态/加密 (对齐 SS IsPotentiallyPolymorphic):
    熵>=6.5 / NOP 占比>15% / XOR 解密循环模式。

Arguments:
    Buf - 代码缓冲。
    Len - 长度。

Return Value:
    TRUE = 可能多态。
--*/
BOOLEAN
IocPoly_IsPotentiallyPolymorphic(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    );

/*++
Routine Description:
    多态/变形完整分析 (死代码主入口，未接入流水线)。
    熵 + XOR 解密循环 + 引擎签名 + 变形迹象 + 模糊哈希。

Arguments:
    Buf    - 代码缓冲。
    Len    - 长度。
    Result - 输出分析结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocPoly_AnalyzeBuffer(
    _In_ const BYTE*     Buf,
    _In_ SIZE_T          Len,
    _Out_ PWKD_POLY_RESULT Result
    );

/*++
Routine Description:
    XOR 解密循环检测 (对齐 SS DetectXORLoop)。
    XOR [reg], imm / XOR [reg], reg + 循环跳转 (E2/75)。

Arguments:
    Buf      - 代码缓冲。
    Len      - 长度。
    LoopOff  - 输出循环偏移。

Return Value:
    TRUE = 检测到 XOR 解密循环。
--*/
BOOLEAN
IocPoly_DetectXorLoop(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ PULONG      LoopOff
    );

/*++
Routine Description:
    计算模糊哈希 (委托 IocScanner_ComputeFuzzyHash, 真 CTPH)。
    输出 "blockSize:sig1:sig2" 格式。

Arguments:
    Buf     - 数据缓冲。
    Len     - 长度。
    Out     - 输出哈希串。
    OutSize - Out 缓冲大小。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocPoly_ComputeFuzzyHash(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ CHAR*       Out,
    _In_  ULONG       OutSize
    );

/*++
Routine Description:
    比较两个模糊哈希的相似度 (0-100, 委托 IocScanner_CompareFuzzyHash CTPH)。

Arguments:
    Hash1 - 哈希串 1。
    Hash2 - 哈希串 2。

Return Value:
    0-100 相似度。
--*/
ULONG
IocPoly_CompareFuzzyHash(
    _In_ PCSTR Hash1,
    _In_ PCSTR Hash2
    );
