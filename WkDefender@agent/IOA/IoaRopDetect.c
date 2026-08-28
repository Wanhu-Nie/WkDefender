/**************************************************/
/*  IoaRopDetect — ROP/JOP/COP/SROP 检测（agent）   */
/*  ShadowStrike ROPDetector 全量功能迁移 2026-08-07 */
/*  重功能实现非复制。字节模式路径（活代码）+        */
/*  地址驱动路径（gadget 库 + 栈分析, 死代码）。      */
/**************************************************/

#include "IoaRopDetect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ntstatus.h>

#include "../Memory/MemoryScan.h"          /* MsReadMemory/MsBuildModuleSet/MsIsAddrInModuleSet */
#include "../ProcessThreads.h"             /* WptGetThreadContext/WptGetThreadStackBounds */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"    /* 唯一公共入口 */

/**************************************************/
/*            寄存器位图 (对齐 SS REG_* L190-205)   */
/**************************************************/
#define WKD_ROP_REG_RAX   0x0001
#define WKD_ROP_REG_RCX   0x0002
#define WKD_ROP_REG_RDX   0x0004
#define WKD_ROP_REG_RBX   0x0008
#define WKD_ROP_REG_RSP   0x0010
#define WKD_ROP_REG_RBP   0x0020
#define WKD_ROP_REG_RSI   0x0040
#define WKD_ROP_REG_RDI   0x0080
#define WKD_ROP_REG_R8    0x0100
#define WKD_ROP_REG_R9    0x0200
#define WKD_ROP_REG_R10   0x0400
#define WKD_ROP_REG_R11   0x0800
#define WKD_ROP_REG_R12   0x1000
#define WKD_ROP_REG_R13   0x2000
#define WKD_ROP_REG_R14   0x4000
#define WKD_ROP_REG_R15   0x8000

/**************************************************/
/*  危险 gadget 模式表 (对齐 SS RoppInitializeDangerousPatterns 12 条) */
/**************************************************/
static const BYTE kRopXchgEsp32[]      = { 0x94 };
static const BYTE kRopXchgRsp64[]      = { 0x48, 0x94 };
static const BYTE kRopMovEspEax[]      = { 0x89, 0xC4 };
static const BYTE kRopMovRspRax[]      = { 0x48, 0x89, 0xC4 };
static const BYTE kRopLeaveRet[]       = { 0xC9, 0xC3 };
static const BYTE kRopPopRdiRet[]      = { 0x5F, 0xC3 };
static const BYTE kRopPopRsiRet[]      = { 0x5E, 0xC3 };
static const BYTE kRopPopRdxRet[]      = { 0x5A, 0xC3 };
static const BYTE kRopJmpRsp[]         = { 0xFF, 0xE4 };
static const BYTE kRopCallRsp[]        = { 0xFF, 0xD4 };
static const BYTE kRopAddRspImm8[]     = { 0x48, 0x83, 0xC4 };
static const BYTE kRopAddEspImm8[]     = { 0x83, 0xC4 };

static const WKD_ROP_DANGEROUS_PATTERN g_RopDangerousPatterns[] = {
    { kRopXchgEsp32,  sizeof(kRopXchgEsp32),  WkdRopGadget_Pivot, 50, "XCHG EAX,ESP" },
    { kRopXchgRsp64,  sizeof(kRopXchgRsp64),  WkdRopGadget_Pivot, 50, "REX.W XCHG RAX,RSP" },
    { kRopMovEspEax,  sizeof(kRopMovEspEax),  WkdRopGadget_Pivot, 50, "MOV ESP,EAX" },
    { kRopMovRspRax,  sizeof(kRopMovRspRax),  WkdRopGadget_Pivot, 50, "REX.W MOV RSP,RAX" },
    { kRopLeaveRet,   sizeof(kRopLeaveRet),   WkdRopGadget_Leave, 25, "LEAVE; RET" },
    { kRopPopRdiRet,  sizeof(kRopPopRdiRet),  WkdRopGadget_Arg,   15, "POP RDI; RET" },
    { kRopPopRsiRet,  sizeof(kRopPopRsiRet),  WkdRopGadget_Arg,   15, "POP RSI; RET" },
    { kRopPopRdxRet,  sizeof(kRopPopRdxRet),  WkdRopGadget_Arg,   15, "POP RDX; RET" },
    { kRopJmpRsp,     sizeof(kRopJmpRsp),     WkdRopGadget_Shell, 60, "JMP RSP" },
    { kRopCallRsp,    sizeof(kRopCallRsp),    WkdRopGadget_Shell, 60, "CALL RSP" },
    { kRopAddRspImm8, sizeof(kRopAddRspImm8), WkdRopGadget_Stack, 20, "ADD RSP,imm8" },
    { kRopAddEspImm8, sizeof(kRopAddEspImm8), WkdRopGadget_Stack, 20, "ADD ESP,imm8" },
};

/**************************************************/
/*               内部辅助                           */
/**************************************************/

//
// FNV-1a 地址哈希 (对齐 SS RoppHashAddress L1821)。
//
static
ULONG
IoaRopHashAddress(
    _In_ ULONG_PTR Address
    )
{
    ULONG_PTR addr = Address;
    ULONG hash = 2166136261;

    while (addr != 0) {
        hash ^= (ULONG)(addr & 0xFF);
        hash *= 16777619;
        addr >>= 8;
    }
    return hash;
}

//
// 解码 ModR/M+SIB+disp 指令后缀长度 (对齐 SS RoppDecodeModRMLength L2064)。
// 返回自 ModR/M 字节起的总长度; 0 = 非法。
//
static
ULONG
IoaRopDecodeModRMLength(
    _In_reads_(MaxSize) const BYTE* Bytes,
    _In_ ULONG MaxSize
    )
{
    UCHAR modrm, mod, rm;
    ULONG length = 1;

    if (MaxSize < 1) return 0;
    modrm = Bytes[0];
    mod = (modrm & 0xC0) >> 6;
    rm = modrm & 0x07;

    if (mod == 3) return 1;                    /* 寄存器直接, 无 SIB/disp */

    if (rm == 4) {                              /* SIB 字节 */
        length++;
        if (length > MaxSize) return 0;
    }
    if (mod == 0) {
        if (rm == 5) length += 4;               /* disp32 (RIP-relative) */
        if (rm == 4 && length >= 2) {
            UCHAR sib = Bytes[1];
            if ((sib & 0x07) == 5) length += 4; /* disp32 */
        }
    } else if (mod == 1) {
        length += 1;                            /* disp8 */
    } else if (mod == 2) {
        length += 4;                            /* disp32 */
    }

    if (length > MaxSize) return 0;
    return length;
}

//
// 分类潜在 gadget (对齐 SS RoppClassifyGadget L2136)。
// 完整解码 FF 前缀 JMP/CALL reg/mem (ModR/M+SIB+disp)。
//
static
WKD_ROP_GADGET_TYPE
IoaRopClassifyGadget(
    _In_reads_(Size) const BYTE* Bytes,
    _In_ ULONG Size,
    _Out_ PULONG GadgetSize
    )
{
    UCHAR opcode, modrm, reg, mod;
    ULONG modrmLen;

    if (Bytes == NULL || Size == 0 || GadgetSize == NULL) return WkdRopGadget_Unknown;
    *GadgetSize = 0;
    opcode = Bytes[0];

    if (opcode == 0xC3) { *GadgetSize = 1; return WkdRopGadget_Ret; }
    if (opcode == 0xC2 && Size >= 3) { *GadgetSize = 3; return WkdRopGadget_RetN; }
    if (opcode == 0x0F && Size >= 2 && Bytes[1] == 0x05) { *GadgetSize = 2; return WkdRopGadget_Syscall; } /* SYSCALL */
    if (opcode == 0x0F && Size >= 2 && Bytes[1] == 0x34) { *GadgetSize = 2; return WkdRopGadget_Syscall; } /* SYSENTER */
    if (opcode == 0xCD && Size >= 2) { *GadgetSize = 2; return WkdRopGadget_Int; }                        /* INT */

    if (opcode == 0xFF && Size >= 2) {
        modrm = Bytes[1];
        reg = (modrm & 0x38) >> 3;              /* FF /reg 字段 */
        mod = (modrm & 0xC0) >> 6;

        modrmLen = IoaRopDecodeModRMLength(Bytes + 1, Size - 1);
        if (modrmLen == 0) return WkdRopGadget_Unknown;
        *GadgetSize = 1 + modrmLen;             /* opcode + modrm+sib+disp */

        switch (reg) {
        case 2:  return (mod == 3) ? WkdRopGadget_CallReg : WkdRopGadget_CallMem; /* FF_CALL_REG=2 */
        case 3:  return WkdRopGadget_CallMem;                                     /* FF_CALL_MEM=3 (m16:32) */
        case 4:  return (mod == 3) ? WkdRopGadget_JmpReg : WkdRopGadget_JmpMem;   /* FF_JMP_REG=4 */
        case 5:  return WkdRopGadget_JmpMem;                                      /* FF_JMP_MEM=5 */
        default: return WkdRopGadget_Unknown;
        }
    }
    return WkdRopGadget_Unknown;
}

//
// gadget 语义分析 (对齐 SS RoppAnalyzeGadgetSemantics L2224):
// PUSH/POP/MOV/XCHG 的寄存器/内存/栈影响位图。
//
static
VOID
IoaRopAnalyzeGadgetSemantics(
    _Inout_ PWKD_ROP_GADGET Gadget
    )
{
    const BYTE* bytes;
    ULONG size, i;

    if (Gadget == NULL || Gadget->Size == 0) return;
    bytes = Gadget->Bytes;
    size = Gadget->Size;

    for (i = 0; i < size; i++) {
        UCHAR opcode = bytes[i];

        /* REX 前缀 (0x40-0x4F) 吞掉 */
        if (opcode >= 0x40 && opcode <= 0x4F && (i + 1 < size)) {
            i++;
            opcode = bytes[i];
        }

        if (opcode >= 0x50 && opcode <= 0x57) {
            /* PUSH r64: 读源寄存器, 改 RSP */
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= WKD_ROP_REG_RSP;
            Gadget->Semantics.RegistersRead |= (ULONG)(1 << (opcode - 0x50));
        } else if (opcode >= 0x58 && opcode <= 0x5F) {
            /* POP r64: 写目的寄存器, 改 RSP */
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= WKD_ROP_REG_RSP;
            Gadget->Semantics.RegistersModified |= (ULONG)(1 << (opcode - 0x58));
        } else if ((opcode == 0x89 || opcode == 0x8B) && (i + 1 < size)) {
            /* MOV r/m,r (0x89) / MOV r,r/m (0x8B) */
            UCHAR modrm = bytes[i + 1];
            if ((modrm & 0xC0) != 0xC0) {
                if (opcode == 0x89) Gadget->Semantics.WritesMemory = TRUE;
                else                Gadget->Semantics.ReadsMemory = TRUE;
            } else {
                UCHAR rm = modrm & 0x07;
                UCHAR reg = (modrm & 0x38) >> 3;
                if (opcode == 0x89 && rm == 4) {
                    /* MOV RSP,reg — stack pivot */
                    Gadget->Semantics.ModifiesStack = TRUE;
                    Gadget->Semantics.RegistersModified |= WKD_ROP_REG_RSP;
                } else if (opcode == 0x8B && reg == 4) {
                    Gadget->Semantics.RegistersRead |= WKD_ROP_REG_RSP;
                }
            }
            i++;  /* 跳过 ModR/M */
        } else if (opcode == 0x94) {
            /* XCHG rAX,rSP — stack pivot */
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= (WKD_ROP_REG_RAX | WKD_ROP_REG_RSP);
        } else if (opcode == 0xC3 || opcode == 0xC2 || opcode == 0xCB || opcode == 0xCA) {
            break;  /* RET/RETN/RETF/RETF imm16 — 终止 */
        }
    }
}

//
// gadget 危险度评分 (对齐 SS RoppCalculateDangerScore L2333), cap 100。
//
static
ULONG
IoaRopCalculateDangerScore(
    _In_ PWKD_ROP_DETECTOR Detector,
    _Inout_ PWKD_ROP_GADGET Gadget
    )
{
    ULONG score = 0;
    ULONG i;

    if (Gadget == NULL) return 0;
    UNREFERENCED_PARAMETER(Detector);   /* 危险模式表为全局, 对齐 SS DangerousPatterns 成员语义 */

    switch (Gadget->Type) {
    case WkdRopGadget_Syscall:
        score += 80;
        Gadget->IsPrivileged = TRUE;
        break;
    case WkdRopGadget_Ret:
    case WkdRopGadget_RetN:
        score += 10;
        break;
    case WkdRopGadget_JmpReg:
    case WkdRopGadget_CallReg:
        score += 30;
        Gadget->CouldBypassCFG = TRUE;
        break;
    case WkdRopGadget_JmpMem:
    case WkdRopGadget_CallMem:
        score += 40;
        break;
    case WkdRopGadget_Int:
        score += 50;
        break;
    default:
        break;
    }

    if (Gadget->Semantics.ModifiesStack) score += 20;
    if (Gadget->Semantics.WritesMemory) score += 15;
    if (Gadget->Semantics.RegistersModified & WKD_ROP_REG_RSP) score += 40;

    /* 危险模式命中加分 (对齐 SS DangerousPatterns 循环 L2382) */
    for (i = 0; i < RTL_NUMBER_OF(g_RopDangerousPatterns); i++) {
        if (Gadget->Size >= g_RopDangerousPatterns[i].Length &&
            memcmp(Gadget->Bytes, g_RopDangerousPatterns[i].Bytes,
                   g_RopDangerousPatterns[i].Length) == 0) {
            score += g_RopDangerousPatterns[i].DangerScore;
        }
    }

    return (score > 100) ? 100 : score;
}

//
// 速率限制 (对齐 SS RoppCheckRateLimit L3398): 1s 窗口计数。
//
static
BOOLEAN
IoaRopCheckRateLimit(
    _In_ PWKD_ROP_DETECTOR Detector
    )
{
    ULONG64 now = GetTickCount64();
    LONG64 count;

    if (now - Detector->LastResetTime >= 1000) {
        Detector->LastResetTime = now;
        InterlockedExchange64(&Detector->AnalysisCount, 0);
    }
    count = InterlockedIncrement64(&Detector->AnalysisCount);
    return (count <= (LONG64)Detector->MaxAnalysesPerSecond);
}

//
// 栈 pivot 检测 (对齐 SS RoppDetectStackPivot L3023): SP 越出 [StackLimit, StackBase]。
//
static
BOOLEAN
IoaRopDetectStackPivot(
    _In_ ULONG_PTR CurrentSp,
    _In_ ULONG_PTR StackBase,
    _In_ ULONG_PTR StackLimit,
    _Out_opt_ ULONG_PTR* PivotSource,
    _Out_opt_ ULONG_PTR* PivotDestination
    )
{
    if (CurrentSp == 0 || StackBase == 0) return FALSE;
    if (StackLimit != 0 && (CurrentSp < StackLimit || CurrentSp > StackBase)) {
        if (PivotSource != NULL) *PivotSource = StackBase;
        if (PivotDestination != NULL) *PivotDestination = CurrentSp;
        return TRUE;
    }
    return FALSE;
}

//
// 模块分布统计登记 (对齐 SS ROP_DETECTION_RESULT.ModuleBreakdown; SS 字段未填充, agent 补)。
//
static
VOID
IoaRopRecordModuleBreakdown(
    _Inout_ PWKD_ROP_DETECTION_RESULT Result,
    _In_ ULONG_PTR ModuleBase,
    _In_opt_ PCWSTR Name
    )
{
    ULONG i;

    for (i = 0; i < Result->ModulesUsed; i++) {
        if (Result->ModuleBreakdown[i].ModuleBase == ModuleBase) {
            Result->ModuleBreakdown[i].GadgetCount++;
            return;
        }
    }
    if (Result->ModulesUsed < WKD_ROP_MAX_MODULE_BREAKDOWN) {
        PWKD_ROP_MODULE_BREAKDOWN b = &Result->ModuleBreakdown[Result->ModulesUsed];
        b->ModuleBase = ModuleBase;
        if (Name != NULL) {
            wcsncpy_s(b->Name, RTL_NUMBER_OF(b->Name), Name, _TRUNCATE);
        }
        b->GadgetCount = 1;
        Result->ModulesUsed++;
    }
}

//
// 攻击分类 (对齐 SS RoppClassifyAttack L3060): 链条目 gadget 类型计数。
// StackPivot 优先 → syscall→SROP → ROP/JOP/COP → Mixed。
//
static
WKD_ROP_ATTACK_TYPE
IoaRopClassifyChain(
    _In_ PWKD_ROP_DETECTION_RESULT Result
    )
{
    ULONG ret = 0, jmp = 0, call = 0, syscall = 0, i;

    if (Result == NULL || !Result->ChainDetected) return WkdRopAttack_Unknown;

    for (i = 0; i < Result->ChainLength; i++) {
        switch (Result->ChainEntries[i].GadgetType) {
        case WkdRopGadget_Ret:
        case WkdRopGadget_RetN:
            ret++;
            break;
        case WkdRopGadget_JmpReg:
        case WkdRopGadget_JmpMem:
            jmp++;
            break;
        case WkdRopGadget_CallReg:
        case WkdRopGadget_CallMem:
            call++;
            break;
        case WkdRopGadget_Syscall:
            syscall++;
            break;
        default:
            break;
        }
    }

    if (Result->StackPivotDetected) return WkdRopAttack_StackPivot;
    if (syscall > 0) return WkdRopAttack_SROP;
    if (ret > jmp && ret > call) return WkdRopAttack_ROP;
    if (jmp > ret && jmp > call) return WkdRopAttack_JOP;
    if (call > ret && call > jmp) return WkdRopAttack_COP;
    if (ret > 0 && (jmp > 0 || call > 0)) return WkdRopAttack_Mixed;
    return WkdRopAttack_ROP;
}

//
// 置信度/严重度评分 (对齐 SS RoppCalculateConfidence L3132):
// 链长≥10/5/3→90/70/50 + pivot+20; 危险 gadget 平均分→severity; privileged→≥80;
// dangerScore≥50 gadget≥3→+20; SROP→≥90 / StackPivot→≥80。
//
static
VOID
IoaRopScoreChain(
    _Inout_ PWKD_ROP_DETECTION_RESULT Result
    )
{
    ULONG confidence = 0, severity = 0, dangerousGadgets = 0, totalDangerScore = 0, i;

    if (Result == NULL || !Result->ChainDetected) {
        if (Result != NULL) { Result->ConfidenceScore = 0; Result->SeverityScore = 0; }
        return;
    }

    if (Result->ChainLength >= 10) {
        confidence = 90;
    } else if (Result->ChainLength >= 5) {
        confidence = 70;
    } else if (Result->ChainLength >= 3) {
        confidence = 50;
    }
    if (Result->StackPivotDetected) confidence = min(100, confidence + 20);

    for (i = 0; i < Result->ChainLength; i++) {
        const WKD_ROP_CHAIN_ENTRY* ce = &Result->ChainEntries[i];
        totalDangerScore += ce->GadgetDangerScore;
        if (ce->GadgetDangerScore >= 50) dangerousGadgets++;
        if (ce->GadgetIsPrivileged) severity = max(severity, 80);
    }
    if (Result->ChainLength > 0) severity = max(severity, totalDangerScore / Result->ChainLength);
    if (dangerousGadgets >= 3) severity = min(100, severity + 20);

    switch (Result->AttackType) {
    case WkdRopAttack_SROP:
        severity = max(severity, 90);
        break;
    case WkdRopAttack_StackPivot:
        severity = max(severity, 80);
        break;
    default:
        break;
    }

    Result->ConfidenceScore = min(confidence, 100);
    Result->SeverityScore = min(severity, 100);
}

//
// 载荷推断 (对齐 SS RoppInferPayload L3206):
// 寄存器位图 RCX/RDX/R8/R9 ≥3 → 多参 API 调用; REG_RSP → pivot; Syscall → 直调链。
//
static
VOID
IoaRopInferChainPayload(
    _Inout_ PWKD_ROP_DETECTION_RESULT Result
    )
{
    BOOLEAN hasSyscall = FALSE, hasStackPivot = FALSE, hasMultiArgSetup = FALSE;
    ULONG argRegistersSet = 0, argCount = 0, i;

    if (Result == NULL || !Result->ChainDetected) return;
    Result->PayloadAnalysis.PayloadInferred = FALSE;

    for (i = 0; i < Result->ChainLength; i++) {
        const WKD_ROP_CHAIN_ENTRY* ce = &Result->ChainEntries[i];
        if (ce->GadgetType == WkdRopGadget_Syscall) hasSyscall = TRUE;
        if (ce->GadgetRegistersModified & WKD_ROP_REG_RSP) hasStackPivot = TRUE;
        if (ce->GadgetRegistersModified & WKD_ROP_REG_RCX) argRegistersSet |= WKD_ROP_REG_RCX;
        if (ce->GadgetRegistersModified & WKD_ROP_REG_RDX) argRegistersSet |= WKD_ROP_REG_RDX;
        if (ce->GadgetRegistersModified & WKD_ROP_REG_R8)  argRegistersSet |= WKD_ROP_REG_R8;
        if (ce->GadgetRegistersModified & WKD_ROP_REG_R9)  argRegistersSet |= WKD_ROP_REG_R9;
    }
    if (argRegistersSet & WKD_ROP_REG_RCX) argCount++;
    if (argRegistersSet & WKD_ROP_REG_RDX) argCount++;
    if (argRegistersSet & WKD_ROP_REG_R8)  argCount++;
    if (argRegistersSet & WKD_ROP_REG_R9)  argCount++;
    if (argCount >= 3) hasMultiArgSetup = TRUE;

    Result->PayloadAnalysis.PayloadInferred = TRUE;

    if (hasSyscall) {
        strcpy_s(Result->PayloadAnalysis.Description,
                 sizeof(Result->PayloadAnalysis.Description),
                 "Direct syscall chain - likely attempting to bypass security hooks");
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
        Result->PayloadAnalysis.MayDisableDefenses = TRUE;
        Result->PayloadAnalysis.MayEscalatePrivileges = TRUE;
    } else if (hasStackPivot && hasMultiArgSetup) {
        strcpy_s(Result->PayloadAnalysis.Description,
                 sizeof(Result->PayloadAnalysis.Description),
                 "Stack pivot with API argument setup - likely VirtualProtect/VirtualAlloc for shellcode");
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
        Result->PayloadAnalysis.MayDisableDefenses = TRUE;
    } else if (hasMultiArgSetup) {
        strcpy_s(Result->PayloadAnalysis.Description,
                 sizeof(Result->PayloadAnalysis.Description),
                 "Multi-argument API call chain - possible memory manipulation (VirtualProtect/VirtualAlloc)");
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    } else if (hasStackPivot) {
        strcpy_s(Result->PayloadAnalysis.Description,
                 sizeof(Result->PayloadAnalysis.Description),
                 "Stack pivot detected - execution flow hijacked to attacker-controlled memory");
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    } else {
        strcpy_s(Result->PayloadAnalysis.Description,
                 sizeof(Result->PayloadAnalysis.Description),
                 "Generic ROP chain - purpose unclear, potential code execution");
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    }
}

//
// 链检测 (对齐 SS RoppDetectChain L2912): 栈槽值 → 可执行模块判定 (MsIsAddrInModuleSet)
// → gadget 库查找 → 连续链 ≥MinChainLength。
//
static
NTSTATUS
IoaRopDetectChain(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ const ULONG_PTR* StackBuffer,
    _In_ SIZE_T SlotCount,
    _In_ const WKD_MEM_MODULE_SET* Modules,
    _Inout_ PWKD_ROP_DETECTION_RESULT Result
    )
{
    SIZE_T i;
    ULONG consecutiveGadgets = 0, totalGadgets = 0;

    for (i = 0; i < SlotCount; i++) {
        ULONG_PTR value = StackBuffer[i];
        WKD_ROP_GADGET gadgetCopy;
        NTSTATUS st;

        if (value < 0x10000 || value == (ULONG_PTR)-1) {
            consecutiveGadgets = 0;
            continue;
        }
        /* 非可执行模块地址: 重置 (SS NonExecutableAddresses) */
        if (!MsIsAddrInModuleSet(Modules, value)) {
            consecutiveGadgets = 0;
            continue;
        }
        st = IoaRop_LookupGadget(Detector, value, &gadgetCopy);
        if (NT_SUCCESS(st)) {
            ULONG idx = Result->ChainLength;
            consecutiveGadgets++;
            totalGadgets++;
            if (idx < WKD_ROP_MAX_CHAIN_LENGTH) {
                WKD_ROP_CHAIN_ENTRY* ce = &Result->ChainEntries[idx];
                ULONG m;
                PCWSTR mname = NULL;

                ce->GadgetAddress = value;
                ce->GadgetType = gadgetCopy.Type;
                ce->GadgetSize = gadgetCopy.Size;
                ce->GadgetDangerScore = gadgetCopy.DangerScore;
                ce->GadgetIsPrivileged = gadgetCopy.IsPrivileged;
                ce->GadgetRegistersModified = gadgetCopy.Semantics.RegistersModified;
                ce->StackOffset = i * sizeof(ULONG_PTR);
                ce->StackValue = value;
                ce->Index = idx;
                Result->ChainLength++;

                for (m = 0; m < Detector->ScannedActiveModules; m++) {
                    if (Detector->ScannedModules[m].ModuleBase == gadgetCopy.ModuleBase) {
                        mname = Detector->ScannedModules[m].ModuleName;
                        break;
                    }
                }
                IoaRopRecordModuleBreakdown(Result, gadgetCopy.ModuleBase, mname);
            }
        } else {
            /* 可执行但不在库: 合法返回地址或未索引 gadget, 打断链 */
            Result->UnknownGadgets++;
            consecutiveGadgets = 0;
        }

        if (consecutiveGadgets >= Detector->Config.MinChainLength) {
            Result->ChainDetected = TRUE;
        }
        if (Result->ChainLength >= Detector->Config.MaxChainLength) break;
    }

    Result->UniqueGadgets = totalGadgets;
    return STATUS_SUCCESS;
}

/**************************************************/
/*            字节模式路径 (活代码, 保留)           */
/**************************************************/

_Use_decl_annotations_
BOOL
IoaRop_DetectGadgetPattern(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_opt_ const WKD_ROP_DANGEROUS_PATTERN** Pattern,
    _Out_opt_ PULONG Offset
    )
/*++
Routine Description:
    在缓冲中查找首个危险 gadget 字节模式。
--*/
{
    ULONG p;
    ULONG i;

    if (Buffer == NULL || Size == 0) return FALSE;

    for (p = 0; p < RTL_NUMBER_OF(g_RopDangerousPatterns); p++) {
        const WKD_ROP_DANGEROUS_PATTERN* pat = &g_RopDangerousPatterns[p];
        for (i = 0; i + pat->Length <= Size; i++) {
            if (memcmp(&Buffer[i], pat->Bytes, pat->Length) == 0) {
                if (Pattern != NULL) *Pattern = pat;
                if (Offset != NULL) *Offset = i;
                return TRUE;
            }
        }
    }
    return FALSE;
}

_Use_decl_annotations_
WKD_ROP_ATTACK_TYPE
IoaRop_ClassifyAttack(
    _Inout_ PWKD_ROP_ANALYSIS_RESULT Result
    )
/*++
Routine Description:
    攻击分类（对齐 SS RoppClassifyAttack L3062）：syscall→SROP；
    RET 多→ROP；JMP 多→JOP；CALL 多→COP；混合→Mixed。
--*/
{
    if (Result == NULL) return WkdRopAttack_Unknown;
    if (!Result->ChainDetected) return WkdRopAttack_Unknown;

    if (Result->SyscallCount > 0) {
        Result->AttackType = WkdRopAttack_SROP;
    } else if (Result->RetCount > Result->JmpCount && Result->RetCount > Result->CallCount) {
        Result->AttackType = WkdRopAttack_ROP;
    } else if (Result->JmpCount > Result->RetCount && Result->JmpCount > Result->CallCount) {
        Result->AttackType = WkdRopAttack_JOP;
    } else if (Result->CallCount > Result->RetCount && Result->CallCount > Result->JmpCount) {
        Result->AttackType = WkdRopAttack_COP;
    } else if (Result->RetCount > 0 && (Result->JmpCount > 0 || Result->CallCount > 0)) {
        Result->AttackType = WkdRopAttack_Mixed;
    } else {
        Result->AttackType = WkdRopAttack_ROP;
    }
    return Result->AttackType;
}

_Use_decl_annotations_
VOID
IoaRop_CalculateConfidence(
    _Inout_ PWKD_ROP_ANALYSIS_RESULT Result
    )
/*++
Routine Description:
    置信度/严重度评分：链长≥10→90 / ≥5→70 / ≥3→50；SROP→严重度 90。
--*/
{
    ULONG confidence = 0;
    ULONG severity = 0;

    if (Result == NULL || !Result->ChainDetected) {
        if (Result != NULL) {
            Result->ConfidenceScore = 0;
            Result->SeverityScore = 0;
        }
        return;
    }

    if (Result->MaxConsecutiveRet >= 10) {
        confidence = 90;
    } else if (Result->MaxConsecutiveRet >= 5) {
        confidence = 70;
    } else if (Result->MaxConsecutiveRet >= 3) {
        confidence = 50;
    }

    if (Result->GadgetCount >= 3) {
        severity = 80;
    } else if (Result->GadgetCount >= 1) {
        severity = 60;
    }

    switch (Result->AttackType) {
    case WkdRopAttack_SROP:
        severity = (severity < 90) ? 90 : severity;
        break;
    case WkdRopAttack_StackPivot:
        severity = (severity < 80) ? 80 : severity;
        break;
    default:
        break;
    }

    Result->ConfidenceScore = (confidence > 100) ? 100 : confidence;
    Result->SeverityScore = (severity > 100) ? 100 : severity;
}

_Use_decl_annotations_
VOID
IoaRop_InferPayload(
    _Inout_ PWKD_ROP_ANALYSIS_RESULT Result
    )
/*++
Routine Description:
    载荷推断：有 syscall → 直接系统调用链；危险 gadget≥2 → 参数设置链。
--*/
{
    if (Result == NULL || !Result->ChainDetected) return;

    Result->PayloadInferred = FALSE;
    Result->PayloadDescription[0] = '\0';

    if (Result->SyscallCount > 0) {
        strcpy_s(Result->PayloadDescription, sizeof(Result->PayloadDescription),
                 "Direct syscall chain - likely bypassing hooks");
        Result->PayloadInferred = TRUE;
    }

    if (Result->GadgetCount >= 2 && Result->PayloadDescription[0] == '\0') {
        strcpy_s(Result->PayloadDescription, sizeof(Result->PayloadDescription),
                 "VirtualProtect/VirtualAlloc for shellcode");
        Result->PayloadInferred = TRUE;
    }

    if (!Result->PayloadInferred) {
        strcpy_s(Result->PayloadDescription, sizeof(Result->PayloadDescription),
                 "Generic ROP chain");
        Result->PayloadInferred = TRUE;
    }
}

_Use_decl_annotations_
BOOL
IoaRop_AnalyzeBuffer(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_ROP_ANALYSIS_RESULT Result
    )
/*++
Routine Description:
    缓冲 ROP 分析（字节模式，活代码）：
      1. 危险 gadget 模式搜索 → GadgetCount
      2. RET/RETN 连续段 → MaxConsecutiveRet
      3. JMP/CALL/SYSCALL 计数
      4. 链判定 → 分类 → 评分 → 载荷推断
    与地址驱动版（IoaRop_AnalyzeStackBuffer）互补：本函数无需 gadget 库。
--*/
{
    ULONG i;
    ULONG consecutiveRet = 0;

    if (Buffer == NULL || Size == 0 || Result == NULL) return FALSE;
    RtlZeroMemory(Result, sizeof(*Result));

    /* 1. 危险 gadget 模式命中计数 */
    for (i = 0; i < Size; i++) {
        const WKD_ROP_DANGEROUS_PATTERN* pat = NULL;
        ULONG off = 0;
        if (IoaRop_DetectGadgetPattern(&Buffer[i], Size - i, &pat, &off)) {
            Result->GadgetCount++;
            i += off + pat->Length - 1;
        }
    }

    /* 2. RET/RETN 连续段 + JMP/CALL/SYSCALL 计数 */
    for (i = 0; i < Size; i++) {
        if (Buffer[i] == 0xC3 || Buffer[i] == 0xC2) {
            consecutiveRet++;
            if (consecutiveRet > Result->MaxConsecutiveRet) {
                Result->MaxConsecutiveRet = consecutiveRet;
            }
            Result->RetCount++;
        } else {
            consecutiveRet = 0;
        }

        /* JMP reg (FF E0-E7) */
        if (Buffer[i] == 0xFF && i + 1 < Size &&
            (Buffer[i + 1] >= 0xE0 && Buffer[i + 1] <= 0xE7)) {
            Result->JmpCount++;
        }
        /* CALL reg (FF D0-D7) */
        if (Buffer[i] == 0xFF && i + 1 < Size &&
            (Buffer[i + 1] >= 0xD0 && Buffer[i + 1] <= 0xD7)) {
            Result->CallCount++;
        }
        /* SYSCALL (0F 05) / SYSENTER (0F 34) / INT 2E (CD 2E) */
        if (i + 1 < Size &&
            ((Buffer[i] == 0x0F && (Buffer[i + 1] == 0x05 || Buffer[i + 1] == 0x34)) ||
             (Buffer[i] == 0xCD && Buffer[i + 1] == 0x2E))) {
            Result->SyscallCount++;
        }
    }

    /* 3. 链判定（对齐 SS MinChainLength=3） */
    if (Result->MaxConsecutiveRet >= 3 || Result->GadgetCount >= 3) {
        Result->ChainDetected = TRUE;
    }

    if (!Result->ChainDetected) {
        return FALSE;
    }

    /* 4. 分类 + 评分 + 载荷推断 */
    IoaRop_ClassifyAttack(Result);
    IoaRop_CalculateConfidence(Result);
    IoaRop_InferPayload(Result);

    return TRUE;
}

/**************************************************/
/*          地址驱动路径 (死代码, 对齐 SS)         */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IoaRop_Initialize(
    _Inout_ PWKD_ROP_DETECTOR Detector
    )
/*++
Routine Description:
    初始化 ROP 检测器状态（对齐 SS RopInitialize L553）。
    Detector 须调用方堆分配（约 500KB+）。初始化锁/配置/统计/速率限制。
--*/
{
    ULONG i;

    if (Detector == NULL) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Detector, sizeof(*Detector));
    Detector->Signature = WKD_ROP_DETECTOR_SIGNATURE;
    InitializeCriticalSection(&Detector->GadgetLock);
    InitializeCriticalSection(&Detector->ModuleLock);

    for (i = 0; i < WKD_ROP_GADGET_HASH_BUCKETS; i++) {
        Detector->GadgetHashCount[i] = 0;
    }

    Detector->Config.MinChainLength = WKD_ROP_MIN_CHAIN_LENGTH;
    Detector->Config.MaxChainLength = WKD_ROP_MAX_CHAIN_LENGTH;
    Detector->Config.ConfidenceThreshold = 50;
    Detector->Config.ScanSystemModules = TRUE;
    Detector->Config.EnableSemanticAnalysis = TRUE;

    Detector->MaxAnalysesPerSecond = 1000;
    Detector->LastResetTime = GetTickCount64();
    Detector->Stats.StartTime = GetTickCount64();

    Detector->Initialized = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
IoaRop_Shutdown(
    _Inout_ PWKD_ROP_DETECTOR Detector
    )
/*++
Routine Description:
    关闭检测器，释放锁资源（对齐 SS RopShutdown L701）。
--*/
{
    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE) return;
    if (!Detector->Initialized) return;

    Detector->Initialized = FALSE;
    DeleteCriticalSection(&Detector->GadgetLock);
    DeleteCriticalSection(&Detector->ModuleLock);
    Detector->Signature = 0;
}

_Use_decl_annotations_
NTSTATUS
IoaRop_ScanModuleForGadgets(
    _Inout_ PWKD_ROP_DETECTOR Detector,
    _In_ ULONG_PTR ModuleBase,
    _In_ const BYTE* ModuleData,
    _In_ SIZE_T ModuleSize,
    _In_opt_ PCWSTR ModuleName
    )
/*++
Routine Description:
    扫描模块内存镜像的可执行节构建 gadget 库（对齐 SS RopScanModuleForGadgets L816）。
    ModuleData 须为模块内存镜像 buffer（节数据按 VirtualAddress 布局，对齐 SS
    ModuleBase+sectionVa 扫模块内存）；ModuleBase 为加载基址（栈槽值匹配）。
    未来调用方可用 MsReadMemory 读整个 SizeOfImage 得到镜像。
    PE 校验/节表复用 IocpAnalyzeBufferEx（替代 RoppValidatePeHeaders L1945）。
    模块去重按 ModuleBase 线性查（替代 RoppIsModuleAlreadyScanned L2022）。
    ※ 死代码：模块全量扫描成本高（每模块 ≤4096 gadget），触发点=栈事件源接入时预构建库。
--*/
{
    NTSTATUS status;
    PPE_PARSER_CONTEXT pctx = NULL;
    ULONG sectionIndex, offset, gadgetCount = 0;
    ULONG i;

    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || ModuleData == NULL || ModuleSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < Detector->ScannedActiveModules; i++) {
        if (Detector->ScannedModules[i].ModuleBase == ModuleBase) return STATUS_OBJECTID_EXISTS;
    }

    pctx = (PPE_PARSER_CONTEXT)malloc(sizeof(PE_PARSER_CONTEXT));
    if (pctx == NULL) return STATUS_NO_MEMORY;
    WpeResetParseContext(pctx);
    status = WpeParseBufferContext(pctx, ModuleData, ModuleSize, FALSE);
    if (!NT_SUCCESS(status) || !pctx->Info.Valid) {
        free(pctx);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    for (sectionIndex = 0; sectionIndex < pctx->Info.NumberOfSections; sectionIndex++) {
        const PE_SECTION* sec = &pctx->Info.Sections[sectionIndex];
        ULONG va, vs;

        if (!sec->IsExecutable) continue;
        va = sec->VirtualAddress;
        vs = sec->VirtualSize;
        if (va >= ModuleSize || vs == 0 || va + vs > ModuleSize || va + vs < va) continue;

        for (offset = 0; offset < vs; offset++) {
            WKD_ROP_GADGET_TYPE type;
            ULONG gadgetSize = 0;
            ULONG backScan, maxBackScan;

            type = IoaRopClassifyGadget(ModuleData + va + offset, vs - offset, &gadgetSize);
            if (type == WkdRopGadget_Unknown || gadgetSize == 0) continue;

            /* 回溯构建 2-16 字节 gadget（对齐 SS L959-983） */
            maxBackScan = min(WKD_ROP_GADGET_MAX_SIZE, offset);
            for (backScan = 0; backScan <= maxBackScan; backScan++) {
                ULONG totalSize = backScan + gadgetSize;
                ULONG_PTR gadgetAddr;
                if (totalSize < 2 || totalSize > WKD_ROP_GADGET_MAX_SIZE) continue;
                gadgetAddr = ModuleBase + va + offset - backScan;
                status = IoaRop_AddGadget(Detector, gadgetAddr, ModuleBase,
                                          ModuleData + va + offset - backScan, totalSize, type);
                if (NT_SUCCESS(status)) {
                    gadgetCount++;
                    if (gadgetCount >= WKD_ROP_MAX_GADGETS_PER_MODULE) goto ScanComplete;
                }
            }
        }
    }

ScanComplete:
    if (Detector->ScannedActiveModules < WKD_ROP_MAX_MODULES_TRACKED) {
        PWKD_ROP_SCANNED_MODULE m = &Detector->ScannedModules[Detector->ScannedActiveModules];
        m->ModuleBase = ModuleBase;
        m->ModuleSize = (ULONG)ModuleSize;
        if (ModuleName != NULL) {
            wcsncpy_s(m->ModuleName, RTL_NUMBER_OF(m->ModuleName), ModuleName, _TRUNCATE);
        }
        m->GadgetCount = gadgetCount;
        m->ScanTime = GetTickCount64();
        m->ModuleHash = IoaRopHashAddress(ModuleBase);
        Detector->ScannedActiveModules++;
    }
    InterlockedAdd64(&Detector->Stats.GadgetsIndexed, gadgetCount);

    free(pctx);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IoaRop_AddGadget(
    _Inout_ PWKD_ROP_DETECTOR Detector,
    _In_ ULONG_PTR Address,
    _In_ ULONG_PTR ModuleBase,
    _In_reads_bytes_(Size) const BYTE* Bytes,
    _In_ ULONG Size,
    _In_ WKD_ROP_GADGET_TYPE Type
    )
/*++
Routine Description:
    单条 gadget 入库（对齐 SS RopAddGadget L1015）：
    语义分析 + 危险度评分 + 哈希入桶（FNV-1a, 1024 桶）。
--*/
{
    ULONG bucket, idx;
    PWKD_ROP_GADGET gadget;

    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || Address == 0 || Bytes == NULL || Size == 0 || Size > WKD_ROP_GADGET_MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Detector->GadgetLock);

    if (Detector->GadgetPoolCount >= WKD_ROP_GADGET_POOL_SIZE) {
        LeaveCriticalSection(&Detector->GadgetLock);
        return STATUS_QUOTA_EXCEEDED;
    }
    bucket = IoaRopHashAddress(Address) % WKD_ROP_GADGET_HASH_BUCKETS;
    if (Detector->GadgetHashCount[bucket] >= WKD_ROP_GADGET_HASH_CHAIN) {
        LeaveCriticalSection(&Detector->GadgetLock);
        return STATUS_QUOTA_EXCEEDED;
    }

    idx = Detector->GadgetPoolCount;
    gadget = &Detector->GadgetPool[idx];
    RtlZeroMemory(gadget, sizeof(*gadget));
    gadget->Address = Address;
    gadget->ModuleBase = ModuleBase;
    gadget->ModuleOffset = (ULONG)(Address - ModuleBase);
    gadget->Type = Type;
    gadget->Size = Size;
    memcpy(gadget->Bytes, Bytes, Size);

    if (Detector->Config.EnableSemanticAnalysis) {
        IoaRopAnalyzeGadgetSemantics(gadget);
    }
    gadget->DangerScore = IoaRopCalculateDangerScore(Detector, gadget);

    Detector->GadgetHash[bucket][Detector->GadgetHashCount[bucket]] = idx;
    Detector->GadgetHashCount[bucket]++;
    Detector->GadgetPoolCount++;

    LeaveCriticalSection(&Detector->GadgetLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IoaRop_LookupGadget(
    _In_ const PWKD_ROP_DETECTOR Detector,
    _In_ ULONG_PTR Address,
    _Out_ PWKD_ROP_GADGET GadgetCopy
    )
/*++
Routine Description:
    按地址查库拷贝 gadget（对齐 SS RopLookupGadget L1099）。
    拷贝出避免生命周期依赖。
--*/
{
    ULONG bucket, k;
    PWKD_ROP_DETECTOR nonConst = (PWKD_ROP_DETECTOR)Detector;

    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || GadgetCopy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(GadgetCopy, sizeof(*GadgetCopy));
    if (Detector->GadgetPoolCount == 0) return STATUS_NOT_FOUND;

    bucket = IoaRopHashAddress(Address) % WKD_ROP_GADGET_HASH_BUCKETS;

    EnterCriticalSection(&nonConst->GadgetLock);
    for (k = 0; k < Detector->GadgetHashCount[bucket]; k++) {
        const WKD_ROP_GADGET* g = &Detector->GadgetPool[Detector->GadgetHash[bucket][k]];
        if (g->Address == Address) {
            memcpy(GadgetCopy, g, sizeof(*GadgetCopy));
            LeaveCriticalSection(&nonConst->GadgetLock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&nonConst->GadgetLock);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
IoaRop_AnalyzeStackBuffer(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ const ULONG_PTR* StackBuffer,
    _In_ SIZE_T Size,
    _In_ ULONG_PTR StackBase,
    _Out_ PWKD_ROP_DETECTION_RESULT* Result
    )
/*++
Routine Description:
    栈缓冲地址驱动分析（对齐 SS RopAnalyzeStackBuffer L1357）：
    栈槽值 → 查 gadget 库 → 连续链判定。值 <0x10000 跳过（对齐 SS）。
    Result 堆分配，调用方 IoaRop_FreeResult。
    ※ 死代码：需已构建 gadget 库（IoaRop_ScanModuleForGadgets 死代码）。
--*/
{
    NTSTATUS status;
    PWKD_ROP_DETECTION_RESULT result = NULL;
    SIZE_T i, slotCount;
    ULONG consecutiveGadgets = 0, totalGadgets = 0;

    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || StackBuffer == NULL || Size == 0 || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Result = NULL;

    if (((ULONG_PTR)StackBuffer & (sizeof(ULONG_PTR) - 1)) != 0) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if (Size > WKD_ROP_STACK_SAMPLE_SIZE || Size < sizeof(ULONG_PTR)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!IoaRopCheckRateLimit(Detector)) return STATUS_QUOTA_EXCEEDED;

    result = (PWKD_ROP_DETECTION_RESULT)malloc(sizeof(WKD_ROP_DETECTION_RESULT));
    if (result == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(result, sizeof(*result));
    result->StackBase = StackBase;

    slotCount = Size / sizeof(ULONG_PTR);
    for (i = 0; i < slotCount; i++) {
        ULONG_PTR value = StackBuffer[i];
        WKD_ROP_GADGET gadgetCopy;

        if (value < 0x10000) {
            consecutiveGadgets = 0;
            continue;
        }

        status = IoaRop_LookupGadget(Detector, value, &gadgetCopy);
        if (NT_SUCCESS(status)) {
            ULONG idx = result->ChainLength;
            consecutiveGadgets++;
            totalGadgets++;
            if (idx < WKD_ROP_MAX_CHAIN_LENGTH) {
                WKD_ROP_CHAIN_ENTRY* ce = &result->ChainEntries[idx];
                ULONG m;
                PCWSTR mname = NULL;

                ce->GadgetAddress = value;
                ce->GadgetType = gadgetCopy.Type;
                ce->GadgetSize = gadgetCopy.Size;
                ce->GadgetDangerScore = gadgetCopy.DangerScore;
                ce->GadgetIsPrivileged = gadgetCopy.IsPrivileged;
                ce->GadgetRegistersModified = gadgetCopy.Semantics.RegistersModified;
                ce->StackOffset = i * sizeof(ULONG_PTR);
                ce->StackValue = value;
                ce->Index = idx;
                result->ChainLength++;

                for (m = 0; m < Detector->ScannedActiveModules; m++) {
                    if (Detector->ScannedModules[m].ModuleBase == gadgetCopy.ModuleBase) {
                        mname = Detector->ScannedModules[m].ModuleName;
                        break;
                    }
                }
                IoaRopRecordModuleBreakdown(result, gadgetCopy.ModuleBase, mname);
            }
            if (consecutiveGadgets >= Detector->Config.MinChainLength) {
                result->ChainDetected = TRUE;
            }
        } else {
            /* 非库内地址打断链（对齐 SS L1464-1475） */
            consecutiveGadgets = 0;
        }
        if (result->ChainLength >= Detector->Config.MaxChainLength) break;
    }
    result->UniqueGadgets = totalGadgets;

    if (result->ChainDetected) {
        result->AttackType = IoaRopClassifyChain(result);
        IoaRopScoreChain(result);
        IoaRopInferChainPayload(result);
        *Result = result;
        return STATUS_SUCCESS;
    }

    free(result);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
IoaRop_AnalyzeStack(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _Out_ PWKD_ROP_DETECTION_RESULT* Result
    )
/*++
Routine Description:
    线程栈完整分析（对齐 SS RopAnalyzeStack L1173）：
      WptGetThreadContext(Rsp→CurrentSp) → WptGetThreadStackBounds(TEB 栈界) →
      MsReadMemory(读 min(4KB, 可用栈)) → MsBuildModuleSet(模块判定) →
      pivot 检测 → 链检测 → 分类/评分/载荷推断。
    ※ 死代码：依赖真实线程栈快照（Wpt / MsReadMemory 跨权限读），触发点=驱动
      SetContext/栈事件上送后接线。
--*/
{
    NTSTATUS status;
    PWKD_ROP_DETECTION_RESULT result = NULL;
    WKD_THREAD_CONTEXT64 ctx;
    ULONG_PTR stackBase = 0, stackLimit = 0, currentSp = 0;
    SIZE_T available, bytesToCopy;
    BYTE* stackBuf = NULL;
    ULONG bytesRead = 0;
    WKD_MEM_MODULE_SET moduleSet;

    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || Result == NULL || ProcessId == 0 || ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *Result = NULL;

    if (!IoaRopCheckRateLimit(Detector)) return STATUS_QUOTA_EXCEEDED;

    result = (PWKD_ROP_DETECTION_RESULT)malloc(sizeof(WKD_ROP_DETECTION_RESULT));
    if (result == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(result, sizeof(*result));
    result->ProcessId = ProcessId;
    result->ThreadId = ThreadId;

    /* 上下文 → CurrentSp（对齐 RoppInitializeAnalysisContext L2560） */
    RtlZeroMemory(&ctx, sizeof(ctx));
    if (WptGetThreadContext(ThreadId, &ctx)) {
        currentSp = ctx.Rsp;
    }
    if (!WptGetThreadStackBounds(ThreadId, &stackBase, &stackLimit)) {
        free(result);
        return STATUS_UNSUCCESSFUL;
    }
    /* 无 CurrentSp 时默认 StackLimit（对齐 SS L2620） */
    if (currentSp == 0 && stackLimit != 0) currentSp = stackLimit;

    if (stackBase == 0 || currentSp == 0) {
        free(result);
        return STATUS_UNSUCCESSFUL;
    }
    if (currentSp >= stackBase) {
        free(result);
        return STATUS_INVALID_PARAMETER;
    }

    result->StackBase = stackBase;
    result->StackLimit = stackLimit;
    result->CurrentSp = currentSp;

    /* 捕获栈（复用 MsReadMemory, 替代 RoppCaptureStack L2663） */
    available = (SIZE_T)(stackBase - currentSp);
    bytesToCopy = min(WKD_ROP_STACK_SAMPLE_SIZE, available);
    if (bytesToCopy < sizeof(ULONG_PTR)) {
        free(result);
        return STATUS_NO_DATA_DETECTED;
    }

    status = MsReadMemory(ProcessId, currentSp, bytesToCopy, &stackBuf, &bytesRead);
    if (!NT_SUCCESS(status) || stackBuf == NULL || bytesRead == 0) {
        free(result);
        return status;
    }

    /* 模块集（复用 MsBuildModuleSet, 替代 RoppBuildModuleCache L2754） */
    RtlZeroMemory(&moduleSet, sizeof(moduleSet));
    MsBuildModuleSet(ProcessId, &moduleSet);

    /* pivot 检测（对齐 RoppDetectStackPivot L3023） */
    result->StackPivotDetected = IoaRopDetectStackPivot(
        currentSp, stackBase, stackLimit,
        &result->PivotSource, &result->PivotDestination);

    /* 链检测（对齐 RoppDetectChain L2912） */
    IoaRopDetectChain(Detector, (const ULONG_PTR*)stackBuf,
                      bytesRead / sizeof(ULONG_PTR), &moduleSet, result);

    /* 对齐 SS RoppCleanupAnalysisContext L2648 安全擦除后再释放 */
    RtlSecureZeroMemory(stackBuf, bytesRead);
    free(stackBuf);   /* MsReadMemory 用 malloc, 用 free 释放 */

    /* 分类/评分/载荷（对齐 SS L1303-1315） */
    if (result->ChainDetected) {
        result->AttackType = IoaRopClassifyChain(result);
        IoaRopScoreChain(result);
        IoaRopInferChainPayload(result);
        InterlockedIncrement64(&Detector->Stats.ChainsDetected);
    }
    InterlockedIncrement64(&Detector->Stats.StacksAnalyzed);

    *Result = result;
    return result->ChainDetected ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
IoaRop_ValidateCallStack(
    _In_ PWKD_ROP_DETECTOR Detector,
    _In_ DWORD ProcessId,
    _In_ DWORD ThreadId,
    _Out_ PBOOLEAN IsValid,
    _Out_opt_ PULONG SuspicionScore
    )
/*++
Routine Description:
    调用栈完整性验证（对齐 SS RopValidateCallStack L1496）：
      链检测 → IsValid=FALSE + confidence；pivot → 70。
    与 WptValidateThread（T1055.003 线程劫持语义）互补：本函数为 ROP 链语义。
--*/
{
    NTSTATUS status;
    PWKD_ROP_DETECTION_RESULT result = NULL;
    ULONG score = 0;

    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || IsValid == NULL || ProcessId == 0 || ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *IsValid = TRUE;
    if (SuspicionScore != NULL) *SuspicionScore = 0;

    status = IoaRop_AnalyzeStack(Detector, ProcessId, ThreadId, &result);

    if (status == STATUS_NOT_FOUND) {
        if (result != NULL) {
            if (result->StackPivotDetected) {
                *IsValid = FALSE;
                score = 70;
            }
            IoaRop_FreeResult(result);
        }
        if (SuspicionScore != NULL) *SuspicionScore = score;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) return status;

    if (result->ChainDetected) {
        *IsValid = FALSE;
        score = result->ConfidenceScore;
    } else if (result->StackPivotDetected) {
        *IsValid = FALSE;
        score = 70;
    }
    if (SuspicionScore != NULL) *SuspicionScore = score;

    IoaRop_FreeResult(result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
IoaRop_FreeResult(
    _In_ PWKD_ROP_DETECTION_RESULT Result
    )
/*++
Routine Description:
    释放堆分配的检测结果（对齐 SS RopFreeResult L1574）。
    agent 无链表, Result 为单块 malloc 分配。
--*/
{
    if (Result != NULL) free(Result);
}

_Use_decl_annotations_
NTSTATUS
IoaRop_GetStatistics(
    _In_ const PWKD_ROP_DETECTOR Detector,
    _Out_ PWKD_ROP_STATISTICS Stats
    )
/*++
Routine Description:
    读取检测器统计（对齐 SS RopGetStatistics L1755）。
--*/
{
    if (Detector == NULL || Detector->Signature != WKD_ROP_DETECTOR_SIGNATURE ||
        !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Stats->GadgetCount = Detector->GadgetPoolCount;
    Stats->ModulesScanned = Detector->ScannedActiveModules;
    Stats->StacksAnalyzed = Detector->Stats.StacksAnalyzed;
    Stats->ChainsDetected = Detector->Stats.ChainsDetected;
    Stats->UpTimeMs = GetTickCount64() - Detector->Stats.StartTime;
    return STATUS_SUCCESS;
}
