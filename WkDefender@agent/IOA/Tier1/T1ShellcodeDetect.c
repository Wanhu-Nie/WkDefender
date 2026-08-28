/**************************************************/
/*  WkDefender — Tier 1 Shellcode 模式检测实现      */
/*  全量移植 PhantomSensor ThreadNotify.c            */
/*  TnpCheckShellcodePatterns — 精确复制 9 种模式    */
/*                                                    */
/*  注：原始实现使用 SEH (ProbeForRead)，agent 侧      */
/*  的调用方已确保 Bytes 指向有效内存。                 */
/**************************************************/

#include "T1ShellcodeDetect.h"
#include <string.h>

BOOL
T1DetectShellcodePatterns(
    _In_reads_(Size) const UCHAR* Bytes,
    _In_ ULONG Size
    )
{
    ULONG i;

    if (Bytes == NULL || Size < 6) {
        return FALSE;
    }

    //
    // Pattern 1: GetPC via call $+5 / pop (E8 00 00 00 00 5x)
    //
    if (Bytes[0] == 0xE8 &&
        Bytes[1] == 0x00 &&
        Bytes[2] == 0x00 &&
        Bytes[3] == 0x00 &&
        Bytes[4] == 0x00 &&
        (Bytes[5] >= 0x58 && Bytes[5] <= 0x5F)) {
        return TRUE;
    }

    //
    // Pattern 2: JMP/CALL ESP (FF E4 / FF D4)
    //
    if (Bytes[0] == 0xFF &&
        (Bytes[1] == 0xE4 || Bytes[1] == 0xD4)) {
        return TRUE;
    }

    //
    // Pattern 3: JMP/CALL EAX (FF E0 / FF D0)
    //
    if (Bytes[0] == 0xFF &&
        (Bytes[1] == 0xE0 || Bytes[1] == 0xD0)) {
        return TRUE;
    }

    //
    // Pattern 4: NOP sled detection (many consecutive NOPs)
    //
    {
        ULONG nopCount = 0;
        for (i = 0; i < Size; i++) {
            if (Bytes[i] == 0x90) {
                nopCount++;
            }
        }
        if (nopCount > 20) {
            return TRUE;
        }
    }

    //
    // Pattern 5: x86 PEB access (FS:[0x30])
    //
    if (Size >= 6 &&
        Bytes[0] == 0x64 &&
        Bytes[1] == 0xA1 &&
        Bytes[2] == 0x30 &&
        Bytes[3] == 0x00 &&
        Bytes[4] == 0x00 &&
        Bytes[5] == 0x00) {
        return TRUE;
    }

    //
    // Pattern 6: x64 PEB access (GS:[0x60])
    //
    if (Size >= 6 &&
        Bytes[0] == 0x65 &&
        Bytes[1] == 0x48 &&
        Bytes[2] == 0x8B &&
        (Bytes[3] == 0x04 || Bytes[3] == 0x0C) &&
        Bytes[4] == 0x25 &&
        Bytes[5] == 0x60) {
        return TRUE;
    }

    //
    // Pattern 7: LEA-based GetPC (48 8D 05 / E8 followed by add/sub)
    //
    if (Size >= 9 &&
        Bytes[0] == 0x48 &&
        Bytes[1] == 0x8D &&
        Bytes[2] == 0x05) {
        if (Bytes[7] == 0x48 && Bytes[8] == 0x83) {
            return TRUE;
        }
    }

    //
    // Pattern 8: XOR reg, reg followed by PUSH/POP sequence
    //
    if ((Bytes[0] == 0x31 || Bytes[0] == 0x33) &&
        (Bytes[1] & 0xC0) == 0xC0) {
        ULONG pushCount = 0;
        for (i = 2; i < 16 && i < Size; i++) {
            if (Bytes[i] >= 0x50 && Bytes[i] <= 0x57) {
                pushCount++;
            }
        }
        if (pushCount >= 4) {
            return TRUE;
        }
    }

    //
    // Pattern 9: SYSCALL/SYSENTER direct invocation
    //
    for (i = 0; i < Size - 1; i++) {
        if ((Bytes[i] == 0x0F && Bytes[i + 1] == 0x05) ||  // SYSCALL
            (Bytes[i] == 0x0F && Bytes[i + 1] == 0x34)) {  // SYSENTER
            return TRUE;
        }
    }

    return FALSE;
}

/**************************************************/
/*               全文壳码扫描                       */
/*  对齐 PS MemoryScanner DetectShellcode          */
/*  (MemoryScanner.cpp L1016-1206)                */
/**************************************************/

/* 缓冲内任意偏移子串匹配 */
static BOOLEAN
T1scContains(
    _In_ const UCHAR* Data,
    _In_ ULONG Size,
    _In_ const UCHAR* Pattern,
    _In_ ULONG PatternLen
    )
{
    ULONG i, j;

    if (Size < PatternLen) return FALSE;
    for (i = 0; i <= Size - PatternLen; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < PatternLen; j++) {
            if (Data[i + j] != Pattern[j]) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/* 连续 NOP 等价指令最大长度（单元 = 一条 NOP 指令，含多字节变体） */
/* 对齐 SS ShellcodeDetector.c SdpDetectNopSledInternal L2303-2355:
 *   - 0x90          标准单字节 NOP
 *   - 0x66 0x90     XCHG AX,AX 双字节 NOP
 *   - 0x0F 0x1F /0  长 NOP (ModR/M + 可选 SIB/disp, 按 SS 长度解码) */
static ULONG
T1scCountMaxNOPSled(
    _In_ const UCHAR* Data,
    _In_ ULONG Size
    )
{
    ULONG maxNOPs = 0, current = 0, i = 0;

    while (i < Size) {
        BOOLEAN isNop = FALSE;

        if (Data[i] == 0x90) {
            isNop = TRUE;
            i++;
        } else if (i + 1 < Size && Data[i] == 0x66 && Data[i + 1] == 0x90) {
            isNop = TRUE;
            i += 2;
        } else if (i + 1 < Size && Data[i] == 0x0F && Data[i + 1] == 0x1F) {
            isNop = TRUE;
            i += 2;
            if (i < Size) {
                /* 长 NOP 长度解码: ModR/M 起 1 字节, 内存操作数再计 SIB/disp */
                UCHAR modrm = Data[i];
                ULONG extra = 1;   /* ModR/M */
                if ((modrm & 0xC0) != 0xC0) {
                    if ((modrm & 0x07) == 0x04) extra++;          /* SIB */
                    if ((modrm & 0xC0) == 0x40) extra++;          /* disp8 */
                    else if ((modrm & 0xC0) == 0x80) extra += 4;  /* disp32 */
                }
                i += extra;
            }
        } else {
            i++;
        }

        if (isNop) {
            current++;
            if (current > maxNOPs) maxNOPs = current;
        } else {
            current = 0;
        }
    }
    return maxNOPs;
}

/*++
 * IocDetectShellcode
 *   全文壳码特征扫描,返回 T1_SC_* 特征位组合。
 *--*/
_Use_decl_annotations_
ULONG
IocDetectShellcode(
    _In_reads_(Size) const PUCHAR Bytes,
    _In_ SIZE_T Size,
    _In_ BOOLEAN Private
    )
/*++
Routine Description:
    在整个缓冲上匹配壳码特征,对齐 PS MemoryScanner::DetectShellcode:
      1. NOP sled  (连续 >= 16 字节 0x90)
      2. GetPC / 常见 prologue 字节模式 (call $+5; pop / lea rax,[rip+])
      3. API hashing (ROL/ROR 循环)
      4. Direct syscall stub (syscall/sysenter/int 2E)
      5. ROP 链  (RET 间隔 2-20 字节连续 >= 5, 需私有区域 >= 64 字节)

Arguments:
    Bytes       - 待扫描缓冲.
    Size        - 缓冲大小.
    IsPrivate   - 区域是否 MEM_PRIVATE (ROP 链检测前置).

Return Value:
    T1_SC_* 特征位组合 (0 = 无特征).
--*/
{
    ULONG flags = 0;

    if (!Bytes || Size == 0) return 0;

    /* 1. NOP sled */
    if (T1scCountMaxNOPSled(Bytes, Size) >= 16) {
        flags |= T1_SC_NOP_SLED;
    }

    /* 2. GetPC / prologue 模式 (对齐 PS SHELLCODE_PATTERNS) */
    static const UCHAR kCallPopEax[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 };
    static const UCHAR kCallPopEbx[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B };
    static const UCHAR kCallPopEcx[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59 };
    static const UCHAR kLeaRip[]     = { 0x48, 0x8D, 0x05 };
    static const UCHAR kJmpPopEbx[]  = { 0xEB, 0x1A, 0x5B };
    static const UCHAR kCldCall[]    = { 0xFC, 0xE8 };

    if (T1scContains(Bytes, Size, kCallPopEax, sizeof(kCallPopEax)) ||
        T1scContains(Bytes, Size, kCallPopEbx, sizeof(kCallPopEbx)) ||
        T1scContains(Bytes, Size, kCallPopEcx, sizeof(kCallPopEcx)) ||
        T1scContains(Bytes, Size, kJmpPopEbx, sizeof(kJmpPopEbx)) ||
        T1scContains(Bytes, Size, kCldCall, sizeof(kCldCall))) {
        flags |= T1_SC_GETPC;
    }

    /* x64 判定: lea rax, [rip+disp32] (48 8D 05 xx xx xx xx) */
    if (T1scContains(Bytes, Size, kLeaRip, sizeof(kLeaRip))) {
        flags |= T1_SC_GETPC | T1_SC_X64;
    }

    /* 3. API hashing (对齐 PS API_HASH_PATTERNS) */
    static const UCHAR kRorImm[] = { 0xC1, 0xC8 };
    static const UCHAR kRolImm[] = { 0xC1, 0xC0 };
    static const UCHAR kRor1[]   = { 0xD1, 0xC8 };
    static const UCHAR kRol1[]   = { 0xD1, 0xC0 };

    if (T1scContains(Bytes, Size, kRorImm, sizeof(kRorImm)) ||
        T1scContains(Bytes, Size, kRolImm, sizeof(kRolImm)) ||
        T1scContains(Bytes, Size, kRor1, sizeof(kRor1)) ||
        T1scContains(Bytes, Size, kRol1, sizeof(kRol1))) {
        flags |= T1_SC_APIHASH;
    }

    /* 4. Direct syscall stub (对齐 PS SYSCALL_PATTERNS) */
    static const UCHAR kSyscall[] = { 0x0F, 0x05 };
    static const UCHAR kSysenter[] = { 0x0F, 0x34 };
    static const UCHAR kInt2e[]   = { 0xCD, 0x2E };

    if (T1scContains(Bytes, Size, kSyscall, sizeof(kSyscall)) ||
        T1scContains(Bytes, Size, kSysenter, sizeof(kSysenter)) ||
        T1scContains(Bytes, Size, kInt2e, sizeof(kInt2e))) {
        flags |= T1_SC_SYSCALL;
    }

    /* 5. ROP 链: RET 间隔 [2,20] 连续 >= 5 (对齐 PS DetectShellcode L1076-1109) */
    if (Private && Size >= 64) {
        const ULONG kMinGap = 2;
        const ULONG kMaxGap = 20;
        const ULONG kMinChain = 5;
        ULONG prevRet = (ULONG)-1;
        ULONG consecutive = 0;
        ULONG maxRun = 0;
        ULONG i;

        for (i = 0; i < Size; i++) {
            if (Bytes[i] != 0xC3) continue;   /* RET */

            if (prevRet == (ULONG)-1) {
                consecutive = 1;
            } else {
                ULONG gap = i - prevRet;
                if (gap >= kMinGap && gap <= kMaxGap) {
                    consecutive++;
                } else {
                    consecutive = 1;          /* 间隔过大/过小,链中断 */
                }
            }
            prevRet = i;
            if (consecutive > maxRun) maxRun = consecutive;
        }

        if (maxRun >= kMinChain) {
            flags |= T1_SC_ROP_CHAIN;
        }
    }

    return flags;
}
