/**************************************************/
/*  WkDefender — Tier 1 Shellcode 模式检测         */
/*  全量移植自 PhantomSensor ThreadNotify.c         */
/*  TnpCheckShellcodePatterns — 9 种模式             */
/*                                                  */
/*  增强: 全文壳码扫描 (对齐 PS MemoryScanner        */
/*  DetectShellcode, 含 ROP 链检测)                 */
/**************************************************/

#pragma once

#include <windows.h>

//
// 检测线程入口点前 128 字节是否为 shellcode
// 返回值: TRUE = 检测到 shellcode 特征
// 对齐 PS TnpCheckShellcodePatterns，精确复制 9 种模式
//
BOOL
T1DetectShellcodePatterns(
    _In_reads_(Size) const UCHAR* Bytes,
    _In_ ULONG Size
    );

/**************************************************/
/*               全文壳码检测特征位                 */
/*  对齐 PS MemoryScanner DetectShellcode          */
/**************************************************/

#define T1_SC_GETPC       0x00000001   /* GetPC/prologue 模式 */
#define T1_SC_APIHASH     0x00000002   /* API 哈希 (ROL/ROR) */
#define T1_SC_SYSCALL     0x00000004   /* 直接 syscall/sysenter */
#define T1_SC_NOP_SLED    0x00000008   /* NOP sled (连续 >= 16) */
#define T1_SC_ROP_CHAIN   0x00000010   /* ROP 链 (RET 间隔 2-20 连续 >= 5) */
#define T1_SC_X64         0x00000020   /* 疑似 x64 (lea rax, [rip+]) */

/*++
 * IocDetectShellcode
 *   全文壳码扫描:在整个缓冲上匹配 NOP sled / GetPC / APIhash /
 *   syscall stub / ROP 链 特征,返回特征位组合 (T1_SC_*).
 *   对齐 PS MemoryScanner::DetectShellcode (MemoryScanner.cpp L1016).
 *   与 T1DetectShellcodePatterns (起始字节语义) 互补:本函数为包含语义.
 *   IsPrivate — 区域是否 MEM_PRIVATE (ROP 链检测需私有区域).
 *--*/
ULONG
IocDetectShellcode(
    _In_reads_(Size) const PUCHAR Bytes,
    _In_ SIZE_T Size,
    _In_ BOOLEAN Private
    );
