/**************************************************/
/*  WkDefender Agent — 熵计算 / 文件 I/O 工具层      */
/*                                                  */
/*  2026-08-15 初版: 自 IOC/IocScanner.c 迁出        */
/*  文件 I/O + 熵计算逻辑。                         */
/*                                                  */
/*  2026-09-08 重构: 多算法哈希迁移至 BCrypUtils      */
/*                                                  */
/*  2026-09-14 重构: 文件类型判定 (IOC_FILE_TYPE /    */
/*  CopDetermineFileTypeInternal / CoDetermineFileType*/
/*  / CoDetermineFileTypeFromBuffer /                */
/*  IocScan_AnalyzeFileTypePath / IsTextContent /    */
/*  GetExtensionInfo / IsExecutable* / IsScript /    */
/*  IsArchive / CanContainMacros / GetMimeForFormat/ */
/*  DetectSpoofing) 迁至 Include/FileSystem/         */
/*  FileAnalyzer.h。本头仅保留熵计算+文件IO工具。    */
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include "../IOC/IocTypes.h"   /* WKD_FILE_TYPE_INFO 等 (IocScan_ContainsPe 无依赖, 备用) */
#include "BCrypUtils.h"        /* 哈希 API 统一出口（2026-09-08 迁移） */

/**************************************************/
/*               文件类型识别                       */
/*  2026-09-14 已迁移至 Include/FileSystem/          */
/*  FileAnalyzer.h, 本头不再声明。                  */
/*  (IocScan_ContainsPe 因不含文件类型判定逻辑,     */
/*   仍保留在此。)                                  */
/**************************************************/

/* 文件缓冲是否含 PE（找 MZ + 校验 e_lfanew 处 PE 签名） */
BOOLEAN IocScan_ContainsPe(_In_ const BYTE* Data, _In_ ULONG Size);

/**************************************************/
/*                  熵计算（统一）                  */
/*  用户态浮点实现；输出规范为 bits（DOUBLE）。     */
/*  字母表决定最大熵基准：字节=8.0，ASCII=7.0。     */
/*  所有旧"0-1000 简化熵"调用点统一改为 bits×1000。 */
/**************************************************/

typedef enum _CO_ENTROPY_ALPHABET {
    CoEntropyAlphabet_Byte       = 256,  /* 二进制字节流：内存/文件/PE 节 */
    CoEntropyAlphabet_Ascii      = 128,  /* 字符序列：管道名/域名/进程名 */
    CoEntropyAlphabet_PrintAscii = 95,   /* 可打印 ASCII */
} CO_ENTROPY_ALPHABET;

/* 核心：真香农熵，返回 bits（[0, log2(alphabet)]）。
 * Sample=0 全量；Sample>0 仅统计首 Sample 字节（大缓冲/流式）。 */
DOUBLE
CoEntropyCalculate(
    _In_ LPCVOID Buffer,
    _In_ SIZE_T  Size,
    _In_ CO_ENTROPY_ALPHABET Alphabet,
    _In_ SIZE_T  Sample
    );

/* 便捷：二进制字节流（可选采样） */
DOUBLE
CoEntropyBinary(
    _In_ LPCVOID Buffer,
    _In_ SIZE_T  Size,
    _In_ SIZE_T  Sample
    );

/* 便捷：宽/窄字符序列（仅 ASCII 0-127 统计） */
DOUBLE
CoEntropyStringW(_In_ LPCWSTR String, _In_ USHORT LengthChars);
DOUBLE
CoEntropyStringA(_In_ LPCSTR String, _In_ USHORT LengthChars);

/* bits → 定点整数（替换旧的 ×100/×1000/×1024 调用） */
ULONG
CoEntropyToFixed(_In_ DOUBLE Bits, _In_ ULONG Scale);

/* bits → 归一化百分比 [0,100]（高熵区域发现用） */
ULONG
CoEntropyToPercent(_In_ DOUBLE Bits, _In_ CO_ENTROPY_ALPHABET Alphabet);

/* 统一阈值（单位 bits） */
#define CO_ENTROPY_THRESHOLD_RANSOMWARE   7.5   /* 文件写/加密载荷 */
#define CO_ENTROPY_THRESHOLD_SHELLCODE    5.5   /* 内存 shellcode 预判 */
#define CO_ENTROPY_THRESHOLD_C2_PIPENAME  4.2   /* 随机化管道/域名 */
#define CO_ENTROPY_THRESHOLD_PACKED_SEC   7.0   /* PE 节加壳 */
#define CO_ENTROPY_THRESHOLD_HIGH_REGION  70    /* 高熵区域（百分比） */


HANDLE
CoOpenFileForSequentialRead(
    _In_ PCWSTR FilePath,
    _Out_opt_ PSIZE_T FileSize
    );

/* 读取文件头缓冲（最大 4KB），Header 由调用者 free() 释放 */
NTSTATUS
CoReadFileHeader(
    _In_ PCWSTR FilePath,
    _Out_opt_ PSIZE_T FileSize,
    _Outptr_ PBYTE* Header,
    _Out_ PSIZE_T HeaderSize
    );