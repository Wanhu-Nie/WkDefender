/**************************************************/
/*  WkDefender Agent — 文件/字节/通用工具层          */
/*                                                  */
/*  2026-08-15 重构: 自 IOC/IocScanner.c 迁出        */
/*  与扫描无关的文件 I/O、文件类型识别(魔数/消歧/     */
/*  分类/扩展名) 与熵计算(统一) 逻辑。               */
/*                                                  */
/*  2026-09-08 重构: 多算法哈希 (SHA256/MD5/CTPH/    */
/*  TLSH) 与哈希高层已迁出至 BCrypUtils.{c,h} 统一   */
/*  整合, 本头通过 BCrypUtils.h 转发其 API 声明,     */
/*  既有调用方（含 IOC 层）保持零改动。             */
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include "../IOC/IocTypes.h"   /* WKD_FILE_FORMAT/WKD_FILE_TYPE_INFO/WKD_FILE_HASH_SET 等 */
#include "BCrypUtils.h"        /* 哈希 API 统一出口（2026-09-08 迁移） */

/**************************************************/
/*               文件类型识别                       */
/**************************************************/

/* 粗分类判定（内部走魔数表） */
typedef enum _IOC_FILE_TYPE {
    IocFileType_Unknown = 0,
    IocFileType_Pe32,
    IocFileType_Pe64,
    IocFileType_Dll,
    IocFileType_Sys,
    IocFileType_Elf,
    IocFileType_Pdf,
    IocFileType_Archive,
    IocFileType_Office,
    IocFileType_Script,
} IOC_FILE_TYPE;

/* 缓冲版粗分类 */
IOC_FILE_TYPE IocScan_DetectFileType(_In_ const BYTE* Data, _In_ ULONG Size);

/* 路径版粗分类 */
IOC_FILE_TYPE CoDetermineFileType(_In_ PCWSTR FilePath);

/* 缓冲版完整文件类型分析 — 魔数匹配 + Disambiguate 精化 +
 * 类别/风险/扩展名映射 + 扩展名欺骗检测。
 * Data 建议 ≥64KB 以覆盖 ISO@0x8001 等多偏移签名。 */
NTSTATUS
CoDetermineFileTypeFromBuffer(
    _In_  const BYTE*          Data,
    _In_  ULONG                Size,
    _In_opt_ PCWSTR            DiskExtension,
    _Out_ PWKD_FILE_TYPE_INFO  Info
    );

/* 路径版完整文件类型分析 — 读文件头 + 路径安全欺骗检测 +
 * 扩展名-内容不匹配判定。 */
NTSTATUS
IocScan_AnalyzeFileTypePath(
    _In_  PCWSTR               FilePath,
    _Out_ PWKD_FILE_TYPE_INFO  Info
    );

/* 文本内容判定（UTF-8 有效性 + 90% 可打印 + NUL 拒） */
BOOLEAN IocScan_IsTextContent(_In_ const BYTE* Data, _In_ ULONG Size);

/* 扩展名完整信息查询（format/category/risk/mime/isCommon） */
NTSTATUS IocScan_GetExtensionInfo(_In_ PCWSTR Extension, _Out_ PWKD_EXTENSION_INFO Info);

/* 可执行判定（Category in Executable/Driver/Library） */
BOOLEAN IocScan_IsExecutable(_In_ PCWSTR FilePath);

/* 缓冲版可执行判定 */
BOOLEAN IocScan_IsExecutableBuffer(_In_ const BYTE* Data, _In_ ULONG Size);

/* 脚本判定 */
BOOLEAN IocScan_IsScript(_In_ PCWSTR FilePath);

/* 归档判定 */
BOOLEAN IocScan_IsArchive(_In_ PCWSTR FilePath);

/* 可含宏判定 */
BOOLEAN IocScan_CanContainMacros(_In_ PCWSTR FilePath);

/* 文件缓冲是否含 PE（找 MZ + 校验 e_lfanew 处 PE 签名） */
BOOLEAN IocScan_ContainsPe(_In_ const BYTE* Data, _In_ ULONG Size);

/* MIME 映射（Web/HTTP 消费语义） */
PCSTR IocScan_GetMimeForFormat(_In_ WKD_FILE_FORMAT Format);

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