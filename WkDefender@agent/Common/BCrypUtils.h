/**************************************************/
/*  WkDefender Agent — BCrypt/哈希工具层（统一整合） */
/*                                                  */
/*  2026-09-08 重构: 自 Common/FileUtils.c 迁出     */
/*  全部加密算法函数（SHA-256/MD5 多算法哈希槽、     */
/*  CTPH 模糊哈希、哈希高层封装与硬件加速检测），     */
/*  FileUtils 回归文件 I/O、熵计算与文件类型识别。   */
/*  今后 Agent 侧 BCrypt/Crypto 使用向本模块收敛。   */
/*  实现在 Common/BCrypUtils.c。                    */
/**************************************************/

#pragma once

#include "../DefendTypes.h"       /* DEF_SHA256_HASH */
#include "../IOC/IocTypes.h"      /* WKD_HASH_ALG/WKD_FILE_HASH_SET */

/**************************************************/
/*          多算法哈希 / CTPH 公共 API               */
/**************************************************/

/* 计算文件 SHA256（BCrypt 分块读取，含 4GB/reparse 护栏）。 */
NTSTATUS
CoComputeFileSha256(
    _In_ PCWSTR FilePath,
    _Out_ PDEF_SHA256_HASH Hash
    );

/* 计算内存缓冲区 SHA256（BCrypt）。 */
BOOLEAN IocScanner_ComputeBufferSha256(_In_ const BYTE* Buffer, _In_ ULONG Size, _Out_ PDEF_SHA256_HASH Hash);

/* 文件 SHA256（BOOLEAN 语义包装；原散落声明于 SignatureCatalog.h/ProcessModule.h，
 * 2026-09-08 统一收敛至本头。 */
BOOLEAN IocScanner_ComputeFileSha256(_In_ PCWSTR FilePath, _Out_ PDEF_SHA256_HASH Hash);

/* 多算法文件哈希（单遍多句柄, 带 4GB / reparse 护栏）。 */
BOOLEAN IocScanner_ComputeFileHashMulti(_In_ PCWSTR FilePath, _In_ ULONG Mask, _Out_ PWKD_FILE_HASH_SET Hashes);

/* 多算法缓冲哈希（单遍多句柄）。 */
BOOLEAN IocScanner_ComputeBufferHashMulti(_In_ const BYTE* Buffer, _In_ ULONG Size, _In_ ULONG Mask, _Out_ PWKD_FILE_HASH_SET Hashes);

/* 多算法缓冲哈希（底层实现；HashMask 为 WKD_HASH_ALG 位图）。 */
BOOLEAN IocScan_HashBufferMulti(_In_ const BYTE* Buf, _In_ ULONG Size, _In_ ULONG Mask, _Out_ PWKD_FILE_HASH_SET Out);

/* 缓冲区 SHA256（底层实现；BCrypt）。 */
BOOLEAN IocScan_ComputeBufferSha256(_In_ const BYTE* Buffer, _In_ ULONG Size, _Out_ PDEF_SHA256_HASH Hash);

/* CTPH 模糊哈希生成（ssdeep 语义）。输出 "blockSize:sig1:sig2"; 0=成功, -1=失败。Out 需 ≥128 字节。 */
INT IocScanner_ComputeFuzzyHash(_In_ const BYTE* Data, _In_ SIZE_T Size, _Out_ CHAR* Out, _In_ ULONG OutCch);

/* CTPH 相似度比较。0-100 相似度, -1=非法输入。 */
INT IocScanner_CompareFuzzyHash(_In_ PCSTR Digest1, _In_ PCSTR Digest2);

/* 计算缓冲区 MD5 小写十六进制串 (33 字节含尾 0)，用于 ImpHash 计算。 */
BOOLEAN IocScan_ComputeMd5Hex(_In_ const BYTE* Data, _In_ ULONG Size, _Out_ CHAR* HexOut);

/**************************************************/
/*          内部实现（不对本头外开放）               */
/*  哈希统计 / SelfTest / 内存映射哈希 /            */
/*  FNV/Equal/DigestSize / 高级比较与归一化         */
/*  均以 static 维护于 BCrypUtils.c。               */
/**************************************************/