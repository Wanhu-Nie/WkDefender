/**************************************************/
/*  WkDefender IOC — 编码字符串提取与分类           */
/*                                                  */
/*  迁移自 ShadowStrike StringExtractor.cpp          */
/*  (PhantomEmulator/Analysis, 1654 行) 按功能融合   */
/*  重实现, 纯 C 非复制。                            */
/*                                                  */
/*  能力面:                                         */
/*    - ASCII / UTF-16LE 字符串提取 (可打印性)       */
/*    - Base64 串检测 + 解码                        */
/*    - 单字节 XOR 串检测 + 解码 (Index of Coincidence  */
/*      密钥长估计 + 采样校验)                      */
/*    - Caesar / ROT13 位移检测 + 解码               */
/*    - 17 类字符串分类 + 聚合可疑评分               */
/*                                                  */
/*  简化迁移说明 (未全量):                          */
/*    - 多字节 XOR (SS DetectMultiByteXOR, IC 密钥   */
/*      长 2..16) → 以单字节 XOR 为主实现, 多字节     */
/*      探测过于启发式且易误报, 标注死代码预留       */
/*    - 栈字符串追踪 (SS ExtractStackString/          */
/*      OnStackWrite) → 依赖模拟器轨, 不迁移         */
/*    - C2 关键词表 (SS kC2Keywords 20 条) → 并入     */
/*      分类权重, 不再独立表                        */
/*                                                  */
/*  编码: UTF-8 with BOM                             */
/**************************************************/

#pragma once

#include "IocTypes.h"

/* 每趟提取串上限 / 串长上限 (防空爆 + 定长可传输) */
#define IOC_STR_MAX_STRINGS      256
#define IOC_STR_MAX_LEN          512

/* 编码类型位 (IocStrEntry.Encoding) */
#define IOC_STR_ENCODING_XOR     0x01
#define IOC_STR_ENCODING_BASE64  0x02
#define IOC_STR_ENCODING_ROT     0x04

/**************************************************/
/*            字符串分类 (对齐 SS StringCategory)    */
/**************************************************/
typedef enum _IOC_STR_CATEGORY {
    IocStrCat_Unknown = 0,
    IocStrCat_URL,            /* http:// https:// ftp:// */
    IocStrCat_Domain,         /* 点分隔域名 */
    IocStrCat_IPAddress,      /* IPv4 */
    IocStrCat_FilePath,       /* 盘符/UNC/常见路径 */
    IocStrCat_RegistryKey,    /* HKLM\\ HKCU\\ ... */
    IocStrCat_CommandLine,    /* 含命令参数/开关 */
    IocStrCat_UserAgent,      /* Mozilla/ curl/ wget/ ... */
    IocStrCat_APIName,        /* 已知敏感 API */
    IocStrCat_DLLName,        /* *.dll */
    IocStrCat_MutexName,      /* Global\\ Local\\ */
    IocStrCat_CryptoKey,      /* 高熵密钥/盐 */
    IocStrCat_Base64Data,     /* Base64 载荷 */
    IocStrCat_EmailAddress,   /* user@domain */
    IocStrCat_Credential,     /* password= token= secret */
    IocStrCat_SuspiciousCommand, /* cmd/powershell/wmic 等 */
    IocStrCat_BenignString,   /* 普通可读文本 */
} IOC_STR_CATEGORY;

/**************************************************/
/*           提取串条目 (定长)                      */
/**************************************************/
typedef struct _IOC_STR_ENTRY {
    CHAR            Text[IOC_STR_MAX_LEN];
    IOC_STR_CATEGORY Category;
    BOOLEAN         IsWide;      /* UTF-16LE */
    BOOLEAN         IsDecoded;   /* 由编码串解码所得 */
    ULONG           Encoding;    /* IOC_STR_ENCODING_* */
    ULONG           Suspiciousness; /* 0-1000 单串可疑度 */
} IOC_STR_ENTRY, *PIOC_STR_ENTRY;

typedef struct _IOC_STR_RESULT {
    ULONG        Count;
    IOC_STR_ENTRY Entries[IOC_STR_MAX_STRINGS];
} IOC_STR_RESULT, *PIOC_STR_RESULT;

/**************************************************/
/*               函数声明                          */
/**************************************************/

/* 扫描文件字节缓冲提取/解码/分类编码字符串。
 * Agg - IOC_SCAN_RESULT 聚合 (填 StrExt* 字段组) — 可 NULL。
 * Out - (可选) 逐串完整输出 (IOC_STR_MAX_STRINGS 截断) — 可 NULL。
 * 返回 STATUS_SUCCESS。 */
NTSTATUS
IocStrExtract(
    _In_      const BYTE*      Data,
    _In_      SIZE_T           Size,
    _Inout_opt_ IOC_SCAN_RESULT* Agg,
    _Out_opt_ PIOC_STR_RESULT  Out
    );
