/**************************************************/
/*  WkDefender Agent — 加壳器检测引擎               */
/*  AntiEvasio / PackerDetector.c                  */
/*                                                  */
/*  迁移自 ShadowStrike PackerDetector              */
/*  (.cpp 4375行 + .hpp 2334行)。纯 C 实现。         */
/*                                                  */
/*  架构：                                           */
/*    1. 熵分析：Shannon 熵 / 卡方检验 /             */
/*       压缩 vs 加密区分（文件/节/Overlay/资源）     */
/*    2. PE 结构分析：节表 / 导入表 / Overlay /       */
/*       Rich 头 / 资源 / 入口点 / .NET 标志          */
/*    3. EP 签名匹配：内嵌 36 条经典签名库            */
/*       （UPX/ASPack/PECompact/MPRESS/Petite/FSG/    */
/*        MEW/NsPack/Themida/VMProtect/Enigma/       */
/*        ASProtect/Armadillo/Obsidium/PELock/       */
/*        PESpin/tElock/Yoda/kkrunchy/Upack/RLPack/  */
/*        NSIS/InnoSetup/7-ZipSFX/ConfuserEx/        */
/*        EXECryptor/Safengine/CodeVirtualizer）      */
/*    4. 加壳 Stub 启发式：PUSHAD 序言/解压循环/      */
/*       XOR 解密/反调试（RDTSC、INT 2D）/API 哈希   */
/*       （字节模式扫描，原反汇编降级）               */
/*    5. YARA 扫描：接入 IocYara_ScanBuffer           */
/*       （工程预留集成点）                           */
/*    6. 数字签名验证：WinVerifyTrust 内联            */
/*                                                  */
/*  降级决策（详见头文件）：                          */
/*    - PhantomDisassembler → 字节模式扫描            */
/*    - PEParser            → 内联 PdkPe* 解析器      */
/*    - SignatureStore      → IocYara_ScanBuffer      */
/*    - asm 时序/调试寄存器 → 省略（原为死代码）      */
/*    - std::vector/map     → 固定上限数组            */
/*    - 结果缓存 8192 项    → 16 项（LRU 线性淘汰）   */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "PackerDetector.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <math.h>
#include <intrin.h>
#include <ntstatus.h>

#include <wintrust.h>
#include <softpub.h>

#include "../IOC/IocYaraScanner.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#include "../Common/BCrypUtils.h"   /* IocScan_ComputeBufferSha256 / CoComputeFileSha256 */

/* M_PI 兜底（MSVC 不保证定义） */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define PDK_TAG 'dKpS'

/**************************************************/
/*          内部工具宏                             */
/**************************************************/

#define PDK_ARRAY_COUNT(a)  (sizeof(a) / sizeof((a)[0]))

#define PDK_CLAMP_FLOAT(v, lo, hi) \
    ((v) < (lo) ? (lo) : ((v) > (hi) ? (hi) : (v)))

#define PDK_CLAMP_LONG(v, lo, hi) \
    ((v) < (lo) ? (lo) : ((v) > (hi) ? (hi) : (v)))

#define PDK_MIN(a, b)  ((a) < (b) ? (a) : (b))
#define PDK_MAX(a, b)  ((a) > (b) ? (a) : (b))

/* 字符串拷贝（带上限 + 强制结尾） */
#define PDK_WCS_COPY(dst, dstCch, src)                      \
    do {                                                    \
        wcsncpy_s((dst), (dstCch), (src), _TRUNCATE);       \
        (dst)[(dstCch) - 1] = L'\0';                        \
    } while (0)

#define PDK_STR_COPY(dst, dstCch, src)                      \
    do {                                                    \
        strncpy_s((dst), (dstCch), (src), _TRUNCATE);       \
        (dst)[(dstCch) - 1] = '\0';                         \
    } while (0)

/**************************************************/
/*          内部结构定义                           */
/**************************************************/

/* EP 签名条目（对齐源 EPSignatures::EPSignature） */
typedef struct _PDK_EP_SIGNATURE {
    PDK_PACKER_TYPE   PackerType;
    WCHAR             Name[PDK_MAX_NAME];
    WCHAR             Version[64];
    BYTE              Pattern[PDK_MAX_EP_BYTES];
    BYTE              Mask[PDK_MAX_EP_BYTES];
    SIZE_T            PatternSize;
    DOUBLE            Confidence;
} PDK_EP_SIGNATURE;

/* 自定义节名模式 */
typedef struct _PDK_CUSTOM_SECTION {
    CHAR              Name[16];
    PDK_PACKER_TYPE   Type;
} PDK_CUSTOM_SECTION;

/* 结果缓存条目（LRU 线性淘汰） */
typedef struct _PDK_CACHE_ENTRY {
    WCHAR             Path[PDK_MAX_PATH];
    PDK_PACKING_INFO  Result;
    BOOLEAN           Used;
    ULONGLONG         StoredTick;   /* 入缓存时刻（GetTickCount64，ms） */
} PDK_CACHE_ENTRY;

/**************************************************/
/*          内置 EP 签名库（对齐源，36 条）        */
/**************************************************/

static const PDK_EP_SIGNATURE g_PdkBuiltInSignatures[] = {

    /* === UPX === */
    {
        PDK_TYPE_UPX, L"UPX", L"3.x",
        { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x57, 0x83, 0xCD, 0xFF },
        { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF },
        16, 0.95
    },
    {
        PDK_TYPE_UPX, L"UPX", L"2.x",
        { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE, 0x00, 0x00, 0xFF, 0xFF, 0x57 },
        { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF },
        13, 0.90
    },
    {
        PDK_TYPE_UPX_MODIFIED, L"UPX (Modified)", L"",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xE8, 0x00 },
        { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00 },
        10, 0.75
    },

    /* === ASPack === */
    {
        PDK_TYPE_ASPACK, L"ASPack", L"2.12",
        { 0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3, 0xE8, 0x01 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        15, 0.95
    },
    {
        PDK_TYPE_ASPACK_V2, L"ASPack", L"2.x",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0xB8 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
        14, 0.90
    },

    /* === PECompact === */
    {
        PDK_TYPE_PECOMPACT, L"PECompact", L"2.x",
        { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        16, 0.90
    },
    {
        PDK_TYPE_PECOMPACT_V3, L"PECompact", L"3.x",
        { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        16, 0.88
    },

    /* === MPRESS === */
    {
        PDK_TYPE_MPRESS, L"MPRESS", L"2.x",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x30 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF },
        14, 0.90
    },

    /* === Petite === */
    {
        PDK_TYPE_PETITE, L"Petite", L"2.x",
        { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        17, 0.88
    },

    /* === FSG === */
    {
        PDK_TYPE_FSG, L"FSG", L"2.0",
        { 0x87, 0x25, 0x00, 0x00, 0x00, 0x00, 0x61, 0x94, 0x55, 0xA4, 0xB6, 0x80, 0xFF, 0x13 },
        { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        14, 0.92
    },
    {
        PDK_TYPE_FSG_V1, L"FSG", L"1.x",
        { 0xBB, 0xD0, 0x01, 0x40, 0x00, 0xBF, 0x00, 0x10, 0x40, 0x00, 0xBE },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        11, 0.90
    },

    /* === MEW === */
    {
        PDK_TYPE_MEW, L"MEW", L"11",
        { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF },
        16, 0.80
    },

    /* === NsPack === */
    {
        PDK_TYPE_NSPACK, L"NsPack", L"3.x",
        { 0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x2D },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
        14, 0.90
    },

    /* === Themida / WinLicense === */
    {
        PDK_TYPE_THEMIDA, L"Themida", L"2.x",
        { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0B, 0xC0, 0x74, 0x68, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE8 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
        16, 0.85
    },
    {
        PDK_TYPE_THEMIDA_V3, L"Themida", L"3.x",
        { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        12, 0.80
    },

    /* === VMProtect === */
    {
        PDK_TYPE_VMPROTECT, L"VMProtect", L"3.x",
        { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        16, 0.70
    },
    {
        PDK_TYPE_VMPROTECT_V2, L"VMProtect", L"2.x",
        { 0x9C, 0x60, 0x68, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF4, 0x83, 0xC6, 0x04, 0x68, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00 },
        16, 0.82
    },

    /* === Enigma Protector === */
    {
        PDK_TYPE_ENIGMA, L"Enigma Protector", L"4.x",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x06, 0x00, 0x00, 0x00, 0x8B, 0xD5 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        15, 0.90
    },

    /* === ASProtect === */
    {
        PDK_TYPE_ASPROTECT, L"ASProtect", L"2.x",
        { 0x68, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3, 0x60 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        13, 0.88
    },

    /* === Armadillo === */
    {
        PDK_TYPE_ARMADILLO, L"Armadillo", L"4.x",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x50, 0x51, 0x0F, 0xCA, 0xF7, 0xD2, 0x9C },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        14, 0.88
    },

    /* === Obsidium === */
    {
        PDK_TYPE_OBSIDIUM, L"Obsidium", L"1.x",
        { 0xEB, 0x02, 0x00, 0x00, 0xE8, 0x25, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        9, 0.85
    },

    /* === PELock === */
    {
        PDK_TYPE_PELOCK, L"PELock", L"2.x",
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x01, 0x9A },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF },
        11, 0.80
    },

    /* === PESpin === */
    {
        PDK_TYPE_PESPIN, L"PESpin", L"1.x",
        { 0xEB, 0x01, 0x68, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x1C, 0x24, 0x83, 0xC3 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        14, 0.90
    },

    /* === tElock === */
    {
        PDK_TYPE_TELOCK, L"tElock", L"0.98",
        { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        16, 0.65
    },

    /* === Yoda's Crypter === */
    {
        PDK_TYPE_YODA_CRYPTER, L"Yoda's Crypter", L"1.x",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00 },
        15, 0.85
    },

    /* === kkrunchy === */
    {
        PDK_TYPE_KKRUNCHY, L"kkrunchy", L"0.23",
        { 0xBD, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x4D, 0x00 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00 },
        15, 0.88
    },

    /* === Upack === */
    {
        PDK_TYPE_UPACK, L"Upack", L"0.3x",
        { 0xBE, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x8B, 0xF8, 0x95, 0xAD, 0x91, 0xF3, 0xA5, 0xAD },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        14, 0.90
    },

    /* === RLPack === */
    {
        PDK_TYPE_RLPACK, L"RLPack", L"1.x",
        { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x04, 0x83, 0xC0, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
        13, 0.85
    },

    /* === NSIS === */
    {
        PDK_TYPE_NSIS, L"NSIS", L"3.x",
        { 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x53, 0x55, 0x56, 0x57, 0x6A, 0x20, 0x33, 0xED },
        { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        14, 0.88
    },
    {
        PDK_TYPE_NSIS_V2, L"NSIS", L"2.x",
        { 0x83, 0xEC, 0x00, 0x53, 0x55, 0x56, 0x57, 0x6A, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 },
        14, 0.85
    },

    /* === Inno Setup === */
    {
        PDK_TYPE_INNO_SETUP, L"Inno Setup", L"6.x",
        { 0x55, 0x8B, 0xEC, 0x83, 0xC4, 0x00, 0x53, 0x56, 0x57, 0x33, 0xC0, 0x89, 0x45 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        13, 0.85
    },

    /* === 7-Zip SFX === */
    {
        PDK_TYPE_SEVENZIP_SFX, L"7-Zip SFX", L"",
        { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x64 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
        16, 0.75
    },

    /* === ConfuserEx (.NET) === */
    {
        PDK_TYPE_CONFUSEREX, L"ConfuserEx", L"1.x",
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x43, 0x6F, 0x72 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF },
        12, 0.70
    },

    /* === EXECryptor === */
    {
        PDK_TYPE_EXECRYPTER, L"EXECryptor", L"2.x",
        { 0xE8, 0x24, 0x00, 0x00, 0x00, 0x8B, 0x4C, 0x24, 0x0C, 0xC7, 0x01, 0x17, 0x00, 0x01, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        15, 0.90
    },

    /* === Safengine === */
    {
        PDK_TYPE_SAFENGINE, L"Safengine", L"2.x",
        { 0x60, 0x9C, 0x60, 0x8B, 0xDD, 0x8B, 0xC5, 0x83, 0xC0, 0x05, 0x89, 0x45, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
        13, 0.88
    },

    /* === Code Virtualizer === */
    {
        PDK_TYPE_CODE_VIRTUALIZER, L"Code Virtualizer", L"2.x",
        { 0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0x80 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
        15, 0.85
    }
};

#define PDK_BUILTIN_SIGNATURE_COUNT \
    PDK_ARRAY_COUNT(g_PdkBuiltInSignatures)

/**************************************************/
/*          已知加壳器节名（小写，对齐源 64 项）    */
/**************************************************/

static const char* const g_PdkKnownPackerSections[] = {
    /* UPX */
    "upx0", "upx1", "upx2", ".upx", ".upx0", ".upx1", ".upx2",
    /* ASPack */
    ".aspack", ".adata", ".asdata",
    /* PECompact */
    ".pec1", ".pec2", "pec1", "pec2", ".pec",
    /* Themida/WinLicense */
    ".themida", ".winlicen", ".vmp0", ".vmp1", ".vmp2",
    /* VMProtect */
    ".vmp", ".vmp0", ".vmp1", ".vmp2",
    /* Enigma */
    ".enigma1", ".enigma2", ".enig",
    /* Armadillo */
    ".armd", ".arma",
    /* ASProtect */
    ".aspr", ".asprdata",
    /* Petite */
    ".petite",
    /* FSG */
    ".fsg",
    /* MEW */
    ".mew",
    /* NsPack */
    ".nsp0", ".nsp1", ".nsp2", ".nspack",
    /* tElock */
    ".tlock",
    /* PESpin */
    ".pespin",
    /* Yoda */
    ".yoda", ".yP",
    /* Obsidium */
    ".obs", ".obsd",
    /* PELock */
    ".plock",
    /* MPRESS */
    ".mpress1", ".mpress2",
    /* kkrunchy */
    ".kkrunchy",
    /* RLPack */
    ".rl", ".rlpack",
    /* Upack */
    ".upack", ".rsrc",
    /* 通用可疑 */
    ".packed", ".crypted", ".encrypt", ".protect", ".stub"
};

/* 已知安装器节名（对齐源 16 项）：用于良性区分 */
static const char* const g_PdkInstallerSections[] = {
    ".ndata",   /* NSIS */
    ".nsis",    /* NSIS */
    ".inno",    /* Inno Setup */
    ".is",      /* InstallShield */
    ".setup",   /* 通用 */
    ".inst",    /* 通用 */
    ".msi",     /* Windows Installer */
    "CODE",     /* Delphi/Inno */
    "DATA",     /* Delphi/Inno */
    "BSS",      /* Delphi/Inno */
    ".idata",   /* 导入数据 */
    ".tls",     /* TLS */
    ".CRT",     /* C 运行时 */
    ".gfids",   /* Control Flow Guard */
    ".00cfg",   /* CFG */
    ".retplne"  /* Retpoline */
};

/* 高频 RWX 节名表（对齐源 8 项） */
static const char* const g_PdkSuspiciousRwxSections[] = {
    ".text", ".code", "CODE", ".rdata", ".data", ".bss", ".rsrc", ".reloc"
};

/**************************************************/
/*          全局状态（SRW 锁保护）                  */
/**************************************************/

static SRWLOCK g_PdkLock = SRWLOCK_INIT;
static BOOLEAN g_PdkInitialized = FALSE;

/* 结果缓存（固定数组，LRU 线性淘汰） */
static PDK_CACHE_ENTRY g_PdkCache[PDK_MAX_CACHE_ENTRIES];
static SIZE_T g_PdkCacheCount = 0;

/* 自定义模式池 */
static PDK_EP_SIGNATURE g_PdkCustomSigs[PDK_MAX_CUSTOM_EPSIG];
static SIZE_T g_PdkCustomSigCount = 0;
static PDK_CUSTOM_SECTION g_PdkCustomSections[PDK_MAX_CUSTOM_SECTIONS];
static SIZE_T g_PdkCustomSectionCount = 0;

/* 检测回调（受 g_PdkLock 保护，调用须在锁外） */
static PKD_DETECTION_CALLBACK g_PdkCallback = NULL;

/* 统计快照（Interlocked 原子维护） */
static PDK_STATISTICS g_PdkStats;

/**************************************************/
/*          内部工具函数                           */
/**************************************************/

/* 设置错误对象 */
static
VOID
PdkErrorSet(
    _Out_ PDK_ERROR* Err,
    _In_ ULONG Win32Code,
    _In_opt_ PCWSTR Message,
    _In_opt_ PCWSTR Context
    )
{
    if (Err == NULL) return;
    Err->Win32Code = Win32Code;
    if (Message != NULL) {
        PDK_WCS_COPY(Err->Message, PDK_MAX_DESC, Message);
    } else {
        Err->Message[0] = L'\0';
    }
    if (Context != NULL) {
        PDK_WCS_COPY(Err->Context, PDK_MAX_PATH, Context);
    } else {
        Err->Context[0] = L'\0';
    }
}

/* 向结果追加错误记录（上限截断） */
static
VOID
PdkRecordError(
    _Inout_ PDK_PACKING_INFO* Result,
    _In_ ULONG Win32Code,
    _In_opt_ PCWSTR Message,
    _In_opt_ PCWSTR Context
    )
{
    PDK_ERROR* slot;

    if (Result == NULL || Result->ErrorCount >= PDK_MAX_ERRORS) {
        return;
    }
    slot = &Result->Errors[Result->ErrorCount++];
    PdkErrorSet(slot, Win32Code, Message, Context);
}

/* 追加描述性指标（上限截断） */
static
VOID
PdkAddIndicator(
    _Inout_ PDK_PACKING_INFO* Result,
    _In_ PCWSTR Text
    )
{
    if (Result == NULL || Text == NULL || Result->IndicatorCount >= PDK_MAX_INDICATORS) {
        return;
    }
    PDK_WCS_COPY(Result->Indicators[Result->IndicatorCount], PDK_MAX_DESC, Text);
    Result->IndicatorCount++;
}

/* 追加异常描述（上限截断） */
static
VOID
PdkAddAnomaly(
    _Inout_ PDK_PACKING_INFO* Result,
    _In_ PCWSTR Text
    )
{
    if (Result == NULL || Text == NULL || Result->AnomalyCount >= PDK_MAX_ANOMALIES) {
        return;
    }
    PDK_WCS_COPY(Result->Anomalies[Result->AnomalyCount], PDK_MAX_DESC, Text);
    Result->AnomalyCount++;
}

/* 取置信度最高的匹配（对齐源 GetBestMatch） */
static
const PDK_PACKER_MATCH*
PdkGetBestMatch(
    _In_ const PDK_PACKING_INFO* Result
    )
{
    const PDK_PACKER_MATCH* best = NULL;
    DOUBLE bestConfidence = 0.0;
    ULONG i;

    if (Result == NULL) return NULL;

    for (i = 0; i < Result->MatchCount; ++i) {
        const PDK_PACKER_MATCH* match = &Result->PackerMatches[i];
        if (match->Confidence > bestConfidence) {
            bestConfidence = match->Confidence;
            best = match;
        }
    }
    return best;
}

/* 结果整体复位（清零 + 默认配置） */
static
VOID
PdkResultReset(
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    if (Result == NULL) return;

    RtlZeroMemory(Result, sizeof(*Result));

    Result->FilePath[0] = L'\0';
    Result->PackerName[0] = L'\0';
    Result->PackerVersion[0] = L'\0';
    Result->Sha256Hash[0] = '\0';
    Result->FileEntropy = 0.0;
    Result->ChiSquared = 0.0;
    Result->PackingConfidence = 0.0;
    Result->AnalysisComplete = FALSE;
    Result->FromCache = FALSE;
    Result->Severity = PDK_SEVERITY_BENIGN;

    /* 默认配置（对齐源 PackerAnalysisConfig 默认值） */
    Result->Config.Depth = PDK_DEPTH_STANDARD;
    Result->Config.Flags = PDK_FLAG_DEFAULT;
    Result->Config.TimeoutMs = PDK_DEFAULT_SCAN_TIMEOUT_MS;
    Result->Config.MaxFileSize = PDK_MAX_FILE_SIZE;
    Result->Config.EnableCaching = TRUE;
    Result->Config.CacheTtlSeconds = PDK_RESULT_CACHE_TTL_SECONDS;
    Result->Config.MinConfidenceThreshold = PDK_MIN_PACKING_CONFIDENCE;
    Result->Config.IncludeRawData = FALSE;
    Result->Config.MaxRawDataSize = 0;
    Result->Config.TreatInstallersAsBenign = TRUE;
    Result->Config.ProcessId = 0;
}

/* 要求初始化（未初始化则自动初始化） */
static
BOOLEAN
PdkEnsureInitialized(
    _Inout_opt_ PDK_ERROR* Err
    )
{
    if (g_PdkInitialized) {
        return TRUE;
    }
    /* 幂等：加锁重查 + 置位 */
    AcquireSRWLockExclusive(&g_PdkLock);
    if (!g_PdkInitialized) {
        RtlZeroMemory(&g_PdkStats, sizeof(g_PdkStats));
        g_PdkInitialized = TRUE;
    }
    ReleaseSRWLockExclusive(&g_PdkLock);
    return TRUE;
}

/* SHA-256 十六进制小写（BCrypt；失败置空串） */
static
VOID
PdkComputeSha256Hex(
    _In_reads_bytes_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size,
    _Out_writes_(72) PCHAR HexOut
    )
{
    static const char hexDigits[] = "0123456789abcdef";
    DEF_SHA256_HASH hash;
    ULONG i;

    HexOut[0] = '\0';
    if (Buffer == NULL || Size == 0 || Size > 0xFFFFFFFFUL) return;

    RtlZeroMemory(&hash, sizeof(hash));
    if (!IocScan_ComputeBufferSha256(Buffer, (ULONG)Size, &hash)) {
        return;
    }
    for (i = 0; i < DEF_SHA256_SIZE; ++i) {
        HexOut[i * 2]     = hexDigits[hash.Data[i] >> 4];
        HexOut[i * 2 + 1] = hexDigits[hash.Data[i] & 0x0F];
    }
    HexOut[DEF_SHA256_SIZE * 2] = '\0';
}

/**************************************************/
/*          缓存辅助（受 g_PdkLock 保护）           */
/**************************************************/

/* 缓存查找：命中返回 TRUE 并拷贝结果（LRU 触碰） */
static
BOOLEAN
PdkCacheLookup(
    _In_ PCWSTR FilePath,
    _Out_ PDK_PACKING_INFO* OutResult
    )
{
    ULONGLONG now;
    SIZE_T i;

    if (FilePath == NULL || FilePath[0] == L'\0') return FALSE;

    now = GetTickCount64();

    AcquireSRWLockExclusive(&g_PdkLock);

    for (i = 0; i < g_PdkCacheCount; ++i) {
        PDK_CACHE_ENTRY* entry = &g_PdkCache[i];

        if (!entry->Used || _wcsicmp(entry->Path, FilePath) != 0) {
            continue;
        }
        /* TTL 过期 → 视为未命中（标记清理） */
        if ((now - entry->StoredTick) / 1000 > PDK_RESULT_CACHE_TTL_SECONDS) {
            entry->Used = FALSE;
            InterlockedIncrement64(&g_PdkStats.CacheMisses);
            ReleaseSRWLockExclusive(&g_PdkLock);
            return FALSE;
        }
        if (OutResult != NULL) {
            *OutResult = entry->Result;
            OutResult->FromCache = TRUE;
        }
        entry->StoredTick = now;   /* LRU 触碰 */
        InterlockedIncrement64(&g_PdkStats.CacheHits);
        ReleaseSRWLockExclusive(&g_PdkLock);
        return TRUE;
    }

    InterlockedIncrement64(&g_PdkStats.CacheMisses);
    ReleaseSRWLockExclusive(&g_PdkLock);
    return FALSE;
}

/* 缓存写入（满则 LRU 淘汰最旧） */
static
VOID
PdkCacheStore(
    _In_ PCWSTR FilePath,
    _In_ const PDK_PACKING_INFO* Result
    )
{
    SIZE_T i;
    SIZE_T victim = (SIZE_T)-1;
    ULONGLONG oldestTick = 0;

    if (FilePath == NULL || FilePath[0] == L'\0' || Result == NULL) return;

    AcquireSRWLockExclusive(&g_PdkLock);

    /* 已存在 → 覆盖 */
    for (i = 0; i < g_PdkCacheCount; ++i) {
        if (g_PdkCache[i].Used && _wcsicmp(g_PdkCache[i].Path, FilePath) == 0) {
            g_PdkCache[i].Result = *Result;
            g_PdkCache[i].StoredTick = GetTickCount64();
            ReleaseSRWLockExclusive(&g_PdkLock);
            return;
        }
    }

    /* 空槽优先，否则找最旧（LRU） */
    for (i = 0; i < g_PdkCacheCount; ++i) {
        if (!g_PdkCache[i].Used) {
            victim = i;
            break;
        }
    }
    if (victim == (SIZE_T)-1) {
        for (i = 0; i < g_PdkCacheCount; ++i) {
            if (i == 0 || g_PdkCache[i].StoredTick < oldestTick) {
                oldestTick = g_PdkCache[i].StoredTick;
                victim = i;
            }
        }
    }

    if (victim == (SIZE_T)-1) {
        ReleaseSRWLockExclusive(&g_PdkLock);
        return;
    }

    PDK_WCS_COPY(g_PdkCache[victim].Path, PDK_MAX_PATH, FilePath);
    g_PdkCache[victim].Result = *Result;
    g_PdkCache[victim].StoredTick = GetTickCount64();
    g_PdkCache[victim].Used = TRUE;
    if (victim >= g_PdkCacheCount) {
        g_PdkCacheCount = victim + 1;
    }

    ReleaseSRWLockExclusive(&g_PdkLock);
}

/**************************************************/
/*          PdkTypeToString（对齐源映射表）        */
/**************************************************/

const WCHAR*
PdkTypeToString(
    _In_ PDK_PACKER_TYPE Type
    )
{
    switch (Type) {
    case PDK_TYPE_UPX:              return L"UPX";
    case PDK_TYPE_UPX_MODIFIED:     return L"UPX (Modified)";
    case PDK_TYPE_UPX_SCRAMBLED:    return L"UPX (Scrambled)";
    case PDK_TYPE_ASPACK:           return L"ASPack";
    case PDK_TYPE_ASPACK_V1:        return L"ASPack v1.x";
    case PDK_TYPE_ASPACK_V2:        return L"ASPack v2.x";
    case PDK_TYPE_PECOMPACT:        return L"PECompact";
    case PDK_TYPE_PECOMPACT_V1:     return L"PECompact v1.x";
    case PDK_TYPE_PECOMPACT_V2:     return L"PECompact v2.x";
    case PDK_TYPE_PECOMPACT_V3:     return L"PECompact v3.x";
    case PDK_TYPE_MPRESS:           return L"MPRESS";
    case PDK_TYPE_MPRESS_V1:        return L"MPRESS v1.x";
    case PDK_TYPE_MPRESS_V2:        return L"MPRESS v2.x";
    case PDK_TYPE_PETITE:           return L"Petite";
    case PDK_TYPE_PETITE_V1:        return L"Petite v1.x";
    case PDK_TYPE_PETITE_V2:        return L"Petite v2.x";
    case PDK_TYPE_FSG:              return L"FSG";
    case PDK_TYPE_FSG_V1:           return L"FSG v1.x";
    case PDK_TYPE_FSG_V2:           return L"FSG v2.x";
    case PDK_TYPE_MEW:              return L"MEW";
    case PDK_TYPE_MEW_V10:          return L"MEW v1.0";
    case PDK_TYPE_MEW_V11:          return L"MEW v1.1";
    case PDK_TYPE_NSPACK:           return L"NsPack";
    case PDK_TYPE_NSPACK_V2:        return L"NsPack v2.x";
    case PDK_TYPE_NSPACK_V3:        return L"NsPack v3.x";
    case PDK_TYPE_UPACK:            return L"Upack";
    case PDK_TYPE_WINUPACK:         return L"WinUpack";
    case PDK_TYPE_KKRUNCHY:         return L"kkrunchy";
    case PDK_TYPE_RLPACK:           return L"RLPack";
    case PDK_TYPE_JDPACK:           return L"JDPack";
    case PDK_TYPE_BEROEXE_PACKER:   return L"BeRoEXEPacker";
    case PDK_TYPE_CEXE:             return L"CExe";
    case PDK_TYPE_PACKMAN:          return L"Packman";
    case PDK_TYPE_PEPACK:           return L"PEPack";
    case PDK_TYPE_WWPACK32:         return L"WWPack32";
    case PDK_TYPE_THEMIDA:          return L"Themida";
    case PDK_TYPE_THEMIDA_V1:       return L"Themida v1.x";
    case PDK_TYPE_THEMIDA_V2:       return L"Themida v2.x";
    case PDK_TYPE_THEMIDA_V3:       return L"Themida v3.x";
    case PDK_TYPE_WINLICENSE:       return L"WinLicense";
    case PDK_TYPE_VMPROTECT:        return L"VMProtect";
    case PDK_TYPE_VMPROTECT_V1:     return L"VMProtect v1.x";
    case PDK_TYPE_VMPROTECT_V2:     return L"VMProtect v2.x";
    case PDK_TYPE_VMPROTECT_V3:     return L"VMProtect v3.x";
    case PDK_TYPE_ENIGMA:           return L"Enigma Protector";
    case PDK_TYPE_ENIGMA_V1:        return L"Enigma Protector v1.x";
    case PDK_TYPE_ENIGMA_V4:        return L"Enigma Protector v4.x";
    case PDK_TYPE_ENIGMA_V6:        return L"Enigma Protector v6.x";
    case PDK_TYPE_ENIGMA_V7:        return L"Enigma Protector v7.x";
    case PDK_TYPE_ASPROTECT:        return L"ASProtect";
    case PDK_TYPE_ASPROTECT_V1:     return L"ASProtect v1.x";
    case PDK_TYPE_ASPROTECT_V2:     return L"ASProtect v2.x";
    case PDK_TYPE_ASPROTECT_SKE:    return L"ASProtect SKE";
    case PDK_TYPE_ARMADILLO:        return L"Armadillo";
    case PDK_TYPE_ARMADILLO_V3:     return L"Armadillo v3.x";
    case PDK_TYPE_ARMADILLO_V4:     return L"Armadillo v4.x";
    case PDK_TYPE_ARMADILLO_V9:     return L"Armadillo v9.x";
    case PDK_TYPE_OBSIDIUM:         return L"Obsidium";
    case PDK_TYPE_OBSIDIUM_V1:      return L"Obsidium v1.x";
    case PDK_TYPE_PELOCK:           return L"PELock";
    case PDK_TYPE_PELOCK_V1:        return L"PELock v1.x";
    case PDK_TYPE_PELOCK_V2:        return L"PELock v2.x";
    case PDK_TYPE_CODE_VIRTUALIZER: return L"Code Virtualizer";
    case PDK_TYPE_CODE_VIRTUALIZER_V1: return L"Code Virtualizer v1.x";
    case PDK_TYPE_CODE_VIRTUALIZER_V2: return L"Code Virtualizer v2.x";
    case PDK_TYPE_CODE_VIRTUALIZER_V3: return L"Code Virtualizer v3.x";
    case PDK_TYPE_EXECRYPTER:       return L"ExeCryptor";
    case PDK_TYPE_EXECRYPTER_V2:    return L"ExeCryptor v2.x";
    case PDK_TYPE_SAFENGINE:        return L"Safengine";
    case PDK_TYPE_ACPROTECT:        return L"ACProtect";
    case PDK_TYPE_EXESHIELD:        return L"EXEShield";
    case PDK_TYPE_SVK_PROTECTOR:    return L"SVKProtector";
    case PDK_TYPE_PCGUARD:          return L"PCGuard";
    case PDK_TYPE_ANTICRACK:        return L"AntiCrack";
    case PDK_TYPE_STARFORCE:        return L"StarForce";
    case PDK_TYPE_STARFORCE_V3:     return L"StarForce v3.x";
    case PDK_TYPE_STARFORCE_V5:     return L"StarForce v5.x";
    case PDK_TYPE_SECUROM:          return L"SecuROM";
    case PDK_TYPE_SECUROM_V4:       return L"SecuROM v4.x";
    case PDK_TYPE_SECUROM_V7:       return L"SecuROM v7.x";
    case PDK_TYPE_SECUROM_V8:       return L"SecuROM v8.x";
    case PDK_TYPE_SAFEDISC:         return L"SafeDisc";
    case PDK_TYPE_SAFEDISC_V2:      return L"SafeDisc v2.x";
    case PDK_TYPE_SAFEDISC_V4:      return L"SafeDisc v4.x";
    case PDK_TYPE_DENUVO:           return L"Denuvo";
    case PDK_TYPE_SOLIDSHIELD:      return L"SolidShield";
    case PDK_TYPE_TAGS_EPROTECT:    return L"Tages EProtect";
    case PDK_TYPE_CDILLA:           return L"CDilla";
    case PDK_TYPE_PESPIN:           return L"PESpin";
    case PDK_TYPE_PESPIN_V0:        return L"PESpin v0.x";
    case PDK_TYPE_PESPIN_V1:        return L"PESpin v1.x";
    case PDK_TYPE_TELOCK:           return L"tElock";
    case PDK_TYPE_TELOCK_V0:        return L"tElock v0.x";
    case PDK_TYPE_TELOCK_V1:        return L"tElock v1.x";
    case PDK_TYPE_YODA_CRYPTER:     return L"Yoda's Crypter";
    case PDK_TYPE_YODA_PROTECTOR:   return L"Yoda's Protector";
    case PDK_TYPE_PECRYPT32:        return L"PECrypt32";
    case PDK_TYPE_MORPHINE:         return L"Morphine";
    case PDK_TYPE_NEOLITE:          return L"Neolite";
    case PDK_TYPE_EXECRYPTER32:     return L"ExeCryptor32";
    case PDK_TYPE_SD_PROTECTOR:     return L"SDProtector";
    case PDK_TYPE_PE_ARMOR:         return L"PE-Armor";
    case PDK_TYPE_POLYCRYPT:        return L"PolyCrypt";
    case PDK_TYPE_PEX:              return L"PEX";
    case PDK_TYPE_CRYPKEY:          return L"CrypKey";
    case PDK_TYPE_CONFUSEREX:       return L"ConfuserEx";
    case PDK_TYPE_CONFUSEREX_V0:    return L"ConfuserEx v0.x";
    case PDK_TYPE_CONFUSEREX_V1:    return L"ConfuserEx v1.x";
    case PDK_TYPE_CONFUSER:         return L"Confuser";
    case PDK_TYPE_DOTNET_REACTOR:   return L".NET Reactor";
    case PDK_TYPE_DOTNET_REACTOR_V4: return L".NET Reactor v4";
    case PDK_TYPE_DOTNET_REACTOR_V5: return L".NET Reactor v5";
    case PDK_TYPE_DOTNET_REACTOR_V6: return L".NET Reactor v6";
    case PDK_TYPE_EAZFUSCATOR:      return L"Eazfuscator.NET";
    case PDK_TYPE_DOTFUSCATOR:      return L"Dotfuscator";
    case PDK_TYPE_SMART_ASSEMBLY:   return L"SmartAssembly";
    case PDK_TYPE_AGILE_NET:        return L"Agile.NET";
    case PDK_TYPE_BABEL_NET:        return L"Babel.NET";
    case PDK_TYPE_CRYPTO_OBFUSCATOR: return L"Crypto Obfuscator";
    case PDK_TYPE_MAXTOCODE:        return L"MaxtoCode";
    case PDK_TYPE_CODEVEIL:         return L"CodeVeil";
    case PDK_TYPE_SPICES_NET:       return L"Spices.Net";
    case PDK_TYPE_GOLIATH_NET:      return L"Goliath.NET";
    case PDK_TYPE_ILPROTECTOR:      return L"ILProtector";
    case PDK_TYPE_PHOENIX_PROTECTOR: return L"Phoenix Protector";
    case PDK_TYPE_DEEPSEA:          return L"DeepSea";
    case PDK_TYPE_XENOCODE:         return L"Xenocode";
    case PDK_TYPE_NSIS:             return L"NSIS";
    case PDK_TYPE_NSIS_V2:          return L"NSIS v2.x";
    case PDK_TYPE_NSIS_V3:          return L"NSIS v3.x";
    case PDK_TYPE_INNO_SETUP:       return L"Inno Setup";
    case PDK_TYPE_INNO_SETUP_V5:    return L"Inno Setup v5.x";
    case PDK_TYPE_INNO_SETUP_V6:    return L"Inno Setup v6.x";
    case PDK_TYPE_INSTALLSHIELD:    return L"InstallShield";
    case PDK_TYPE_WIX:              return L"WiX";
    case PDK_TYPE_ADVANCED_INSTALLER: return L"Advanced Installer";
    case PDK_TYPE_SETUP_FACTORY:    return L"Setup Factory";
    case PDK_TYPE_CREATE_INSTALL:   return L"CreateInstall";
    case PDK_TYPE_INSTALLAWARE:     return L"InstallAware";
    case PDK_TYPE_WISE:             return L"Wise Installer";
    case PDK_TYPE_GHOST_INSTALLER:  return L"Ghost Installer";
    case PDK_TYPE_SEVENZIP_SFX:     return L"7-Zip SFX";
    case PDK_TYPE_WINRAR_SFX:       return L"WinRAR SFX";
    case PDK_TYPE_WINZIP_SFX:       return L"WinZip SFX";
    case PDK_TYPE_ZIP_SFX:          return L"Zip SFX";
    case PDK_TYPE_CAB_SFX:          return L"CAB SFX";
    case PDK_TYPE_ARJ_SFX:          return L"ARJ SFX";
    case PDK_TYPE_CRYPTERX:         return L"CrypterX";
    case PDK_TYPE_NJCRYPTER:        return L"NJCrypter";
    case PDK_TYPE_DARKCOMET_STUB:   return L"DarkComet Stub";
    case PDK_TYPE_ANDROMEDA_LOADER: return L"Andromeda Loader";
    case PDK_TYPE_SMOKELOADER_PACKER: return L"SmokeLoader Packer";
    case PDK_TYPE_EMOTET_PACKER:    return L"Emotet Packer";
    case PDK_TYPE_TRICKBOT_PACKER:  return L"Trickbot Packer";
    case PDK_TYPE_DRIDEX_PACKER:    return L"Dridex Packer";
    case PDK_TYPE_QAKBOT_PACKER:    return L"QakBot Packer";
    case PDK_TYPE_ICEDID_PACKER:    return L"IcedID Packer";
    case PDK_TYPE_BAZARLOADER_PACKER: return L"BazarLoader Packer";
    case PDK_TYPE_RYUK_PACKER:      return L"Ryuk Packer";
    case PDK_TYPE_CONTI_PACKER:     return L"Conti Packer";
    case PDK_TYPE_COBALT_STRIKE_BEACON: return L"Cobalt Strike Beacon";
    case PDK_TYPE_CUSTOM_PACKER:    return L"Custom Packer";
    default:                        return L"Unknown";
    }
}

/**************************************************/
/*          PE 解析器（自包含，对齐源 PEParser）     */
/**************************************************/

#define PDK_IMAGE_DOS_SIGNATURE       0x5A4D  /* 'MZ' */
#define PDK_IMAGE_NT_SIGNATURE        0x00004550  /* 'PE\0\0' */
#define PDK_IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define PDK_DIRECTORY_COM_DESCRIPTOR  14      /* .NET CLR 头目录 */

/* 节特征位（对齐 winnt.h） */
#define PDK_IMAGE_SCN_MEM_EXECUTE     0x20000000
#define PDK_IMAGE_SCN_MEM_READ        0x40000000
#define PDK_IMAGE_SCN_MEM_WRITE       0x80000000
#define PDK_IMAGE_SCN_CNT_CODE        0x00000020
#define PDK_IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040

#define PDK_IMAGE_FILE_MACHINE_AMD64  0x8664

/* 常驻解析用的节条目 */
typedef struct _PDK_PE_SECTION {
    CHAR      Name[16];
    ULONG     VirtualAddress;
    ULONG     VirtualSize;
    ULONG     RawAddress;
    ULONG     RawSize;
    ULONG     Characteristics;
    BOOLEAN   IsExecutable;
    BOOLEAN   IsWritable;
    BOOLEAN   IsReadable;
    BOOLEAN   HasCode;
    BOOLEAN   HasInitializedData;
} PDK_PE_SECTION;

/* 解析上下文（缓冲一次解析，全程只读） */
typedef struct _PDK_PE_CONTEXT {
    const BYTE* Buffer;
    SIZE_T      Size;
    USHORT      Machine;
    BOOLEAN     Is64Bit;
    ULONG       NtHeaderOffset;
    ULONG       EntryPointRva;
    ULONGLONG   ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       Characteristics;
    ULONG       NumberOfSections;
    ULONG       SizeOfOptionalHeader;
    ULONG       DataDirectories[PDK_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    PDK_PE_SECTION Sections[PDK_MAX_PE_SECTIONS];
    ULONG       SectionCount;
    BOOLEAN     IsDotNet;
    ULONGLONG   OverlayOffset;
    ULONGLONG   OverlaySize;
    BOOLEAN     Parsed;
} PDK_PE_CONTEXT;

/* 边界检查读 U16 */
static
BOOLEAN
PdkPeReadU16(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _In_ ULONG Offset,
    _Out_ USHORT* Value
    )
{
    if (Ctx == NULL || Value == NULL) return FALSE;
    if ((ULONGLONG)Offset + sizeof(USHORT) > Ctx->Size) return FALSE;
    *Value = *(const USHORT*)(Ctx->Buffer + Offset);
    return TRUE;
}

/* 边界检查读 U32 */
static
BOOLEAN
PdkPeReadU32(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _In_ ULONG Offset,
    _Out_ ULONG* Value
    )
{
    if (Ctx == NULL || Value == NULL) return FALSE;
    if ((ULONGLONG)Offset + sizeof(ULONG) > Ctx->Size) return FALSE;
    *Value = *(const ULONG*)(Ctx->Buffer + Offset);
    return TRUE;
}

/* 边界检查读缓冲 */
static
BOOLEAN
PdkPeReadBytes(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _In_ ULONG Offset,
    _Out_writes_(Count) BYTE* Out,
    _In_ ULONG Count
    )
{
    if (Ctx == NULL || Out == NULL) return FALSE;
    if ((ULONGLONG)Offset + (ULONGLONG)Count > Ctx->Size) return FALSE;
    memcpy(Out, Ctx->Buffer + Offset, Count);
    return TRUE;
}

/*++
 * PdkPeParse
 *   解析 PE 缓冲到上下文：校验 MZ/PE 签名、节表（≤PDK_MAX_PE_SECTIONS，
 *   超出节仍计入 NumberOfSections 供聚合统计）、数据目录、.NET 标志、
 *   Overlay 区间（SizeOfHeaders + Σ RawSize 对齐文件尾）。
 *--*/
static
BOOLEAN
PdkPeParse(
    _In_reads_bytes_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size,
    _Out_ PDK_PE_CONTEXT* Ctx
    )
{
    USHORT dosMagic;
    ULONG  peOffset;
    ULONG  ntSignature;
    USHORT machine;
    USHORT numSections;
    USHORT sizeOfOptional;
    ULONG  sectionTableOff;
    ULONG  optBase;
    ULONG  i;
    ULONGLONG rawEnd;

    if (Buffer == NULL || Size < sizeof(IMAGE_DOS_HEADER) || Ctx == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Ctx, sizeof(*Ctx));
    Ctx->Buffer = Buffer;
    Ctx->Size = Size;

    dosMagic = *(const USHORT*)Buffer;
    if (dosMagic != PDK_IMAGE_DOS_SIGNATURE) return FALSE;

    peOffset = *(const ULONG*)(Buffer + 0x3C);          /* e_lfanew */
    if ((ULONGLONG)peOffset + 4 + 20 > Size) return FALSE;

    ntSignature = *(const ULONG*)(Buffer + peOffset);
    if (ntSignature != PDK_IMAGE_NT_SIGNATURE) return FALSE;

    machine = *(const USHORT*)(Buffer + peOffset + 4);
    numSections = *(const USHORT*)(Buffer + peOffset + 6);
    sizeOfOptional = *(const USHORT*)(Buffer + peOffset + 20);

    /* 可选头字段（32 位） */
    if (sizeOfOptional < 96) return FALSE;

    optBase = peOffset + 24;
    Ctx->NtHeaderOffset = peOffset;
    Ctx->Machine = machine;
    Ctx->Is64Bit = (machine == PDK_IMAGE_FILE_MACHINE_AMD64);
    Ctx->Characteristics = *(const USHORT*)(Buffer + peOffset + 22);
    Ctx->SizeOfOptionalHeader = sizeOfOptional;

    if (Ctx->Is64Bit) {
        if (sizeOfOptional < 112) return FALSE;
        Ctx->EntryPointRva = *(const ULONG*)(Buffer + optBase + 16);
        Ctx->ImageBase     = *(const ULONGLONG*)(Buffer + optBase + 24);
        Ctx->SectionAlignment = *(const ULONG*)(Buffer + optBase + 32);
        Ctx->FileAlignment    = *(const ULONG*)(Buffer + optBase + 36);
        Ctx->SizeOfImage      = *(const ULONG*)(Buffer + optBase + 56);
        Ctx->SizeOfHeaders    = *(const ULONG*)(Buffer + optBase + 60);
        memcpy(Ctx->DataDirectories, Buffer + optBase + 112, sizeof(Ctx->DataDirectories));
    } else {
        Ctx->EntryPointRva = *(const ULONG*)(Buffer + optBase + 16);
        Ctx->ImageBase     = *(const ULONG*)(Buffer + optBase + 28);
        Ctx->SectionAlignment = *(const ULONG*)(Buffer + optBase + 32);
        Ctx->FileAlignment    = *(const ULONG*)(Buffer + optBase + 36);
        Ctx->SizeOfImage      = *(const ULONG*)(Buffer + optBase + 56);
        Ctx->SizeOfHeaders    = *(const ULONG*)(Buffer + optBase + 60);
        memcpy(Ctx->DataDirectories, Buffer + optBase + 96, sizeof(Ctx->DataDirectories));
    }

    /* .NET 标志：目录 14（COM 描述符）非空 */
    Ctx->IsDotNet = (Ctx->DataDirectories[PDK_DIRECTORY_COM_DESCRIPTOR] != 0);

    /* 节表 */
    sectionTableOff = optBase + sizeOfOptional;
    Ctx->NumberOfSections = numSections;
    if (numSections > PDK_MAX_PE_SECTIONS) {
        Ctx->SectionCount = PDK_MAX_PE_SECTIONS;
    } else {
        Ctx->SectionCount = numSections;
    }

    for (i = 0; i < Ctx->SectionCount; ++i) {
        const BYTE* raw = Buffer + sectionTableOff + (SIZE_T)i * 40;
        PDK_PE_SECTION* sec = &Ctx->Sections[i];
        ULONG chars;

        if ((ULONGLONG)sectionTableOff + (SIZE_T)(i + 1) * 40 > Size) {
            Ctx->SectionCount = i;   /* 截断非法节表 */
            break;
        }

        memcpy(sec->Name, raw, 8);
        sec->Name[8] = '\0';
        sec->VirtualSize   = *(const ULONG*)(raw + 8);
        sec->VirtualAddress = *(const ULONG*)(raw + 12);
        sec->RawSize       = *(const ULONG*)(raw + 16);
        sec->RawAddress    = *(const ULONG*)(raw + 20);
        chars = *(const ULONG*)(raw + 36);
        sec->Characteristics = chars;
        sec->IsExecutable = (chars & PDK_IMAGE_SCN_MEM_EXECUTE) != 0;
        sec->IsWritable   = (chars & PDK_IMAGE_SCN_MEM_WRITE) != 0;
        sec->IsReadable   = (chars & PDK_IMAGE_SCN_MEM_READ) != 0;
        sec->HasCode      = (chars & PDK_IMAGE_SCN_CNT_CODE) != 0;
        sec->HasInitializedData = (chars & PDK_IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
    }

    /* Overlay：从 SizeOfHeaders 与各节 Raw 末端取最大者到文件尾 */
    rawEnd = Ctx->SizeOfHeaders;
    for (i = 0; i < Ctx->SectionCount; ++i) {
        ULONGLONG end = (ULONGLONG)Ctx->Sections[i].RawAddress + Ctx->Sections[i].RawSize;
        if (end > rawEnd) rawEnd = end;
    }
    if (rawEnd < Size) {
        Ctx->OverlayOffset = rawEnd;
        Ctx->OverlaySize = Size - rawEnd;
    }

    Ctx->Parsed = TRUE;
    return TRUE;
}

/* RVA → 文件偏移（按节区段） */
static
BOOLEAN
PdkPeRvaToOffset(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _In_ ULONG Rva,
    _Out_ ULONG* FileOffset
    )
{
    ULONG i;

    if (Ctx == NULL || FileOffset == NULL) return FALSE;

    for (i = 0; i < Ctx->SectionCount; ++i) {
        const PDK_PE_SECTION* sec = &Ctx->Sections[i];
        ULONGLONG vaEnd = (ULONGLONG)sec->VirtualAddress + sec->VirtualSize;
        if (Rva >= sec->VirtualAddress && Rva < vaEnd) {
            ULONGLONG delta = (ULONGLONG)Rva - sec->VirtualAddress;
            if (delta >= sec->RawSize) return FALSE;   /* 落在未映射区 */
            *FileOffset = sec->RawAddress + (ULONG)delta;
            return TRUE;
        }
    }
    return FALSE;
}

/* 定位节（可空查包含指定 RVA 的节索引），返回是否落在代码节 */
static
BOOLEAN
PdkPeSectionForRva(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _In_ ULONG Rva,
    _Out_opt_ ULONG* SectionIndex
    )
{
    ULONG i;

    if (Ctx == NULL) return FALSE;

    for (i = 0; i < Ctx->SectionCount; ++i) {
        const PDK_PE_SECTION* sec = &Ctx->Sections[i];
        ULONGLONG vaEnd = (ULONGLONG)sec->VirtualAddress + sec->VirtualSize;
        if (Rva >= sec->VirtualAddress && Rva < vaEnd) {
            if (SectionIndex != NULL) *SectionIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

/* 节名小写比较辅助 */
static
BOOLEAN
PdkSectionNameEquals(
    _In_ PCSTR SectionName,
    _In_ PCSTR LowerPattern
    )
{
    SIZE_T i;

    for (i = 0; i < 8; ++i) {
        char c = SectionName[i];
        char p = LowerPattern[i];

        if (c == '\0' && p == '\0') return TRUE;
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        if (c != p) return FALSE;
        if (c == '\0') return TRUE;
    }
    return TRUE;
}

/**************************************************/
/*          导入表解析                             */
/**************************************************/

/* 关键 API 名称表（动态解析特征） */
static const char* const g_PdkSuspiciousImportNames[] = {
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtCreateThreadEx",
    "RtlDecompressBuffer",
    "RtlDecompressFragment",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtSetInformationThread"
};

/*++
 * PdkPeParseImports
 *   解析导入表：DLL 名收集、关键 API 探测、总数统计。
 *   结果上限：PDK_MAX_DLLS / PDK_MAX_SUSPICIOUS_IMPORTS。
 *--*/
static
VOID
PdkPeParseImports(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_IMPORT_INFO* Out
    )
{
    ULONG importDirRva;
    ULONG importDirSize;
    ULONG offset;
    ULONG numDirs;
    ULONG i;

    if (Ctx == NULL || Out == NULL) return;
    if (!Ctx->Parsed) return;

    importDirRva = Ctx->DataDirectories[1];
    importDirSize = Ctx->DataDirectories[2];
    if (importDirRva == 0 || importDirSize == 0) return;

    if (!PdkPeRvaToOffset(Ctx, importDirRva, &offset)) return;
    numDirs = importDirSize / 20;
    if (numDirs == 0) return;

    for (i = 0; i < numDirs; ++i) {
        ULONG descOff = offset + i * 20;
        ULONG nameRva;
        ULONG nameOff;
        ULONG iatRva;
        ULONG thunkOff;
        ULONG thunkCount;
        SIZE_T dllIdx;

        if ((ULONGLONG)descOff + 20 > Ctx->Size) break;

        /* IMAGE_IMPORT_DESCRIPTOR: Name@12, FirstThunk@16 */
        nameRva = *(const ULONG*)(Ctx->Buffer + descOff + 12);
        iatRva  = *(const ULONG*)(Ctx->Buffer + descOff + 16);
        if (nameRva == 0) break;   /* 目录结束 */

        if (Out->DllCount >= PDK_MAX_DLLS) break;
        if (!PdkPeRvaToOffset(Ctx, nameRva, &nameOff)) continue;
        if ((ULONGLONG)nameOff + 1 > Ctx->Size) continue;

        {
            const char* dllName = (const char*)(Ctx->Buffer + nameOff);
            PDK_STR_COPY(Out->Dlls[Out->DllCount], 64, dllName);
            Out->DllCount++;
        }
        dllIdx = Out->DllCount - 1;

        /* 遍历 thunk 表统计导入函数（上限保护） */
        if (!PdkPeRvaToOffset(Ctx, iatRva, &thunkOff)) continue;
        thunkCount = 0;
        for (;;) {
            ULONG64 entry;

            if ((ULONGLONG)thunkOff + 8 > Ctx->Size) break;
            if (Ctx->Is64Bit) {
                entry = *(const ULONGLONG*)(Ctx->Buffer + thunkOff);
            } else {
                entry = *(const ULONG*)(Ctx->Buffer + thunkOff);
            }
            if (entry == 0) break;                     /* 数组结束 */
            thunkOff += Ctx->Is64Bit ? 8 : 4;
            thunkCount++;
            if (thunkCount > 100000) break;            /* 防御异常表 */

            /* 按名称导入？（最高位置 0 表示序号导入） */
            if ((entry & ((Ctx->Is64Bit) ? 0x8000000000000000ULL : 0x80000000ULL)) == 0) {
                ULONG hintNameRva = (ULONG)(entry & 0x7FFFFFFF);
                ULONG hintNameOff;
                const char* funcName;

                if (!PdkPeRvaToOffset(Ctx, hintNameRva, &hintNameOff)) continue;
                if ((ULONGLONG)hintNameOff + 2 > Ctx->Size) continue;
                funcName = (const char*)(Ctx->Buffer + hintNameOff + 2); /* 跳过 Hint */

                /* 可疑 API 名称匹配 */
                if (Out->SuspiciousImportCount < PDK_MAX_SUSPICIOUS_IMPORTS) {
                    SIZE_T k;
                    for (k = 0; k < PDK_ARRAY_COUNT(g_PdkSuspiciousImportNames); ++k) {
                        if (_stricmp(funcName, g_PdkSuspiciousImportNames[k]) == 0) {
                            MultiByteToWideChar(CP_ACP, 0, funcName, -1,
                                Out->SuspiciousImports[Out->SuspiciousImportCount], PDK_MAX_NAME);
                            Out->SuspiciousImportCount++;
                            break;
                        }
                    }
                }

                if (strcmp(funcName, "GetProcAddress") == 0) {
                    Out->HasGetProcAddress = TRUE;
                } else if (strcmp(funcName, "LoadLibraryA") == 0 ||
                           strcmp(funcName, "LoadLibraryW") == 0) {
                    Out->HasLoadLibrary = TRUE;
                } else if (strcmp(funcName, "VirtualAlloc") == 0 ||
                           strcmp(funcName, "VirtualProtect") == 0) {
                    Out->HasVirtualMemoryApis = TRUE;
                }
            }
        }

        Out->TotalImports += thunkCount;
    }

    Out->Valid = TRUE;
    Out->HasMinimalImports = (Out->TotalImports < PDK_MIN_NORMAL_IMPORTS);

    if (Out->HasMinimalImports) {
        /* 指示器由上层添加 */
    }
}

/**************************************************/
/*          Rich 头解析（对齐源 PEParser）         */
/**************************************************/

#define PDK_RICH_SIGNATURE  0x68636952  /* 'Rich' */
#define PDK_DANS_SIGNATURE  0x536E6144  /* 'DanS' */
#define PDK_MAX_RICH_SEARCH_BYTES 4096

/*++
 * PdkPeParseRichHeader
 *   反向搜索 "Rich"（窗口 ≤4KB，防 e_lfanew 放大攻击），
 *   XOR key 还原 DanS 与条目（buildId/productId/useCount）。
 *--*/
static
VOID
PdkPeParseRichHeader(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_RICH_HEADER_INFO* Out
    )
{
    ULONG searchEnd;
    ULONG i;
    ULONG richOff = 0;
    ULONG xorKey = 0;
    ULONG dansOff = 0;
    size_t entryOff;

    if (Ctx == NULL || Out == NULL || !Ctx->Parsed) return;
    if (Ctx->NtHeaderOffset < 8) {
        Out->Valid = TRUE;
        return;   /* 无 Rich 头空间 */
    }

    /* 搜索窗口：DOS 头 64 字节 + 4KB 上限，且不越过 NT 头 */
    searchEnd = Ctx->NtHeaderOffset;
    if (searchEnd > 64 + PDK_MAX_RICH_SEARCH_BYTES) {
        searchEnd = 64 + PDK_MAX_RICH_SEARCH_BYTES;
    }

    for (i = searchEnd; i >= 68; --i) {
        ULONG val;
        if (!PdkPeReadU32(Ctx, i - 4, &val)) continue;
        if (val == PDK_RICH_SIGNATURE) {
            richOff = i - 4;
            break;
        }
    }
    if (richOff == 0) {
        Out->Valid = TRUE;
        return;
    }

    if (!PdkPeReadU32(Ctx, richOff + 4, &xorKey)) {
        Out->Valid = TRUE;
        return;
    }

    Out->HasRichHeader = TRUE;
    Out->Checksum = xorKey;

    /* 反向找 DanS（XOR 后） */
    for (i = richOff; i >= 68; i -= 4) {
        ULONG val;
        if (!PdkPeReadU32(Ctx, i - 4, &val)) continue;
        if ((val ^ xorKey) == PDK_DANS_SIGNATURE) {
            dansOff = i - 4;
            break;
        }
    }
    if (dansOff == 0) {
        Out->IsCorrupted = TRUE;
        Out->Valid = TRUE;
        return;
    }

    /* 条目：DanS + 3 个填充 DWORD 之后 */
    entryOff = (size_t)dansOff + 16;
    while (entryOff + 8 <= richOff && Out->EntryCount < PDK_MAX_RICH_ENTRIES) {
        ULONG id;
        ULONG count;

        if (!PdkPeReadU32(Ctx, (ULONG)entryOff, &id) ||
            !PdkPeReadU32(Ctx, (ULONG)entryOff + 4, &count)) {
            break;
        }
        id ^= xorKey;
        count ^= xorKey;
        if (id == 0 && count == 0) break;

        Out->Entries[Out->EntryCount].BuildNumber = (USHORT)(id >> 16);
        Out->Entries[Out->EntryCount].ProductId = (USHORT)(id & 0xFFFF);
        Out->Entries[Out->EntryCount].UseCount = count;
        swprintf_s(Out->Entries[Out->EntryCount].Description, 64,
            L"Build %u / Product 0x%04X", (id >> 16), (id & 0xFFFF));
        Out->EntryCount++;
        entryOff += 8;
    }

    Out->Valid = TRUE;
}

/**************************************************/
/*          资源解析（三级目录遍历聚合）            */
/**************************************************/

#define PDK_MAX_RESOURCE_VISITS 4096

/* 遍历资源目录（深度受限） */
static
VOID
PdkPeWalkResourceDir(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _In_ ULONG DirOffset,
    _In_ INT Depth,
    _Inout_ ULONG* Visited,
    _Inout_ PDK_RESOURCE_INFO* Out
    )
{
    ULONG numNamed;
    ULONG numId;
    ULONG total;
    ULONG i;

    if (Depth > 4 || DirOffset == 0 || *Visited >= PDK_MAX_RESOURCE_VISITS) return;
    if ((ULONGLONG)DirOffset + 16 > Ctx->Size) return;
    if (!PdkPeReadU32(Ctx, DirOffset, &numNamed)) return;
    if (!PdkPeReadU32(Ctx, DirOffset + 4, &numId)) return;

    total = numNamed + numId;
    if (total > 4096) total = 4096;   /* 防御恶意条目数 */
    if ((ULONGLONG)DirOffset + 16 + (ULONGLONG)total * 8 > Ctx->Size) return;

    for (i = 0; i < total; ++i) {
        ULONG entryOff = DirOffset + 16 + i * 8;
        ULONG nameRva;
        ULONG child;

        (*Visited)++;
        if (*Visited >= PDK_MAX_RESOURCE_VISITS) return;

        if (!PdkPeReadU32(Ctx, entryOff, &nameRva) ||
            !PdkPeReadU32(Ctx, entryOff + 4, &child)) {
            return;
        }

        if (nameRva & 0x80000000) {
            /* 命名资源：取名称字符串（可选） */
            ULONG strOff;
            if (PdkPeRvaToOffset(Ctx, nameRva & 0x7FFFFFFF, &strOff)) {
                /* 收集语言标识时使用（此处忽略名称细节） */
                (void)strOff;
            }
        } else {
            USHORT langId = (USHORT)(nameRva & 0xFFFF);
            if (Depth == 3) {
                /* 第三级 = 语言 */
                if (Out->LanguageCount < PDK_MAX_RES_LANGUAGES) {
                    Out->Languages[Out->LanguageCount++] = langId;
                }
            }
        }

        if (child & 0x80000000) {
            /* 叶子：数据条目 */
            ULONG dataOff;
            ULONG size;
            ULONG dataRva;

            if (!PdkPeRvaToOffset(Ctx, child & 0x7FFFFFFF, &dataOff)) continue;
            if ((ULONGLONG)dataOff + 16 > Ctx->Size) continue;
            if (!PdkPeReadU32(Ctx, dataOff, &dataRva)) continue;
            if (!PdkPeReadU32(Ctx, dataOff + 4, &size)) continue;
            if (!PdkPeRvaToOffset(Ctx, dataRva, &dataOff)) continue;

            /* 聚合统计 */
            Out->Count++;
            Out->TotalSize += size;
            if ((ULONGLONG)size > Out->LargestResourceSize) {
                Out->LargestResourceSize = (ULONGLONG)size;
            }

            /* 熵聚合 + 高熵资源统计（仅限边界有效且 >= 最小分析大小） */
            if (size >= PDK_MIN_SECTION_ENTROPY_BYTES &&
                (ULONGLONG)dataOff + (ULONGLONG)size <= Ctx->Size) {
                DOUBLE resEntropy = PkdCalculateEntropy(Ctx->Buffer + dataOff, (SIZE_T)size);
                Out->AverageEntropy += resEntropy;
                Out->ResourceEntropyCount++;
                if (resEntropy >= PDK_HIGH_SECTION_ENTROPY) {
                    Out->HighEntropyCount++;
                    if (Out->SuspiciousCount < PDK_MAX_SUSPICIOUS_RES) {
                        _snwprintf_s(Out->SuspiciousResources[Out->SuspiciousCount], PDK_MAX_DESC,
                            _TRUNCATE, L"High-entropy resource (%u bytes, entropy %.2f)",
                            size, resEntropy);
                        Out->SuspiciousCount++;
                    }
                }
            }
        } else {
            /* 子目录 */
            ULONG subOff;
            if (PdkPeRvaToOffset(Ctx, child & 0x7FFFFFFF, &subOff)) {
                PdkPeWalkResourceDir(Ctx, subOff, Depth + 1, Visited, Out);
            }
        }
    }
}

/*++
 * PdkPeParseResources
 *   从目录 2（资源）解析资源树，聚合统计。
 *--*/
static
VOID
PdkPeParseResources(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_RESOURCE_INFO* Out
    )
{
    ULONG resDirRva;
    ULONG resDirOff;
    ULONG visited = 0;

    if (Ctx == NULL || Out == NULL || !Ctx->Parsed) return;

    resDirRva = Ctx->DataDirectories[2];
    if (resDirRva == 0) {
        Out->Valid = TRUE;
        return;
    }
    if (!PdkPeRvaToOffset(Ctx, resDirRva, &resDirOff)) {
        Out->Valid = TRUE;
        return;
    }

    PdkPeWalkResourceDir(Ctx, resDirOff, 0, &visited, Out);

    if (Out->ResourceEntropyCount > 0) {
        Out->AverageEntropy /= (DOUBLE)Out->ResourceEntropyCount;
        Out->ResourceEntropyCount = 0;
    }
    Out->Valid = TRUE;
}

/**************************************************/
/*          分析模块                               */
/**************************************************/

/*++
 * PdkCalculateEntropy
 *   Shannon 熵（对齐源 CalculateEntropy）。
 *--*/
DOUBLE
PkdCalculateEntropy(
    _In_reads_bytes_opt_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size
    )
{
    ULONG freq[256];
    DOUBLE entropy;
    DOUBLE total;
    SIZE_T i;

    if (Buffer == NULL || Size == 0) {
        return 0.0;
    }

    RtlZeroMemory(freq, sizeof(freq));
    for (i = 0; i < Size; ++i) {
        freq[Buffer[i]]++;
    }

    entropy = 0.0;
    total = (DOUBLE)Size;
    for (i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            DOUBLE p = (DOUBLE)freq[i] / total;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* 卡方检验（对齐源 CalculateChiSquared） */
static
DOUBLE
PdkCalculateChiSquared(
    _In_reads_bytes_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size
    )
{
    ULONG freq[256];
    DOUBLE expected;
    DOUBLE chi;
    SIZE_T i;

    if (Buffer == NULL || Size == 0) return 0.0;

    RtlZeroMemory(freq, sizeof(freq));
    for (i = 0; i < Size; ++i) {
        freq[Buffer[i]]++;
    }

    expected = (DOUBLE)Size / 256.0;
    chi = 0.0;
    for (i = 0; i < 256; ++i) {
        DOUBLE diff = (DOUBLE)freq[i] - expected;
        chi += (diff * diff) / expected;
    }
    return chi;
}

/*++
 * PdkAnalyzeEntropyInternal
 *  文件熵 + 各节熵聚合：压缩/加密判定（对齐源 L2372-2432）。
 *--*/
static
VOID
PdkAnalyzeEntropyInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    DOUBLE totalEntropy = 0.0;
    SIZE_T entropyCount = 0;
    ULONG i;

    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    Result->FileEntropy = PkdCalculateEntropy(Ctx->Buffer, Ctx->Size);
    Result->ChiSquared = PdkCalculateChiSquared(Ctx->Buffer, Ctx->Size);

    for (i = 0; i < Ctx->SectionCount; ++i) {
        const PDK_PE_SECTION* sec = &Ctx->Sections[i];

        /* 溢出安全边界检查 */
        if (sec->RawSize >= PDK_MIN_SECTION_ENTROPY_BYTES &&
            (ULONGLONG)sec->RawAddress <= Ctx->Size &&
            (ULONGLONG)sec->RawSize <= Ctx->Size - sec->RawAddress) {

            DOUBLE secEntropy = PkdCalculateEntropy(
                Ctx->Buffer + sec->RawAddress, sec->RawSize);

            if (secEntropy > Result->MaxSectionEntropy) {
                Result->MaxSectionEntropy = secEntropy;
                PDK_STR_COPY(Result->MaxEntropySectionName, 16, sec->Name);
            }

            totalEntropy += secEntropy;
            entropyCount++;

            if (sec->HasCode) {
                Result->CodeSectionEntropy = secEntropy;
            } else if (sec->HasInitializedData) {
                Result->DataSectionEntropy = secEntropy;
            }

            if (secEntropy >= PDK_HIGH_SECTION_ENTROPY) {
                Result->HighEntropySectionCount++;
            }
        }
    }

    if (entropyCount > 0) {
        Result->AverageSectionEntropy = totalEntropy / (DOUBLE)entropyCount;
    }

    Result->EntropyIndicatesCompression =
        (Result->FileEntropy >= PDK_MIN_COMPRESSED_ENTROPY &&
         Result->FileEntropy < PDK_MIN_ENCRYPTED_ENTROPY);

    Result->EntropyIndicatesEncryption =
        (Result->FileEntropy >= PDK_MIN_ENCRYPTED_ENTROPY);

    if (Result->EntropyIndicatesEncryption) {
        WCHAR tmp[96];
        _snwprintf_s(tmp, 96, _TRUNCATE, L"Very high entropy (%.2f) indicates encryption",
            Result->FileEntropy);
        PdkAddIndicator(Result, tmp);
    } else if (Result->EntropyIndicatesCompression) {
        WCHAR tmp[96];
        _snwprintf_s(tmp, 96, _TRUNCATE, L"High entropy (%.2f) indicates compression",
            Result->FileEntropy);
        PdkAddIndicator(Result, tmp);
    }
}

/*++
 * PdkAnalyzeSectionsInternal
 *  节表分析：熵/W+X/空节/已知加壳器节名/非标准节（对齐源 L2453-2531）。
 *  聚合统计对所有节生效；明细仅保留前 PDK_MAX_SECTIONS。
 *--*/
static
VOID
PdkAnalyzeSectionsInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    ULONG i;
    WCHAR tmp[128];
    BOOLEAN isStandard;

    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    Result->SectionCountRaw = Ctx->NumberOfSections;
    Result->SectionCount = 0;

    for (i = 0; i < Ctx->SectionCount; ++i) {
        const PDK_PE_SECTION* peSec = &Ctx->Sections[i];
        PDK_SECTION_INFO* sec;
        SIZE_T k;

        if (Result->SectionCount < PDK_MAX_SECTIONS) {
            sec = &Result->Sections[Result->SectionCount];
            RtlZeroMemory(sec, sizeof(*sec));
            PDK_STR_COPY(sec->Name, 16, peSec->Name);
            sec->VirtualAddress = peSec->VirtualAddress;
            sec->VirtualSize = peSec->VirtualSize;
            sec->RawSize = peSec->RawSize;
            sec->RawDataPointer = peSec->RawAddress;
            sec->Characteristics = peSec->Characteristics;
            sec->IsExecutable = peSec->IsExecutable;
            sec->IsWritable = peSec->IsWritable;
            sec->IsReadable = peSec->IsReadable;
            sec->IsEmpty = (peSec->VirtualSize > 0 && peSec->RawSize == 0);
        } else {
            sec = NULL;   /* 超出明细上限：仅统计 */
        }

        if (peSec->IsExecutable) Result->ExecutableSectionCount++;
        if (peSec->IsWritable) Result->WritableSectionCount++;

        if (peSec->RawSize >= PDK_MIN_SECTION_ENTROPY_BYTES &&
            (ULONGLONG)peSec->RawAddress <= Ctx->Size &&
            (ULONGLONG)peSec->RawSize <= Ctx->Size - peSec->RawAddress) {
            DOUBLE entropy = PkdCalculateEntropy(
                Ctx->Buffer + peSec->RawAddress, peSec->RawSize);
            if (sec != NULL) {
                sec->Entropy = entropy;
                sec->HasHighEntropy = (entropy >= PDK_HIGH_SECTION_ENTROPY);
            }
        }

        /* 已知加壳器节名匹配（小写） */
        for (k = 0; k < PDK_ARRAY_COUNT(g_PdkKnownPackerSections); ++k) {
            if (PdkSectionNameEquals(peSec->Name, g_PdkKnownPackerSections[k])) {
                Result->PackerSectionMatches++;
                if (sec != NULL) {
                    sec->IsPackerSection = TRUE;
                    PDK_STR_COPY(sec->MatchedPackerName, 16, g_PdkKnownPackerSections[k]);
                }
                break;
            }
        }

        /* 自定义节名模式（读锁保护，命中生成 EP 签名级匹配记录语义由判定吸收） */
        if (!peSec->IsPackerSection) {
            SIZE_T cs;
            AcquireSRWLockShared(&g_PdkLock);
            for (cs = 0; cs < g_PdkCustomSectionCount; ++cs) {
                if (PdkSectionNameEquals(peSec->Name,
                        g_PdkCustomSections[cs].Name)) {
                    Result->PackerSectionMatches++;
                    if (sec != NULL) {
                        sec->IsPackerSection = TRUE;
                        PDK_STR_COPY(sec->MatchedPackerName, 16,
                            g_PdkCustomSections[cs].Name);
                    }
                    break;
                }
            }
            ReleaseSRWLockShared(&g_PdkLock);
        }

        if (peSec->IsExecutable && peSec->IsWritable) {
            Result->HasWritableCodeSections = TRUE;
            if (sec != NULL && sec->AnomalyCount < PDK_MAX_SEC_ANOMALIES) {
                PDK_WCS_COPY(sec->Anomalies[sec->AnomalyCount], PDK_MAX_DESC,
                    L"Section is both writable and executable");
                sec->AnomalyCount++;
            }
        }

        /* 标准节判定 */
        isStandard = (PdkSectionNameEquals(peSec->Name, ".text") ||
                      PdkSectionNameEquals(peSec->Name, ".data") ||
                      PdkSectionNameEquals(peSec->Name, ".rdata") ||
                      PdkSectionNameEquals(peSec->Name, ".bss") ||
                      PdkSectionNameEquals(peSec->Name, ".idata") ||
                      PdkSectionNameEquals(peSec->Name, ".edata") ||
                      PdkSectionNameEquals(peSec->Name, ".rsrc") ||
                      PdkSectionNameEquals(peSec->Name, ".reloc") ||
                      PdkSectionNameEquals(peSec->Name, ".tls") ||
                      PdkSectionNameEquals(peSec->Name, "code") ||
                      PdkSectionNameEquals(peSec->Name, "data"));
        if (!isStandard) {
            Result->HasNonStandardSections = TRUE;
        }

        if (sec != NULL) {
            Result->SectionCount++;
        }
    }

    if (Result->PackerSectionMatches > 0) {
        _snwprintf_s(tmp, 128, _TRUNCATE, L"%u known packer section(s) detected",
            Result->PackerSectionMatches);
        PdkAddIndicator(Result, tmp);
    }

    if (Result->HasWritableCodeSections) {
        PdkAddIndicator(Result, L"Writable and executable sections detected");
        PdkAddAnomaly(Result, L"W+X sections present");
    }

    if (Result->HighEntropySectionCount > 0) {
        _snwprintf_s(tmp, 128, _TRUNCATE, L"%lu high-entropy section(s)",
            Result->HighEntropySectionCount);
        PdkAddIndicator(Result, tmp);
    }
}

/*++
 * PdkMatchEPSignatureInternal
 *  内置 + 自定义 EP 签名比对（掩码逐字节），取置信度最高者（对齐源 L3215-3264）。
 *--*/
static
BOOLEAN
PdkMatchEPSignatureInternal(
    _In_reads_bytes_(Size) const BYTE* EpBytes,
    _In_ SIZE_T Size,
    _Out_ PDK_PACKER_MATCH* Best
    )
{
    const PDK_EP_SIGNATURE* sig;
    SIZE_T sigIdx;
    BOOLEAN found = FALSE;
    DOUBLE bestConfidence = 0.0;

    if (EpBytes == NULL || Size == 0 || Best == NULL) return FALSE;

    /* 内置签名 */
    for (sigIdx = 0; sigIdx < PDK_BUILTIN_SIGNATURE_COUNT; ++sigIdx) {
        sig = &g_PdkBuiltInSignatures[sigIdx];
        if (sig->PatternSize > Size) continue;

        {
            SIZE_T k;
            BOOLEAN matched = TRUE;
            for (k = 0; k < sig->PatternSize; ++k) {
                BYTE maskByte = (k < sig->PatternSize) ? sig->Mask[k] : 0xFF;
                if ((EpBytes[k] & maskByte) != (sig->Pattern[k] & maskByte)) {
                    matched = FALSE;
                    break;
                }
            }
            if (matched && sig->Confidence > bestConfidence) {
                RtlZeroMemory(Best, sizeof(*Best));
                Best->PackerType = sig->PackerType;
                Best->Category = PdkGetCategory(sig->PackerType);
                Best->Method = PDK_METHOD_EP_SIGNATURE;
                Best->Confidence = sig->Confidence;
                bestConfidence = sig->Confidence;
                PDK_WCS_COPY(Best->PackerName, PDK_MAX_NAME, sig->Name);
                PDK_WCS_COPY(Best->Version, 64, sig->Version);
                Best->Severity = PdkGetSeverity(sig->PackerType);
                PDK_STR_COPY(Best->MitreId, 16, PdkTypeToMitreId(sig->PackerType));
                found = TRUE;
            }
        }
    }

    /* 自定义签名（读锁保护） */
    AcquireSRWLockShared(&g_PdkLock);
    for (sigIdx = 0; sigIdx < g_PdkCustomSigCount; ++sigIdx) {
        sig = &g_PdkCustomSigs[sigIdx];
        if (sig->PatternSize > Size) continue;

        {
            SIZE_T k;
            BOOLEAN matched = TRUE;
            for (k = 0; k < sig->PatternSize; ++k) {
                BYTE maskByte = (k < sig->PatternSize) ? sig->Mask[k] : 0xFF;
                if ((EpBytes[k] & maskByte) != (sig->Pattern[k] & maskByte)) {
                    matched = FALSE;
                    break;
                }
            }
            if (matched && sig->Confidence > bestConfidence) {
                RtlZeroMemory(Best, sizeof(*Best));
                Best->PackerType = sig->PackerType;
                Best->Category = PdkGetCategory(sig->PackerType);
                Best->Method = PDK_METHOD_EP_SIGNATURE;
                Best->Confidence = sig->Confidence;
                bestConfidence = sig->Confidence;
                PDK_WCS_COPY(Best->PackerName, PDK_MAX_NAME, sig->Name);
                PDK_WCS_COPY(Best->Version, 64, sig->Version);
                Best->Severity = PdkGetSeverity(sig->PackerType);
                PDK_STR_COPY(Best->MitreId, 16, PdkTypeToMitreId(sig->PackerType));
                found = TRUE;
            }
        }
    }
    ReleaseSRWLockShared(&g_PdkLock);

    return found;
}

/*++
 * PdkAddMatch
 *  回调拷贝到锁外调用，匹配压入结果（对齐源 L3266-3291）。
 *--*/
static
VOID
PdkAddMatch(
    _Inout_ PDK_PACKING_INFO* Result,
    _In_ const PDK_PACKER_MATCH* Match
    )
{
    PKD_DETECTION_CALLBACK callbackCopy = NULL;

    if (Result == NULL || Match == NULL) return;

    /* 锁内拷贝回调，锁外调用（防死锁） */
    AcquireSRWLockShared(&g_PdkLock);
    if (g_PdkCallback != NULL && Result->FilePath[0] != L'\0') {
        callbackCopy = g_PdkCallback;
    }
    ReleaseSRWLockShared(&g_PdkLock);

    if (callbackCopy != NULL) {
        callbackCopy(Result->FilePath, Match);
    }

    if (Result->MatchCount < PDK_MAX_MATCHES) {
        Result->PackerMatches[Result->MatchCount] = *Match;
        Result->MatchCount++;
    }
}

/*++
 * PdkAnalyzeEntryPointInternal
 *  入口点定位/所在节/前导字节捕获/签名匹配（对齐源 L2533-2584）。
 *--*/
static
VOID
PdkAnalyzeEntryPointInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    ULONG epOff;
    SIZE_T bytesToRead;
    ULONG secIdx = 0;
    BOOLEAN inSection;

    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    Result->EntryPointInfo.Rva = Ctx->EntryPointRva;
    Result->EntryPointInfo.Valid = TRUE;

    if (!PdkPeRvaToOffset(Ctx, Ctx->EntryPointRva, &epOff) || epOff >= Ctx->Size) {
        Result->EpOutsideCodeSection = TRUE;
        PdkAddAnomaly(Result, L"Entry point outside valid sections");
        return;
    }

    Result->EntryPointInfo.FileOffset = epOff;
    Result->EntryPointInfo.IsInValidSection = TRUE;

    inSection = PdkPeSectionForRva(Ctx, Ctx->EntryPointRva, &secIdx);
    if (inSection) {
        PDK_PE_SECTION* sec = &Ctx->Sections[secIdx];
        PDK_STR_COPY(Result->EntryPointInfo.ContainingSection, 16, sec->Name);
        Result->EntryPointInfo.IsOutsideCodeSection = !sec->HasCode;

        if (secIdx == Ctx->SectionCount - 1) {
            PdkAddIndicator(Result, L"Entry point in last section (common packer pattern)");
        }
    }

    bytesToRead = (SIZE_T)PDK_MAX_EP_BYTES;
    if (bytesToRead > Ctx->Size - epOff) {
        bytesToRead = Ctx->Size - epOff;
    }

    if (bytesToRead > 0) {
        PDK_PACKER_MATCH match;

        Result->EntryPointInfo.EpBytesSize = (ULONG)bytesToRead;
        memcpy(Result->EntryPointInfo.EpBytes, Ctx->Buffer + epOff, bytesToRead);

        if (PdkMatchEPSignatureInternal(
                Result->EntryPointInfo.EpBytes,
                Result->EntryPointInfo.EpBytesSize,
                &match)) {
            Result->EntryPointInfo.MatchedPacker = match.PackerType;
            PDK_WCS_COPY(Result->EntryPointInfo.MatchedSignature, PDK_MAX_DESC, match.PackerName);
            Result->EntryPointInfo.MatchConfidence = match.Confidence;
            PdkAddMatch(Result, &match);
        }
    }
}

/*++
 * PdkAnalyzeImportsInternal
 *  导入分析聚合：关键 API/最小导入/动态解析模式（对齐源 L2586-2631）。
 *--*/
static
VOID
PdkAnalyzeImportsInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    WCHAR tmp[128];

    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    PdkPeParseImports(Ctx, &Result->ImportInfo);
    if (!Result->ImportInfo.Valid) return;

    Result->HasMinimalImports = Result->ImportInfo.HasMinimalImports;

    if (Result->HasMinimalImports) {
        _snwprintf_s(tmp, 128, _TRUNCATE, L"Minimal imports (%lu total)",
            (ULONG)Result->ImportInfo.TotalImports);
        PdkAddIndicator(Result, tmp);
    }

    if (Result->ImportInfo.HasGetProcAddress &&
        Result->ImportInfo.HasLoadLibrary &&
        Result->ImportInfo.TotalImports < 10) {
        PdkAddIndicator(Result, L"Dynamic API resolution pattern detected");
    }
}

/*++
 * PdkAnalyzeOverlayInternal
 *  Overlay 分析：魔数识别/熵/压缩加密判定（对齐源 L2633-2699）。
 *--*/
static
VOID
PdkAnalyzeOverlayInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    SIZE_T overlayClamped;
    SIZE_T bytesToCopy;
    SIZE_T overlayAnalyzeSize;
    WCHAR tmp[128];

    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    if (Ctx->OverlaySize == 0) {
        Result->OverlayInfo.Valid = TRUE;
        Result->OverlayInfo.HasOverlay = FALSE;
        return;
    }

    Result->OverlayInfo.Valid = TRUE;
    Result->OverlayInfo.HasOverlay = TRUE;
    Result->OverlayInfo.Offset = Ctx->OverlayOffset;
    Result->OverlayInfo.Size = Ctx->OverlaySize;
    Result->OverlayInfo.PercentageOfFile =
        ((DOUBLE)Ctx->OverlaySize / (DOUBLE)Ctx->Size) * 100.0;

    /* 魔数识别（含 4-15 字节小 Overlay 缺口修复） */
    overlayClamped = Ctx->OverlaySize;
    if (overlayClamped > Ctx->Size - Ctx->OverlayOffset) {
        overlayClamped = Ctx->Size - Ctx->OverlayOffset;
    }
    bytesToCopy = overlayClamped < 16 ? overlayClamped : 16;
    if (bytesToCopy > 0) {
        const BYTE* overlayData = Ctx->Buffer + Ctx->OverlayOffset;

        memcpy(Result->OverlayInfo.MagicBytes, overlayData, bytesToCopy);

        if (bytesToCopy >= 2 && overlayData[0] == 0x50 && overlayData[1] == 0x4B) {
            PDK_WCS_COPY(Result->OverlayInfo.DetectedFormat, 64, L"ZIP archive");
        } else if (bytesToCopy >= 4 && overlayData[0] == 0xEF && overlayData[1] == 0xBE &&
                   overlayData[2] == 0xAD && overlayData[3] == 0xDE) {
            PDK_WCS_COPY(Result->OverlayInfo.DetectedFormat, 64, L"NSIS data");
        } else if (bytesToCopy >= 4 && overlayData[0] == 0x52 && overlayData[1] == 0x61 &&
                   overlayData[2] == 0x72 && overlayData[3] == 0x21) {
            PDK_WCS_COPY(Result->OverlayInfo.DetectedFormat, 64, L"RAR archive");
        } else if (bytesToCopy >= 4 && overlayData[0] == 0x37 && overlayData[1] == 0x7A &&
                   overlayData[2] == 0xBC && overlayData[3] == 0xAF) {
            PDK_WCS_COPY(Result->OverlayInfo.DetectedFormat, 64, L"7-Zip archive");
        } else if (bytesToCopy >= 2 && overlayData[0] == 0x1F && overlayData[1] == 0x8B) {
            PDK_WCS_COPY(Result->OverlayInfo.DetectedFormat, 64, L"GZIP compressed");
        }
    }

    /* Overlay 熵（上限 PDK_MAX_OVERLAY_SIZE） */
    overlayAnalyzeSize = Ctx->OverlaySize;
    if (overlayAnalyzeSize > PDK_MAX_OVERLAY_SIZE) {
        overlayAnalyzeSize = (SIZE_T)PDK_MAX_OVERLAY_SIZE;
    }
    if (overlayAnalyzeSize >= PDK_MIN_SECTION_ENTROPY_BYTES &&
        Ctx->OverlayOffset <= Ctx->Size &&
        overlayAnalyzeSize <= Ctx->Size - Ctx->OverlayOffset) {
        Result->OverlayInfo.Entropy = PkdCalculateEntropy(
            Ctx->Buffer + Ctx->OverlayOffset, overlayAnalyzeSize);
        Result->OverlayInfo.IsCompressed =
            (Result->OverlayInfo.Entropy >= PDK_MIN_COMPRESSED_ENTROPY);
        Result->OverlayInfo.IsEncrypted =
            (Result->OverlayInfo.Entropy >= PDK_MIN_ENCRYPTED_ENTROPY);
    }

    if (Result->OverlayInfo.PercentageOfFile > PDK_SUSPICIOUS_OVERLAY_PERCENTAGE) {
        _snwprintf_s(tmp, 128, _TRUNCATE, L"Large overlay (%.1f%% of file)",
            Result->OverlayInfo.PercentageOfFile);
        PdkAddIndicator(Result, tmp);
    }
}

/*++
 * PdkAnalyzeRichHeaderInternal
 *  Rich 头分析（对齐源 L2701-2723）。
 *--*/
static
VOID
PdkAnalyzeRichHeaderInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    PdkPeParseRichHeader(Ctx, &Result->RichHeaderInfo);
}

/*++
 * PdkAnalyzeResourcesInternal
 *  资源聚合分析：数量/大小/高熵资源/语言（对齐源 L2725-2762）。
 *--*/
static
VOID
PdkAnalyzeResourcesInternal(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    PdkPeParseResources(Ctx, &Result->ResourceInfo);
}

/**************************************************/
/*          轻量 x86 指令解码器（反汇编降级）       */
/*  仅用于 Stub 统计：长度推进 + 类别分类。         */
/**************************************************/

/* 指令类别位 */
#define PDK_INST_PUSH        0x00000001
#define PDK_INST_POP         0x00000002
#define PDK_INST_XOR         0x00000004
#define PDK_INST_ROL_ROR     0x00000008
#define PDK_INST_ADD_SUB     0x00000010
#define PDK_INST_LOOP        0x00000020
#define PDK_INST_JNZ         0x00000040
#define PDK_INST_JMP         0x00000080
#define PDK_INST_CALL        0x00000100
#define PDK_INST_RDTSC       0x00000200
#define PDK_INST_INT         0x00000400
#define PDK_INST_CPUID       0x00000800
#define PDK_INST_VM_DETECT   0x00001000
#define PDK_INST_NOP         0x00002000
#define PDK_INST_WRITE_MEM   0x00004000
#define PDK_INST_DEC         0x00008000
#define PDK_INST_INC         0x00010000
#define PDK_INST_SUB         0x00020000
#define PDK_INST_ROTATE_GRP  0x00040000   /* ROL/ROR 类操作码 */
#define PDK_INST_MEM_XOR     0x00080000
#define PDK_INST_INDIRECT_CALL 0x00100000
#define PDK_INST_STACK_MOD   0x00200000   /* ADD/SUB 到 SP/ESP/RSP */

typedef struct _PDK_DECODE_RESULT {
    ULONG    Length;
    ULONG    Flags;
    BYTE     RegField;    /* ModRM reg，无 ModRM=0xFF */
    BYTE     ModField;
    BYTE     RmField;
    LONG     ImmValue;
    BOOLEAN  HasImm;
} PDK_DECODE_RESULT;

/* ModRM 变长解码（32 位地址尺寸简化；返回 ModRM+SIB+disp 长度） */
static
ULONG
PdkModRmLen(
    _In_ const BYTE* Code,
    _In_ SIZE_T Size,
    _Out_ BYTE* ModField,
    _Out_ BYTE* RegField,
    _Out_ BYTE* RmField
    )
{
    BYTE mrm;
    BYTE mod, reg, rm;

    if (Code == NULL || Size < 1) return 0;
    mrm = Code[0];
    mod = (mrm >> 6) & 3;
    reg = (mrm >> 3) & 7;
    rm = mrm & 7;

    if (ModField) *ModField = mod;
    if (RegField) *RegField = reg;
    if (RmField) *RmField = rm;

    if (mod == 3) {
        return 1;
    }
    if (mod == 0 && rm == 4) {
        /* SIB */
        if (Size < 2) return 0;
        if ((Code[1] & 7) == 5) return 1 + 4;
        return 2;
    }
    if (mod == 0 && rm == 5) {
        return 1 + 4;
    }
    if (mod == 1) {
        return 1 + 1;
    }
    if (mod == 2) {
        return 1 + 4;
    }
    return 1;
}

/*++
 * PdkDecodeInstr
 *  轻量指令解码：输出长度与类别标志。无法解码返回 FALSE。
 *  覆盖加壳 Stub 常见指令集（PUSHAD/循环/XOR/API 哈希/反调试等）。
 *--*/
static
BOOLEAN
PdkDecodeInstr(
    _In_reads_bytes_(Size) const BYTE* Code,
    _In_ SIZE_T Size,
    _In_ BOOLEAN Is64Bit,
    _Out_ PDK_DECODE_RESULT* Out
    )
{
    SIZE_T idx = 0;
    BYTE opcode1;
    BYTE modField = 0xFF;
    BYTE regField = 0xFF;
    BYTE rmField = 0xFF;
    ULONG mrmLen = 0;
    LONG imm = 0;
    BOOLEAN hasImm = FALSE;

    if (Code == NULL || Size == 0 || Out == NULL) return FALSE;
    RtlZeroMemory(Out, sizeof(*Out));

    /* 前缀（含 64 位 REX：0x40-0x4F） */
    for (;;) {
        if (idx >= Size) return FALSE;
        opcode1 = Code[idx];
        if (opcode1 == 0xF0 || opcode1 == 0xF2 || opcode1 == 0xF3 ||
            opcode1 == 0x66 || opcode1 == 0x67 ||
            opcode1 == 0x2E || opcode1 == 0x36 || opcode1 == 0x3E ||
            opcode1 == 0x26 || opcode1 == 0x64 || opcode1 == 0x65) {
            idx++;
            continue;
        }
        if (Is64Bit && opcode1 >= 0x40 && opcode1 <= 0x4F) {
            idx++;   /* REX 前缀 */
            continue;
        }
        break;
    }
    if (idx >= Size) return FALSE;

    opcode1 = Code[idx];
    idx++;

    /* 两字节 0x0F 组 */
    if (opcode1 == 0x0F) {
        BYTE opcode2;
        const BYTE* body;

        if (idx >= Size) return FALSE;
        opcode2 = Code[idx];
        idx++;
        body = Code + idx;

        /* 无 ModRM 的 0F 组 */
        switch (opcode2) {
        case 0x05:  /* SYSCALL */
        case 0x06:  /* CLTS */
        case 0x07:  /* SYSRET */
        case 0x08:  /* INVD */
        case 0x09:  /* WBINVD */
        case 0x0B:  /* UD2 */
        case 0x30:  /* WRMSR */
        case 0x31:  /* RDTSC */
        case 0x32:  /* RDMSR */
        case 0x33:  /* RDPMC */
        case 0x34:  /* SYSENTER */
        case 0x35:  /* SYSEXIT */
            Out->Length = (ULONG)idx;
            if (opcode2 == 0x31) Out->Flags |= PDK_INST_RDTSC;
            return TRUE;
        case 0xA2:  /* CPUID */
            Out->Length = (ULONG)idx;
            Out->Flags |= PDK_INST_CPUID;
            return TRUE;
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            /* 0F 80-8F: Jcc rel32（无 ModRM）；0F 8C-8F 同 Jcc */
            Out->Length = (ULONG)idx + 4;
            Out->Flags |= PDK_INST_JMP;
            return TRUE;
        default:
            break;
        }

        /* VM 检测指令（0F 00 / 0F 01） */
        if (opcode2 == 0x00 || opcode2 == 0x01) {
            mrmLen = PdkModRmLen(body, Size - idx, &modField, &regField, &rmField);
            if (mrmLen == 0) return FALSE;
            if (regField <= 1) {
                Out->Flags |= PDK_INST_VM_DETECT;   /* SLDT/STR/SGDT/SIDT */
            }
            Out->Length = (ULONG)idx + mrmLen;
            return TRUE;
        }

        /* 其余 0F 指令带 ModRM */
        mrmLen = PdkModRmLen(body, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;

        if (opcode2 == 0xAF || opcode2 == 0xB6 || opcode2 == 0xB7 ||
            opcode2 == 0xBC || opcode2 == 0xBD) {
            /* IMUL/MOVZX/MOVSX/BSF/BSR */
            Out->Length = (ULONG)idx + mrmLen;
            return TRUE;
        }
        if (opcode2 == 0xC2 || opcode2 == 0xC6 || opcode2 == 0xC7 || opcode2 == 0x70 || opcode2 == 0x76) {
            /* 带 imm8（CMPPS/CMPSD/SHUFPS/PSHUFD 等） */
            if (idx + mrmLen + 1 > Size) return FALSE;
            Out->Length = (ULONG)idx + mrmLen + 1;
            return TRUE;
        }
        if (opcode2 == 0xA4 || opcode2 == 0xAC || opcode2 == 0xB0 || opcode2 == 0xB1) {
            /* SHLD/SHRD/CMPXCHG 带 ModRM（0xB0/B1 imm8 变体） */
            if (idx + mrmLen + 1 > Size) return FALSE;
            Out->Length = (ULONG)idx + mrmLen + 1;
            return TRUE;
        }

        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    }

    /* 单字节 opcode 分类 */
    switch (opcode1) {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        Out->Flags |= PDK_INST_PUSH;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        Out->Flags |= PDK_INST_POP;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x60:  /* PUSHAD */
        Out->Flags |= PDK_INST_PUSH;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x61:  /* POPAD */
        Out->Flags |= PDK_INST_POP;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x9C:  /* PUSHF */
        Out->Flags |= PDK_INST_PUSH;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x9D:  /* POPF */
        Out->Flags |= PDK_INST_POP;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x68:  /* PUSH imm32 */
        if (idx + 4 > Size) return FALSE;
        imm = *(const LONG*)(Code + idx);
        Out->Flags |= PDK_INST_PUSH;
        Out->ImmValue = imm;
        Out->HasImm = TRUE;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0x6A:  /* PUSH imm8 */
        if (idx + 1 > Size) return FALSE;
        imm = (LONG)(char)Code[idx];
        Out->Flags |= PDK_INST_PUSH;
        Out->ImmValue = imm;
        Out->HasImm = TRUE;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        /* Jcc rel8（0x75 = JNZ） */
        Out->Flags |= PDK_INST_JMP;
        if (opcode1 == 0x75) Out->Flags |= PDK_INST_JNZ;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0xE0: case 0xE1: case 0xE2:  /* LOOPNE/LOOPE/LOOP */
        Out->Flags |= PDK_INST_LOOP;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0xE3:  /* JCXZ */
        Out->Flags |= PDK_INST_JMP;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0xE8:  /* CALL rel32 */
        if (idx + 4 > Size) return FALSE;
        Out->Flags |= PDK_INST_CALL;
        Out->ImmValue = *(const LONG*)(Code + idx);
        Out->HasImm = TRUE;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0xE9:  /* JMP rel32 */
        if (idx + 4 > Size) return FALSE;
        Out->Flags |= PDK_INST_JMP;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0xEB:  /* JMP rel8 */
        Out->Flags |= PDK_INST_JMP;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0x90:  /* NOP */
    case 0x91:  /* XCHG EAX,EAX（NOP 等价） */
        Out->Flags |= PDK_INST_NOP;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0xCC:  /* INT 3 */
        Out->Flags |= PDK_INST_INT;
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0xCD:  /* INT imm8 */
        if (idx + 1 > Size) return FALSE;
        Out->Flags |= PDK_INST_INT;
        Out->ImmValue = Code[idx];
        Out->HasImm = TRUE;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:  /* MOVS */
    case 0xAA: case 0xAB:  /* STOS */
    case 0xAC: case 0xAD:  /* LODS */
    case 0xAE: case 0xAF:  /* SCAS */
        if (opcode1 == 0xA4 || opcode1 == 0xA5 || opcode1 == 0xAA || opcode1 == 0xAB) {
            Out->Flags |= PDK_INST_WRITE_MEM;
        }
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0xC3:  /* RET */
    case 0xC9:  /* LEAVE */
    case 0xCB:
    case 0xCF:
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0xC2:  /* RET imm16 */
    case 0xCA:
        if (idx + 2 > Size) return FALSE;
        Out->Length = (ULONG)idx + 2;
        return TRUE;
    case 0xF4:  /* HLT */
    case 0xF5:  /* CMC */
    case 0xF8: case 0xF9:  /* CLC/STC */
    case 0xFA: case 0xFB:  /* CLI/STI */
    case 0xFC: case 0xFD:  /* CLD/STD */
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x98: case 0x99:  /* CWDE/CDQ */
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0xD7:  /* XLAT */
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x04: case 0x0C: case 0x14: case 0x1C:
    case 0x24: case 0x2C: case 0x34: case 0x3C:
        /* AL, imm8 运算（0x34 = XOR AL,imm8；0x2C = SUB AL,imm8） */
        if (idx + 1 > Size) return FALSE;
        if (opcode1 == 0x34) Out->Flags |= PDK_INST_XOR;
        if (opcode1 == 0x2C) Out->Flags |= PDK_INST_ADD_SUB | PDK_INST_SUB;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0x05: case 0x0D: case 0x15: case 0x1D:
    case 0x25: case 0x2D: case 0x35: case 0x3D:
        /* EAX, imm32 运算（0x35 = XOR EAX,imm32；0x2D = SUB EAX,imm32） */
        if (idx + 4 > Size) return FALSE;
        if (opcode1 == 0x35) Out->Flags |= PDK_INST_XOR;
        if (opcode1 == 0x05) Out->Flags |= PDK_INST_ADD_SUB;
        if (opcode1 == 0x2D) Out->Flags |= PDK_INST_ADD_SUB | PDK_INST_SUB;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0xA8:  /* TEST AL,imm8 */
        if (idx + 1 > Size) return FALSE;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0xA9:  /* TEST EAX,imm32 */
        if (idx + 4 > Size) return FALSE;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        /* MOV r8, imm8 */
        if (idx + 1 > Size) return FALSE;
        Out->Length = (ULONG)idx + 1;
        return TRUE;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        /* MOV r32, imm32 */
        if (idx + 4 > Size) return FALSE;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0xA0: case 0xA1: case 0xA2: case 0xA3:
        /* MOV moffs（地址尺寸） */
        if (idx + 4 > Size) return FALSE;
        Out->Length = (ULONG)idx + 4;
        return TRUE;
    case 0x6B:  /* IMUL r, r/m, imm8 */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (idx + mrmLen + 1 > Size) return FALSE;
        Out->Length = (ULONG)idx + mrmLen + 1;
        return TRUE;
    case 0x69:  /* IMUL r, r/m, imm32 */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (idx + mrmLen + 4 > Size) return FALSE;
        Out->Length = (ULONG)idx + mrmLen + 4;
        return TRUE;
    case 0x80: case 0x81: case 0x82: case 0x83:
        /* Grp1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP Eb/Ev, imm */
        {
            BYTE reg;
            ULONG immLen = (opcode1 == 0x80 || opcode1 == 0x82 || opcode1 == 0x83) ? 1 : 4;

            if (idx + 1 > Size) return FALSE;
            mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
            if (mrmLen == 0) return FALSE;
            reg = regField;
            if (idx + mrmLen + immLen > Size) return FALSE;
            if (reg == 6 || reg == 1) {
                Out->Flags |= PDK_INST_XOR;       /* /6 = XOR */
                if (reg == 6) Out->Flags |= PDK_INST_MEM_XOR;   /* 常见 mem XOR 解密 */
            }
            if (reg == 0 || reg == 5) {
                Out->Flags |= PDK_INST_ADD_SUB;   /* /0 = ADD, /5 = SUB */
                if (reg == 5) Out->Flags |= PDK_INST_SUB;
                /* 栈修改检测 */
                if (modField == 3 && rmField == 4) {
                    Out->Flags |= PDK_INST_STACK_MOD;
                }
            }
            Out->Length = (ULONG)idx + mrmLen + immLen;
            return TRUE;
        }
    case 0x30: case 0x31: case 0x32: case 0x33:
        /* XOR r/m, r / XOR r, r/m */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        Out->Flags |= PDK_INST_XOR;
        if (modField != 3) {
            Out->Flags |= PDK_INST_MEM_XOR;
        }
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
        /* ADD/SUB r/m, r */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        Out->Flags |= PDK_INST_ADD_SUB;
        if (opcode1 >= 0x28) Out->Flags |= PDK_INST_SUB;
        if (modField == 3 && rmField == 4) {
            Out->Flags |= PDK_INST_STACK_MOD;
        }
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        /* ROL/ROR/SHL/SHR/SAL/SAR r/m, 1/CL */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (regField <= 1) {
            Out->Flags |= PDK_INST_ROL_ROR | PDK_INST_ROTATE_GRP;
        }
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0xC0: case 0xC1:
        /* ROL/ROR r/m, imm8 */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (regField <= 1) {
            Out->Flags |= PDK_INST_ROL_ROR | PDK_INST_ROTATE_GRP;
        }
        if (idx + mrmLen + 1 > Size) return FALSE;
        Out->Length = (ULONG)idx + mrmLen + 1;
        return TRUE;
    case 0xC6:  /* MOV Eb, imm8 */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (idx + mrmLen + 1 > Size) return FALSE;
        if (modField != 3) Out->Flags |= PDK_INST_WRITE_MEM;
        Out->Length = (ULONG)idx + mrmLen + 1;
        return TRUE;
    case 0xC7:  /* MOV Ev, imm32 */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (idx + mrmLen + 4 > Size) return FALSE;
        if (modField != 3) Out->Flags |= PDK_INST_WRITE_MEM;
        Out->Length = (ULONG)idx + mrmLen + 4;
        return TRUE;
    case 0x88: case 0x89: case 0x8A: case 0x8B:
        /* MOV r/m, r / MOV r, r/m */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if ((opcode1 == 0x88 || opcode1 == 0x89) && modField != 3) {
            Out->Flags |= PDK_INST_WRITE_MEM;
        }
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0x84: case 0x85:  /* TEST r/m, r */
    case 0x86: case 0x87:  /* XCHG r/m, r */
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0xFF:
        /* Grp5: INC/DEC/CALL/CALLF/JMP/JMPF/PUSH */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        switch (regField) {
        case 0: Out->Flags |= PDK_INST_INC; break;
        case 1: Out->Flags |= PDK_INST_DEC; break;
        case 2:
            Out->Flags |= PDK_INST_CALL;
            if (modField == 3) Out->Flags |= PDK_INST_INDIRECT_CALL;
            break;
        case 4: Out->Flags |= PDK_INST_JMP; break;
        case 6: Out->Flags |= PDK_INST_PUSH; break;
        default: break;
        }
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0xF6: case 0xF7:
        /* Grp3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (regField == 0) {
            /* TEST 带 imm */
            ULONG immLen = (opcode1 == 0xF6) ? 1 : 4;
            if (idx + mrmLen + immLen > Size) return FALSE;
            Out->Length = (ULONG)idx + mrmLen + immLen;
        } else {
            Out->Length = (ULONG)idx + mrmLen;
        }
        return TRUE;
    case 0xFE:
        /* Grp4: INC/DEC r/m8 */
        if (idx + 1 > Size) return FALSE;
        mrmLen = PdkModRmLen(Code + idx, Size - idx, &modField, &regField, &rmField);
        if (mrmLen == 0) return FALSE;
        if (regField == 0) Out->Flags |= PDK_INST_INC;
        if (regField == 1) Out->Flags |= PDK_INST_DEC;
        Out->Length = (ULONG)idx + mrmLen;
        return TRUE;
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
        /* 32 位下 INC reg */
        if (!Is64Bit) {
            Out->Flags |= PDK_INST_INC;
        } else {
            return FALSE;   /* REX 前缀不应到此 */
        }
        Out->Length = (ULONG)idx;
        return TRUE;
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        /* 32 位下 DEC reg */
        if (!Is64Bit) {
            Out->Flags |= PDK_INST_DEC;
        } else {
            return FALSE;
        }
        Out->Length = (ULONG)idx;
        return TRUE;
    default:
        /* 其余未知操作码：保守推进 1 字节 */
        Out->Length = (ULONG)idx;
        Out->RegField = 0xFF;
        return TRUE;
    }
}

/*++
 * PdkAnalyzeStubCode
 *  Stub 字节模式分析（对齐源 L2792-3193，反汇编 → 字节降级）：
 *  寄存器保存/PUSHAD、解压循环、XOR 解密、API 哈希、
 *  反调试、VM 检测、栈枢轴、多态 NOP、自修改代码。
 *--*/
static
VOID
PdkAnalyzeStubCode(
    _In_reads_bytes_(CodeSize) const BYTE* Code,
    _In_ SIZE_T CodeSize,
    _In_ BOOLEAN Is64Bit,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    SIZE_T offset = 0;
    ULONG pushCount = 0;
    ULONG popCount = 0;
    ULONG xorCount = 0;
    ULONG rolRorCount = 0;
    ULONG addSubCount = 0;
    ULONG callCount = 0;
    ULONG jmpCount = 0;
    ULONG nopCount = 0;
    ULONG decCount = 0;
    ULONG incCount = 0;
    ULONG memXorCount = 0;
    ULONG regXorCount = 0;
    ULONG instructionCount = 0;
    BOOLEAN hasUnpackLoop = FALSE;
    BOOLEAN hasDecJnzLoop = FALSE;
    BOOLEAN hasSubJnzLoop = FALSE;
    BOOLEAN hasApiHashing = FALSE;
    BOOLEAN hasStackPivot = FALSE;
    BOOLEAN hasRdtsc = FALSE;
    BOOLEAN hasInt2d = FALSE;
    BOOLEAN hasInt3 = FALSE;
    BOOLEAN hasCpuid = FALSE;
    BOOLEAN hasVmDetection = FALSE;
    BOOLEAN hasWriteToCode = FALSE;
    BOOLEAN hasIndirectCall = FALSE;
    /* 上一指令类别（历史窗口 = 1 条） */
    ULONG prevFlags = 0;

    while (offset < CodeSize && instructionCount < PDK_MAX_STUB_BYTES) {
        PDK_DECODE_RESULT dec;
        ULONG flags;

        if (!PdkDecodeInstr(Code + offset, CodeSize - offset, Is64Bit, &dec)) {
            offset++;
            continue;
        }
        flags = dec.Flags;
        offset += dec.Length;
        instructionCount++;

        if (flags & PDK_INST_PUSH) {
            pushCount++;
            /* PUSHAD 计 8 个寄存器（0x60 已由 PdkDecodeInstr 标记 PUSH，源此处 +1） */
            if (Code[offset - dec.Length] == 0x60) {
                pushCount += 7;
            }
            if (Code[offset - dec.Length] == 0x9C) {
                /* PUSHF 仅 +1（已计入） */
            }
        }
        if (flags & PDK_INST_POP) {
            popCount++;
            if (Code[offset - dec.Length] == 0x61) {
                popCount += 7;
            }
        }

        if (flags & PDK_INST_LOOP) hasUnpackLoop = TRUE;

        if (flags & PDK_INST_XOR) {
            xorCount++;
            if (flags & PDK_INST_MEM_XOR) {
                memXorCount++;
            } else {
                regXorCount++;
            }
        }

        if (flags & PDK_INST_ROL_ROR) {
            rolRorCount++;
            /* API 哈希：ROL/ROR 前一条为 XOR/ADD（源 L2938-2945） */
            if ((prevFlags & PDK_INST_XOR) || (prevFlags & PDK_INST_ADD_SUB)) {
                hasApiHashing = TRUE;
            }
        }

        if (flags & PDK_INST_ADD_SUB) {
            addSubCount++;
            if ((flags & PDK_INST_STACK_MOD) && dec.HasImm &&
                llabs((LONGLONG)dec.ImmValue) > 4096) {
                hasStackPivot = TRUE;
            }
        }

        if (flags & PDK_INST_DEC) decCount++;
        if (flags & PDK_INST_INC) incCount++;

        if (flags & PDK_INST_JNZ) {
            /* DEC+JNZ / SUB+JNZ 循环 */
            if (prevFlags & PDK_INST_DEC) hasDecJnzLoop = TRUE;
            if (prevFlags & PDK_INST_SUB) hasSubJnzLoop = TRUE;
            jmpCount++;
        } else if (flags & PDK_INST_JMP) {
            jmpCount++;
        }

        if ((flags & PDK_INST_CALL) && (flags & PDK_INST_INDIRECT_CALL)) {
            hasIndirectCall = TRUE;
        }
        if (flags & PDK_INST_CALL) callCount++;

        if (flags & PDK_INST_RDTSC) hasRdtsc = TRUE;

        if (flags & PDK_INST_INT) {
            if (dec.HasImm && dec.ImmValue == 0x2D) {
                hasInt2d = TRUE;
            } else if (dec.HasImm && dec.ImmValue == 0x03) {
                hasInt3 = TRUE;
            } else if (!dec.HasImm) {
                hasInt3 = TRUE;   /* INT 3 = 0xCC */
            }
        }

        if (flags & PDK_INST_CPUID) hasCpuid = TRUE;
        if (flags & PDK_INST_VM_DETECT) hasVmDetection = TRUE;
        if (flags & PDK_INST_NOP) nopCount++;
        if (flags & PDK_INST_WRITE_MEM) hasWriteToCode = TRUE;

        prevFlags = flags;
    }

    /* === 指示器生成（对齐源 L3120-3193） === */

    if (pushCount >= 5 && instructionCount < 30) {
        PdkAddIndicator(Result, L"Register preservation at entry (packer stub pattern)");
    }
    if (pushCount >= 8 && popCount >= 8) {
        PdkAddIndicator(Result, L"PUSHAD/POPAD pattern detected (classic packer)");
    }
    if (hasUnpackLoop) {
        PdkAddIndicator(Result, L"LOOP instruction decompression/decryption pattern");
    }
    if (hasDecJnzLoop) {
        PdkAddIndicator(Result, L"DEC+JNZ unpacking loop detected");
    }
    if (hasSubJnzLoop) {
        PdkAddIndicator(Result, L"SUB+JNZ counter loop detected");
    }
    if (memXorCount >= 3) {
        PdkAddIndicator(Result, L"XOR memory decryption pattern detected");
    }
    if (hasApiHashing || (rolRorCount >= 2 && xorCount >= 2)) {
        PdkAddIndicator(Result, L"API hashing pattern (ROL/ROR+XOR) detected");
    }
    if (hasStackPivot) {
        PdkAddIndicator(Result, L"Stack pivot detected (large ESP/RSP modification)");
    }
    if (hasRdtsc) {
        PdkAddIndicator(Result, L"RDTSC timing check (anti-debugging)");
    }
    if (hasInt2d) {
        PdkAddIndicator(Result, L"INT 2D anti-debugging technique");
    }
    if (hasInt3) {
        PdkAddIndicator(Result, L"INT 3 breakpoint instruction");
    }
    if (hasVmDetection) {
        PdkAddIndicator(Result, L"VM/sandbox detection instructions");
    }
    if (hasCpuid) {
        PdkAddIndicator(Result, L"CPUID instruction (potential VM detection)");
    }
    if (hasIndirectCall && callCount >= 2) {
        PdkAddIndicator(Result, L"Indirect calls (dynamic API resolution)");
    }
    if (hasWriteToCode && (hasUnpackLoop || hasDecJnzLoop || hasSubJnzLoop)) {
        PdkAddIndicator(Result, L"Self-modifying code pattern (runtime unpacking)");
    }
    if (nopCount >= 5 && instructionCount < 50) {
        PdkAddIndicator(Result, L"Polymorphic NOP sequences (code obfuscation)");
    }
    if (jmpCount >= 10 && instructionCount < 100) {
        PdkAddIndicator(Result, L"High control flow complexity (obfuscation)");
    }
}

/*++
 * PdkPerformHeuristicAnalysis
 *  启发式聚合：Stub 分析 + 动态解析 + EP 位置（对齐源 L2764-2790）。
 *--*/
static
VOID
PdkPerformHeuristicAnalysis(
    _In_ const PDK_PE_CONTEXT* Ctx,
    _Inout_ PDK_PACKING_INFO* Result
    )
{
    if (Ctx == NULL || Result == NULL || !Ctx->Parsed) return;

    if (Result->EntryPointInfo.EpBytesSize > 0) {
        PdkAnalyzeStubCode(
            Result->EntryPointInfo.EpBytes,
            Result->EntryPointInfo.EpBytesSize,
            Ctx->Is64Bit,
            Result);
    }

    if (Result->ImportInfo.HasGetProcAddress &&
        Result->ImportInfo.HasLoadLibrary) {
        if (Result->ImportInfo.TotalImports < PDK_SUSPICIOUS_LOW_IMPORT_COUNT) {
            PdkAddIndicator(Result, L"Minimal imports with dynamic API resolution");
            Result->HasSuspiciousCharacteristics = TRUE;
        }
    }

    if (Result->EntryPointInfo.IsOutsideCodeSection) {
        PdkAddIndicator(Result, L"Entry point outside code section");
        Result->HasSuspiciousCharacteristics = TRUE;
    }
}

/*++
 * PdkDeterminePackingVerdict
 *  加权评分判定（对齐源 L3293-3392）。
 *--*/
static
VOID
PdkDeterminePackingVerdict(
    _Inout_ PDK_PACKING_INFO* Result,
    _In_ const PDK_ANALYSIS_CONFIG* Config
    )
{
    DOUBLE score = 0.0;
    DOUBLE maxPossibleScore = 0.0;
    DOUBLE bestEpConfidence = 0.0;
    ULONG i;

    if (Result == NULL || Config == NULL) return;

    maxPossibleScore += PDK_WEIGHT_ENTROPY;
    if (Result->EntropyIndicatesEncryption) {
        score += PDK_WEIGHT_ENTROPY;
    } else if (Result->EntropyIndicatesCompression) {
        score += PDK_WEIGHT_ENTROPY * 0.7;
    } else if (Result->FileEntropy > 6.0) {
        score += PDK_WEIGHT_ENTROPY * 0.4;
    }

    maxPossibleScore += PDK_WEIGHT_SECTION_ANOMALIES;
    if (Result->PackerSectionMatches > 0) {
        score += PDK_WEIGHT_SECTION_ANOMALIES;
    } else if (Result->HasWritableCodeSections) {
        score += PDK_WEIGHT_SECTION_ANOMALIES * 0.6;
    } else if (Result->HighEntropySectionCount > 0) {
        score += PDK_WEIGHT_SECTION_ANOMALIES * 0.4;
    }

    maxPossibleScore += PDK_WEIGHT_EP_SIGNATURE;
    for (i = 0; i < Result->MatchCount; ++i) {
        if (Result->PackerMatches[i].Method == PDK_METHOD_EP_SIGNATURE &&
            Result->PackerMatches[i].Confidence > bestEpConfidence) {
            bestEpConfidence = Result->PackerMatches[i].Confidence;
        }
    }
    score += PDK_WEIGHT_EP_SIGNATURE * bestEpConfidence;

    maxPossibleScore += PDK_WEIGHT_IMPORT_ANOMALIES;
    if (Result->HasMinimalImports) {
        score += PDK_WEIGHT_IMPORT_ANOMALIES * 0.6;
        if (Result->ImportInfo.HasGetProcAddress && Result->ImportInfo.HasLoadLibrary) {
            score += PDK_WEIGHT_IMPORT_ANOMALIES * 0.4;
        }
    }

    maxPossibleScore += PDK_WEIGHT_OVERLAY;
    if (Result->OverlayInfo.HasOverlay &&
        Result->OverlayInfo.PercentageOfFile > PDK_SUSPICIOUS_OVERLAY_PERCENTAGE) {
        score += PDK_WEIGHT_OVERLAY;
    }

    maxPossibleScore += PDK_WEIGHT_STRUCTURAL;
    if (Result->EpOutsideCodeSection || Result->HasNonStandardSections) {
        score += PDK_WEIGHT_STRUCTURAL * 0.5;
    }
    if (Result->HasSuspiciousCharacteristics) {
        score += PDK_WEIGHT_STRUCTURAL * 0.5;
    }

    maxPossibleScore += PDK_WEIGHT_YARA_MATCH;
    for (i = 0; i < Result->MatchCount; ++i) {
        if (Result->PackerMatches[i].Method == PDK_METHOD_YARA_RULE) {
            score += PDK_WEIGHT_YARA_MATCH;
            break;
        }
    }

    Result->PackingConfidence = (maxPossibleScore > 0) ?
        (score / maxPossibleScore) : 0.0;

    Result->IsPacked = (Result->PackingConfidence >= Config->MinConfidenceThreshold);

    if (Result->MatchCount > 0) {
        const PDK_PACKER_MATCH* best = PdkGetBestMatch(Result);
        if (best != NULL) {
            Result->PrimaryPacker = best->PackerType;
            PDK_WCS_COPY(Result->PackerName, PDK_MAX_NAME, best->PackerName);
            PDK_WCS_COPY(Result->PackerVersion, 64, best->Version);
            Result->PackerCategory = best->Category;
            Result->Severity = best->Severity;
        }
    } else if (Result->IsPacked) {
        Result->PrimaryPacker = PDK_TYPE_UNKNOWN;
        Result->PackerCategory = PDK_CATEGORY_UNKNOWN;

        if (Result->EntropyIndicatesEncryption) {
            Result->PackerCategory = PDK_CATEGORY_CRYPTER;
            Result->Severity = PDK_SEVERITY_HIGH;
        } else if (Result->EntropyIndicatesCompression) {
            Result->PackerCategory = PDK_CATEGORY_COMPRESSION;
            Result->Severity = PDK_SEVERITY_LOW;
        }
    }

    if (Result->IsInstaller && Config->TreatInstallersAsBenign) {
        Result->Severity = PDK_SEVERITY_BENIGN;
    }

    if (Result->MatchCount > 1) {
        Result->HasMultipleLayers = TRUE;
        Result->LayerCount = Result->MatchCount;
    }
}

/* 反脱壳技术：EP 字节窗口扫描（对齐源 L3196-3213） */
static
VOID
PdkFindAntiUnpacking(
    _In_ const PDK_PACKING_INFO* PackingInfo,
    _Inout_ PDK_UNPACKING_HINTS* Hints
    )
{
    SIZE_T i;

    if (PackingInfo == NULL || Hints == NULL) return;

    /* RDTSC: 0F 31 */
    for (i = 0; i + 1 < PackingInfo->EntryPointInfo.EpBytesSize; ++i) {
        if (PackingInfo->EntryPointInfo.EpBytes[i] == 0x0F &&
            PackingInfo->EntryPointInfo.EpBytes[i + 1] == 0x31) {
            if (Hints->AntiUnpackingCount < PDK_MAX_ANIUNPACK_TECH) {
                PDK_WCS_COPY(Hints->AntiUnpackingTechniques[Hints->AntiUnpackingCount],
                    PDK_MAX_NAME, L"RDTSC timing check");
                Hints->AntiUnpackingCount++;
            }
            break;
        }
    }

    /* INT 2D: CD 2D */
    for (i = 0; i + 1 < PackingInfo->EntryPointInfo.EpBytesSize; ++i) {
        if (PackingInfo->EntryPointInfo.EpBytes[i] == 0xCD &&
            PackingInfo->EntryPointInfo.EpBytes[i + 1] == 0x2D) {
            if (Hints->AntiUnpackingCount < PDK_MAX_ANIUNPACK_TECH) {
                PDK_WCS_COPY(Hints->AntiUnpackingTechniques[Hints->AntiUnpackingCount],
                    PDK_MAX_NAME, L"INT 2D debugger check");
                Hints->AntiUnpackingCount++;
            }
            break;
        }
    }
}

/**************************************************/
/*          文件读取辅助（内存映射）               */
/**************************************************/

/* 映射只读打开文件；成功返回 TRUE，*Base 需调用方 Unmap */
static
BOOLEAN
PdkReadFileViaMapping(
    _In_ PCWSTR FilePath,
    _Outptr_result_maybenull_ BYTE** Base,
    _Out_ SIZE_T* FileSize,
    _Out_ HANDLE* FileHandle,
    _Out_ HANDLE* MappingHandle
    )
{
    HANDLE hFile;
    HANDLE hMapping;
    LARGE_INTEGER fileSize;
    BYTE* base;

    if (FilePath == NULL || Base == NULL || FileSize == NULL ||
        FileHandle == NULL || MappingHandle == NULL) {
        return FALSE;
    }

    *Base = NULL;
    *FileSize = 0;
    *FileHandle = NULL;
    *MappingHandle = NULL;

    hFile = CreateFileW(FilePath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > 0x7FFFFFFF) {
        CloseHandle(hFile);
        return FALSE;
    }

    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    base = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (base == NULL) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    *Base = base;
    *FileSize = (SIZE_T)fileSize.QuadPart;
    *FileHandle = hFile;
    *MappingHandle = hMapping;
    return TRUE;
}

/*============================================================================
 *  PdkAnalyzeBufferInternal —— 核心编排（对齐源 AnalyzeBufferInternal）
 *  阶段：解析 → 熵 → 节 → EP → 导入 → Overlay → Rich → 资源
 *        → 签名验证(文件) → YARA(文件) → 启发式 → 判定 → 脱壳提示
 *==========================================================================*/
static
BOOLEAN
PdkAnalyzeBufferInternal(
    _In_reads_bytes_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size,
    _In_opt_ const PDK_ANALYSIS_CONFIG* Config,
    _In_opt_ PCWSTR FilePath,
    _Inout_ PDK_PACKING_INFO* Result,
    _Inout_opt_ PDK_ERROR* Err
    )
{
    PDK_PE_CONTEXT ctx;
    ULONGLONG startTick;
    ULONGLONG endTick;
    UINT32 flags;
    BOOLEAN haveFile = FALSE;

    if (Buffer == NULL || Size == 0 || Result == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"分析参数无效", NULL);
        return FALSE;
    }

    haveFile = (FilePath != NULL && FilePath[0] != L'\0');
    startTick = GetTickCount64();
    Result->AnalysisStartTick = startTick;

    if (Config != NULL) {
        Result->Config = *Config;
    }
    flags = Result->Config.Flags;

    if (haveFile) {
        PDK_WCS_COPY(Result->FilePath, PDK_MAX_PATH, FilePath);
    } else {
        Result->FilePath[0] = L'\0';
    }

    /* 文件哈希（缓存/报告标识） */
    if (Size > 0 && Size <= 0x7FFFFFFF) {
        PdkComputeSha256Hex(Buffer, Size, Result->Sha256Hash);
    }
    Result->FileSize = (ULONGLONG)Size;

    /* 文件大小上限 */
    if (Result->Config.MaxFileSize > 0 && Size > Result->Config.MaxFileSize) {
        PdkRecordError(Result, ERROR_FILE_TOO_LARGE,
            L"文件超过 MaxFileSize 上限", FilePath);
        Result->AnalysisComplete = TRUE;
        endTick = GetTickCount64();
        Result->AnalysisEndTick = endTick;
        Result->AnalysisDurationMs = endTick - startTick;
        return TRUE;
    }

    /* 1. PE 解析 */
    RtlZeroMemory(&ctx, sizeof(ctx));
    if (!PdkPeParse(&ctx, Buffer, Size)) {
        PdkRecordError(Result, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
        Result->AnalysisComplete = TRUE;
        endTick = GetTickCount64();
        Result->AnalysisEndTick = endTick;
        Result->AnalysisDurationMs = endTick - startTick;
        return TRUE;
    }

    /* 2. 熵分析 */
    if (flags & PDK_FLAG_ENABLE_ENTROPY) {
        PdkAnalyzeEntropyInternal(&ctx, Result);
    }

    /* 3. 节分析 */
    if (flags & PDK_FLAG_ENABLE_SECTION) {
        PdkAnalyzeSectionsInternal(&ctx, Result);
    }

    /* 4. 入口点 + EP 签名 */
    if (flags & PDK_FLAG_ENABLE_EP_SIGNATURE) {
        PdkAnalyzeEntryPointInternal(&ctx, Result);
    }

    /* 5. 导入分析 */
    if (flags & PDK_FLAG_ENABLE_IMPORT) {
        PdkAnalyzeImportsInternal(&ctx, Result);
    }

    /* 6. Overlay */
    if (flags & PDK_FLAG_ENABLE_OVERLAY) {
        PdkAnalyzeOverlayInternal(&ctx, Result);
    }

    /* 7. Rich 头 */
    if (flags & PDK_FLAG_ENABLE_RICH_HEADER) {
        PdkAnalyzeRichHeaderInternal(&ctx, Result);
    }

    /* 8. 资源 */
    if (flags & PDK_FLAG_ENABLE_RESOURCE) {
        PdkAnalyzeResourcesInternal(&ctx, Result);
    }

    /* 9. Authenticode 签名验证（需要文件路径） */
    if (haveFile && (flags & PDK_FLAG_ENABLE_SIG_VERIFY)) {
        PkdVerifySignature(FilePath, &Result->SignatureInfo, Err);
    }

    /* 10. YARA 扫描（需要文件路径） */
    if (haveFile && (flags & PDK_FLAG_ENABLE_YARA)) {
        PDK_PACKER_MATCH yaraMatches[PDK_MAX_MATCHES];
        ULONG yaraCount = PDK_MAX_MATCHES;
        ULONG m;

        RtlZeroMemory(yaraMatches, sizeof(yaraMatches));
        if (PkdScanWithYARA(FilePath, yaraMatches, &yaraCount, Err)) {
            for (m = 0; m < yaraCount; ++m) {
                PdkAddMatch(Result, &yaraMatches[m]);
            }
        }
    }

    /* 11. .NET 程序集 */
    Result->IsDotNetAssembly = ctx.IsDotNet;

    /* 12. 安装器判定（节名 + Overlay 魔数，基于已解析上下文） */
    {
        ULONG s;
        for (s = 0; s < ctx.SectionCount; ++s) {
            SIZE_T k;
            for (k = 0; k < PDK_ARRAY_COUNT(g_PdkInstallerSections); ++k) {
                if (PdkSectionNameEquals(ctx.Sections[s].Name, g_PdkInstallerSections[k])) {
                    Result->IsInstaller = TRUE;
                    break;
                }
            }
            if (Result->IsInstaller) break;
        }
        /* Overlay 魔数：ZIP / NSIS / 7z 自解压数据常见 */
        if (!Result->IsInstaller &&
            Result->OverlayInfo.Valid &&
            Result->OverlayInfo.HasOverlay &&
            Result->OverlayInfo.Size >= 4 &&
            Result->OverlayInfo.DetectedFormat[0] != L'\0') {
            if (_wcsicmp(Result->OverlayInfo.DetectedFormat, L"ZIP archive") == 0 ||
                _wcsicmp(Result->OverlayInfo.DetectedFormat, L"NSIS data") == 0 ||
                _wcsicmp(Result->OverlayInfo.DetectedFormat, L"7-Zip archive") == 0) {
                Result->IsInstaller = TRUE;
                Result->IsSfxArchive = TRUE;
            }
        }
    }

    /* 13. 启发式（Stub 字节模式） */
    if (flags & PDK_FLAG_ENABLE_HEURISTIC) {
        PdkPerformHeuristicAnalysis(&ctx, Result);
    }

    /* 14. 打包判定（加权评分） */
    PdkDeterminePackingVerdict(Result, &Result->Config);

    /* 15. 脱壳提示 */
    if (Result->IsPacked || Result->MatchCount > 0) {
        PkdGenerateUnpackingHints(Result, &Result->UnpackingHints, Err);
    }

    /* 16. 收尾：完成标记 + 统计 */
    Result->AnalysisComplete = TRUE;
    endTick = GetTickCount64();
    Result->AnalysisEndTick = endTick;
    Result->AnalysisDurationMs = endTick - startTick;

    InterlockedIncrement64(&g_PdkStats.TotalAnalyses);
    InterlockedExchangeAdd64((volatile LONGLONG*)&g_PdkStats.BytesAnalyzed, (LONGLONG)Size);
    InterlockedExchangeAdd64((volatile LONGLONG*)&g_PdkStats.TotalAnalysisTimeUs,
        (LONGLONG)(Result->AnalysisDurationMs * 1000));
    if (Result->IsPacked) {
        InterlockedIncrement64(&g_PdkStats.PackedFilesDetected);
        if (Result->PackerCategory < 16) {
            InterlockedIncrement64(&g_PdkStats.CategoryDetections[Result->PackerCategory]);
        }
        switch (Result->PackerCategory) {
        case PDK_CATEGORY_INSTALLER:
        case PDK_CATEGORY_SFX_ARCHIVE:
            InterlockedIncrement64(&g_PdkStats.InstallersDetected);
            break;
        case PDK_CATEGORY_CRYPTER:
            InterlockedIncrement64(&g_PdkStats.CryptersDetected);
            break;
        case PDK_CATEGORY_PROTECTOR:
        case PDK_CATEGORY_VM_PROTECTION:
        case PDK_CATEGORY_DOTNET_PROTECTOR:
        case PDK_CATEGORY_MALWARE_PACKER:
        case PDK_CATEGORY_LEGITIMATE_PROTECTION:
            InterlockedIncrement64(&g_PdkStats.ProtectorsDetected);
            break;
        default:
            break;
        }
    }

    return TRUE;
}

/**************************************************/
/*          公共 API：生命周期                      */
/**************************************************/

/*++
 * PkdInitialize —— 初始化引擎（幂等）。
 *--*/
_Use_decl_annotations_
NTSTATUS
PkdInitialize(
    PDK_ERROR* Err
    )
{
    if (!PdkEnsureInitialized(Err)) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

/*++
 * PkdShutdown —— 关闭引擎并清理缓存与自定义模式。
 *--*/
_Use_decl_annotations_
VOID
PkdShutdown(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_PdkLock);
    RtlZeroMemory(g_PdkCache, sizeof(g_PdkCache));
    g_PdkCacheCount = 0;
    g_PdkCustomSigCount = 0;
    g_PdkCustomSectionCount = 0;
    g_PdkCallback = NULL;
    g_PdkInitialized = FALSE;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

/*++
 * PkdIsInitialized —— 查询初始化状态。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdIsInitialized(
    VOID
    )
{
    BOOLEAN init;

    AcquireSRWLockShared(&g_PdkLock);
    init = g_PdkInitialized;
    ReleaseSRWLockShared(&g_PdkLock);
    return init;
}

/**************************************************/
/*          公共 API：文件 / 缓冲分析               */
/**************************************************/

/*++
 * PkdAnalyzeFile —— 文件分析（缓存优先）。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeFile(
    PCWSTR FilePath,
    const PDK_ANALYSIS_CONFIG* Config,
    PDK_PACKING_INFO* Result,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    BOOLEAN ok;
    BOOLEAN caching;

    if (FilePath == NULL || FilePath[0] == L'\0' || Result == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }
    if (!PdkEnsureInitialized(Err)) {
        return FALSE;
    }

    PdkResultReset(Result);
    if (Config != NULL) {
        Result->Config = *Config;
    }

    /* 缓存命中直接返回 */
    caching = Result->Config.EnableCaching;
    if (caching && PdkCacheLookup(FilePath, Result)) {
        return TRUE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        PdkRecordError(Result, ERROR_OPEN_FAILED, L"无法读取文件", FilePath);
        InterlockedIncrement64(&g_PdkStats.AnalysisErrors);
        return FALSE;
    }

    ok = PdkAnalyzeBufferInternal(base, fileSize, &Result->Config, FilePath, Result, Err);

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (ok && caching && Result->AnalysisComplete) {
        PdkCacheStore(FilePath, Result);
    }

    return ok;
}

/*++
 * PkdAnalyzeBuffer —— 内存缓冲 PE 分析。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeBuffer(
    const BYTE* Buffer,
    SIZE_T Size,
    const PDK_ANALYSIS_CONFIG* Config,
    PDK_PACKING_INFO* Result,
    PDK_ERROR* Err
    )
{
    if (Buffer == NULL || Size == 0 || Result == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }
    if (!PdkEnsureInitialized(Err)) {
        return FALSE;
    }

    PdkResultReset(Result);
    if (Config != NULL) {
        Result->Config = *Config;
    }

    return PdkAnalyzeBufferInternal(Buffer, Size, &Result->Config, NULL, Result, Err);
}

/**************************************************/
/*          公共 API：批量分析                      */
/**************************************************/

/* 批处理分布聚合辅助 */
static
VOID
PdkBatchAddDistribution(
    _Inout_ PDK_BATCH_DISTRIBUTION* Dist,
    _In_ PDK_PACKER_TYPE Type
    )
{
    ULONG i;

    if (Dist == NULL) return;

    for (i = 0; i < Dist->EntryCount; ++i) {
        if (Dist->Entries[i].Type == Type) {
            Dist->Entries[i].Count++;
            return;
        }
    }
    if (Dist->EntryCount < PDK_MAX_DISTRIBUTION) {
        Dist->Entries[Dist->EntryCount].Type = Type;
        Dist->Entries[Dist->EntryCount].Count = 1;
        Dist->EntryCount++;
    }
}

/*++
 * PkdAnalyzeFiles —— 批量文件分析。
 *--*/
_Use_decl_annotations_
NTSTATUS
PkdAnalyzeFiles(
    PCWSTR* FilePaths,
    ULONG Count,
    const PDK_ANALYSIS_CONFIG* Config,
    PKD_PROGRESS_CALLBACK ProgressCallback,
    PDK_BATCH_RESULT* BatchResult,
    PDK_ERROR* Err
    )
{
    ULONG i;

    if (FilePaths == NULL || BatchResult == NULL ||
        (Count > 0 && FilePaths == NULL)) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return STATUS_INVALID_PARAMETER;
    }
    if (!PdkEnsureInitialized(Err)) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(BatchResult, sizeof(*BatchResult));
    BatchResult->StartTick = GetTickCount64();
    BatchResult->TotalFiles = Count;

    for (i = 0; i < Count; ++i) {
        PDK_PACKING_INFO* result;
        BOOLEAN ok;

        if (FilePaths[i] == NULL || FilePaths[i][0] == L'\0') {
            BatchResult->FailedFiles++;
            continue;
        }
        if (BatchResult->ResultCount >= PDK_MAX_BATCH_FILES) {
            break;
        }

        result = &BatchResult->Results[BatchResult->ResultCount];
        if (ProgressCallback != NULL) {
            ProgressCallback(FilePaths[i], i, Count);
        }

        ok = PkdAnalyzeFile(FilePaths[i], Config, result, Err);
        if (ok) {
            BatchResult->ResultCount++;
            PdkBatchAddDistribution(&BatchResult->PackerDistribution,
                result->PrimaryPacker);
            PdkBatchAddDistribution(&BatchResult->CategoryDistribution,
                (PDK_PACKER_TYPE)result->PackerCategory);
            if (result->IsPacked) BatchResult->PackedFiles++;
            if (result->IsInstaller) BatchResult->InstallerFiles++;
        } else {
            BatchResult->FailedFiles++;
        }
    }

    BatchResult->EndTick = GetTickCount64();
    BatchResult->TotalDurationMs = BatchResult->EndTick - BatchResult->StartTick;
    return STATUS_SUCCESS;
}

/*++
 * PkdAnalyzeDirectory —— 目录递归分析。
 *--*/
_Use_decl_annotations_
NTSTATUS
PkdAnalyzeDirectory(
    PCWSTR DirectoryPath,
    BOOLEAN Recursive,
    const PDK_ANALYSIS_CONFIG* Config,
    PKD_PROGRESS_CALLBACK ProgressCallback,
    PDK_BATCH_RESULT* BatchResult,
    PDK_ERROR* Err
    )
{
    static const WCHAR* const exeExts[] = {
        L".exe", L".dll", L".sys", L".ocx", L".scr", L".drv"
    };
    WCHAR searchPath[PDK_MAX_PATH * 2];
    WIN32_FIND_DATAW ffd;
    HANDLE hFind;
    ULONG processed = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (DirectoryPath == NULL || DirectoryPath[0] == L'\0' ||
        BatchResult == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return STATUS_INVALID_PARAMETER;
    }
    if (!PdkEnsureInitialized(Err)) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(BatchResult, sizeof(*BatchResult));
    BatchResult->StartTick = GetTickCount64();

    _snwprintf_s(searchPath, PDK_MAX_PATH * 2, _TRUNCATE,
        L"%s\\*", DirectoryPath);
    hFind = FindFirstFileW(searchPath, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        BatchResult->EndTick = GetTickCount64();
        BatchResult->TotalDurationMs = BatchResult->EndTick - BatchResult->StartTick;
        PdkErrorSet(Err, GetLastError(), L"无法枚举目录", DirectoryPath);
        return STATUS_UNSUCCESSFUL;
    }

    do {
        WCHAR fullPath[PDK_MAX_PATH * 2];
        BOOLEAN isExe = FALSE;
        ULONG e;

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (Recursive && ffd.cFileName[0] != L'.') {
                _snwprintf_s(fullPath, PDK_MAX_PATH * 2, _TRUNCATE,
                    L"%s\\%s", DirectoryPath, ffd.cFileName);
                (VOID)PkdAnalyzeDirectory(fullPath, Recursive, Config,
                    ProgressCallback, BatchResult, Err);
            }
            continue;
        }

        /* 扩展名过滤 */
        for (e = 0; e < PDK_ARRAY_COUNT(exeExts); ++e) {
            SIZE_T nameLen = wcslen(ffd.cFileName);
            SIZE_T extLen = wcslen(exeExts[e]);
            if (nameLen > extLen &&
                _wcsicmp(ffd.cFileName + nameLen - extLen, exeExts[e]) == 0) {
                isExe = TRUE;
                break;
            }
        }
        if (!isExe) continue;

        BatchResult->TotalFiles++;
        _snwprintf_s(fullPath, PDK_MAX_PATH * 2, _TRUNCATE,
            L"%s\\%s", DirectoryPath, ffd.cFileName);

        if (BatchResult->ResultCount >= PDK_MAX_BATCH_FILES) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        if (ProgressCallback != NULL) {
            ProgressCallback(fullPath, processed++, BatchResult->TotalFiles);
        }

        {
            PDK_PACKING_INFO* result = &BatchResult->Results[BatchResult->ResultCount];
            if (PkdAnalyzeFile(fullPath, Config, result, Err)) {
                BatchResult->ResultCount++;
                PdkBatchAddDistribution(&BatchResult->PackerDistribution,
                    result->PrimaryPacker);
                PdkBatchAddDistribution(&BatchResult->CategoryDistribution,
                    (PDK_PACKER_TYPE)result->PackerCategory);
                if (result->IsPacked) BatchResult->PackedFiles++;
                if (result->IsInstaller) BatchResult->InstallerFiles++;
            } else {
                BatchResult->FailedFiles++;
            }
        }
    } while (FindNextFileW(hFind, &ffd) != 0);

    FindClose(hFind);

    BatchResult->EndTick = GetTickCount64();
    BatchResult->TotalDurationMs = BatchResult->EndTick - BatchResult->StartTick;
    return status;
}

/**************************************************/
/*          公共 API：单点分析                      */
/**************************************************/

/*++
 * PkdCalculateSectionEntropy —— 文件内指定区间熵。
 *--*/
_Use_decl_annotations_
DOUBLE
PkdCalculateSectionEntropy(
    PCWSTR FilePath,
    ULONG SectionOffset,
    ULONG SectionSize,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    DOUBLE entropy = -1.0;

    if (FilePath == NULL || FilePath[0] == L'\0') {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return -1.0;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return -1.0;
    }

    if ((ULONGLONG)SectionOffset <= fileSize &&
        (ULONGLONG)SectionSize <= fileSize - SectionOffset) {
        entropy = PkdCalculateEntropy(base + SectionOffset, SectionSize);
    } else {
        PdkErrorSet(Err, ERROR_BAD_ARGUMENTS, L"节区间超出文件范围", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return entropy;
}

/*++
 * PkdAnalyzeSections —— 文件节分析（用户输出数组）。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeSections(
    PCWSTR FilePath,
    PDK_SECTION_INFO* Sections,
    ULONG* Count,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    PDK_PACKING_INFO tmp;
    ULONG i;
    BOOLEAN ok = FALSE;

    if (FilePath == NULL || Sections == NULL || Count == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        RtlZeroMemory(&tmp, sizeof(tmp));
        PdkResultReset(&tmp);
        PdkAnalyzeSectionsInternal(&ctx, &tmp);
        if (tmp.SectionCount > *Count) {
            tmp.SectionCount = *Count;
        }
        for (i = 0; i < tmp.SectionCount; ++i) {
            Sections[i] = tmp.Sections[i];
        }
        *Count = tmp.SectionCount;
        ok = TRUE;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
        *Count = 0;
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdAnalyzeImports —— 文件导入分析。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeImports(
    PCWSTR FilePath,
    PDK_IMPORT_INFO* OutImports,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    BOOLEAN ok = FALSE;

    if (FilePath == NULL || OutImports == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        RtlZeroMemory(OutImports, sizeof(*OutImports));
        PdkPeParseImports(&ctx, OutImports);
        ok = OutImports->Valid;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdAnalyzeOverlay —— 文件 Overlay 分析。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeOverlay(
    PCWSTR FilePath,
    PDK_OVERLAY_INFO* OutOverlay,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    PDK_PACKING_INFO tmp;
    BOOLEAN ok = FALSE;

    if (FilePath == NULL || OutOverlay == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        RtlZeroMemory(&tmp, sizeof(tmp));
        PdkResultReset(&tmp);
        PdkAnalyzeOverlayInternal(&ctx, &tmp);
        *OutOverlay = tmp.OverlayInfo;
        ok = TRUE;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdAnalyzeEntryPoint —— 文件入口点分析。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeEntryPoint(
    PCWSTR FilePath,
    PDK_ENTRY_POINT_INFO* OutEp,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    PDK_PACKING_INFO tmp;
    BOOLEAN ok = FALSE;

    if (FilePath == NULL || OutEp == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        RtlZeroMemory(&tmp, sizeof(tmp));
        PdkResultReset(&tmp);
        PdkAnalyzeEntryPointInternal(&ctx, &tmp);
        *OutEp = tmp.EntryPointInfo;
        ok = TRUE;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdMatchEPSignature —— EP 签名公开入口。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdMatchEPSignature(
    const BYTE* EpBytes,
    SIZE_T Size,
    PDK_PACKER_MATCH* Match,
    PDK_ERROR* Err
    )
{
    if (EpBytes == NULL || Size == 0 || Match == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }
    if (!PdkEnsureInitialized(Err)) {
        return FALSE;
    }
    return PdkMatchEPSignatureInternal(EpBytes, Size, Match);
}

/*++
 * PkdVerifySignature —— WinVerifyTrust Authenticode 验证
 *  （对齐 ProcessEvasionDetector.c PesIsSignatureValid 模式）。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdVerifySignature(
    PCWSTR FilePath,
    PDK_SIGNATURE_INFO* OutSignature,
    PDK_ERROR* Err
    )
{
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA trustData;
    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status;

    if (FilePath == NULL || OutSignature == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    RtlZeroMemory(OutSignature, sizeof(*OutSignature));
    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    RtlZeroMemory(&trustData, sizeof(trustData));

    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = FilePath;

    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_REVOKE_WHOLECHAIN | WTD_SAFER_FLAG;
    trustData.pFile = &fileInfo;

    status = WinVerifyTrust(NULL, &actionId, &trustData);

    OutSignature->HasSignature = TRUE;
    OutSignature->IsValid = FALSE;
    OutSignature->IsSelfSigned = FALSE;
    OutSignature->IsRevoked = FALSE;

    if (status == ERROR_SUCCESS) {
        OutSignature->HasSignature = TRUE;
        OutSignature->IsValid = TRUE;

        /* 关闭验证状态 */
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        (VOID)WinVerifyTrust(NULL, &actionId, &trustData);
        OutSignature->Valid = TRUE;
        return TRUE;
    }

    if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN) {
        OutSignature->HasSignature = FALSE;
    } else {
        if (status == CERT_E_REVOKED) {
            OutSignature->IsRevoked = TRUE;
        }
        /* 其他错误码 → 有签名但无效 */
    }

    /* 关闭验证状态 */
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (VOID)WinVerifyTrust(NULL, &actionId, &trustData);

    OutSignature->Valid = TRUE;
    PdkErrorSet(Err, (ULONG)status, L"签名验证未通过", FilePath);
    return TRUE;
}

/*++
 * PkdAnalyzeRichHeader —— 文件 Rich 头分析。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeRichHeader(
    PCWSTR FilePath,
    PDK_RICH_HEADER_INFO* OutRichHeader,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    PDK_PACKING_INFO tmp;
    BOOLEAN ok = FALSE;

    if (FilePath == NULL || OutRichHeader == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        RtlZeroMemory(&tmp, sizeof(tmp));
        PdkResultReset(&tmp);
        PdkAnalyzeRichHeaderInternal(&ctx, &tmp);
        *OutRichHeader = tmp.RichHeaderInfo;
        ok = TRUE;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdAnalyzeResources —— 文件资源分析。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdAnalyzeResources(
    PCWSTR FilePath,
    PDK_RESOURCE_INFO* OutResources,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    BOOLEAN ok = FALSE;

    if (FilePath == NULL || OutResources == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        RtlZeroMemory(OutResources, sizeof(*OutResources));
        PdkPeParseResources(&ctx, OutResources);
        ok = OutResources->Valid;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdScanWithYARA —— YARA 规则扫描（经 IocYara_ScanBuffer）。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdScanWithYARA(
    PCWSTR FilePath,
    PDK_PACKER_MATCH* Matches,
    ULONG* Count,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    BOOLEAN detected = FALSE;
    ULONG score = 0;
    WCHAR ruleName[128];
    ULONG outCount = 0;
    PDK_PACKER_TYPE mappedType = PDK_TYPE_UNKNOWN;
    PDK_PACKER_CATEGORY mappedCategory = PDK_CATEGORY_UNKNOWN;
    BOOLEAN ok = FALSE;
    NTSTATUS st;

    if (FilePath == NULL || Matches == NULL || Count == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    st = IocYara_ScanBuffer(base, (ULONG)fileSize, &detected,
        &score, ruleName, ARRAYSIZE(ruleName));
    if (!NT_SUCCESS(st)) {
        PdkErrorSet(Err, (ULONG)st, L"YARA 扫描失败", FilePath);
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    if (detected) {
        WCHAR lower[128];
        SIZE_T i;

        outCount = 0;
        if (outCount < *Count) {
            RtlZeroMemory(&Matches[outCount], sizeof(PDK_PACKER_MATCH));

            /* 规则名小写映射（对齐源 ScanWithYARA） */
            for (i = 0; ruleName[i] != L'\0' && i < 64; ++i) {
                WCHAR c = ruleName[i];
                if (c >= L'A' && c <= L'Z') {
                    c = (WCHAR)(c + (L'a' - L'A'));
                }
                lower[i] = c;
            }
            lower[i] = L'\0';

            if (wcsstr(lower, L"upx") != NULL) {
                mappedType = PDK_TYPE_UPX;
                mappedCategory = PDK_CATEGORY_COMPRESSION;
            } else if (wcsstr(lower, L"themida") != NULL) {
                mappedType = PDK_TYPE_THEMIDA;
                mappedCategory = PDK_CATEGORY_PROTECTOR;
            } else if (wcsstr(lower, L"vmprotect") != NULL) {
                mappedType = PDK_TYPE_VMPROTECT;
                mappedCategory = PDK_CATEGORY_PROTECTOR;
            } else if (wcsstr(lower, L"aspack") != NULL) {
                mappedType = PDK_TYPE_ASPACK;
                mappedCategory = PDK_CATEGORY_COMPRESSION;
            } else if (wcsstr(lower, L"mpress") != NULL) {
                mappedType = PDK_TYPE_MPRESS;
                mappedCategory = PDK_CATEGORY_COMPRESSION;
            } else if (wcsstr(lower, L"petite") != NULL) {
                mappedType = PDK_TYPE_PETITE;
                mappedCategory = PDK_CATEGORY_COMPRESSION;
            } else if (wcsstr(lower, L"enigma") != NULL) {
                mappedType = PDK_TYPE_ENIGMA;
                mappedCategory = PDK_CATEGORY_PROTECTOR;
            } else if (wcsstr(lower, L"asprotect") != NULL ||
                       wcsstr(lower, L"aspr") != NULL) {
                mappedType = PDK_TYPE_ASPROTECT;
                mappedCategory = PDK_CATEGORY_PROTECTOR;
            } else if (wcsstr(lower, L"armadillo") != NULL) {
                mappedType = PDK_TYPE_ARMADILLO;
                mappedCategory = PDK_CATEGORY_PROTECTOR;
            } else if (wcsstr(lower, L"pespin") != NULL) {
                mappedType = PDK_TYPE_PESPIN;
                mappedCategory = PDK_CATEGORY_PROTECTOR;
            } else if (wcsstr(lower, L"nsis") != NULL) {
                mappedType = PDK_TYPE_NSIS;
                mappedCategory = PDK_CATEGORY_INSTALLER;
            } else if (wcsstr(lower, L"inno") != NULL) {
                mappedType = PDK_TYPE_INNO_SETUP;
                mappedCategory = PDK_CATEGORY_INSTALLER;
            } else if (wcsstr(lower, L"sfx") != NULL ||
                       wcsstr(lower, L"7zip") != NULL) {
                mappedType = PDK_TYPE_SEVENZIP_SFX;
                mappedCategory = PDK_CATEGORY_SFX_ARCHIVE;
            } else if (wcsstr(lower, L"dotnet") != NULL ||
                       wcsstr(lower, L"confuser") != NULL) {
                mappedType = PDK_TYPE_CONFUSEREX;
                mappedCategory = PDK_CATEGORY_DOTNET_PROTECTOR;
            } else if (wcsstr(lower, L"malware") != NULL ||
                       wcsstr(lower, L"crypter") != NULL) {
                mappedType = PDK_TYPE_CUSTOM_PACKER;
                mappedCategory = PDK_CATEGORY_MALWARE_PACKER;
            }

            Matches[outCount].PackerType = mappedType;
            Matches[outCount].Category = mappedCategory;
            Matches[outCount].Method = PDK_METHOD_YARA_RULE;
            Matches[outCount].Confidence = 0.85;
            Matches[outCount].Severity = PDK_SEVERITY_MEDIUM;
            PDK_WCS_COPY(Matches[outCount].PackerName, PDK_MAX_NAME, ruleName);
            PDK_WCS_COPY(Matches[outCount].Details, PDK_MAX_DESC,
                L"YARA rule match");
            PDK_STR_COPY(Matches[outCount].MitreId, 16,
                PdkTypeToMitreId(mappedType));
            outCount = 1;
        }
        *Count = outCount;
        ok = TRUE;
    } else {
        *Count = 0;
        ok = TRUE;
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return ok;
}

/*++
 * PkdGenerateUnpackingHints —— 脱壳建议生成。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdGenerateUnpackingHints(
    const PDK_PACKING_INFO* PackingInfo,
    PDK_UNPACKING_HINTS* OutHints,
    PDK_ERROR* Err
    )
{
    if (PackingInfo == NULL || OutHints == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    RtlZeroMemory(OutHints, sizeof(*OutHints));

    /* 反脱壳技术扫描 */
    PdkFindAntiUnpacking(PackingInfo, OutHints);

    /* EP 所在节 → 模拟 OEP 估算：压缩壳常见于首个节边界附近 */
    OutHints->EstimatedOep = PackingInfo->EntryPointInfo.Rva;
    PDK_WCS_COPY(OutHints->OepMethod, 64, L"Entry point of unpacked image (simulated)");

    /* 工具建议（对齐源 SuggestedTool 映射） */
    switch (PackingInfo->PrimaryPacker) {
    case PDK_TYPE_UPX:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME, L"upx -d");
        OutHints->NeedsIatReconstruction = FALSE;
        break;
    case PDK_TYPE_ASPROTECT:
    case PDK_TYPE_ARMADILLO:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
            L"OllDbg + Process Dump + Import REConstructor");
        OutHints->NeedsIatReconstruction = TRUE;
        break;
    case PDK_TYPE_THEMIDA:
    case PDK_TYPE_VMPROTECT:
    case PDK_TYPE_ENIGMA:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
            L"HyperDbg (manual unpacking)");
        OutHints->NeedsIatReconstruction = TRUE;
        break;
    case PDK_TYPE_MPRESS:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
            L"OllDbg + Process Dump");
        OutHints->NeedsIatReconstruction = TRUE;
        break;
    case PDK_TYPE_PETITE:
    case PDK_TYPE_FSG:
    case PDK_TYPE_MEW:
    case PDK_TYPE_UPACK:
    case PDK_TYPE_NSPACK:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
            L"OllDbg + Import REConstructor");
        OutHints->NeedsIatReconstruction = TRUE;
        break;
    case PDK_TYPE_NSIS:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
            L"7-Zip (extract installer archive)");
        OutHints->NeedsIatReconstruction = FALSE;
        break;
    case PDK_TYPE_INNO_SETUP:
        PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
            L"Inno Extractor");
        OutHints->NeedsIatReconstruction = FALSE;
        break;
    default:
        if (PackingInfo->MatchCount == 0) {
            PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
                L"Manual analysis with Scylla (IAT rebuild)");
            OutHints->NeedsIatReconstruction = TRUE;
        } else {
            PDK_WCS_COPY(OutHints->SuggestedTool, PDK_MAX_NAME,
                L"Manual analysis with debugger");
            OutHints->NeedsIatReconstruction = TRUE;
        }
        break;
    }

    /* 压缩/加密算法提示 */
    if (PackingInfo->EntropyIndicatesCompression) {
        PDK_WCS_COPY(OutHints->CompressionAlgorithm, 64,
            L"Unknown compression (high entropy > 6.0)");
    }
    if (PackingInfo->EntropyIndicatesEncryption) {
        PDK_WCS_COPY(OutHints->EncryptionAlgorithm, 64,
            L"Unknown encryption (very high entropy > 7.0)");
    }
    if (PackingInfo->ResourceInfo.Valid &&
        PackingInfo->ResourceInfo.AverageEntropy >= PDK_HIGH_SECTION_ENTROPY) {
        if (OutHints->EncryptionAlgorithm[0] == L'\0') {
            PDK_WCS_COPY(OutHints->EncryptionAlgorithm, 64,
                L"Encrypted resource section (entropy-based)");
        }
    }

    /* 复杂度评估 */
    OutHints->ComplexityRating = 1;
    if (OutHints->AntiUnpackingCount > 0) OutHints->ComplexityRating += 1;
    if (PackingInfo->HasMultipleLayers) OutHints->ComplexityRating += 1;
    if (PackingInfo->IsDotNetAssembly) OutHints->ComplexityRating += 1;
    if (PackingInfo->EntryPointInfo.IsOutsideCodeSection) OutHints->ComplexityRating += 1;
    OutHints->HasMultipleLayers = PackingInfo->HasMultipleLayers;
    OutHints->EstimatedLayerCount = PackingInfo->LayerCount;

    /* 估算原始大小（基于虚拟大小 vs 文件大小） */
    if (PackingInfo->FileSize > 0) {
        OutHints->EstimatedOriginalSize =
            (ULONGLONG)((DOUBLE)PackingInfo->FileSize /
                (PackingInfo->PackingConfidence > 0.05 ?
                 PackingInfo->PackingConfidence : 0.05));
    }

    OutHints->Valid = TRUE;
    return TRUE;
}

/*++
 * PkdIsInstaller —— 安装器判定（节名 + Overlay 魔数）。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdIsInstaller(
    PCWSTR FilePath,
    PWSTR InstallerType,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    BOOLEAN result = FALSE;

    if (FilePath == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }
    if (InstallerType != NULL) {
        InstallerType[0] = L'\0';
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (!PdkPeParse(&ctx, base, fileSize)) {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    /* 节名匹配 */
    {
        ULONG s;
        for (s = 0; s < ctx.SectionCount && !result; ++s) {
            SIZE_T k;
            for (k = 0; k < PDK_ARRAY_COUNT(g_PdkInstallerSections); ++k) {
                if (PdkSectionNameEquals(ctx.Sections[s].Name,
                        g_PdkInstallerSections[k])) {
                    result = TRUE;
                    if (InstallerType != NULL) {
                        if (_stricmp(g_PdkInstallerSections[k], ".nsis") == 0) {
                            PDK_WCS_COPY(InstallerType, PDK_MAX_NAME, L"NSIS");
                        } else if (_stricmp(g_PdkInstallerSections[k], ".inno") == 0) {
                            PDK_WCS_COPY(InstallerType, PDK_MAX_NAME, L"InnoSetup");
                        } else if (g_PdkInstallerSections[k][0] == '.') {
                            _snwprintf_s(InstallerType, PDK_MAX_NAME, _TRUNCATE,
                                L"Generic (%S)", g_PdkInstallerSections[k]);
                        } else {
                            PDK_WCS_COPY(InstallerType, PDK_MAX_NAME, L"Generic");
                        }
                    }
                    break;
                }
            }
        }
    }

    /* Overlay 魔数兜底判定（未命中节名时） */
    if (!result && ctx.OverlaySize >= 4 &&
        (ULONGLONG)ctx.OverlayOffset + 4 <= fileSize) {
        const BYTE* data = base + ctx.OverlayOffset;
        if (memcmp(data, "PK\x03\x04", 4) == 0) {
            result = TRUE;
            if (InstallerType != NULL) {
                PDK_WCS_COPY(InstallerType, PDK_MAX_NAME, L"ZIP SFX");
            }
        } else if (data[0] == 0xEF && data[1] == 0xBE && data[2] == 0xAD &&
                   data[3] == 0xDE) {
            result = TRUE;
            if (InstallerType != NULL) {
                PDK_WCS_COPY(InstallerType, PDK_MAX_NAME, L"NSIS");
            }
        }
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return result;
}

/*++
 * PkdIsDotNetAssembly —— .NET 程序集判定（CLR 目录）。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdIsDotNetAssembly(
    PCWSTR FilePath,
    PDK_ERROR* Err
    )
{
    BYTE* base = NULL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    PDK_PE_CONTEXT ctx;
    BOOLEAN result = FALSE;

    if (FilePath == NULL) {
        PdkErrorSet(Err, ERROR_INVALID_PARAMETER, L"参数无效", NULL);
        return FALSE;
    }

    if (!PdkReadFileViaMapping(FilePath, &base, &fileSize, &hFile, &hMapping)) {
        PdkErrorSet(Err, GetLastError(), L"无法读取文件", FilePath);
        return FALSE;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (PdkPeParse(&ctx, base, fileSize)) {
        result = ctx.IsDotNet;
    } else {
        PdkErrorSet(Err, ERROR_BAD_EXE_FORMAT, L"不是有效的 PE 文件", FilePath);
    }

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return result;
}

/**************************************************/
/*          公共 API：回调 / 缓存 / 自定义 / 统计    */
/**************************************************/

/*++
 * PkdSetDetectionCallback / PkdClearDetectionCallback。
 *--*/
_Use_decl_annotations_
VOID
PkdSetDetectionCallback(
    PKD_DETECTION_CALLBACK Callback
    )
{
    AcquireSRWLockExclusive(&g_PdkLock);
    g_PdkCallback = Callback;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

_Use_decl_annotations_
VOID
PkdClearDetectionCallback(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_PdkLock);
    g_PdkCallback = NULL;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

/*++
 * 缓存查询 / 失效 / 清空 / 大小。
 *--*/
_Use_decl_annotations_
BOOLEAN
PkdGetCachedResult(
    PCWSTR FilePath,
    PDK_PACKING_INFO* OutResult
    )
{
    if (FilePath == NULL || OutResult == NULL) return FALSE;
    if (!g_PdkInitialized) return FALSE;
    return PdkCacheLookup(FilePath, OutResult);
}

_Use_decl_annotations_
VOID
PkdInvalidateCache(
    PCWSTR FilePath
    )
{
    SIZE_T i;

    if (FilePath == NULL) return;
    AcquireSRWLockExclusive(&g_PdkLock);
    for (i = 0; i < g_PdkCacheCount; ++i) {
        if (g_PdkCache[i].Used && _wcsicmp(g_PdkCache[i].Path, FilePath) == 0) {
            g_PdkCache[i].Used = FALSE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_PdkLock);
}

_Use_decl_annotations_
VOID
PkdClearCache(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_PdkLock);
    RtlZeroMemory(g_PdkCache, sizeof(g_PdkCache));
    g_PdkCacheCount = 0;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

_Use_decl_annotations_
SIZE_T
PkdGetCacheSize(
    VOID
    )
{
    SIZE_T count;

    AcquireSRWLockShared(&g_PdkLock);
    count = g_PdkCacheCount;
    ReleaseSRWLockShared(&g_PdkLock);
    return count;
}

/*++
 * PkdAddCustomEPSignature —— 全掩码精确自定义签名。
 *--*/
_Use_decl_annotations_
VOID
PkdAddCustomEPSignature(
    PCWSTR PackerName,
    const BYTE* Signature,
    SIZE_T SignatureSize,
    PDK_PACKER_TYPE Type
    )
{
    PDK_EP_SIGNATURE* sig;

    if (PackerName == NULL || Signature == NULL || SignatureSize == 0 ||
        SignatureSize > PDK_MAX_EP_BYTES) {
        return;
    }

    AcquireSRWLockExclusive(&g_PdkLock);
    if (g_PdkCustomSigCount >= PDK_MAX_CUSTOM_EPSIG) {
        ReleaseSRWLockExclusive(&g_PdkLock);
        return;
    }
    sig = &g_PdkCustomSigs[g_PdkCustomSigCount];
    RtlZeroMemory(sig, sizeof(*sig));
    PDK_WCS_COPY(sig->Name, PDK_MAX_NAME, PackerName);
    PDK_STR_COPY(sig->Version, 16, "custom");
    sig->PackerType = Type;
    sig->PatternSize = SignatureSize;
    memcpy(sig->Pattern, Signature, SignatureSize);
    RtlFillMemory(sig->Mask, SignatureSize, 0xFF);
    sig->Confidence = 0.80;
    g_PdkCustomSigCount++;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

/*++
 * PkdAddCustomSectionPattern / PkdClearCustomPatterns。
 *--*/
_Use_decl_annotations_
VOID
PkdAddCustomSectionPattern(
    PCSTR SectionName,
    PDK_PACKER_TYPE Type
    )
{
    PDK_CUSTOM_SECTION* sec;

    if (SectionName == NULL || SectionName[0] == '\0') return;

    AcquireSRWLockExclusive(&g_PdkLock);
    if (g_PdkCustomSectionCount >= PDK_MAX_CUSTOM_SECTIONS) {
        ReleaseSRWLockExclusive(&g_PdkLock);
        return;
    }
    sec = &g_PdkCustomSections[g_PdkCustomSectionCount];
    RtlZeroMemory(sec, sizeof(*sec));
    PDK_STR_COPY(sec->Name, 16, SectionName);
    sec->Type = Type;
    g_PdkCustomSectionCount++;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

_Use_decl_annotations_
VOID
PkdClearCustomPatterns(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_PdkLock);
    RtlZeroMemory(g_PdkCustomSigs, sizeof(g_PdkCustomSigs));
    g_PdkCustomSigCount = 0;
    RtlZeroMemory(g_PdkCustomSections, sizeof(g_PdkCustomSections));
    g_PdkCustomSectionCount = 0;
    ReleaseSRWLockExclusive(&g_PdkLock);
}

/*++
 * PkdGetStatistics / PkdResetStatistics。
 *--*/
_Use_decl_annotations_
VOID
PkdGetStatistics(
    PDK_STATISTICS* OutStats
    )
{
    if (OutStats == NULL) return;
    *OutStats = g_PdkStats;
}

_Use_decl_annotations_
VOID
PkdResetStatistics(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_PdkLock);
    RtlZeroMemory(&g_PdkStats, sizeof(g_PdkStats));
    ReleaseSRWLockExclusive(&g_PdkLock);
}