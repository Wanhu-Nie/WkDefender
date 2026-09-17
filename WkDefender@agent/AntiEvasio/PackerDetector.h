/**************************************************/
/*  WkDefender Agent — 加壳器检测引擎               */
/*  AntiEvasio / PackerDetector.h                  */
/*                                                  */
/*  迁移自 ShadowStrike PackerDetector              */
/*  (.hpp 2334行 + .cpp 4375行)。纯 C 实现。         */
/*                                                  */
/*  检测能力（六路合成判定）：                       */
/*    1. 熵分析：Shannon 熵 / 卡方检验 /            */
/*       压缩 vs 加密区分（宽/节/Overlay/资源四级）  */
/*    2. PE 结构分析：节表 / 导入表 / Overlay /      */
/*       Rich 头 / 资源 / 入口点 / .NET 标志         */
/*    3. EP 签名匹配：内嵌 40 条经典签名库           */
/*       （UPX/ASPack/PECompact/MPRESS/Themida/      */
/*        VMProtect/Enigma/NSIS/CS 等）              */
/*    4. 加壳 Stub 启发式：PUSHAD/解压循环/XOR 解密/ */
/*       反调试/API 哈希（字节模式，原反汇编降级）   */
/*    5. YARA 扫描：接入 IocYara_ScanBuffer          */
/*       （工程预留集成点）                          */
/*    6. 数字签名验证：WinVerifyTrust 内联           */
/*                                                  */
/*  降级决策（纯 C 化）：                            */
/*    - PhantomDisassembler → 字节模式扫描          */
/*    - PEParser            → 内联 PdkPe* 解析器    */
/*    - SignatureStore      → IocYara_ScanBuffer    */
/*    - asm 时序/调试寄存器 → 省略（未被调用）       */
/*    - std::vector/map     → 固定上限数组           */
/*    - 结果缓存 8192 项    → 16 项（LRU 淘汰）      */
/*                                                  */
/*  线程安全：公共 API 以 g_PdkLock（SRW）保护全局    */
/*  状态；统计计数器采用 Interlocked 原子操作。      */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#pragma once

#ifndef _WIN32
#error "此模块仅支持 Windows 平台"
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

/**************************************************/
/*          常量：资源上限与长度限制                */
/**************************************************/

/* 最大分析文件大小（500MB，源对齐） */
#define PDK_MAX_FILE_SIZE           (500ULL * 1024 * 1024)

/* 最大 Overlay 分析大小（100MB） */
#define PDK_MAX_OVERLAY_SIZE        (100ULL * 1024 * 1024)

/* 结果数组上限（源为 std::vector 无硬上限，压缩以控制结构尺寸） */
#define PDK_MAX_SECTIONS            24      /* 源 256；超出节仍参与聚合统计 */
#define PDK_MAX_MATCHES             12
#define PDK_MAX_INDICATORS          64      /* 源 500 */
#define PDK_MAX_ANOMALIES           32
#define PDK_MAX_DLLS                48
#define PDK_MAX_SUSPICIOUS_IMPORTS  24
#define PDK_MAX_ERRORS              8
#define PDK_MAX_RICH_ENTRIES        32
#define PDK_MAX_RES_LANGUAGES       16
#define PDK_MAX_SUSPICIOUS_RES      16
#define PDK_MAX_ANIUNPACK_TECH      16
#define PDK_MAX_HINTS_NOTES         8
#define PDK_MAX_SIG_ERRORS          8
#define PDK_MAX_BATCH_FILES         128
#define PDK_MAX_DISTRIBUTION        32
#define PDK_MAX_CACHE_ENTRIES       16      /* 源 8192 → 固定数组降级 */
#define PDK_MAX_CUSTOM_EPSIG        32
#define PDK_MAX_CUSTOM_SECTIONS     32
#define PDK_MAX_PE_SECTIONS         64      /* 解析器内部节上限（聚合统计） */

/* 字符串长度限制 */
#define PDK_MAX_PATH                512     /* 文件路径 */
#define PDK_MAX_NAME                160     /* 模块/节名 */
#define PDK_MAX_DESC                192     /* 指示器/异常/描述 */

/* 入口点签名匹配字节数（源 MAX_EP_BYTES） */
#define PDK_MAX_EP_BYTES            512

/* Stub 字节扫描上限（源 MAX_STUB_INSTRUCTIONS=256 指令 → 固定字节窗口） */
#define PDK_MAX_STUB_BYTES          256

/* 熵分析最小节大小（源 MIN_SECTION_SIZE_FOR_ENTROPY） */
#define PDK_MIN_SECTION_ENTROPY_BYTES 256

/* 默认扫描超时（ms）/ 缓存 TTL（秒） */
#define PDK_DEFAULT_SCAN_TIMEOUT_MS 30000
#define PDK_RESULT_CACHE_TTL_SECONDS 600

/**************************************************/
/*          常量：熵阈值（对齐源 PackerConstants） */
/**************************************************/

#define PDK_MIN_COMPRESSED_ENTROPY  6.0     /* 压缩数据熵下限 */
#define PDK_MIN_ENCRYPTED_ENTROPY   7.0     /* 加密数据熵下限 */
#define PDK_MAX_THEORETICAL_ENTROPY 8.0
#define PDK_HIGH_SECTION_ENTROPY    6.5     /* 高熵节阈值 */
#define PDK_VERY_HIGH_ENTROPY       7.5
#define PDK_NORMAL_CODE_ENTROPY_MIN 4.0
#define PDK_NORMAL_CODE_ENTROPY_MAX 6.5
#define PDK_NORMAL_DATA_ENTROPY_MAX 5.5

/**************************************************/
/*          常量：检测阈值与权重                   */
/**************************************************/

#define PDK_MIN_PACKING_CONFIDENCE      0.3
#define PDK_HIGH_CONFIDENCE_THRESHOLD   0.75
#define PDK_DEFINITE_PACKING_THRESHOLD  0.9
#define PDK_MIN_NORMAL_IMPORTS          5
#define PDK_SUSPICIOUS_LOW_IMPORT_COUNT 3
#define PDK_EP_SIGNATURE_SIZE           256
#define PDK_SUSPICIOUS_OVERLAY_PERCENTAGE 50.0

#define PDK_WEIGHT_ENTROPY          2.0
#define PDK_WEIGHT_SECTION_ANOMALIES 1.5
#define PDK_WEIGHT_EP_SIGNATURE     3.0
#define PDK_WEIGHT_IMPORT_ANOMALIES 1.5
#define PDK_WEIGHT_YARA_MATCH       2.5
#define PDK_WEIGHT_OVERLAY          1.0
#define PDK_WEIGHT_STRUCTURAL       1.5
#define PDK_WEIGHT_NO_SIGNATURE     0.5

/**************************************************/
/*          枚举：加壳器类别（对齐源枚举值）        */
/**************************************************/

typedef enum _PDK_PACKER_CATEGORY {
    PDK_CATEGORY_UNKNOWN = 0,
    PDK_CATEGORY_COMPRESSION = 1,       /* 纯压缩（UPX/ASPack） */
    PDK_CATEGORY_PROTECTOR = 2,         /* 商业保护（Themida/VMProtect） */
    PDK_CATEGORY_CRYPTER = 3,           /* 加密型 */
    PDK_CATEGORY_DOTNET_PROTECTOR = 4,  /* .NET 混淆/保护 */
    PDK_CATEGORY_INSTALLER = 5,         /* 安装器/SFX */
    PDK_CATEGORY_VM_PROTECTION = 6,     /* VM 保护 */
    PDK_CATEGORY_CUSTOM = 7,            /* 私有加壳器 */
    PDK_CATEGORY_MALWARE_PACKER = 8,    /* 恶意软件专用 */
    PDK_CATEGORY_LEGITIMATE_PROTECTION = 9,
    PDK_CATEGORY_SFX_ARCHIVE = 10,      /* 自解压归档 */
    PDK_CATEGORY_MULTI_LAYER = 11       /* 多层组合 */
} PDK_PACKER_CATEGORY;

/**************************************************/
/*          枚举：加壳器类型（对齐源枚举值）        */
/**************************************************/

typedef enum _PDK_PACKER_TYPE {
    PDK_TYPE_UNKNOWN = 0,

    /* === 压缩加壳器 (1-100) === */
    PDK_TYPE_UPX = 1,
    PDK_TYPE_UPX_MODIFIED = 2,
    PDK_TYPE_UPX_SCRAMBLED = 3,
    PDK_TYPE_ASPACK = 10,
    PDK_TYPE_ASPACK_V1 = 11,
    PDK_TYPE_ASPACK_V2 = 12,
    PDK_TYPE_PECOMPACT = 20,
    PDK_TYPE_PECOMPACT_V1 = 21,
    PDK_TYPE_PECOMPACT_V2 = 22,
    PDK_TYPE_PECOMPACT_V3 = 23,
    PDK_TYPE_MPRESS = 30,
    PDK_TYPE_MPRESS_V1 = 31,
    PDK_TYPE_MPRESS_V2 = 32,
    PDK_TYPE_PETITE = 40,
    PDK_TYPE_PETITE_V1 = 41,
    PDK_TYPE_PETITE_V2 = 42,
    PDK_TYPE_FSG = 50,
    PDK_TYPE_FSG_V1 = 51,
    PDK_TYPE_FSG_V2 = 52,
    PDK_TYPE_MEW = 60,
    PDK_TYPE_MEW_V10 = 61,
    PDK_TYPE_MEW_V11 = 62,
    PDK_TYPE_NSPACK = 70,
    PDK_TYPE_NSPACK_V2 = 71,
    PDK_TYPE_NSPACK_V3 = 72,
    PDK_TYPE_UPACK = 80,
    PDK_TYPE_WINUPACK = 81,
    PDK_TYPE_KKRUNCHY = 90,
    PDK_TYPE_RLPACK = 91,
    PDK_TYPE_JDPACK = 92,
    PDK_TYPE_BEROEXE_PACKER = 93,
    PDK_TYPE_CEXE = 94,
    PDK_TYPE_PACKMAN = 95,
    PDK_TYPE_PEPACK = 96,
    PDK_TYPE_WWPACK32 = 97,

    /* === 商业保护器 (101-200) === */
    PDK_TYPE_THEMIDA = 101,
    PDK_TYPE_THEMIDA_V1 = 102,
    PDK_TYPE_THEMIDA_V2 = 103,
    PDK_TYPE_THEMIDA_V3 = 104,
    PDK_TYPE_WINLICENSE = 105,
    PDK_TYPE_VMPROTECT = 110,
    PDK_TYPE_VMPROTECT_V1 = 111,
    PDK_TYPE_VMPROTECT_V2 = 112,
    PDK_TYPE_VMPROTECT_V3 = 113,
    PDK_TYPE_ENIGMA = 120,
    PDK_TYPE_ENIGMA_V1 = 121,
    PDK_TYPE_ENIGMA_V4 = 122,
    PDK_TYPE_ENIGMA_V6 = 123,
    PDK_TYPE_ENIGMA_V7 = 124,
    PDK_TYPE_ASPROTECT = 130,
    PDK_TYPE_ASPROTECT_V1 = 131,
    PDK_TYPE_ASPROTECT_V2 = 132,
    PDK_TYPE_ASPROTECT_SKE = 133,
    PDK_TYPE_ARMADILLO = 140,
    PDK_TYPE_ARMADILLO_V3 = 141,
    PDK_TYPE_ARMADILLO_V4 = 142,
    PDK_TYPE_ARMADILLO_V9 = 143,
    PDK_TYPE_OBSIDIUM = 150,
    PDK_TYPE_OBSIDIUM_V1 = 151,
    PDK_TYPE_PELOCK = 160,
    PDK_TYPE_PELOCK_V1 = 161,
    PDK_TYPE_PELOCK_V2 = 162,
    PDK_TYPE_CODE_VIRTUALIZER = 170,
    PDK_TYPE_CODE_VIRTUALIZER_V1 = 171,
    PDK_TYPE_CODE_VIRTUALIZER_V2 = 172,
    PDK_TYPE_CODE_VIRTUALIZER_V3 = 173,
    PDK_TYPE_EXECRYPTER = 180,
    PDK_TYPE_EXECRYPTER_V2 = 181,
    PDK_TYPE_SAFENGINE = 190,
    PDK_TYPE_ACPROTECT = 191,
    PDK_TYPE_EXESHIELD = 192,
    PDK_TYPE_SVK_PROTECTOR = 193,
    PDK_TYPE_PCGUARD = 194,
    PDK_TYPE_ANTICRACK = 195,

    /* === 游戏/DRM 保护 (201-250) === */
    PDK_TYPE_STARFORCE = 201,
    PDK_TYPE_STARFORCE_V3 = 202,
    PDK_TYPE_STARFORCE_V5 = 203,
    PDK_TYPE_SECUROM = 210,
    PDK_TYPE_SECUROM_V4 = 211,
    PDK_TYPE_SECUROM_V7 = 212,
    PDK_TYPE_SECUROM_V8 = 213,
    PDK_TYPE_SAFEDISC = 220,
    PDK_TYPE_SAFEDISC_V2 = 221,
    PDK_TYPE_SAFEDISC_V4 = 222,
    PDK_TYPE_DENUVO = 230,
    PDK_TYPE_SOLIDSHIELD = 240,
    PDK_TYPE_TAGS_EPROTECT = 241,
    PDK_TYPE_CDILLA = 242,

    /* === 加密器 (251-300) === */
    PDK_TYPE_PESPIN = 251,
    PDK_TYPE_PESPIN_V0 = 252,
    PDK_TYPE_PESPIN_V1 = 253,
    PDK_TYPE_TELOCK = 260,
    PDK_TYPE_TELOCK_V0 = 261,
    PDK_TYPE_TELOCK_V1 = 262,
    PDK_TYPE_YODA_CRYPTER = 270,
    PDK_TYPE_YODA_PROTECTOR = 271,
    PDK_TYPE_PECRYPT32 = 280,
    PDK_TYPE_MORPHINE = 281,
    PDK_TYPE_NEOLITE = 282,
    PDK_TYPE_EXECRYPTER32 = 283,
    PDK_TYPE_SD_PROTECTOR = 284,
    PDK_TYPE_PE_ARMOR = 285,
    PDK_TYPE_POLYCRYPT = 286,
    PDK_TYPE_PEX = 287,
    PDK_TYPE_CRYPKEY = 288,

    /* === .NET 保护器 (301-350) === */
    PDK_TYPE_CONFUSEREX = 301,
    PDK_TYPE_CONFUSEREX_V0 = 302,
    PDK_TYPE_CONFUSEREX_V1 = 303,
    PDK_TYPE_CONFUSER = 304,
    PDK_TYPE_DOTNET_REACTOR = 310,
    PDK_TYPE_DOTNET_REACTOR_V4 = 311,
    PDK_TYPE_DOTNET_REACTOR_V5 = 312,
    PDK_TYPE_DOTNET_REACTOR_V6 = 313,
    PDK_TYPE_EAZFUSCATOR = 320,
    PDK_TYPE_DOTFUSCATOR = 321,
    PDK_TYPE_SMART_ASSEMBLY = 322,
    PDK_TYPE_AGILE_NET = 323,
    PDK_TYPE_BABEL_NET = 324,
    PDK_TYPE_CRYPTO_OBFUSCATOR = 325,
    PDK_TYPE_MAXTOCODE = 326,
    PDK_TYPE_CODEVEIL = 327,
    PDK_TYPE_SPICES_NET = 328,
    PDK_TYPE_GOLIATH_NET = 329,
    PDK_TYPE_ILPROTECTOR = 330,
    PDK_TYPE_PHOENIX_PROTECTOR = 331,
    PDK_TYPE_DEEPSEA = 332,
    PDK_TYPE_XENOCODE = 333,

    /* === 安装器 (351-400) === */
    PDK_TYPE_NSIS = 351,
    PDK_TYPE_NSIS_V2 = 352,
    PDK_TYPE_NSIS_V3 = 353,
    PDK_TYPE_INNO_SETUP = 360,
    PDK_TYPE_INNO_SETUP_V5 = 361,
    PDK_TYPE_INNO_SETUP_V6 = 362,
    PDK_TYPE_INSTALLSHIELD = 370,
    PDK_TYPE_WIX = 380,
    PDK_TYPE_ADVANCED_INSTALLER = 381,
    PDK_TYPE_SETUP_FACTORY = 382,
    PDK_TYPE_CREATE_INSTALL = 383,
    PDK_TYPE_INSTALLAWARE = 384,
    PDK_TYPE_WISE = 385,
    PDK_TYPE_GHOST_INSTALLER = 386,

    /* === SFX 归档 (401-420) === */
    PDK_TYPE_SEVENZIP_SFX = 401,
    PDK_TYPE_WINRAR_SFX = 402,
    PDK_TYPE_WINZIP_SFX = 403,
    PDK_TYPE_ZIP_SFX = 404,
    PDK_TYPE_CAB_SFX = 405,
    PDK_TYPE_ARJ_SFX = 406,

    /* === 恶意软件专用 (421-500) === */
    PDK_TYPE_CRYPTERX = 421,
    PDK_TYPE_NJCRYPTER = 422,
    PDK_TYPE_DARKCOMET_STUB = 423,
    PDK_TYPE_ANDROMEDA_LOADER = 424,
    PDK_TYPE_SMOKELOADER_PACKER = 425,
    PDK_TYPE_EMOTET_PACKER = 426,
    PDK_TYPE_TRICKBOT_PACKER = 427,
    PDK_TYPE_DRIDEX_PACKER = 428,
    PDK_TYPE_QAKBOT_PACKER = 429,
    PDK_TYPE_ICEDID_PACKER = 430,
    PDK_TYPE_BAZARLOADER_PACKER = 431,
    PDK_TYPE_RYUK_PACKER = 432,
    PDK_TYPE_CONTI_PACKER = 433,
    PDK_TYPE_COBALT_STRIKE_BEACON = 434,

    PDK_TYPE_CUSTOM_PACKER = 499,
    PDK_TYPE_MAX_PACKER_ID = 500
} PDK_PACKER_TYPE;

/**************************************************/
/*          枚举：检测方法与严重级别               */
/**************************************************/

typedef enum _PDK_DETECTION_METHOD {
    PDK_METHOD_UNKNOWN = 0,
    PDK_METHOD_EP_SIGNATURE = 1,
    PDK_METHOD_SECTION_NAME = 2,
    PDK_METHOD_YARA_RULE = 3,
    PDK_METHOD_ENTROPY = 4,
    PDK_METHOD_IMPORT = 5,
    PDK_METHOD_STRUCTURAL = 6,
    PDK_METHOD_HEURISTIC = 7,
    PDK_METHOD_STRING = 8,
    PDK_METHOD_HASH = 9,
    PDK_METHOD_OVERLAY = 10,
    PDK_METHOD_RICH_HEADER = 11,
    PDK_METHOD_RESOURCE = 12,
    PDK_METHOD_COMBINED = 255
} PDK_DETECTION_METHOD;

typedef enum _PDK_PACKER_SEVERITY {
    PDK_SEVERITY_BENIGN = 0,        /* 合法软件 */
    PDK_SEVERITY_LOW = 1,           /* 常见加壳/安装器 */
    PDK_SEVERITY_MEDIUM = 2,        /* 商业保护器 */
    PDK_SEVERITY_HIGH = 3,          /* 加密器/可疑 */
    PDK_SEVERITY_CRITICAL = 4       /* 恶意软件专用 */
} PDK_PACKER_SEVERITY;

typedef enum _PDK_ANALYSIS_DEPTH {
    PDK_DEPTH_QUICK = 0,            /* 熵 + EP 签名 */
    PDK_DEPTH_STANDARD = 1,         /* + 节 + 导入 */
    PDK_DEPTH_DEEP = 2,             /* + YARA + 启发式 */
    PDK_DEPTH_COMPREHENSIVE = 3     /* 全部技术 */
} PDK_ANALYSIS_DEPTH;

/**************************************************/
/*          常量：分析标志位（对齐源枚举值）        */
/**************************************************/

#define PDK_FLAG_NONE                    0x00000000

/* 检测技术 */
#define PDK_FLAG_ENABLE_ENTROPY          0x00000001
#define PDK_FLAG_ENABLE_SECTION          0x00000002
#define PDK_FLAG_ENABLE_EP_SIGNATURE     0x00000004
#define PDK_FLAG_ENABLE_YARA             0x00000008
#define PDK_FLAG_ENABLE_IMPORT           0x00000010
#define PDK_FLAG_ENABLE_OVERLAY          0x00000020
#define PDK_FLAG_ENABLE_RESOURCE         0x00000040
#define PDK_FLAG_ENABLE_RICH_HEADER      0x00000080
#define PDK_FLAG_ENABLE_STRING           0x00000100
#define PDK_FLAG_ENABLE_HEURISTIC        0x00000200
#define PDK_FLAG_ENABLE_SIG_VERIFY       0x00000400

/* 行为标志 */
#define PDK_FLAG_ENABLE_CACHING          0x00010000
#define PDK_FLAG_ENABLE_PARALLEL         0x00020000   /* 保留（不支持并行） */
#define PDK_FLAG_STOP_ON_FIRST           0x00040000   /* 保留 */
#define PDK_FLAG_INCLUDE_LAYERS          0x00080000   /* 保留（层已自动检测） */
#define PDK_FLAG_INCLUDE_HINTS           0x00100000
#define PDK_FLAG_INCLUDE_RAW             0x00200000   /* 保留 */

/* 预设组合（对齐源） */
#define PDK_FLAG_QUICK_SCAN \
    (PDK_FLAG_ENABLE_ENTROPY | PDK_FLAG_ENABLE_SECTION | PDK_FLAG_ENABLE_EP_SIGNATURE | PDK_FLAG_ENABLE_CACHING)
#define PDK_FLAG_STANDARD_SCAN \
    (PDK_FLAG_QUICK_SCAN | PDK_FLAG_ENABLE_IMPORT | PDK_FLAG_ENABLE_OVERLAY | PDK_FLAG_ENABLE_SIG_VERIFY)
#define PDK_FLAG_DEEP_SCAN \
    (PDK_FLAG_STANDARD_SCAN | PDK_FLAG_ENABLE_YARA | PDK_FLAG_ENABLE_RESOURCE | PDK_FLAG_ENABLE_HEURISTIC)
#define PDK_FLAG_COMPREHENSIVE_SCAN \
    (0x000007FFu | PDK_FLAG_ENABLE_CACHING | PDK_FLAG_ENABLE_PARALLEL | PDK_FLAG_INCLUDE_LAYERS | PDK_FLAG_INCLUDE_HINTS)
#define PDK_FLAG_DEFAULT PDK_FLAG_STANDARD_SCAN

#define PDK_HAS_FLAG(flags, flag) \
    (((UINT32)(flags) & (UINT32)(flag)) != 0)

/**************************************************/
/*          工具函数（内联映射）                   */
/**************************************************/

/* 类别 → 字符串 */
static __inline const char* PdkCategoryToString(PDK_PACKER_CATEGORY Category)
{
    switch (Category) {
    case PDK_CATEGORY_COMPRESSION:         return "Compression Packer";
    case PDK_CATEGORY_PROTECTOR:           return "Protector";
    case PDK_CATEGORY_CRYPTER:             return "Crypter";
    case PDK_CATEGORY_DOTNET_PROTECTOR:    return ".NET Protector";
    case PDK_CATEGORY_INSTALLER:           return "Installer";
    case PDK_CATEGORY_VM_PROTECTION:       return "VM Protection";
    case PDK_CATEGORY_CUSTOM:              return "Custom Packer";
    case PDK_CATEGORY_MALWARE_PACKER:      return "Malware Packer";
    case PDK_CATEGORY_LEGITIMATE_PROTECTION: return "Legitimate Protection";
    case PDK_CATEGORY_SFX_ARCHIVE:         return "SFX Archive";
    case PDK_CATEGORY_MULTI_LAYER:         return "Multi-Layer";
    default:                               return "Unknown";
    }
}

/* 类型 → MITRE ATT&CK ID（对齐源，均归 T1027.002） */
static __inline const char* PdkTypeToMitreId(PDK_PACKER_TYPE Type)
{
    (void)Type;
    return "T1027.002";
}

/* 类型 → 类别（按枚举值区间划分，对齐源） */
static __inline PDK_PACKER_CATEGORY PdkGetCategory(PDK_PACKER_TYPE Type)
{
    const UINT16 id = (UINT16)Type;
    if (id >= 1 && id <= 100)    return PDK_CATEGORY_COMPRESSION;
    if (id >= 101 && id <= 200)  return PDK_CATEGORY_PROTECTOR;
    if (id >= 201 && id <= 250)  return PDK_CATEGORY_LEGITIMATE_PROTECTION;
    if (id >= 251 && id <= 300)  return PDK_CATEGORY_CRYPTER;
    if (id >= 301 && id <= 350)  return PDK_CATEGORY_DOTNET_PROTECTOR;
    if (id >= 351 && id <= 400)  return PDK_CATEGORY_INSTALLER;
    if (id >= 401 && id <= 420)  return PDK_CATEGORY_SFX_ARCHIVE;
    if (id >= 421 && id <= 500)  return PDK_CATEGORY_MALWARE_PACKER;
    return PDK_CATEGORY_UNKNOWN;
}

/* 类型 → 默认严重级别（对齐源） */
static __inline PDK_PACKER_SEVERITY PdkGetSeverity(PDK_PACKER_TYPE Type)
{
    const UINT16 id = (UINT16)Type;
    if (id >= 421 && id <= 500) return PDK_SEVERITY_CRITICAL;   /* 恶意专用 */
    if (id >= 251 && id <= 300) return PDK_SEVERITY_HIGH;       /* 加密器 */
    if (Type == PDK_TYPE_VMPROTECT || Type == PDK_TYPE_THEMIDA ||
        Type == PDK_TYPE_CODE_VIRTUALIZER) return PDK_SEVERITY_MEDIUM;
    if (id >= 101 && id <= 200) return PDK_SEVERITY_MEDIUM;     /* 商业保护 */
    if (id >= 351 && id <= 400) return PDK_SEVERITY_BENIGN;     /* 安装器 */
    if (id >= 401 && id <= 420) return PDK_SEVERITY_LOW;        /* SFX */
    return PDK_SEVERITY_LOW;
}

/* 公共：类型 → 显示名（实现于 .c） */
const WCHAR* PdkTypeToString(PDK_PACKER_TYPE Type);

/**************************************************/
/*          结构：错误信息                         */
/**************************************************/

typedef struct _PDK_ERROR {
    ULONG   Win32Code;              /* ERROR_SUCCESS = 无错误 */
    WCHAR   Message[PDK_MAX_DESC];
    WCHAR   Context[PDK_MAX_PATH];
} PDK_ERROR;

static __inline BOOLEAN PdkErrorHasError(const PDK_ERROR* Err)
{
    return (Err != NULL) && (Err->Win32Code != ERROR_SUCCESS);
}

static __inline void PdkErrorClear(PDK_ERROR* Err)
{
    if (Err != NULL) {
        Err->Win32Code = ERROR_SUCCESS;
        Err->Message[0] = L'\0';
        Err->Context[0] = L'\0';
    }
}

/**************************************************/
/*          结构：节分析信息                       */
/**************************************************/

#define PDK_MAX_SEC_ANOMALIES 4

typedef struct _PDK_SECTION_INFO {
    CHAR    Name[16];               /* 节名（PE 上限 8 字符） */
    ULONG   VirtualAddress;
    ULONG   VirtualSize;
    ULONG   RawSize;
    ULONG   RawDataPointer;
    ULONG   Characteristics;
    DOUBLE  Entropy;
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
    BOOLEAN IsReadable;
    BOOLEAN HasHighEntropy;
    BOOLEAN IsEmpty;                /* VirtualSize>0 && RawSize==0 */
    BOOLEAN IsPackerSection;
    CHAR    MatchedPackerName[16];
    WCHAR   Anomalies[PDK_MAX_SEC_ANOMALIES][PDK_MAX_DESC];
    ULONG   AnomalyCount;
} PDK_SECTION_INFO;

/**************************************************/
/*          结构：导入分析信息                     */
/**************************************************/

typedef struct _PDK_IMPORT_INFO {
    SIZE_T  TotalImports;
    SIZE_T  DllCount;
    BOOLEAN HasGetProcAddress;
    BOOLEAN HasLoadLibrary;
    BOOLEAN HasVirtualMemoryApis;
    BOOLEAN HasMinimalImports;
    CHAR    Dlls[PDK_MAX_DLLS][64];          /* DLL 名（ANSI） */
    WCHAR   SuspiciousImports[PDK_MAX_SUSPICIOUS_IMPORTS][PDK_MAX_NAME];
    ULONG   SuspiciousImportCount;
    WCHAR   Anomalies[PDK_MAX_ANOMALIES][PDK_MAX_DESC];
    ULONG   AnomalyCount;
    BOOLEAN Valid;
} PDK_IMPORT_INFO;

/**************************************************/
/*          结构：Overlay 分析信息                 */
/**************************************************/

typedef struct _PDK_OVERLAY_INFO {
    BOOLEAN HasOverlay;
    ULONGLONG Offset;
    ULONGLONG Size;
    DOUBLE  Entropy;
    DOUBLE  PercentageOfFile;
    WCHAR   DetectedFormat[64];
    BOOLEAN IsCompressed;
    BOOLEAN IsEncrypted;
    BYTE    MagicBytes[16];
    BOOLEAN Valid;
} PDK_OVERLAY_INFO;

/**************************************************/
/*          结构：入口点分析信息                   */
/**************************************************/

typedef struct _PDK_ENTRY_POINT_INFO {
    ULONG   Rva;
    ULONG   FileOffset;
    BOOLEAN IsInValidSection;
    CHAR    ContainingSection[16];
    BOOLEAN IsOutsideCodeSection;
    BYTE    EpBytes[PDK_MAX_EP_BYTES];     /* 入口前若干字节（签名匹配用） */
    ULONG   EpBytesSize;
    WCHAR   MatchedSignature[PDK_MAX_DESC];
    PDK_PACKER_TYPE MatchedPacker;
    DOUBLE  MatchConfidence;
    BOOLEAN Valid;
} PDK_ENTRY_POINT_INFO;

/**************************************************/
/*          结构：数字签名信息                     */
/**************************************************/

typedef struct _PDK_SIGNATURE_INFO {
    BOOLEAN HasSignature;
    BOOLEAN IsValid;
    BOOLEAN IsSelfSigned;
    BOOLEAN IsRevoked;
    WCHAR   SignerName[PDK_MAX_NAME];
    WCHAR   IssuerName[PDK_MAX_NAME];
    CHAR    Thumbprint[80];
    WCHAR   Errors[PDK_MAX_SIG_ERRORS][PDK_MAX_DESC];
    ULONG   ErrorCount;
    BOOLEAN Valid;
} PDK_SIGNATURE_INFO;

/**************************************************/
/*          结构：Rich 头分析信息                  */
/**************************************************/

typedef struct _PDK_RICH_COMPILER_ENTRY {
    USHORT  BuildNumber;
    USHORT  ProductId;
    ULONG   UseCount;
    WCHAR   Description[64];
} PDK_RICH_COMPILER_ENTRY;

typedef struct _PDK_RICH_HEADER_INFO {
    BOOLEAN HasRichHeader;
    ULONG   Checksum;
    PDK_RICH_COMPILER_ENTRY Entries[PDK_MAX_RICH_ENTRIES];
    ULONG   EntryCount;
    WCHAR   DetectedCompiler[64];
    BOOLEAN IsCorrupted;
    BOOLEAN IsStripped;
    BOOLEAN Valid;
} PDK_RICH_HEADER_INFO;

/**************************************************/
/*          结构：检测匹配                         */
/**************************************************/

typedef struct _PDK_PACKER_MATCH {
    PDK_PACKER_TYPE   PackerType;
    PDK_PACKER_CATEGORY Category;
    PDK_DETECTION_METHOD Method;
    DOUBLE  Confidence;
    WCHAR   PackerName[PDK_MAX_NAME];
    WCHAR   Version[64];
    PDK_PACKER_SEVERITY Severity;
    CHAR    MitreId[16];
    WCHAR   MatchedPattern[PDK_MAX_DESC];
    ULONGLONG MatchLocation;
    WCHAR   Details[PDK_MAX_DESC];
} PDK_PACKER_MATCH;

/**************************************************/
/*          结构：脱壳提示                         */
/**************************************************/

typedef struct _PDK_UNPACKING_HINTS {
    ULONG   EstimatedOep;
    WCHAR   OepMethod[64];
    WCHAR   SuggestedTool[PDK_MAX_NAME];
    WCHAR   AntiUnpackingTechniques[PDK_MAX_ANIUNPACK_TECH][PDK_MAX_NAME];
    ULONG   AntiUnpackingCount;
    BOOLEAN NeedsIatReconstruction;
    ULONGLONG EstimatedOriginalSize;
    WCHAR   CompressionAlgorithm[64];
    WCHAR   EncryptionAlgorithm[64];
    BOOLEAN HasMultipleLayers;
    ULONG   EstimatedLayerCount;
    ULONG   ComplexityRating;
    WCHAR   Notes[PDK_MAX_HINTS_NOTES][PDK_MAX_NAME];
    ULONG   NoteCount;
    BOOLEAN Valid;
} PDK_UNPACKING_HINTS;

/**************************************************/
/*          结构：分析配置                         */
/**************************************************/

typedef struct _PDK_ANALYSIS_CONFIG {
    PDK_ANALYSIS_DEPTH Depth;
    UINT32  Flags;
    ULONG   TimeoutMs;
    ULONGLONG MaxFileSize;
    BOOLEAN EnableCaching;
    ULONG   CacheTtlSeconds;
    DOUBLE  MinConfidenceThreshold;
    BOOLEAN IncludeRawData;
    SIZE_T  MaxRawDataSize;
    BOOLEAN TreatInstallersAsBenign;
    ULONG   ProcessId;
} PDK_ANALYSIS_CONFIG;

/**************************************************/
/*          结构：资源分析信息                     */
/**************************************************/

typedef struct _PDK_RESOURCE_INFO {
    SIZE_T  Count;
    SIZE_T  HighEntropyCount;
    ULONGLONG TotalSize;
    ULONGLONG LargestResourceSize;
    DOUBLE  AverageEntropy;
    SIZE_T  ResourceEntropyCount;   /* 参与平均熵的资源数（内部聚合） */
    USHORT  Languages[PDK_MAX_RES_LANGUAGES];
    ULONG   LanguageCount;
    WCHAR   SuspiciousResources[PDK_MAX_SUSPICIOUS_RES][PDK_MAX_DESC];
    ULONG   SuspiciousCount;
    BOOLEAN Valid;
} PDK_RESOURCE_INFO;

/**************************************************/
/*          结构：综合检测结果                     */
/**************************************************/

typedef struct _PDK_PACKING_INFO {
    /* === 标识 === */
    WCHAR   FilePath[PDK_MAX_PATH];
    ULONGLONG FileSize;
    CHAR    Sha256Hash[72];

    /* === 检测摘要 === */
    BOOLEAN IsPacked;
    DOUBLE  PackingConfidence;
    PDK_PACKER_TYPE   PrimaryPacker;
    WCHAR   PackerName[PDK_MAX_NAME];
    WCHAR   PackerVersion[64];
    PDK_PACKER_CATEGORY PackerCategory;
    PDK_PACKER_SEVERITY Severity;
    BOOLEAN IsInstaller;
    BOOLEAN IsSfxArchive;
    BOOLEAN IsDotNetAssembly;
    BOOLEAN HasMultipleLayers;
    ULONG   LayerCount;

    /* === 详细发现 === */
    PDK_PACKER_MATCH PackerMatches[PDK_MAX_MATCHES];
    ULONG   MatchCount;
    PDK_SECTION_INFO Sections[PDK_MAX_SECTIONS];
    ULONG   SectionCount;
    PDK_IMPORT_INFO ImportInfo;
    PDK_OVERLAY_INFO OverlayInfo;
    PDK_ENTRY_POINT_INFO EntryPointInfo;
    PDK_SIGNATURE_INFO SignatureInfo;
    PDK_RICH_HEADER_INFO RichHeaderInfo;
    PDK_RESOURCE_INFO ResourceInfo;
    PDK_UNPACKING_HINTS UnpackingHints;

    /* === 熵指标 === */
    DOUBLE  FileEntropy;
    DOUBLE  ChiSquared;
    DOUBLE  MonteCarloPiError;
    DOUBLE  CodeSectionEntropy;
    DOUBLE  DataSectionEntropy;
    DOUBLE  MaxSectionEntropy;
    CHAR    MaxEntropySectionName[16];
    DOUBLE  AverageSectionEntropy;
    BOOLEAN EntropyIndicatesCompression;
    BOOLEAN EntropyIndicatesEncryption;

    /* === 异常与指示器 === */
    BOOLEAN EpOutsideCodeSection;
    BOOLEAN HasNonStandardSections;
    BOOLEAN HasWritableCodeSections;
    BOOLEAN HasMinimalImports;
    BOOLEAN HasSuspiciousCharacteristics;
    WCHAR   Anomalies[PDK_MAX_ANOMALIES][PDK_MAX_DESC];
    ULONG   AnomalyCount;
    WCHAR   Indicators[PDK_MAX_INDICATORS][PDK_MAX_DESC];
    ULONG   IndicatorCount;

    /* === 统计 === */
    ULONG   SectionCountRaw;        /* 实际节数（含超出结果数组部分） */
    ULONG   ExecutableSectionCount;
    ULONG   WritableSectionCount;
    ULONG   HighEntropySectionCount;
    ULONG   PackerSectionMatches;

    /* === 元数据 === */
    ULONGLONG AnalysisStartTick;
    ULONGLONG AnalysisEndTick;
    ULONGLONG AnalysisDurationMs;
    PDK_ANALYSIS_CONFIG Config;
    PDK_ERROR Errors[PDK_MAX_ERRORS];
    ULONG   ErrorCount;
    BOOLEAN AnalysisComplete;
    BOOLEAN FromCache;
} PDK_PACKING_INFO;

/**************************************************/
/*          结构：批处理结果与分布                 */
/**************************************************/

typedef struct _PDK_TYPE_COUNT_ENTRY {
    PDK_PACKER_TYPE Type;
    ULONG   Count;
} PDK_TYPE_COUNT_ENTRY;

typedef struct _PDK_BATCH_DISTRIBUTION {
    PDK_TYPE_COUNT_ENTRY Entries[PDK_MAX_DISTRIBUTION];
    ULONG   EntryCount;
} PDK_BATCH_DISTRIBUTION;

typedef struct _PDK_BATCH_RESULT {
    PDK_PACKING_INFO Results[PDK_MAX_BATCH_FILES];
    ULONG   ResultCount;
    ULONG   TotalFiles;
    ULONG   PackedFiles;
    ULONG   InstallerFiles;
    ULONG   FailedFiles;
    ULONGLONG TotalDurationMs;
    ULONGLONG StartTick;
    ULONGLONG EndTick;
    PDK_BATCH_DISTRIBUTION PackerDistribution;
    PDK_BATCH_DISTRIBUTION CategoryDistribution;
} PDK_BATCH_RESULT;

/**************************************************/
/*          结构：统计快照                         */
/**************************************************/

typedef struct _PDK_STATISTICS {
    ULONGLONG TotalAnalyses;
    ULONGLONG PackedFilesDetected;
    ULONGLONG InstallersDetected;
    ULONGLONG CryptersDetected;
    ULONGLONG ProtectorsDetected;
    ULONGLONG CacheHits;
    ULONGLONG CacheMisses;
    ULONGLONG AnalysisErrors;
    ULONGLONG TotalAnalysisTimeUs;
    ULONGLONG BytesAnalyzed;
    ULONGLONG CategoryDetections[16];
} PDK_STATISTICS;

/**************************************************/
/*          回调类型                               */
/**************************************************/

/* 批处理进度回调 */
typedef VOID (CALLBACK *PKD_PROGRESS_CALLBACK)(
    _In_ PCWSTR CurrentFile,
    _In_ ULONG  FilesProcessed,
    _In_ ULONG  TotalFiles
    );

/* 实时检测回调（每个匹配触发一次） */
typedef VOID (CALLBACK *PKD_DETECTION_CALLBACK)(
    _In_ PCWSTR File,
    _In_ const PDK_PACKER_MATCH* Match
    );

/**************************************************/
/*          公共 API                               */
/**************************************************/

/*++
 * PkdInitialize
 *   初始化检测引擎（加载内嵌 EP 签名库 + 清空缓存）。
 *--*/
NTSTATUS
PkdInitialize(
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdShutdown
 *   关闭引擎（清空缓存与自定义模式）。
 *--*/
VOID
PkdShutdown(
    VOID
    );

/*++
 * PkdIsInitialized
 *   查询引擎是否已初始化。
 *--*/
BOOLEAN
PkdIsInitialized(
    VOID
    );

/*++
 * PkdAnalyzeFile
 *   分析文件是否加壳；Result 输出完整发现。
 *--*/
BOOLEAN
PkdAnalyzeFile(
    _In_ PCWSTR FilePath,
    _In_opt_ const PDK_ANALYSIS_CONFIG* Config,
    _Inout_ PDK_PACKING_INFO* Result,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeBuffer
 *   分析内存缓冲 PE 镜像是否加壳。
 *--*/
BOOLEAN
PkdAnalyzeBuffer(
    _In_reads_bytes_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size,
    _In_opt_ const PDK_ANALYSIS_CONFIG* Config,
    _Inout_ PDK_PACKING_INFO* Result,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeFiles
 *   批量分析多个文件（支持进度回调）。
 *--*/
NTSTATUS
PkdAnalyzeFiles(
    _In_reads_(Count) PCWSTR* FilePaths,
    _In_ ULONG Count,
    _In_opt_ const PDK_ANALYSIS_CONFIG* Config,
    _In_opt_ PKD_PROGRESS_CALLBACK ProgressCallback,
    _Inout_ PDK_BATCH_RESULT* BatchResult,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeDirectory
 *   分析目录下可执行文件（.exe/.dll/.sys/.ocx/.scr/.drv）。
 *--*/
NTSTATUS
PkdAnalyzeDirectory(
    _In_ PCWSTR DirectoryPath,
    _In_ BOOLEAN Recursive,
    _In_opt_ const PDK_ANALYSIS_CONFIG* Config,
    _In_opt_ PKD_PROGRESS_CALLBACK ProgressCallback,
    _Inout_ PDK_BATCH_RESULT* BatchResult,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdCalculateEntropy
 *   计算缓冲的 Shannon 熵（0.0 - 8.0）。
 *--*/
DOUBLE
PkdCalculateEntropy(
    _In_reads_bytes_opt_(Size) const BYTE* Buffer,
    _In_ SIZE_T Size
    );

/*++
 * PkdCalculateSectionEntropy
 *   计算文件指定节区间的熵（失败返回 -1.0）。
 *--*/
DOUBLE
PkdCalculateSectionEntropy(
    _In_ PCWSTR FilePath,
    _In_ ULONG  SectionOffset,
    _In_ ULONG  SectionSize,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeSections
 *   Sections 容量由 *Count 传入，实际写入数回填。
 *--*/
BOOLEAN
PkdAnalyzeSections(
    _In_ PCWSTR FilePath,
    _Out_writes_to_(*Count, *Count) PDK_SECTION_INFO* Sections,
    _Inout_ ULONG* Count,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeImports
 *   分析 PE 导入表（数量/关键 API/稀疏度）。
 *--*/
BOOLEAN
PkdAnalyzeImports(
    _In_ PCWSTR FilePath,
    _Inout_ PDK_IMPORT_INFO* OutImports,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeOverlay
 *   分析 PE Overlay（偏移/大小/格式魔数/熵）。
 *--*/
BOOLEAN
PkdAnalyzeOverlay(
    _In_ PCWSTR FilePath,
    _Inout_ PDK_OVERLAY_INFO* OutOverlay,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeEntryPoint
 *   分析入口点（所在节/前导字节/EP 签名匹配）。
 *--*/
BOOLEAN
PkdAnalyzeEntryPoint(
    _In_ PCWSTR FilePath,
    _Inout_ PDK_ENTRY_POINT_INFO* OutEp,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdMatchEPSignature
 *   对 EP 前导字节执行内嵌签名匹配；命中返回 TRUE 并填充 Match。
 *--*/
BOOLEAN
PkdMatchEPSignature(
    _In_reads_bytes_(Size) const BYTE* EpBytes,
    _In_ SIZE_T Size,
    _Out_ PDK_PACKER_MATCH* Match,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdVerifySignature
 *   使用 WinVerifyTrust 验证文件 Authenticode 签名。
 *--*/
BOOLEAN
PkdVerifySignature(
    _In_ PCWSTR FilePath,
    _Inout_ PDK_SIGNATURE_INFO* OutSignature,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeRichHeader
 *   分析 PE Rich 头（存在性/校验和/编译器条目）。
 *--*/
BOOLEAN
PkdAnalyzeRichHeader(
    _In_ PCWSTR FilePath,
    _Inout_ PDK_RICH_HEADER_INFO* OutRichHeader,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdAnalyzeResources
 *   分析 PE 资源（数量/大小/熵/语言）。
 *--*/
BOOLEAN
PkdAnalyzeResources(
    _In_ PCWSTR FilePath,
    _Inout_ PDK_RESOURCE_INFO* OutResources,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdScanWithYARA
 *   经 IocYara_ScanBuffer 扫描；Matches 容量由 *Count 传入。
 *--*/
BOOLEAN
PkdScanWithYARA(
    _In_ PCWSTR FilePath,
    _Out_writes_to_(*Count, *Count) PDK_PACKER_MATCH* Matches,
    _Inout_ ULONG* Count,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdGenerateUnpackingHints
 *   依据检测结果生成脱壳建议。
 *--*/
BOOLEAN
PkdGenerateUnpackingHints(
    _In_ const PDK_PACKING_INFO* PackingInfo,
    _Inout_ PDK_UNPACKING_HINTS* OutHints,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdIsInstaller
 *   判定文件是否为安装器（节名/Overlay 魔数）。
 *   InstallerType 可空；非空时输出类型名。
 *--*/
BOOLEAN
PkdIsInstaller(
    _In_ PCWSTR FilePath,
    _Out_writes_opt_(PDK_MAX_NAME) PWSTR InstallerType,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdIsDotNetAssembly
 *   判定文件是否为 .NET 程序集（COM 描述符目录）。
 *--*/
BOOLEAN
PkdIsDotNetAssembly(
    _In_ PCWSTR FilePath,
    _Inout_opt_ PDK_ERROR* Err
    );

/*++
 * PkdSetDetectionCallback / PkdClearDetectionCallback
 *   设置/清除实时检测回调。
 *--*/
VOID
PkdSetDetectionCallback(
    _In_opt_ PKD_DETECTION_CALLBACK Callback
    );

VOID
PkdClearDetectionCallback(
    VOID
    );

/*++
 * PkdGetCachedResult
 *   命中返回 TRUE 并拷贝缓存结果。
 *--*/
BOOLEAN
PkdGetCachedResult(
    _In_ PCWSTR FilePath,
    _Out_ PDK_PACKING_INFO* OutResult
    );

VOID
PkdInvalidateCache(
    _In_ PCWSTR FilePath
    );

VOID
PkdClearCache(
    VOID
    );

SIZE_T
PkdGetCacheSize(
    VOID
    );

/*++
 * PkdAddCustomEPSignature
 *   追加自定义 EP 签名（全掩码精确匹配，置信度 0.80）。
 *--*/
VOID
PkdAddCustomEPSignature(
    _In_ PCWSTR PackerName,
    _In_reads_bytes_(SignatureSize) const BYTE* Signature,
    _In_ SIZE_T SignatureSize,
    _In_ PDK_PACKER_TYPE Type
    );

/*++
 * PkdAddCustomSectionPattern / PkdClearCustomPatterns
 *   追加/清除自定义节名模式。
 *--*/
VOID
PkdAddCustomSectionPattern(
    _In_ PCSTR SectionName,
    _In_ PDK_PACKER_TYPE Type
    );

VOID
PkdClearCustomPatterns(
    VOID
    );

/*++
 * PkdGetStatistics / PkdResetStatistics
 *   获取/重置统计快照。
 *--*/
VOID
PkdGetStatistics(
    _Out_ PDK_STATISTICS* OutStats
    );

VOID
PkdResetStatistics(
    VOID
    );