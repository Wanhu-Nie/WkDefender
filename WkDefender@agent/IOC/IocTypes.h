/**************************************************/
/*  WkDefender IOC 引擎 — 专用类型                  */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               命令行检测标志位                   */
/**************************************************/

#define IOC_CMD_FLAG_PS_ENCODED         0x00000001
#define IOC_CMD_FLAG_DOWNLOADER         0x00000002
#define IOC_CMD_FLAG_REFLECTIVE         0x00000004
#define IOC_CMD_FLAG_SUSPICIOUS         0x00000008
#define IOC_CMD_FLAG_OBFUSCATED         0x00000010
#define IOC_CMD_FLAG_CREDENTIAL_DUMP    0x00000020

/**************************************************/
/*               证书签名状态                       */
/*  对齐 PS SignatureStatus(ProcessAnalyzer)       */
/**************************************************/

typedef enum _DEF_CERT_STATUS {
    DefCertStatus_Unknown       = 0,    // 无法判定
    DefCertStatus_Valid         = 1,    // Authenticode 有效
    DefCertStatus_ValidCatalog  = 2,    // 目录签名有效
    DefCertStatus_Revoked       = 3,    // 证书被吊销
    DefCertStatus_Expired       = 4,    // 证书过期
    DefCertStatus_Invalid       = 5,    // 有签名但无效
    DefCertStatus_UntrustedRoot = 6,    // 不受信根
    DefCertStatus_Unsigned      = 7,    // 未签名
} DEF_CERT_STATUS, *PDEF_CERT_STATUS;

/**************************************************/
/*               证书签名者类别                     */
/*  (SS FileReputation 微软/可信发行商迁移, 2026-08-06) */
/**************************************************/

#define WKD_SIGNER_CATEGORY_UNKNOWN     0   /* 无法判定/未签名 */
#define WKD_SIGNER_CATEGORY_MICROSOFT   1   /* 微软签名者 (精确全串) */
#define WKD_SIGNER_CATEGORY_TRUSTED     2   /* 可信发行商 (精确全串) */
#define WKD_SIGNER_CATEGORY_VALID       3   /* 有效签名但非上述 */

/**************************************************/
/*               文件信誉等级                       */
/*  (SS FileReputation ReputationLevel 迁移,       */
/*   9 级枚举全量, 判定逻辑对齐 CalculateFinalScore) */
/**************************************************/

typedef enum _WKD_REPUTATION_LEVEL {
    WkdRep_KnownMalware = 0,        /* score < -70 (确认恶意) */
    WkdRep_HighlyMalicious,         /* [-70, -30) (强恶意指示) */
    WkdRep_Suspicious,              /* [-30, 0) (可疑特征) */
    WkdRep_PotentiallyUnwanted,     /* 预留 (SS 枚举有但无判定产出) */
    WkdRep_Unknown,                 /* 0 (从未见过) */
    WkdRep_LowPrevalence,           /* 预留 (需 prevalence 数据) */
    WkdRep_KnownSafe,               /* (0, 70) (高频干净) */
    WkdRep_Trusted,                 /* >= 70 (可信发行商签名) */
    WkdRep_MicrosoftSigned          /* 微软签名者 (等级覆盖) */
} WKD_REPUTATION_LEVEL, *PWKD_REPUTATION_LEVEL;

/**************************************************/
/*               文件信誉结果                       */
/*  (SS FileReputation ReputationResult 迁移,       */
/*   C 化定长: [-100,100] score + 9 级 + 置信度 +    */
/*   来源归因; 与 FinalVerdict 并行不改变其语义)     */
/**************************************************/

typedef struct _WKD_FILE_REPUTATION {
    LONG                Score;              /* [-100,100] 信誉分 */
    WKD_REPUTATION_LEVEL Level;             /* 9 级信誉等级 */
    ULONG               Confidence;         /* 0-1000 (SS double×1000, 对齐 HeuristicConfidence 尺度) */
    ULONG               ReasonCount;        /* 归因条数, cap 8 */
    WCHAR               Reasons[8][64];     /* 归因 (经 TxtSanitizeForDisplay 消毒) */
    ULONG               Sources;            /* 信号源位图 (复用 DEF_DETECTION_SOURCE 位) */
    ULONG64             EvaluatedAt;        /* FILETIME 评估时间 */
} WKD_FILE_REPUTATION, *PWKD_FILE_REPUTATION;

/**************************************************/
/*               文件类型识别                       */
/*  (SS FileTypeAnalyzer 迁移, 2026-08-06,          */
/*   FileFormat/FileCategory/RiskLevel/Spoofing     */
/*   C 化定长; 枚举值对齐 SS 分区间编号)            */
/**************************************************/

/* 细格式 (对齐 SS FileFormat 分区间: 可执行1-99/脚本100-199/
 * 文档200-299/归档300-399/图像400-499/音频500-549/视频550-599/
 * 数据600-699/证书700-749/字体750-799/其他800+) */
typedef enum _WKD_FILE_FORMAT {
    WkdFmt_Unknown = 0,

    /* 可执行 (1-99) */
    WkdFmt_Pe32 = 1,        /* PE32 EXE */
    WkdFmt_Pe64 = 2,        /* PE64 EXE */
    WkdFmt_Dll32 = 3,       /* PE32 DLL */
    WkdFmt_Dll64 = 4,       /* PE64 DLL */
    WkdFmt_Sys32 = 5,       /* PE32 内核驱动 */
    WkdFmt_Sys64 = 6,       /* PE64 内核驱动 */
    WkdFmt_Elf32 = 10,      /* ELF 32 位 (跨平台, 死代码) */
    WkdFmt_Elf64 = 11,      /* ELF 64 位 (跨平台, 死代码) */
    WkdFmt_MachO32 = 20,    /* Mach-O 32 位 (跨平台, 死代码) */
    WkdFmt_MachO64 = 21,    /* Mach-O 64 位 (跨平台, 死代码) */
    WkdFmt_MachOUniversal = 22, /* Mach-O Universal (跨平台, 死代码) */
    WkdFmt_JavaClass = 30,  /* Java Class (跨平台, 死代码) */
    WkdFmt_JavaJar = 31,    /* Java JAR */
    WkdFmt_DotNetAssembly = 40, /* .NET 托管程序集 */
    WkdFmt_WebAssembly = 50,    /* WebAssembly (跨平台, 死代码) */

    /* 脚本 (100-199) */
    WkdFmt_PowerShell = 100,
    WkdFmt_Batch = 101,
    WkdFmt_VBScript = 102,
    WkdFmt_JScript = 103,
    WkdFmt_JavaScript = 104,
    WkdFmt_Python = 105,
    WkdFmt_Ruby = 106,
    WkdFmt_Perl = 107,
    WkdFmt_ShellScript = 108,
    WkdFmt_Php = 109,
    WkdFmt_Lua = 110,
    WkdFmt_Hta = 111,

    /* 文档 (200-299) */
    WkdFmt_Pdf = 200,
    WkdFmt_Doc = 201,
    WkdFmt_Docx = 202,
    WkdFmt_Xls = 203,
    WkdFmt_Xlsx = 204,
    WkdFmt_Ppt = 205,
    WkdFmt_Pptx = 206,
    WkdFmt_Rtf = 207,
    WkdFmt_Odt = 210,
    WkdFmt_Ods = 211,
    WkdFmt_Odp = 212,
    WkdFmt_Html = 220,
    WkdFmt_Xml = 221,
    WkdFmt_Mhtml = 222,

    /* 归档 (300-399) */
    WkdFmt_Zip = 300,
    WkdFmt_Rar = 301,
    WkdFmt_Rar5 = 302,
    WkdFmt_SevenZip = 303,
    WkdFmt_Tar = 304,
    WkdFmt_Gzip = 305,
    WkdFmt_Bzip2 = 306,
    WkdFmt_Xz = 307,
    WkdFmt_Cab = 310,
    WkdFmt_Msi = 311,
    WkdFmt_Iso = 320,
    WkdFmt_Vhd = 321,
    WkdFmt_Vhdx = 322,

    /* 图像 (400-499) */
    WkdFmt_Jpeg = 400,
    WkdFmt_Png = 401,
    WkdFmt_Gif = 402,
    WkdFmt_Bmp = 403,
    WkdFmt_Tiff = 404,
    WkdFmt_Ico = 405,
    WkdFmt_Webp = 406,
    WkdFmt_Svg = 410,
    WkdFmt_Psd = 411,

    /* 音频 (500-549) */
    WkdFmt_Mp3 = 500,
    WkdFmt_Wav = 501,
    WkdFmt_Flac = 502,
    WkdFmt_Ogg = 503,
    WkdFmt_Wma = 504,
    WkdFmt_Aac = 505,
    WkdFmt_M4a = 506,

    /* 视频 (550-599) */
    WkdFmt_Mp4 = 550,
    WkdFmt_Avi = 551,
    WkdFmt_Mkv = 552,
    WkdFmt_Mov = 553,
    WkdFmt_Wmv = 554,
    WkdFmt_Flv = 555,
    WkdFmt_Webm = 556,

    /* 数据 (600-699) */
    WkdFmt_Sqlite = 600,
    WkdFmt_Mdb = 601,
    WkdFmt_Json = 610,
    WkdFmt_Yaml = 611,
    WkdFmt_Ini = 612,
    WkdFmt_Reg = 613,

    /* 证书 (700-749) */
    WkdFmt_Der = 700,
    WkdFmt_Pem = 701,
    WkdFmt_Crt = 702,
    WkdFmt_Pfx = 703,

    /* 字体 (750-799) */
    WkdFmt_Ttf = 750,
    WkdFmt_Otf = 751,
    WkdFmt_Woff = 752,
    WkdFmt_Woff2 = 753,

    /* 其他 (800+) */
    WkdFmt_Lnk = 800,
    WkdFmt_Url = 801,
    WkdFmt_Evtx = 810,
    WkdFmt_Prefetch = 811,
    WkdFmt_Registry = 812,
} WKD_FILE_FORMAT, *PWKD_FILE_FORMAT;

/* 大类 (对齐 SS FileCategory 21 类) */
typedef enum _WKD_FILE_CATEGORY {
    WkdCat_Unknown = 0,
    WkdCat_Executable = 1,      /* PE/ELF/Mach-O/.NET/Java */
    WkdCat_Script = 2,          /* PS1/VBS/JS/PY/... */
    WkdCat_Document = 3,        /* PDF/DOCX/RTF/... */
    WkdCat_Spreadsheet = 4,     /* XLSX/CSV */
    WkdCat_Presentation = 5,    /* PPTX */
    WkdCat_Archive = 6,         /* ZIP/RAR/7Z/... */
    WkdCat_Image = 7,           /* JPG/PNG/BMP/... */
    WkdCat_Audio = 8,           /* MP3/WAV/FLAC */
    WkdCat_Video = 9,           /* MP4/AVI/MKV */
    WkdCat_Database = 10,       /* SQLite/MDB */
    WkdCat_Configuration = 11,  /* INI/XML/JSON */
    WkdCat_Font = 12,           /* TTF/OTF */
    WkdCat_DiskImage = 13,      /* ISO/VHD */
    WkdCat_Installer = 14,      /* MSI/DEB/RPM */
    WkdCat_Library = 15,        /* DLL/SO */
    WkdCat_Driver = 16,         /* SYS */
    WkdCat_Certificate = 17,    /* CRT/PEM */
    WkdCat_SourceCode = 18,     /* C/CPP/H */
    WkdCat_Data = 19,           /* 二进制数据 */
    WkdCat_Empty = 20,          /* 零字节文件 */
    WkdCat_Text = 21,           /* 纯文本 */
} WKD_FILE_CATEGORY, *PWKD_FILE_CATEGORY;

/* 风险等级 (对齐 SS RiskLevel 5 级) */
typedef enum _WKD_RISK_LEVEL {
    WkdRisk_Safe = 0,       /* 图像/音频/视频 */
    WkdRisk_Low = 1,        /* 文本/配置 */
    WkdRisk_Medium = 2,     /* 文档 (可含宏) */
    WkdRisk_High = 3,       /* 归档/脚本 */
    WkdRisk_Critical = 4,   /* 可执行 */
} WKD_RISK_LEVEL, *PWKD_RISK_LEVEL;

/* 欺骗类型 (对齐 SS SpoofingType 6 类) */
typedef enum _WKD_SPOOFING_TYPE {
    WkdSpoof_None = 0,
    WkdSpoof_ExtensionMismatch = 1, /* 扩展名与内容不符 (如 .jpg 实为 PE) */
    WkdSpoof_DoubleExtension = 2,   /* file.txt.exe */
    WkdSpoof_RtlOverride = 3,       /* RTLO 双向控制字符滥用 */
    WkdSpoof_Homoglyph = 4,         /* 形近字符 */
    WkdSpoof_UnicodeAbuse = 5,      /* 其他 Unicode 技巧 */
    WkdSpoof_HiddenExtension = 6,   /* 超长文件名/尾部空格点 */
} WKD_SPOOFING_TYPE, *PWKD_SPOOFING_TYPE;

/* 魔数签名表项 (仿 WkdArc_MagicTable 风格, SS mask 实测全空裁剪) */
typedef struct _WKD_MAGIC_SIGNATURE {
    const BYTE*     Bytes;      /* 魔数字节（const 数据指针，运行时签名注册可赋值） */
    ULONG           Length;     /* 签名长度 */
    ULONG           Offset;     /* 匹配偏移 (0=文件头) */
    WKD_FILE_FORMAT Format;     /* 匹配格式 (待 Disambiguate 精化) */
} WKD_MAGIC_SIGNATURE, *PWKD_MAGIC_SIGNATURE;

/* 文件类型分析结果 (对齐 SS FileTypeInfo, C 化定长) */
typedef struct _WKD_FILE_TYPE_INFO {
    BOOLEAN             Detected;           /* 是否识别出类型 */
    ULONG               Confidence;         /* 0-100 (SS double 0.0-1.0 ×100) */
    WKD_FILE_FORMAT     Format;
    WKD_FILE_CATEGORY   Category;
    WKD_RISK_LEVEL      RiskLevel;
    WCHAR               Extension[16];      /* 真实扩展名 (如 L".exe") */
    CHAR                Description[64];    /* 人类可读描述 */
    CHAR                MimeType[96];       /* MIME 类型 (对齐 SS FileTypeInfo.mimeType) */

    /* 欺骗检测 */
    BOOLEAN             IsSpoofed;
    WKD_SPOOFING_TYPE   SpoofingType;
    WCHAR               DiskExtension[16];  /* 磁盘扩展名 */
    WCHAR               SuggestedExt[16];   /* 建议扩展名 */

    /* 附加标志 */
    BOOLEAN             IsExecutable;
    BOOLEAN             IsScript;
    BOOLEAN             IsArchive;
    BOOLEAN             CanContainMacros;
    BOOLEAN             IsCompound;         /* OLE 复合文件 */
    ULONG               MagicOffset;        /* 魔数匹配偏移 */
    CHAR                MatchedSignature[64];
    ULONG64             FileSize;

    /* 脚本指示器 (SS ScriptIndicators 迁移) */
    BOOLEAN             HasBOM;
    BOOLEAN             HasShebang;
    BOOLEAN             HasScriptKeywords;
    CHAR                BomType[12];        /* "UTF-8"/"UTF-16 LE"/"UTF-16 BE" */
    CHAR                ShebangInterpreter[256];
    WKD_FILE_FORMAT     ScriptType;         /* DetectScriptType 结果 (脚本格式) */
    CHAR                DetectedKeywords[4][32]; /* 检测关键词 (≤4) */
    ULONG               KeywordCount;
} WKD_FILE_TYPE_INFO, *PWKD_FILE_TYPE_INFO;

/* 扩展名完整信息 (对齐 SS ExtensionInfo, C 化定长; 供 GetExtensionInfo 查询) */
typedef struct _WKD_EXTENSION_INFO {
    CHAR                Extension[24];      /* 小写带点 (如 ".exe") */
    WKD_FILE_FORMAT     Format;
    WKD_FILE_CATEGORY   Category;
    WKD_RISK_LEVEL      RiskLevel;
    CHAR                MimeType[96];       /* MIME 类型 (GetMimeForFormat 填充, 最长 ~74 字符) */
    BOOLEAN             IsCommon;           /* 是否已知常见扩展名 */
} WKD_EXTENSION_INFO, *PWKD_EXTENSION_INFO;

/**************************************************/
/*           签名异常检测 (SS DSV AnomalyType)       */
/*  SignatureHunting 迁移 (2026-08-09)              */
/*  对齐 DigitalSignatureValidator.cpp              */
/*  AnalyzeSignature L1998-2268 + OnKernelImageLoad  */
/**************************************************/

typedef enum _WKD_SIG_ANOMALY_TYPE {
    WkdSigAnom_None                 = 0,
    WkdSigAnom_StolenCertificate    = 1,   /* 已知被盗证书 (APT) */
    WkdSigAnom_SelfSignedExecutable = 2,   /* 非系统目录自签名 */
    WkdSigAnom_ShortValidityCert    = 3,   /* 有效期 <30 天 (burner cert) */
    WkdSigAnom_RecentlyIssuedCert   = 4,   /* 签发 <7 天 */
    WkdSigAnom_WeakHashAlgorithm    = 5,   /* MD5/SHA1 弱哈希签名 */
    WkdSigAnom_TestSignatureInProd  = 6,   /* 生产环境测试签名 */
    WkdSigAnom_CatalogOnlyNoEmbedded= 7,   /* 仅目录签名无内嵌 (规避) */
    WkdSigAnom_TimestampInFuture    = 8,   /* 未来时间戳 (Timestomp) */
    WkdSigAnom_RevokedButStillUsed  = 9,   /* 吊销证书仍使用 */
    WkdSigAnom_SupplyChainAnomaly   = 10,  /* 内核/用户态签名等级不匹配 (镜像链) */
    WkdSigAnom_UnsignedDriver       = 11   /* 未签名驱动加载 (镜像链, rootkit 线索) */
} WKD_SIG_ANOMALY_TYPE, *PWKD_SIG_ANOMALY_TYPE;

#define WKD_SIG_ANOMALY_SEVERITY_INFO       0
#define WKD_SIG_ANOMALY_SEVERITY_LOW        1
#define WKD_SIG_ANOMALY_SEVERITY_MEDIUM     2
#define WKD_SIG_ANOMALY_SEVERITY_HIGH       3
#define WKD_SIG_ANOMALY_SEVERITY_CRITICAL   4

#define WKD_SIG_HUNT_MAX_ANOMALIES  11   /* 9 类 AnalyzeSignature + 2 类镜像链 */

/* 单条签名异常 */
typedef struct _WKD_SIG_ANOMALY {
    WKD_SIG_ANOMALY_TYPE Type;          /* 异常类型 */
    UCHAR                Severity;      /* WKD_SIG_ANOMALY_SEVERITY_* */
    CHAR                 MitreId[16];   /* 如 "T1553.002" */
    ULONG                RiskContribution; /* 0-100 单异常贡献分 */
} WKD_SIG_ANOMALY, *PWKD_SIG_ANOMALY;

/* 签名狩猎分析结果 (DSV AnalyzeSignature 迁移) */
typedef struct _WKD_SIGNATURE_HUNT_RESULT {
    ULONG            RiskScore;      /* 0-100 聚合 (取各 anomaly 贡献最大值, 对齐 SS max 聚合) */
    ULONG            AnomalyCount;
    WKD_SIG_ANOMALY  Anomaly[WKD_SIG_HUNT_MAX_ANOMALIES];
    BOOLEAN          IsStolenCert;   /* 叶/链命中被盗证书库 */
    CHAR             ThreatActor[64];/* 命中被盗证书威胁组织 */
    CHAR             Campaign[64];   /* 命中活动名 */
    BOOLEAN          IsWhql;         /* WHQL 驱动签名 (3 EKU OID) */
    BOOLEAN          IsTestSigned;   /* 测试签名 (3 微软测试根 + 关键字) */
    BOOLEAN          Ran;            /* 已执行 (未执行时 RiskScore 无效) */
} WKD_SIGNATURE_HUNT_RESULT, *PWKD_SIGNATURE_HUNT_RESULT;

/* 被盗证书数据库条目 (SS StolenCertEntry L749-755, 外部威胁情报注入) */
typedef struct _WKD_STOLEN_CERT_ENTRY {
    CHAR Thumbprint[64];    /* SHA1 指纹 hex 小写 */
    CHAR ThreatActor[64];   /* 威胁组织, 如 "Lazarus" */
    CHAR Campaign[64];      /* 活动名, 如 "ShadowHammer" */
    CHAR MitreGroup[16];    /* MITRE 组 ID, 如 "G0016" */
    UCHAR Severity;         /* WKD_SIG_ANOMALY_SEVERITY_* */
} WKD_STOLEN_CERT_ENTRY, *PWKD_STOLEN_CERT_ENTRY;

typedef const WKD_STOLEN_CERT_ENTRY *PCWKD_STOLEN_CERT_ENTRY;

/**************************************************/
/*           证书验证信息 (WKD_MODULE 内嵌)         */
/*                                                   */
/*  2026-08-18 从 IOC_SCAN_RESULT 证书字段抽离，     */
/*  作为文件级权威副本内嵌 WKD_MODULE，替代证书字段  */
/*  散落于 FileResult。四组：状态/详情/深度校验/信誉。 */
/*  所有字段定长无指针，可整体值类型赋值。           */
/**************************************************/

typedef struct _WKD_CERT_INFO {
    /* ── 状态组 ── */
    DEF_CERT_STATUS     CertStatus;         /* Result->CertStatus */
    BOOLEAN             CertValid;          /* Result->CertValid */
    BOOLEAN             CertTrusted;        /* Result->CertTrusted */
    ULONG               CertScore;          /* Result->CertScore */

    /* ── 详情组 ── */
    WCHAR               SignerName[256];    /* Result->SignerName */
    WCHAR               IssuerName[256];    /* Result->IssuerName */
    CHAR                Thumbprint[64];     /* Result->Thumbprint (SHA1 hex 小写) */
    ULONG64             CertValidFrom;      /* Result->CertValidFrom (Unix 秒) */
    ULONG64             CertValidTo;        /* Result->CertValidTo */
    WCHAR               ChainName[16][256]; /* Result->ChainName (链, 叶→根) */
    CHAR                ChainThumbprint[16][64]; /* Result->ChainThumbprint */
    ULONG               ChainDepth;         /* Result->ChainDepth */
    BOOLEAN             IsTrustedStrict;    /* Result->IsTrustedStrict (CERT_TRUST_NO_ERROR) */

    /* ── 深度校验组 ── */
    BOOLEAN             IsSelfSigned;       /* Result->IsSelfSigned */
    BOOLEAN             IsCodeSigningEku;   /* Result->IsCodeSigningEku */
    BOOLEAN             IsWhql;             /* Result->IsWhql */
    BOOLEAN             IsDualSigned;       /* Result->IsDualSigned */
    CHAR                SignatureAlgorithm[48]; /* Result->SignatureAlgorithm */
    BOOLEAN             IsWeakSignature;    /* Result->IsWeakSignature */
    BOOLEAN             IsRevocationChecked;/* Result->IsRevocationChecked */
    ULONG64             SignTime;           /* Result->SignTime (Unix 秒) */
    CHAR                CatalogName[260];   /* Result->CatalogName (ValidCatalog) */

    /* ── 信誉组 ── */
    LONG                SignerReputation;   /* Result->SignerReputation (-100..100) */
    ULONG               SignerCategory;     /* Result->SignerCategory (WKD_SIGNER_CATEGORY_*) */
    BOOLEAN             IsEvCert;           /* Result->IsEvCert */
    LONG                CertReputationAdjust; /* Result->CertReputationAdjust */
} WKD_CERT_INFO, *PWKD_CERT_INFO;

/**************************************************/
/*         PE 深度分析结果 (WKD_MODULE 内嵌)       */
/*                                                   */
/*  2026-08-18 从 IOC_SCAN_RESULT PE 分析字段抽离，   */
/*  作为文件级深度分析权威副本内嵌 WKD_MODULE。        */
/*  与 WKD_MODULE_PE_FACTS 区分：Facts 是 PE 头基元    */
/*  （构建期填），PeAnalysis 是深度分析产出（异步填）。 */
/*  进程级信号（CmdlineFlags/CmdlineConfidence/       */
/*  YaraSubmitted）不落模块，保留在 FileResult。       */
/*  所有字段定长无指针，可整体值类型赋值。            */
/**************************************************/

typedef struct _WKD_PE_ANALYSIS {
    /* ── LOLBin ── */
    BOOLEAN             IsLolbin;           /* Result->IsLolbin */
    ULONG               LolbinConfidence;   /* Result->LolbinConfidence */

    /* ── PE 头异常 ── */
    BOOLEAN             HasSuspiciousSections;  /* Result->HasSuspiciousSections */
    BOOLEAN             HasSuspiciousImports;   /* Result->HasSuspiciousImports */

    /* ── 导入 ── */
    ULONG               ImportSuspiciousCount;  /* Result->ImportSuspiciousCount */
    BOOLEAN             HasDynamicLoading;      /* Result->HasDynamicLoading */
    CHAR                ImpHash[33];            /* Result->ImpHash */
    CHAR                ImpHashStandard[33];    /* Result->ImpHashStandard */

    /* ── 加壳 ── */
    BOOLEAN             IsPacked;           /* Result->IsPacked */
    CHAR                PackerName[32];     /* Result->PackerName */

    /* ── 字符串/启发式 ── */
    ULONG               StringScore;        /* Result->StringScore */
    BOOLEAN             HeuristicRan;       /* Result->HeuristicRan */
    ULONG               HeuristicConfidence;/* Result->HeuristicConfidence */
    CHAR                ThreatName[64];     /* Result->ThreatName */

    /* ── 静态解包闭环（预留接线） ── */
    BOOLEAN             UnpackAttempted;    /* Result->UnpackAttempted */
    BOOLEAN             Unpacked;           /* Result->Unpacked */
    ULONG               UnpackedSize;       /* Result->UnpackedSize */
    BYTE                UnpackedHash[32];   /* Result->UnpackedHash */
    ULONG               UnpackedEntropy;    /* Result->UnpackedEntropy */
    ULONG               UnpackedEntryPointRva; /* Result->UnpackedEntryPointRva */

    /* ── 文件类型/欺骗 ── */
    WKD_FILE_FORMAT     FileFormat;         /* Result->FileFormat */
    WKD_FILE_CATEGORY   FileCategory;       /* Result->FileCategory */
    WKD_RISK_LEVEL      RiskLevel;          /* Result->RiskLevel */
    BOOLEAN             IsSpoofed;          /* Result->IsSpoofed */
    WKD_SPOOFING_TYPE   SpoofingType;       /* Result->SpoofingType */
    WCHAR               SuggestedExtension[16]; /* Result->SuggestedExtension */

    /* ── 签名狩猎（异步深度，门控 g_IoaSignatureHuntingEnabled） ── */
    WKD_SIGNATURE_HUNT_RESULT SignatureHunt;    /* Result->SignatureHunt */
    BOOLEAN                  SigHuntRan;        /* 已狩猎 */

    /* ── 综合（最终判定；Cmdline 进程级不落模块） ── */
    DEF_IOC_VERDICT     FinalVerdict;       /* Result->FinalVerdict */
    ULONG               FinalConfidence;    /* Result->FinalConfidence */
    ULONG               EvidenceCount;      /* Result->EvidenceCount */
    BOOLEAN             HashChecked;        /* Result->HashChecked */
    DEF_IOC_VERDICT     HashVerdict;        /* Result->HashVerdict */
    ULONG               HashConfidence;     /* Result->HashConfidence */
    WKD_FILE_REPUTATION Reputation;         /* Result->Reputation */
} WKD_PE_ANALYSIS, *PWKD_PE_ANALYSIS;

/**************************************************/
/*               扫描结果                           */
/**************************************************/

typedef struct _IOC_SCAN_RESULT {
    /* 哈希 */
    BOOLEAN             HashChecked;
    DEF_IOC_VERDICT     HashVerdict;
    ULONG               HashConfidence;

    /* 证书 */
    DEF_CERT_STATUS     CertStatus;
    BOOLEAN             CertValid;
    BOOLEAN             CertTrusted;
    WCHAR               SignerName[256];
    ULONG               CertScore;

    /* 证书详情 (对齐 SS ExtractCertificateDetailsImpl, 2026-08) */
    WCHAR               IssuerName[256];
    CHAR                Thumbprint[64];         /* SHA1 指纹 hex 小写 */
    ULONG64             CertValidFrom;          /* Unix 秒 (0=未知) */
    ULONG64             CertValidTo;
    WCHAR               ChainName[16][256];     /* 证书链 (≤16 元素, 叶→根) */
    CHAR                ChainThumbprint[16][64];/* 链各元素 SHA1 指纹 hex 小写 (SS DSV 链级被盗证书检测 2026-08-09) */
    ULONG               ChainDepth;
    BOOLEAN             IsTrustedStrict;        /* 链完整且 CERT_TRUST_NO_ERROR */
    BOOLEAN             IsSelfSigned;           /* 叶证书自签名 (DN 直比, SS CV ParseCertificateContext 迁移 2026-08-09) */

    /* 证书深度校验 (SS PE_sig_verf.cpp 迁移, 2026-08):
     * EKU/弱算法/吊销/时间戳/catalog 由 IocScan_ExtractCertDetails 深度提取填充。 */
    BOOLEAN             IsCodeSigningEku;   /* 叶子含代码签名 EKU 1.3.6.1.5.5.7.3.3 */
    BOOLEAN             IsWhql;             /* WHQL 驱动签名 (3 EKU OID, SS DSV L1573-1611 迁移 2026-08-09) */
    BOOLEAN             IsDualSigned;       /* 双重签名 (CMSG_SIGNER_COUNT≥2, SS isDualSigned 缺口补全 2026-08-09) */
    CHAR                SignatureAlgorithm[48];  /* 签名算法 OID 串 (如 "1.2.840.113549.1.1.5") */
    BOOLEAN             IsWeakSignature;    /* 命中 8 弱 OID 表 (MD2/MD4/MD5/SHA1×5) */
    BOOLEAN             IsRevocationChecked;/* 吊销已检查 (cache-only, 门控) */
    ULONG64             SignTime;           /* 计数器签名时间 Unix 秒 (0=无, 死代码填充) */
    CHAR                CatalogName[260];   /* catalog 命中路径 (ValidCatalog 时, 门控) */
    /* 吊销原因细分 (SS CertificateValidator GetRevocationStatus 增量迁移 2026-09-02):
     * CertStatus=Revoked 时由 SignatureVerifier Revoked 分支经
     * IocCert_GetRevocationStatus 填充 ("Certificate revoked (Reason: ...)"),
     * 消费面: 信誉归因细分 (SignatureReputation 已接线)。0 前缀=未细分。 */
    WCHAR               RevokeReason[96];

    /* LOLBin */
    BOOLEAN             IsLolbin;
    ULONG               LolbinConfidence;

    /* 命令行 */
    ULONG               CmdlineFlags;
    ULONG               CmdlineConfidence;

    /* PE 头 (支架) */
    BOOLEAN             HasSuspiciousSections;
    BOOLEAN             HasSuspiciousImports;

    /* YARA (异步回写) */
    BOOLEAN             YaraSubmitted;

    /* 启发式静态分析 (SS HeuristicAnalyzer 迁移, 2026-08-04) */
    BOOLEAN             HeuristicRan;          /* 深度启发式是否已执行 */
    ULONG               HeuristicConfidence;   /* 启发式可疑度 0-1000 (加权聚合) */

    /* 导入分析 */
    ULONG               ImportSuspiciousCount; /* 可疑导入函数数 */
    BOOLEAN             HasDynamicLoading;     /* LoadLibrary + GetProcAddress 动态加载组合 */
    CHAR                ImpHash[33];           /* 导入哈希 (MD5 hex, 小写 dll.func 排序拼接, 保持既有行为) */
    CHAR                ImpHashStandard[33];   /* 标准 Mandiant ImpHash (不排序, 对齐 SS ComputeImpHashImpl) */

    /* 加壳检测 */
    BOOLEAN             IsPacked;
    CHAR                PackerName[32];        /* 加壳器名 (节名匹配 / Generic 熵回退) */

    /* 字符串分析 */
    ULONG               StringScore;           /* 0-1000 (URL/IP/注册表/勒索信/可疑API) */

    /* 编码字符串提取 (SS StringExtractor 迁移, 2026-08-19)：
     * 检测 XOR/Base64/ROT 编码的混淆字符串并 17 类分类，聚合可疑度。
     * 简化迁移说明：完整动态字符串数组 (SS std::vector<ExtractedString>)
     * 不落 IOC_SCAN_RESULT (保持定长可 ALPC 传输)，仅承载聚合统计；
     * 逐串完整输出由 IocStrExtract 独立 API 返回 (运营侧未来消费)。 */
    BOOLEAN             StrExtRan;          /* StringExtractor 是否执行 */
    BOOLEAN             StrExtFoundAny;     /* 提取到任何字符串 */
    ULONG               StrExtCount;        /* 提取串总数 (cap) */
    ULONG               StrExtSuspicious;   /* 可疑分类串数 */
    BOOLEAN             StrExtHasXor;       /* 命中单/多字节 XOR */
    BOOLEAN             StrExtHasBase64;    /* 命中 Base64 */
    BOOLEAN             StrExtHasRot;       /* 命中 Caesar/ROT13 */
    ULONG               StrExtDecodedCount; /* 成功解码串数 */
    ULONG               StrExtScore;        /* 聚合可疑分 0-1000 */

    /* .NET 深度分析 (SS DotNetAnalyzer 静态子集迁移, 2026-08-19)：
     * CLR 元数据表解析 → 混淆器指纹/托管 API 分类/PInvoke/payload 提取。
     * 简化迁移说明：%cctor 字符串解密依赖 MSIL 解释执行 (模拟器轨) 不迁移；
     * 完整字符串解密/动态执行标志不填充。仅静态元数据 + 指纹判定。 */
    BOOLEAN             NetAnalyzed;        /* .NET 深度分析是否执行 */
    CHAR                NetObfuscator[48];  /* 检出的混淆器名 (ConfuserEx/... 或空) */
    ULONG               NetObfFlags;        /* DotNetObfuscation 位掩码 */
    ULONG               NetSuspiciousApi;   /* 可疑托管 API 调用数 */
    BOOLEAN             NetHasReflectionLoading; /* Assembly.Load 反射加载 */
    BOOLEAN             NetHasProcessCreation;   /* Process.Start 进程创建 */
    BOOLEAN             NetHasNetwork;          /* 网络 API */
    BOOLEAN             NetHasCrypto;           /* 对称/非对称加密 */
    BOOLEAN             NetHasAntiAnalysis;     /* 反调试/反分析 */
    BOOLEAN             NetHasSuspiciousPInvoke;/* 敏感 P/Invoke */
    BOOLEAN             NetHasPayloadEmbed;     /* 高熵资源/FieldRVA 载荷 */
    ULONG               NetScore;           /* .NET 威胁分 0-1000 */

    /* 启发式威胁名 (对齐 SS GenerateThreatName, 格式 Heuristic:Win/Packed) */
    CHAR                ThreatName[64];        /* 对齐 IOC_MAX_THREAT_NAME_LENGTH */

    /* 综合 */
    DEF_IOC_VERDICT     FinalVerdict;
    ULONG               FinalConfidence;
    ULONG               EvidenceCount;

    /* 静态解包闭环 (SS PackerUnpacker 迁移, 预留接线 — 本阶段死代码填充) */
    BOOLEAN             UnpackAttempted;       /* 是否尝试静态解包 */
    BOOLEAN             Unpacked;              /* 解包成功 */
    ULONG               UnpackedSize;
    BYTE                UnpackedHash[32];      /* 解包载荷 SHA256 */
    ULONG               UnpackedEntropy;       /* 解包镜像 0-1000 简化熵 */
    ULONG               UnpackedEntryPointRva; /* OEP */

    /* 信誉评分 (SS FileReputation 迁移, 2026-08-06):
     * 与 FinalVerdict 并行, 不改 4 值判定语义;
     * 由 IocScan_ReputationScore 填充, 供 VerdictEngine/持久化未来消费。 */
    WKD_FILE_REPUTATION Reputation;
    LONG                SignerReputation;   /* -100..100 签名者信誉 (微软+90/可信+70/有效+30/未签名-10) */
    ULONG               SignerCategory;     /* WKD_SIGNER_CATEGORY_* */
    BOOLEAN             IsEvCert;           /* EV 证书提升 (CERT_EV_PROP_ID) */
    LONG                CertReputationAdjust; /* cert_reputation 表命中调整 (SS GetCertificateTrust 接线, 0=未命中/未查) */

    /* 文件类型识别 (SS FileTypeAnalyzer 迁移, 2026-08-06):
     * 完整 WKD_FILE_TYPE_INFO 由 IocScan_AnalyzeFileType* 独立主入口返回,
     * 此处仅精简承接字段, 供 IocScan_Aggregate/未来流水线消费。 */
    WKD_FILE_FORMAT     FileFormat;
    WKD_FILE_CATEGORY   FileCategory;
    WKD_RISK_LEVEL      RiskLevel;
    BOOLEAN             IsSpoofed;
    WKD_SPOOFING_TYPE   SpoofingType;
    WCHAR               SuggestedExtension[16]; /* 扩展名-内容不匹配时的建议扩展名 */

    /* 签名狩猎 (SS DSV AnalyzeSignature 迁移, 2026-08-09):
     * 统一证书验证入口 (门控 g_IoaSignatureHuntingEnabled) 填充;
     * RiskScore/异常列表供镜像链/判定/信誉融合消费。 */
    WKD_SIGNATURE_HUNT_RESULT SignatureHunt;
} IOC_SCAN_RESULT, *PIOC_SCAN_RESULT;

/**************************************************/
/*               IOC 引擎统计                       */
/**************************************************/

typedef struct _IOC_ENGINE_STATS {
    volatile ULONG      TotalScans;
    volatile ULONG      SystemSkipped;      /* 无镜像假进程豁免跳过（ExemptProcess） */
    volatile ULONG      HashHits;
    volatile ULONG      CertFailures;
    volatile ULONG      LolbinHits;
    volatile ULONG      CmdlineHits;
    volatile ULONG      YaraSubmitted;
    volatile ULONG      MemoryScans;
    volatile ULONG      SuspiciousModules;
} IOC_ENGINE_STATS, *PIOC_ENGINE_STATS;

/**************************************************/
/*               多算法哈希 (SS FileHasher)         */
/*  对齐 SS FileHasher.hpp FileHashes (纯 C 载体)   */
/**************************************************/

typedef enum _WKD_HASH_ALG {
    WkdHash_None      = 0,
    WkdHash_MD5       = 0x0001,
    WkdHash_SHA1      = 0x0002,
    WkdHash_SHA256    = 0x0004,
    WkdHash_SHA512    = 0x0008,
    WkdHash_SHA3_256  = 0x0010,
    WkdHash_SHA3_512  = 0x0020,
    WkdHash_Fuzzy     = 0x0040,
    WkdHash_AllCrypto = 0x003F,
    WkdHash_All       = 0x007F
} WKD_HASH_ALG;

typedef struct _WKD_FILE_HASH_SET {
    BOOLEAN Md5Valid;      BYTE Md5[16];
    BOOLEAN Sha1Valid;     BYTE Sha1[20];
    BOOLEAN Sha256Valid;   BYTE Sha256[32];
    BOOLEAN Sha512Valid;   BYTE Sha512[64];
    BOOLEAN Sha3_256Valid; BYTE Sha3_256[32];
    BOOLEAN Sha3_512Valid; BYTE Sha3_512[64];
    /* CTPH 模糊哈希 (buffer 核心, "blockSize:sig1:sig2" ≤109+1, 对齐 SS kMaxResultLength=148) */
    BOOLEAN FuzzyValid;    CHAR Fuzzy[128];
    BOOLEAN HasErrors;
    ULONG   ErrorCode;     /* win32/ntstatus 简化 (对齐 SS HashUtils::Error) */
} WKD_FILE_HASH_SET, *PWKD_FILE_HASH_SET;

/* const 指针别名 (读取方, 对齐 PC* 命名惯例) */
typedef const WKD_FILE_HASH_SET *PCWKD_FILE_HASH_SET;

/**************************************************/
/*               媒体文件分析                       */
/*  (SS MediaFileScanner 迁移, 2026-08-06:          */
/*   格式验证/隐写检测/元数据·EXIF/漏洞载荷/追加数据 */
/*   C 化定长, 枚举值对齐 SS 原编号; 虚标枚举不迁)   */
/**************************************************/

/* 媒体类型 (对齐 SS MediaType; 仅迁移 SS 实际实现的格式,
 * ICO/FLAC/OGG/AVI/MKV/MOV 为 SS 虚标枚举从不被识别,
 * 文件类型面由 WKD_FILE_FORMAT WkdFmt_* 已覆盖) */
typedef enum _WKD_MEDIA_TYPE {
    WkdMedia_Unknown = 0,
    WkdMedia_Jpeg    = 1,
    WkdMedia_Png     = 2,
    WkdMedia_Gif     = 3,
    WkdMedia_Bmp     = 4,
    WkdMedia_Tiff    = 5,
    WkdMedia_Webp    = 6,
    WkdMedia_Mp3     = 20,
    WkdMedia_Wav     = 21,
    WkdMedia_Mp4     = 40,
} WKD_MEDIA_TYPE, *PWKD_MEDIA_TYPE;

/* 隐写技术 (对齐 SS StegoTechnique; Palette/AlphaChannel 无实现不迁) */
typedef enum _WKD_STEGO_TECHNIQUE {
    WkdStego_None       = 0,
    WkdStego_Lsb        = 1,    /* LSB 卡方 (仅 BMP 像素区生效, PNG 缺陷标注) */
    WkdStego_Dct        = 2,    /* JPEG DCT 系数 LSB 平衡 */
    WkdStego_EofAppended = 4,   /* JPEG EOI 后追加 */
    WkdStego_Metadata   = 5,    /* 大元数据段 */
} WKD_STEGO_TECHNIQUE, *PWKD_STEGO_TECHNIQUE;

/* 媒体威胁类型 (对齐 SS MediaThreatType 全量) */
typedef enum _WKD_MEDIA_THREAT_TYPE {
    WkdMediaThreat_None             = 0,
    WkdMediaThreat_Steganography    = 1,
    WkdMediaThreat_MalformedHeader  = 2,
    WkdMediaThreat_BufferOverflow   = 3,
    WkdMediaThreat_EmbeddedExecutable = 4,
    WkdMediaThreat_AppendedArchive  = 5,
    WkdMediaThreat_Polyglot         = 6,
    WkdMediaThreat_ScriptInjection  = 7,
    WkdMediaThreat_CveExploit       = 8,    /* SS 仅 TIFF 循环 IFD 链 DoS */
} WKD_MEDIA_THREAT_TYPE, *PWKD_MEDIA_THREAT_TYPE;

#define WKD_MEDIA_MAX_THREATS    8             /* SS vector 无上限 → 定长 cap 8 */
#define WKD_MEDIA_MAX_COMMENTS   8
#define WKD_MEDIA_MAX_APPENDED   (10 * 1024 * 1024)  /* SS MAX_APPENDED_EXTRACT */
#define WKD_MEDIA_MAX_FILE_SIZE  (100 * 1024 * 1024) /* SS MAX_SCAN_FILE_SIZE */

/* 媒体威胁 (对齐 SS MediaThreat; Description 覆盖最长描述 ~80 字符) */
typedef struct _WKD_MEDIA_THREAT {
    WKD_MEDIA_THREAT_TYPE Type;
    ULONG                 Severity;
    ULONG                 Offset;
    CHAR                  Description[128];
} WKD_MEDIA_THREAT, *PWKD_MEDIA_THREAT;

/* 媒体元数据 (对齐 SS MediaMetadata; 裁剪 SS 只设标志不提取值的
 * colorSpace/GPS 坐标/缩略图字节/dateTime 虚字段, 保留 HasGPS/HasThumbnail 标志) */
typedef struct _WKD_MEDIA_METADATA {
    ULONG     Width;
    ULONG     Height;
    ULONG     BitDepth;
    BOOLEAN   HasThumbnail;
    BOOLEAN   HasGPS;
    CHAR      CameraMake[64];
    CHAR      CameraModel[64];
    CHAR      Comments[WKD_MEDIA_MAX_COMMENTS][256];
    ULONG     CommentCount;
} WKD_MEDIA_METADATA, *PWKD_MEDIA_METADATA;

/* 隐写分析结果 (对齐 SS StegoAnalysis; Confidence 0-100,
 * ExtractedData 由 IocMedia_ExtractAppendedData 独立 API 覆盖, 不在结构内) */
typedef struct _WKD_STEGO_ANALYSIS {
    BOOLEAN               StegoDetected;
    WKD_STEGO_TECHNIQUE   Technique;
    ULONG                 Confidence;          /* 0-100 */
    ULONG64               EstimatedPayloadSize;
    CHAR                  AnalysisDetails[128];
} WKD_STEGO_ANALYSIS, *PWKD_STEGO_ANALYSIS;

/* 媒体扫描结果 (~3.5KB, 调用方堆分配; 对齐 WKD_DOC_SCAN_RESULT
 * RiskScore 0-100 + Verdict 0-3 风格) */
typedef struct _WKD_MEDIA_SCAN_RESULT {
    WKD_MEDIA_TYPE    MediaType;
    ULONG64           FileSize;
    BOOLEAN           IsValid;
    ULONG             RiskScore;               /* 0-100 (SS riskScore clamp) */
    ULONG             Verdict;                 /* 0 Clean / 1 Suspicious / 2 Malicious / 3 预留 */
    WKD_MEDIA_METADATA Metadata;
    WKD_STEGO_ANALYSIS Stego;
    WKD_MEDIA_THREAT  Threats[WKD_MEDIA_MAX_THREATS];
    ULONG             ThreatCount;
    BOOLEAN           HasAppendedData;
    ULONG64           AppendedDataSize;
} WKD_MEDIA_SCAN_RESULT, *PWKD_MEDIA_SCAN_RESULT;

/**************************************************/
/*            可疑 API 分类 (PE 启发式)             */
/*  迁移自 IocScanner.c 5.1 区 (2026-08-19),       */
/*  由 PeAnalyzer.c 启发式分析消费。               */
/**************************************************/
typedef enum _IOC_SUSPICIOUS_API_CATEGORY {
    IocApiCat_None = 0,
    IocApiCat_ProcessManipulation,
    IocApiCat_MemoryOperations,
    IocApiCat_CodeInjection,
    IocApiCat_AntiDebug,
    IocApiCat_RegistryOperations,
    IocApiCat_FileOperations,
    IocApiCat_NetworkOperations,
    IocApiCat_CryptoOperations,
    IocApiCat_ServiceOperations,
    IocApiCat_PrivilegeEscalation,
    IocApiCat_CredentialAccess,
    IocApiCat_InfoGathering,
    IocApiCat_Evasion,
    IocApiCat_InputCapture,
    IocApiCat_ScreenCapture,
    IocApiCat_ClipboardAccess,
    IocApiCat_Wmi,
    IocApiCat_Com,
    IocApiCat_Shell,
    IocApiCat_DynamicCode,
} IOC_SUSPICIOUS_API_CATEGORY, *PIOC_SUSPICIOUS_API_CATEGORY;

typedef struct _IOC_API_CAT_ENTRY {
    PCSTR Name;
    IOC_SUSPICIOUS_API_CATEGORY Category;
} IOC_API_CAT_ENTRY, *PIOC_API_CAT_ENTRY;

/**************************************************/
/*              加壳类型枚举 (PE 启发式)            */
/*  迁移自 IocScanner.c 5.2 区 (2026-08-19)。      */
/**************************************************/
typedef enum _PE_PACKER_TYPE {
    IocPacker_Unknown = 0,
    IocPacker_Upx, IocPacker_Aspack, IocPacker_Fsg, IocPacker_PeCompact,
    IocPacker_Mpress, IocPacker_Mew, IocPacker_NsPack, IocPacker_Petite,
    IocPacker_RlPack, IocPacker_WinUpack,
    IocPacker_Themida, IocPacker_VmProtect, IocPacker_Obsidium,
    IocPacker_Enigma, IocPacker_Armadillo, IocPacker_AsProtect,
    IocPacker_Nsis, IocPacker_InnoSetup, IocPacker_AutoIt, IocPacker_PyInstaller,
    IocPacker_PESpin,        /* SS PackerUnpacker .pespin / EP 签名, 2026-08 */
    IocPacker_Generic,
} PE_PACKER_TYPE, *PPE_PACKER_TYPE;

typedef struct _PE_PACKER_ENTRY {
    PCSTR SectionName;
    PE_PACKER_TYPE Type;
    BOOLEAN IsInstaller;   /* 安装包/SFX: 降权 (SS 5 分) */
    BOOLEAN IsProtector;   /* 商业加密壳: 提权 (SS 15 分) */
} PE_PACKER_ENTRY, *PPE_PACKER_ENTRY;
