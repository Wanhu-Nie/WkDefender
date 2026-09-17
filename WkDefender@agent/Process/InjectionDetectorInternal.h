/**************************************************/
/*  WkDefender Agent — 注入检测器私有内部头         */
/*                                                  */
/*  2026-09-15 新增: 反射加载检测决策层内部类型      */
/*  (Rid*), 仅供 Process\ReflectiveInjectionDetector.c */
/*  使用。                                          */
/*                                                  */
/*  对齐 ShadowStrike ReflectiveDLLDetector.hpp      */
/*  (LoaderSignature / PECandidate /                */
/*   ReflectiveConstants 内部部分)。                */
/**************************************************/

#pragma once

#include "../Include/Process/InjectionDetector.h"   /* RID_LOAD_TYPE / RID_CONFIDENCE / 公共 API */
#include "../Memory/MemoryScan.h"                    /* WKD_MEM_THREAT / WKD_MEMORY_REGION / 模块集 */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"            /* WKD_PE_DEEP_INFO (深度特征补齐) */

/**************************************************/
/*        决策层常量 (对齐 SS ReflectiveConstants)  */
/**************************************************/

/* 签名长度 (SIGNATURE_LENGTH, ReflectiveDLLDetector.hpp) */
#define RID_SIGNATURE_LENGTH   32

/* 单次扫描候选/检测上限 (固定数组落地, 防无界增长) */
#define RID_MAX_CANDIDATES     64
#define RID_MAX_DETECTIONS     16

/* PE 深验后候选区首块读入上限 (MAX_PE_HEADER_SCAN, 4096 对齐) */
#define RID_HEADER_SCAN_SIZE   4096

/* 熵阈值 (0-1000 尺度, 对齐 WPA_ENTROPY_THRESHOLD_PACKED/ENCRYPTED) */
#define RID_ENTROPY_PACKED     7000    /* ≥ 7.0 bits: 节表打包 */
#define RID_ENTROPY_ENCRYPTED  7500    /* ≥ 7.5 bits: 加密载荷 */

/* 上报置信度门槛 (对齐 SS alertThreshold = Medium) */
#define RID_ALERT_CONFIDENCE   RidConf_Medium

/* 确认级阈值 (对齐 IoaClassifyInjection 确认回填 95/90) */
#define RID_CONFIRM_CONFIDENCE 95
#define RID_CONFIRM_RISK       90

/**************************************************/
/*        加载器签名 (对齐 SS LoaderSignature)      */
/**************************************************/

typedef struct _RID_LOADER_SIGNATURE {
    CHAR          Name[48];                   /* 加载器名称 (Cobalt Strike Beacon / ...) */
    RID_LOAD_TYPE Type;                       /* 类型分类 */
    CHAR          MitreId[16];                /* T1620 / T1055.001 */
    CHAR          Description[96];            /* 描述 */
    UCHAR         Pattern[RID_SIGNATURE_LENGTH]; /* 签名模式 */
    UCHAR         Mask[RID_SIGNATURE_LENGTH];    /* 掩码 (0x00 = 忽略位) */
    ULONG         Offset;                     /* 相对候选区起点的偏移 */
    BOOLEAN       HasPattern;                 /* 是否配置字节模式 (全零掩码 = 仅启发式) */
} RID_LOADER_SIGNATURE, *PRID_LOADER_SIGNATURE;

/**************************************************/
/*        决策中间态候选 (对齐 SS PECandidate)      */
/**************************************************/

typedef struct _RID_CANDIDATE {
    ULONG_PTR   BaseAddress;        /* 候选 PE 基址 */
    SIZE_T      RegionSize;         /* 所在区域大小 */
    ULONG       Protection;         /* 当前保护 PAGE_* */
    ULONG       ThreadCount;        /* 起始地址落入本区域的线程数 (hasThreadStartingHere 计数) */
    ULONG       CallStackFrames;    /* Deep/Forensic: 关联线程最大未背衬帧数 */

    BOOLEAN     IsRwx;              /* RWX 保护 */
    BOOLEAN     IsFileBacked;       /* 模块表内 (文件支撑) */
    BOOLEAN     IsInPeb;            /* 已加载模块表 (EnumProcessModules) */
    BOOLEAN     IsValidPe;          /* 深度验证有效 */
    BOOLEAN     IsPacked;           /* 节表高熵/打包 */
    BOOLEAN     IsEncrypted;        /* 整体高熵/加密 */
    BOOLEAN     HasTls;             /* TLS 目录 (反射加载器初始化常用) */
    BOOLEAN     HasReloc;           /* 重定位表 (手工 rebase 需要) */

    WKD_PE_DEEP_INFO Deep;          /* 深度分析明细 (SHA256/节熵/数据目录) */
} RID_CANDIDATE, *PRID_CANDIDATE;

/**************************************************/
/*        内部函数声明 (仅本模块 + 诊断接线)        */
/**************************************************/

/* 加载器签名线性匹配: 区域前部 [Buffer, Size) 对签名表逐条比对 */
BOOLEAN
RidMatchLoaderSignature(
    _In_  const BYTE* Buffer,
    _In_  ULONG       Size,
    _Out_ PRID_LOADER_SIGNATURE Signature
    );

/* 加载器类型分类: 签名命中优先, 否则特征组合启发式 (RidClassifyLoadType) */
RID_LOAD_TYPE
RidClassifyLoadType(
    _In_ PRID_CANDIDATE Candidate
    );

/* 综合风险评分 0-100 (ReflectiveDetection::CalculateRiskScore 迁移) */
ULONG
RidCalculateRiskScore(
    _In_ PRID_CANDIDATE Candidate,
    _In_ RID_CONFIDENCE  Confidence,
    _In_ RID_LOAD_TYPE   LoadType,
    _In_ BOOLEAN         CorrelatedWithKnownThreat
    );

/**************************************************/
/*  进程镂空检测私有结构 (ProcessHollowingDetector)  */
/*                                                  */
/*  2026-09-15 迁出: 自 IOC\IocProcessEnrich.c 文件 */
/*  头部 IPE_PEB* 布局 (对齐 C 版 HollowingDetector  */
/*  PH_PEB), 仅供 Process\ProcessHollowingDetector.c */
/*  使用。                                          */
/*  Ipep* 内部辅助 (IpepReadRemoteMemory 等) 均为    */
/*  static, 不在此声明。                           */
/**************************************************/

/* PEB 布局 (仅定义到 ProcessParameters 偏移 @0x20) */
typedef struct _PH_PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[1];         /* 0x08 */
    PVOID ImageBaseAddress;     /* 0x10 (对齐 C 版 PH_PEB) */
    PVOID Ldr;                  /* 0x18 */
    PVOID ProcessParameters;    /* 0x20 */
} PH_PEB64, *PPH_PEB64;

typedef struct _PH_PEB32 {
    BYTE Reserved1[4];
    ULONG Mutant;               /* 0x04 */
    ULONG ImageBaseAddress;     /* 0x08 */
    ULONG Ldr;                  /* 0x0C */
    ULONG ProcessParameters;    /* 0x10 */
} PH_PEB32, *PPH_PEB32;

/* RTL_USER_PROCESS_PARAMETERS 布局 (仅定义到 ImagePathName) */
typedef struct _PH_PROCESS_PARAMETERS64 {
    BYTE Reserved1[16];             /* 0x00-0x10 */
    PVOID Reserved2[10];            /* 0x10-0x60 */
    UNICODE_STRING ImagePathName;   /* 0x60 */
    UNICODE_STRING CommandLine;     /* 0x70 */
} PH_PROCESS_PARAMETERS64, *PPH_PROCESS_PARAMETERS64;

typedef struct _PH_PROCESS_PARAMETERS32 {
    BYTE Reserved1[16];             /* 0x00-0x10 */
    ULONG Reserved2[5];             /* 0x10-0x24 */
    BYTE Reserved3[12];             /* 0x24-0x30 (CURDIR) */
    ULONG Reserved4[6];             /* 0x30-0x48 (3 x UNICODE_STRING) */
} PH_PROCESS_PARAMETERS32, *PPH_PROCESS_PARAMETERS32;