/**************************************************/
/*  WkDefender Agent — 进程域模块挂载              */
/*                                                  */
/*  2026-08-15 新增：全局唯一 WKD_MODULE + 进程私有  */
/*  WKD_MODULE_INSTANCE（参照驱动 ProcessModule-     */
/*  Tracker，agent 版）。                            */
/*                                                  */
/*  生命周期模型（同构驱动）：                       */
/*    RefCount = 表引用(1) + 视图引用 + pin           */
/*    PsFindOrCreateModule 两阶段（锁内查→锁外解析   */
/*    →try-insert 取赢家）；PsDereferenceWkdModule 归零  */
/*    (RefCount==1) 摘表→锁外释放；发布后不可变。     */
/*                                                  */
/*  PE 事实 + SHA256：IocAnalyzePeFromFilePath /                 */
/*  IocScanner_ComputeFileSha256（均线程安全）。      */
/*                                                  */
/*  2026-08-15 镜像分析流水线扩展（ImageAnalyzer）：  */
/*    AnalysisState/CompleteEvent/FileResult =       */
/*    文件级静态分析结果权威副本（一次计算全局共享）， */
/*    对齐驱动"全局不可变对象"模型；深度分析结果由     */
/*    Tier3 异步填充，Tier1 命中 Done 则 O(1) 复用。  */
/**************************************************/

#pragma once

#include "ProcessTypes.h"
#include "../Common/HashMap.h"           /* 通用哈希表 (2026-08-20 阶段5：任意 key 抽象) */
#include "../Notification/EventTypes.h"    /* WKD_EVENT_HEADER / PEVENT_PAYLOAD_IMAGE_LOAD */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"    /* PE_INFO (Facts 提取) */
#include "../IOC/IocTypes.h"               /* IOC_SCAN_RESULT (FileResult 载体) */
#include "../IOC/IocScanner.h"             /* IocScanner_ComputeFileSha256 */

#define MAX_MODULES_PER_PROCESS   128
#define WKD_MODULE_TABLE_BUCKETS         128
#define WKD_MODULE_TABLE_MAX_ENTRIES     4096

/**************************************************/
/*            模块分析状态                         */
/*                                                  */
/*  ImageAnalyzer Tier1 的并发契约（2026-08-18 四态） */
/*    NONE        — 未分析（兼容 CAS 抢占起点）      */
/*    CREATED     — 已入表+Facts/CertInfo/hash 就绪, */
/*                  轻量判定可得，深度未启动          */
/*    IN_PROGRESS — 深度已入队/工作线程进行中        */
/*    DONE        — 深度完成，PeAnalysis/FileResult   */
/*                  有效，O(1) 复用                   */
/**************************************************/

#define WKD_MODULE_ANALYSIS_NONE         0
#define WKD_MODULE_ANALYSIS_CREATED      1
#define WKD_MODULE_ANALYSIS_IN_PROGRESS  2
#define WKD_MODULE_ANALYSIS_DONE         3

/**************************************************/
/*           全局唯一镜像对象                       */
/**************************************************/

typedef struct _WKD_MODULE {
    volatile LONG  RefCount;             /* 表引用(1) + 视图引用 + pin */
    WKD_IMAGE_TYPE ImageType;            /* 扩展名判定 */
    ULONG64        ImageSize;            /* 首见映射大小（仅记录，不参与查重） */
    LARGE_INTEGER  LastWriteTime;        /* 文件末写时间（防替换，业务层比对） */
    PUNICODE_STRING ImagePath;           /* 原始路径副本（显示/业务比对用） */
    DEF_SHA256_HASH Sha256;              /* agent 计算 */
    UCHAR          SignatureStatus;      /* 驱动上送 IMG_SIGNATURE_* */
    WKD_MODULE_PE_FACTS  Facts;          /* IocAnalyzePeFromFilePath 提取（基元位域摘要） */
    WKD_CERT_INFO        CertInfo;       /* 证书验证权威副本 (2026-08-18 阶段1) */
    WKD_PE_ANALYSIS      PeAnalysis;     /* 深度分析权威副本 (2026-08-18 阶段3) */
    PE_INFO        PeInfo;               /* 完整 PE 几何快照（IocAnalyzePe 产物，2026-08-19）：
                                           * 含节表 Sections[] + 数据目录 DataDirectories[]，
                                           * 供 PmBuildLazyContext 重建惰性解析 Ctx，
                                           * 消除深度分析（IocHeuristicPeAnalysis）二次完整解析。 */
    ULONG          SectionAlignment;
    ULONG          FileAlignment;
    SIZE_T         SizeOfImage;
    ULONG          DllCharacteristics;  /* 补存（IocAnalyzePeFromFilePath 提取，PeHeaders 缓解检测） */
    WKD_IMAGE_PROPERTIES ImageProperties;

    /* 文件级静态分析结果（ImageAnalyzer 流水线）：
     * AnalysisState=Done 后 FileResult 有效，全进程共享，一经发布不可变。 */
    volatile LONG  AnalysisState;        /* WKD_MODULE_ANALYSIS_* */
    HANDLE         CompleteEvent;        /* IN_PROGRESS 期间存在，Done 后 SetEvent+释放 */
    PIOC_SCAN_RESULT FileResult;         /* 文件级静态结果（堆分配，Done 后有效） */
} WKD_MODULE, *PWKD_MODULE;

/**************************************************/
/*           全局模块表                             */
/*                                                   */
/*  2026-08-20 阶段5：Common/HashMap 任意 key 抽象。  */
/*  Value=WKD_MODULE，表 key=归一化小写路径字节（哈   */
/*  希/拷贝/比较统一表内完成，无谓词注入）。          */
/*  mtime 防替换为业务层锁外校验（命中后比对）。引用   */
/*  回调仅 Reference（Find 命中 pin），摘除/释放由  */
/*  PsDereferenceWkdModule 完成（Dereference=NULL）。  */
/**************************************************/

typedef struct _WKD_MODULE_TABLE {
    BOOLEAN         Initialized;
    WKD_HASH_MAP    Map;            /* 通用哈希表（SRWLOCK + 桶 + 回调） */
} WKD_MODULE_TABLE, *PWKD_MODULE_TABLE;

extern WKD_MODULE_TABLE g_WkdModuleTable;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
PmInitialize(
    VOID
    );

VOID
PmCleanup(
    VOID
    );

NTSTATUS
PsFindOrCreateModule(
    _In_ PCWSTR ImagePath,
    _In_opt_ SIZE_T ImageSize,
    _In_ UCHAR SignatureStatus,
    _Out_ PWKD_MODULE* Module
    );

/* 深度分析结果 → 模块 PeAnalysis 权威副本（ImageAnalyzer worker 调用） */
VOID
PmExtractPeAnalysis(
    _In_  PIOC_SCAN_RESULT  Result,
    _Out_ PWKD_PE_ANALYSIS  PeAnalysis
    );

NTSTATUS
PsModuleInstanceAttachProcess(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Inout_ PWKD_MODULE Module,
    _In_opt_ PVOID ImageBase,
    _Out_opt_ PWKD_MODULE_INSTANCE* Instance
    );

/* 按模块名（尾部文件名, 如 L"ntdll.dll"）在进程模块实例链中
 * 定位模块实例。磁盘视图（ImageBase=NULL）视为未命中；
 * 命中实例保证 ImageBase 为有效映射基址。 */
NTSTATUS
PsLookupModuleInstanceByName(
    _In_ const PWKD_PROCESS WkdProcess,
    _In_ PCWSTR ModuleName,
    _Out_ PWKD_MODULE_INSTANCE* Instance
    );

/* 获取进程主模块（exe 映像）实例：MainModule 标志由挂载首个实例
 * 置位（进程创建期补挂的 exe 磁盘视图，2026-09-07）。磁盘视图
 * （ImageBase=NULL）视为未命中，命中实例 ImageBase 有效。 */
_Must_inspect_result_
NTSTATUS
PsGetMainModuleInstance(
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PWKD_MODULE_INSTANCE* Instance
    );

VOID
PsDestroyModuleContext(
    _Inout_ PWKD_PROCESS Process
    );

NTSTATUS
PsHandleImageLoad(
    _In_ const PWKD_EVENT_HEADER Event
    );

/* 模块引用计数与本体释放 (2026-08-27 补全, 重构遗漏 — 调用方
 * IocEngine/ImageAnalyzer/ProcessSnapshot/ProcessModule 早已引用)：
 *   PsReferenceWkdModule / PsDereferenceWkdModule 成对 (对齐
 *   ProcessTypes.h "计数沿用 PsReferenceWkdModule/PsDereferenceWkdModule")；
 *   PsDereferenceWkdModule 在仅剩表引用时摘表归零, 锁外调用
 *   PspDestroyWkdModule 释放本体 (含 CompleteEvent 句柄通知关闭)。 */
LONG
PsReferenceWkdModule(
    _Inout_ PWKD_MODULE WkdModule
    );

LONG
PsDereferenceWkdModule(
    _In_ PWKD_MODULE WkdModule
    );