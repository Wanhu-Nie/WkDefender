/**************************************************/
/*  WkDefender — 镜像加载通知 + 深度检测             */
/*  参考 PhantomSensor ImageNotify.c 全量检测能力     */
/*                                                   */
/*  2026-08-09 镜像职责收敛：                        */
/*    - 新增 CI 签名过滤（SeGetCachedSigningLevel，   */
/*      IMAGE_INFO_EX.FileObject 门控）               */
/*    - 新增路径白名单（内置目录前缀表，DOS 归一化）  */
/*    - 线格式 v2：移除 ThreatScore/Sha256Hash/熵字段，*/
/*      新增 SignatureStatus（hash/熵归 agent）        */
/*                                                   */
/*  功能面全量迁移（2026-08-05）：                    */
/*    - ImageInfo 标志分析（SystemMode/AllPids/       */
/*      MachineMismatch/Unbacked 无背衬内存）         */
/*    - PE 头增强（EP-in-code / .NET / 安全目录 /     */
/*      TLS 回调 / 驱动子系统判定）                   */
/*    - 系统 DLL 伪装 typosquatting 检测              */
/*    - 网络路径 / 双扩展名 / 无背衬信号              */
/*    - 镜像类型细分（Dll/Exe/Sys/Drv/Ocx/Cpl/Scr/Efi）*/
/*    - 事件上下文（父PID/会话/线程）                 */
/*    - 无锁速率限制                                  */
/*    - 死代码区（BYOVD/IOC匹配/哈希缓存/镂空/        */
/*      Section/回调注册表/Init状态机 等）            */
/**************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include "../Process/ProcessMonitor.h"

//
// 池标记
//
#define WKD_IMG_POOL_TAG    'mIWK'
#define WKD_IMG_EVENT_TAG   'eIWK'

//
// 镜像指示器位（对齐 PS IMG_LOAD_FLAGS 子集）
//
#define IMG_INDICATOR_SUSPICIOUS_PATH           0x00000001  // 可疑路径 (Temp/Downloads/ProgramData)
#define IMG_INDICATOR_MASQUERADING_DLL          0x00000002  // 伪装系统 DLL 名（精确匹配）
#define IMG_INDICATOR_LOW_ENTROPY               0x00000004  // 低熵（疑似压缩/加密）
#define IMG_INDICATOR_HIGH_ENTROPY              0x00000008  // 高熵（疑似混淆/加密）
#define IMG_INDICATOR_WX_CODE_SECTION           0x00000010  // 代码段可写 (SelfModifying)
#define IMG_INDICATOR_NO_EXPORTS                0x00000020  // DLL 无导出
#define IMG_INDICATOR_BOOT_IMAGE                0x00000040  // 引导阶段关键镜像

//
// 迁移新增（对齐 SS ImgFlag_*/ImgSuspicious_* 语义）
//
#define IMG_INDICATOR_NETWORK_PATH              0x00000080  // UNC 网络路径加载（SS NetworkPath）
#define IMG_INDICATOR_DOUBLE_EXTENSION          0x00000100  // 双扩展名 .pdf.dll（SS DoubleExtension）
#define IMG_INDICATOR_TYPOSQUATTING             0x00000200  // 系统 DLL 名 typosquatting（1字符/±1字符）
#define IMG_INDICATOR_UNBACKED                  0x00000400  // 无背衬内存映射（SS PhantomDll/UnbackedMemory）
#define IMG_INDICATOR_ENTRYPOINT_OUTSIDE_CODE   0x00000800  // EP 不在代码段（SS ProcessHollow）

//
// 信息位（检出不上分）
//
#define IMG_INDICATOR_SYSTEM_MODULE             0x00001000  // MappedToAllPids 系统共享模块
#define IMG_INDICATOR_MACHINE_MISMATCH          0x00002000  // 架构不匹配（32/64 位交叉加载）
#define IMG_INDICATOR_DOTNET                    0x00004000  // .NET 托管模块（COM_DIR）
#define IMG_INDICATOR_SECURITY_DIR              0x00008000  // 含安全目录（潜在签名）
#define IMG_INDICATOR_TLS_CALLBACK              0x00010000  // 含 TLS 回调

//
// 镜像威胁评分阈值（对齐 PS ImgpCalculateThreatScore）
//
#define IMG_THREAT_PATH_SUSPICIOUS      30
#define IMG_THREAT_MASQUERADE           40
#define IMG_THREAT_HIGH_ENTROPY         25
#define IMG_THREAT_WX_SECTION           35      // wkd 保留 35（SS=25，WX 危害更高，注释说明差异）
#define IMG_THREAT_NO_EXPORTS           15
#define IMG_THREAT_LOW_ENTROPY          10
#define IMG_THREAT_NETWORK_PATH         25      // 对齐 SS
#define IMG_THREAT_DOUBLE_EXTENSION     30      // 对齐 SS
#define IMG_THREAT_TYPOSQUATTING        40      // 与 MASQUERADE 同档
#define IMG_THREAT_UNBACKED             50      // 对齐 SS PhantomDll
#define IMG_THREAT_ENTRYPOINT_OUTSIDE   50      // 对齐 SS ProcessHollow
#define IMG_THREAT_KNOWN_VULNERABLE     80      // 对齐 SS KnownVulnerable（死代码用）

//
// PE 头缓存大小（对齐 PS IMG_MAX_PE_HEADER_SIZE）
//
#define WKD_IMG_PE_HEADER_MAX   4096

//
// 镜像签名状态（SignatureStatus 线格式值）
//
#define IMG_SIGNATURE_UNEVALUATED   0   // FileObject 不可用，跳过签名判定（不视为未签名）
#define IMG_SIGNATURE_VALID         1   // CI 签名等级 > SE_SIGNING_LEVEL_UNSIGNED
#define IMG_SIGNATURE_UNSIGNED      2   // 无 CI 缓存或未签名

//
// 镜像加载消息体（驱动→Agent，线格式）
// ★ 线格式结构：驱动与 agent 共享，禁止增删字段！
// v2（2026-08-09）：移除 ThreatScore（恒 0 未消费）/Sha256Hash/HashComputed
// （哈希归 agent），新增 SignatureStatus。
//
typedef struct _WKD_MESSAGE_BODY_IMAGE_LOAD {
    PVOID   ImageBase;
    SIZE_T  ImageSize;
    UNICODE_STRING ImagePath;   /* Buffer 指向内联数据 */

    /* === 深度分析字段 === */
    ULONG   ImageType;          // 0=user, 1=kernel
    ULONG   ImageIndicators;    // IMG_INDICATOR_* 位图
    UCHAR   SignatureStatus;    // IMG_SIGNATURE_*
    UCHAR   Reserved[3];        // 对齐 WKD_IMG_PE_BASIC 边界

} WKD_MESSAGE_BODY_IMAGE_LOAD, *PWKD_MESSAGE_BODY_IMAGE_LOAD;

//
// 镜像类型细分 WKD_IMAGE_TYPE 已迁至 Process/ProcessModuleTracker.h
// （经 ProcessMonitor.h 间接 include，消除 ImageNotify.h↔ProcessModuleTracker.h 依赖）
//

//
// ======================================================================
// 死代码区结构声明（对齐 PS ImageNotify.h，功能面覆盖，不接入流水线）
// ======================================================================
//

//
// [死代码][SS ImageNotify.h:364 对齐] IMG_NOTIFY_CONFIG 配置结构
// 不接入原因：wkd 配置走 agent 推送通道（同 IocAppControlSetPolicyMode 模式），
// 本文件无配置入口。
//
typedef struct _IMG_NOTIFY_CONFIG {
    ULONG Size;
    ULONG Version;
    BOOLEAN EnablePeAnalysis;
    BOOLEAN EnableHashComputation;
    BOOLEAN EnableSignatureCheck;
    BOOLEAN EnableSuspiciousDetection;
    BOOLEAN EnableDriverMonitoring;
    BOOLEAN EnableVulnerableDriverCheck;
    BOOLEAN EnableDriverBlocking;
    BOOLEAN EnableModuleTracking;
    BOOLEAN MonitorSystemProcesses;
    BOOLEAN MonitorKernelImages;
    BOOLEAN SkipMicrosoftSigned;
    BOOLEAN SkipWhqlSigned;
    BOOLEAN SkipCatalogSigned;
    ULONG MinThreatScoreToReport;
    ULONG HighEntropyThreshold;
    ULONG MaxEventsPerSecond;
    ULONG64 MaxFileSizeForHash;
    ULONG HashTimeoutMs;
} IMG_NOTIFY_CONFIG, *PIMG_NOTIFY_CONFIG;

//
// [死代码][SS ImageNotify.h:415 对齐] IMG_NOTIFY_STATISTICS 统计
// 不接入原因：同上，统计随配置走 agent 查询通道。
//
typedef struct _IMG_NOTIFY_STATISTICS {
    volatile LONG64 TotalImagesLoaded;
    volatile LONG64 UserModeImages;
    volatile LONG64 KernelModeImages;
    volatile LONG64 SignedImages;
    volatile LONG64 UnsignedImages;
    volatile LONG64 SuspiciousImages;
    volatile LONG64 BlockedImages;
    volatile LONG64 HashesComputed;
    volatile LONG64 PeAnalyses;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 EventsDropped;
    volatile LONG64 CallbackErrors;
    volatile LONG64 ModulesTracked;
    LARGE_INTEGER StartTime;
} IMG_NOTIFY_STATISTICS, *PIMG_NOTIFY_STATISTICS;

//
// [死代码][SS ImageNotify.h:437 对齐] IMG_HASH_CACHE_ENTRY 哈希缓存条目
// 不接入原因：集中哈希缓存归 agent（架构决策 #30），驱动不建 FileId→hash 缓存。
//
typedef struct _IMG_HASH_CACHE_ENTRY {
    LIST_ENTRY HashListEntry;
    ULONG64 FileId;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER CacheTime;
    UCHAR Sha256Hash[32];
    UCHAR Sha1Hash[20];
    UCHAR Md5Hash[16];
    BOOLEAN IsValid;
    volatile LONG RefCount;
} IMG_HASH_CACHE_ENTRY, *PIMG_HASH_CACHE_ENTRY;

//
// [死代码][SS ImageNotify.h:260 对齐] IMG_VULNERABLE_DRIVER 脆弱驱动条目
// 不接入原因：依赖缺失（驱动无密码学能力，脆弱驱动哈希比对归 agent，架构决策 #30）。
//
typedef struct _IMG_VULNERABLE_DRIVER_ENTRY {
    LIST_ENTRY HashEntry;
    UCHAR Sha256Hash[32];
    WCHAR DriverName[64];
    CHAR CveId[32];
} IMG_VULNERABLE_DRIVER_ENTRY, *PIMG_VULNERABLE_DRIVER_ENTRY;

//
// [死代码][SS ImageNotify.h:475 对齐] 回调类型
// 不接入原因：无内部订阅者，wkd 事件分配直接 ExAllocatePool2，回调注册表废弃。
//
typedef NTSTATUS (*IMG_PRE_LOAD_CALLBACK)(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN BlockLoad,
    _In_opt_ PVOID Context
    );

typedef VOID (*IMG_POST_LOAD_CALLBACK)(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo,
    _In_opt_ PVOID Context
    );

//
// ======================================================================
// 函数声明
// ======================================================================
//

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbInitializeImageNotify(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ImgNotifyCleanup(
    VOID
    );

//
// L0 采集器内部函数（CbpNotifyImageLoad 等）均为 static，不在此声明。
// 检测判定函数（ImgpIsPathSuspicious / ImgpIsMasqueradingName /
// ImgpDetectMasquerade / ImgpDetectSuspiciousIndicators）已迁往
// AnalysisEngine/IocImage.c（L1 检测层，2026-08-08 L0/L1 边界重构）。
// 2026-08-11：PE 解析助手（ImgpParsePeFacts 等）已删——归全局 WKD_MODULE
// PspParseModule；ImgNotifyProcessTerminated 死代码已删——统一由
// PspDestroyProcess → PsDestroyWkdModuleContext 覆盖。
//
