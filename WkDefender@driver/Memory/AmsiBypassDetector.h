/**************************************************/
/*  WkDefender — AMSI 绕过检测器                      */
/*  参考 PhantomSensor AmsiBypassDetector.{c,h}       */
/*  MITRE ATT&CK: T1562.001 Disable or Modify Tools  */
/*  (AMSI bypass)                                     */
/*                                                    */
/*  检测能力:                                         */
/*    - amsi.dll 函数序言补丁签名匹配                 */
/*      (ret / mov eax,E_INVALIDARG / xor eax / NOP)  */
/*    - 干净基线 prologue 对比 (检出未知补丁/内联hook) */
/*    - amsi.dll 区域保护变更检测 (变可写)             */
/*  架构:                                             */
/*    - 自注册 PsSetLoadImageNotifyRoutine 追踪        */
/*      amsi.dll 加载 (不依赖 CbInitializeImageNotify) */
/*    - 自建 30s 周期 worker 线程主动扫描              */
/*      (覆盖脚本宿主自进程内 patch, syscall 监控会    */
/*      跳过 Source==Target)                          */
/*    - 基线陈旧防护: prologue 与基线不一致时先校验     */
/*      磁盘 amsi.dll 文件时间戳/大小, 过期自动刷新     */
/*    - 检测结果经 ALPC 上送 agent (WkdMessage_        */
/*      AmsiBypassDetected)                           */
/**************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

/**************************************************/
/*                      常量                       */
/**************************************************/

#define ABD_POOL_TAG            'bAsW'      /* WsAb — Detector 状态 */
#define ABD_POOL_TAG_PROC       'pAsW'      /* WsAp — 进程条目 */
#define ABD_POOL_TAG_BASELINE   'bBaW'      /* WaBb — 干净基线副本 */

#define ABD_MAX_TRACKED_PROCESSES   256
#define ABD_PROLOGUE_SIZE           16
#define ABD_HASH_SIZE               32      /* SHA-256（SS 对齐，死代码预留） */
#define ABD_FUNCTION_NAME_MAX       64
#define ABD_MAX_CRITICAL_FUNCTIONS  8

/* 周期扫描间隔 (对齐 SS ABD_SCAN_INTERVAL_100NS = 30s) */
#define ABD_SCAN_INTERVAL_100NS     (-(LONGLONG)30 * 10000000LL)

/* CAS 生命周期 */
#define ABD_STATE_UNINITIALIZED     0
#define ABD_STATE_INITIALIZING      1
#define ABD_STATE_READY             2
#define ABD_STATE_SHUTTING_DOWN     3

/**************************************************/
/*              绕过类型分类                        */
/**************************************************/

typedef enum _ABD_BYPASS_TYPE {
    AbdBypass_None                  = 0,
    AbdBypass_PatchAmsiScanBuffer,      /* AmsiScanBuffer 序言补丁（ret/mov eax） */

    /* ── 以下为 SS 声明未实现的分类，仅对齐枚举 API 面（死代码） ── */
    AbdBypass_PatchAmsiOpenSession,     /* AmsiOpenSession 序言补丁（SS 未实现检测） */
    AbdBypass_PatchAmsiInitialize,      /* AmsiInitialize 序言补丁（SS 未实现检测） */
    AbdBypass_AmsiDllUnloaded,          /* amsi.dll 强制卸载（SS 未实现检测） */
    AbdBypass_AmsiDllNotLoaded,         /* amsi.dll 阻止加载（SS 未实现检测） */
    AbdBypass_AmsiContextOverwrite,     /* AMSI context 指针清零（SS 未实现检测） */
    AbdBypass_MemoryProtectionChange,   /* amsi.dll 区域被改可写（已实现） */
    AbdBypass_EtwEventWritePatch,       /* EtwEventWrite 补丁 / ETW 致盲（SS 未实现检测） */
    AbdBypass_EtwProviderDisabled,      /* ETW provider 禁用（SS 未实现检测） */
    AbdBypass_InlineHook,               /* 未知内联 hook（已实现，NopSled 签名命中归此类） */
    AbdBypass_Max
} ABD_BYPASS_TYPE, *PABD_BYPASS_TYPE;

/**************************************************/
/*               检测结果结构                       */
/**************************************************/

typedef struct _ABD_DETECTION {
    ABD_BYPASS_TYPE BypassType;
    HANDLE          ProcessId;
    PVOID           TargetAddress;      /* 被补丁的函数地址 */
    UCHAR           OriginalBytes[ABD_PROLOGUE_SIZE];
    UCHAR           CurrentBytes[ABD_PROLOGUE_SIZE];
    LARGE_INTEGER   DetectionTime;
    CHAR            FunctionName[ABD_FUNCTION_NAME_MAX];
} ABD_DETECTION, *PABD_DETECTION;

/**************************************************/
/*                 统计结构                         */
/**************************************************/

typedef struct _ABD_STATISTICS {
    volatile LONG64 ProcessesMonitored;
    volatile LONG64 AmsiLoadsObserved;
    volatile LONG64 BypassesDetected;
    volatile LONG64 PatchDetections;
    volatile LONG64 ProtectionChangeDetections;
    volatile LONG64 EtwPatchDetections;     /* SS 对齐：ETW patch 检测计数（检测未实现，字段保留） */
    volatile LONG64 ScansPerformed;
} ABD_STATISTICS, *PABD_STATISTICS;

/**************************************************/
/*                函数声明                          */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdCleanup(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
AbdIsActive(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdNotifyImageLoad(
    _In_ HANDLE ProcessId,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_opt_ PCUNICODE_STRING ImageName
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdScanProcess(
    _In_ HANDLE ProcessId,
    _Out_ PABD_DETECTION Detection
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
AbdCheckProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdRemoveProcessTracking(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AbdGetStatistics(
    _Out_ PABD_STATISTICS Stats
    );
