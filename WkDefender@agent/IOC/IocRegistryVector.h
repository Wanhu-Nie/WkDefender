/**************************************************/
/*  WkDefender IOC — 注册表注入向量检测              */
/*                                                  */
/*  职责: 检查 AppInit_DLLs / IFEO (Image File      */
/*        Execution Options) 注册表注入向量          */
/*                                                  */
/*  移植自: ShadowStrike DLLInjectionDetector       */
/*         CheckAppInitDLLsImpl / CheckIFEOImpl      */
/*  调用方式: 一次性检查 (IrvCheckAll), 周期调度由    */
/*        接线方 (编排器/UI) 决定, 本模块不自起线程   */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               常量                               */
/**************************************************/

#define IRV_PATH_BUFFER_MAX     260
#define IRV_DLL_BUFFER_MAX      520

/**************************************************/
/*               类型声明                           */
/**************************************************/

/* 注册表注入向量类型 */
typedef enum _WKD_REG_VECTOR_TYPE {
    WkdRv_AppInitDlls        = 1,   /* AppInit_DLLs 持久化 */
    WkdRv_AppInitDllsWoW64   = 2,   /* WoW64 视图 AppInit_DLLs */
    WkdRv_IfeoDebugger       = 3,   /* IFEO Debugger 劫持 */
    WkdRv_IfeoVerifierDlls   = 4,   /* IFEO GlobalFlag+VerifierDlls */
} WKD_REG_VECTOR_TYPE, *PWKD_REG_VECTOR_TYPE;

/* 单条注册表注入向量 */
typedef struct _WKD_REGISTRY_VECTOR {
    WKD_REG_VECTOR_TYPE Type;       /* 向量类型 */
    WCHAR  RegistryPath[IRV_PATH_BUFFER_MAX];   /* 注册表键路径 */
    WCHAR  ValueName[64];           /* 值名称 */
    WCHAR  DllPath[IRV_DLL_BUFFER_MAX];         /* 配置的 DLL 路径 */
    BOOLEAN IsEnabled;              /* AppInit 是否被启用 */
    BOOLEAN IsSuspicious;           /* 判定为可疑注入向量 */
    WCHAR  Reason[256];             /* 怀疑原因 */
} WKD_REGISTRY_VECTOR, *PWKD_REGISTRY_VECTOR;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IrvCheckAppInitDlls — 检查 AppInit_DLLs 注入向量 (含 WoW64 双视图)。
 *
 * 读取 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows 的
 * AppInit_DLLs / LoadAppInit_DLLs, 64 位与 32 位视图分别判定。
 *
 * 参数:
 *   Vectors - 输出向量数组 (必填)。
 *   Max     - 数组容量。
 *   Count   - 实际写入条数 (可为 NULL)。
 *
 * 返回值:
 *   写入的向量条数。
 */
ULONG
IrvCheckAppInitDlls(
    _Out_writes_to_(*Count, *Count) PWKD_REGISTRY_VECTOR Vectors,
    _In_ ULONG Max,
    _Out_opt_ PULONG Count
    );

/*
 * IrvCheckIfeo — 检查 Image File Execution Options 注入向量。
 *
 * 枚举 HKLM\...\Image File Execution Options 全部子键, 检测
 * Debugger (经典 IFEO 劫持) 与 GlobalFlag+VerifierDlls
 * (Application Verifier 滥用)。
 *
 * 参数:
 *   Vectors - 输出向量数组 (必填)。
 *   Max     - 数组容量。
 *   Count   - 实际写入条数 (可为 NULL)。
 *
 * 返回值:
 *   写入的向量条数。
 */
ULONG
IrvCheckIfeo(
    _Out_writes_to_(*Count, *Count) PWKD_REGISTRY_VECTOR Vectors,
    _In_ ULONG Max,
    _Out_opt_ PULONG Count
    );

/*
 * IrvCheckAll — 全量注册表注入向量检查。
 *
 * 依次执行 IrvCheckAppInitDlls + IrvCheckIfeo。
 *
 * 参数:
 *   Vectors - 输出向量数组 (必填)。
 *   Max     - 数组容量。
 *   Count   - 实际写入条数 (可为 NULL)。
 *
 * 返回值:
 *   写入的向量条数。
 */
ULONG
IrvCheckAll(
    _Out_writes_to_(*Count, *Count) PWKD_REGISTRY_VECTOR Vectors,
    _In_ ULONG Max,
    _Out_opt_ PULONG Count
    );
