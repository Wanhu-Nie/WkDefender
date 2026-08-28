/**************************************************/
/*  WkDefender IOC 引擎 — 模拟执行骨架              */
/*  迁移自 ShadowStrike EmulationEngine (Stage 8)   */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码骨架：                                 */
/*   - 完整模拟执行需模拟器 (WHP/Unicorn/           */
/*     PhantomEmulator) → EmulatePE 占位            */
/*   - 可迁移逻辑落盘: OEP 启发式 / API 分类 /     */
/*     API 严重性评估（供静态解包+行为分析复用）    */
/*   - 与 PeUnpack 静态解包衔接点: 解包镜像二次     */
/*     扫描 (IocScan_UnpackClosure)                 */
/**************************************************/

#pragma once

#include <windows.h>

/**************************************************/
/*               枚举                               */
/**************************************************/

typedef enum _WKD_EMU_STATE {
    WkdEmuState_Uninitialized = 0,
    WkdEmuState_Ready,
    WkdEmuState_Running,
    WkdEmuState_Completed,
    WkdEmuState_Timeout,
    WkdEmuState_Error,
} WKD_EMU_STATE;

typedef enum _WKD_EMU_API_CATEGORY {
    WkdEmuApi_Unknown = 0,
    WkdEmuApi_FileSystem,
    WkdEmuApi_Registry,
    WkdEmuApi_Process,
    WkdEmuApi_Memory,
    WkdEmuApi_Network,
    WkdEmuApi_Crypto,
    WkdEmuApi_SystemInfo,
    WkdEmuApi_Service,
    WkdEmuApi_Security,
    WkdEmuApi_DynamicCode,
    WkdEmuApi_AntiAnalysis,
    WkdEmuApi_Injection,
} WKD_EMU_API_CATEGORY, *PWKD_EMU_API_CATEGORY;

typedef enum _WKD_EMU_API_SEVERITY {
    WkdEmuSev_Benign = 0,
    WkdEmuSev_Low = 25,
    WkdEmuSev_Medium = 50,
    WkdEmuSev_High = 75,
    WkdEmuSev_Critical = 100,
} WKD_EMU_API_SEVERITY, *PWKD_EMU_API_SEVERITY;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

typedef struct _WKD_EMU_RESULT {
    WKD_EMU_STATE   State;
    BOOLEAN         IsMalicious;
    ULONG           ThreatScore;        /* 0-100 */
    BOOLEAN         WasPacked;
    BOOLEAN         UnpackSuccessful;
    ULONG           OepRva;             /* OEP RVA */
    CHAR            PackerName[32];
    ULONG           ApiCallCount;
    ULONG           SuspiciousApiCount;
    CHAR            ThreatName[64];
} WKD_EMU_RESULT, *PWKD_EMU_RESULT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    OEP 启发式检测 (对齐 SS DetectOEP + PeUnpack):
    标准序言 push ebp; mov ebp, esp (55 8B EC) / 64 位 48 83 EC。

Arguments:
    Buf       - 内存转储/解包镜像。
    Len       - 长度。
    OepOffset - 输出 OEP 偏移。

Return Value:
    TRUE = 找到 OEP。
--*/
BOOLEAN
IocEmu_DetectOEP(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_opt_ PULONG OepOffset
    );

/*++
Routine Description:
    API 分类 (对齐 SS CategorizeAPI)：按 DLL 名映射行为类别。

Arguments:
    DllName  - DLL 名。
    FuncName - 函数名 (可空)。
    Category - 输出类别。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocEmu_CategorizeApi(
    _In_ PCWSTR DllName,
    _In_opt_ PCWSTR FuncName,
    _Out_ PWKD_EMU_API_CATEGORY Category
    );

/*++
Routine Description:
    API 严重性评估 (对齐 SS AssessAPISeverity)：
    敏感 API (注入/内存写/提权) → Critical。

Arguments:
    DllName  - DLL 名。
    FuncName - 函数名。
    Severity - 输出严重级。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocEmu_AssessApiSeverity(
    _In_ PCWSTR DllName,
    _In_ PCWSTR FuncName,
    _Out_ PWKD_EMU_API_SEVERITY Severity
    );

/*++
Routine Description:
    完整模拟执行 (死代码骨架，依赖缺失)。
    需要模拟器后端 (WHP/Unicorn/PhantomEmulator)。
    当前返回 STATUS_NOT_IMPLEMENTED；接入 PeUnpack
    静态解包时仅填充解包字段。

Arguments:
    Buf    - PE 文件数据。
    Len    - 长度。
    Result - 输出结果。

Return Value:
    STATUS_NOT_IMPLEMENTED。
--*/
NTSTATUS
IocEmu_EmulatePE(
    _In_ const BYTE*     Buf,
    _In_ SIZE_T          Len,
    _Out_ PWKD_EMU_RESULT Result
    );
