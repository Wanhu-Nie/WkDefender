/**************************************************/
/*  WkDefender IOC 引擎 — 沙箱分析骨架 + ML 占位    */
/*  迁移自 ShadowStrike SandboxAnalyzer (Stage 7)   */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码骨架：                                 */
/*   - 动态沙箱需 Hyper-V/VMware 基础设施 → 状态机 */
/*     与任务结构落盘，执行占位                     */
/*   - ML 分类 (PhantomCortex) 需 ONNX Runtime →     */
/*     接口签名占位 + 依赖说明                      */
/**************************************************/

#pragma once

#include <windows.h>

/**************************************************/
/*               枚举                               */
/**************************************************/

typedef enum _WKD_SANDBOX_VM_STATE {
    WkdSbVm_Stopped = 0,
    WkdSbVm_Starting,
    WkdSbVm_Running,
    WkdSbVm_Paused,
    WkdSbVm_Stopping,
    WkdSbVm_Error,
} WKD_SANDBOX_VM_STATE;

typedef enum _WKD_SANDBOX_TASK_STATE {
    WkdSbTask_Queued = 0,
    WkdSbTask_Preparing,
    WkdSbTask_Executing,
    WkdSbTask_Monitoring,
    WkdSbTask_Completed,
    WkdSbTask_Failed,
    WkdSbTask_Timeout,
    WkdSbTask_Cancelled,
} WKD_SANDBOX_TASK_STATE;

typedef enum _WKD_SANDBOX_THREAT_LEVEL {
    WkdSbLevel_Clean = 0,        /* 0-20 */
    WkdSbLevel_Suspicious,       /* 21-40 */
    WkdSbLevel_LikelyMalicious,  /* 41-60 */
    WkdSbLevel_Malicious,        /* 61-80 */
    WkdSbLevel_HighlyMalicious,  /* 81-100 */
} WKD_SANDBOX_THREAT_LEVEL;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

typedef struct _WKD_SANDBOX_ARTIFACT {
    CHAR    ArtifactType[32];       /* dropped_file / memory_dump / pcap */
    CHAR    OriginalPath[MAX_PATH];
    ULONG   Size;
    CHAR    Sha256[65];
    BOOLEAN IsMalicious;
} WKD_SANDBOX_ARTIFACT, *PWKD_SANDBOX_ARTIFACT;

#define WKD_SANDBOX_MAX_ARTIFACTS   64
#define WKD_SANDBOX_MAX_INDICATORS  32

typedef struct _WKD_SANDBOX_VERDICT {
    BOOLEAN         IsMalicious;
    ULONG           ThreatScore;        /* 0-100 */
    WKD_SANDBOX_THREAT_LEVEL ScoreLevel;
    CHAR            MalwareFamily[64];
    CHAR            MalwareType[32];
    WKD_SANDBOX_TASK_STATE TaskState;
    ULONG           DurationSeconds;

    ULONG           IndicatorCount;
    CHAR            Indicators[WKD_SANDBOX_MAX_INDICATORS][128];
    CHAR            MitreIds[16][24];
    ULONG           MitreCount;

    ULONG           ArtifactCount;
    WKD_SANDBOX_ARTIFACT Artifacts[WKD_SANDBOX_MAX_ARTIFACTS];
} WKD_SANDBOX_VERDICT, *PWKD_SANDBOX_VERDICT;

typedef struct _WKD_SANDBOX_TASK {
    ULONG                   TaskId;
    WCHAR                   SamplePath[MAX_PATH];
    WKD_SANDBOX_TASK_STATE  State;
    volatile LONG           Progress;       /* 0-100 */
    ULONG                   TimeoutSeconds;
    ULONG                   StartTick;
    WKD_SANDBOX_VERDICT     Verdict;
} WKD_SANDBOX_TASK, *PWKD_SANDBOX_TASK;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    提交样本至沙箱分析 (死代码骨架，依赖缺失)。
    需要 Hyper-V/VMware 基础设施。当前占位。

Arguments:
    SamplePath - 样本路径。
    Timeout    - 超时秒数。
    TaskId     - 输出任务 ID。

Return Value:
    STATUS_NOT_IMPLEMENTED。
--*/
NTSTATUS
IocSandbox_SubmitSample(
    _In_ PCWSTR SamplePath,
    _In_ ULONG  Timeout,
    _Out_ PULONG TaskId
    );

/*++
Routine Description:
    查询分析结果。

Arguments:
    TaskId - 任务 ID。
    Verdict - 输出判定。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocSandbox_GetVerdict(
    _In_ ULONG                  TaskId,
    _Out_ PWKD_SANDBOX_VERDICT Verdict
    );

/*++
Routine Description:
    计算威胁级别 (对齐 SS CalculateThreatLevel)。

Arguments:
    Score - 0-100 分。

Return Value:
    威胁级别。
--*/
WKD_SANDBOX_THREAT_LEVEL
IocSandbox_CalcThreatLevel(
    _In_ ULONG Score
    );

/*++
Routine Description:
    ML 分类占位 (PhantomCortex, 依赖缺失 ONNX)。
    功能面覆盖：接口签名保留，返回 ML 未可用。

Arguments:
    Features - 特征指针 (预留)。
    FeatureCount - 特征数。
    Verdict  - 输出 0=良性 1=可疑 2=恶意。
    Confidence - 输出置信度 0-1。

Return Value:
    STATUS_NOT_IMPLEMENTED。
--*/
NTSTATUS
IocSandbox_MlClassify(
    _In_opt_ const FLOAT* Features,
    _In_ ULONG            FeatureCount,
    _Out_ PULONG          Verdict,
    _Out_ PFLOAT          Confidence
    );
