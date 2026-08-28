/**************************************************/
/*  WkDefender IOC 引擎 — 沙箱分析骨架实现          */
/**************************************************/

#include "IocSandboxAnalyzer.h"

#include <ntstatus.h>

/**************************************************/
/*               威胁级别                           */
/**************************************************/

WKD_SANDBOX_THREAT_LEVEL
IocSandbox_CalcThreatLevel(
    _In_ ULONG Score
    )
{
    if (Score >= 81) return WkdSbLevel_HighlyMalicious;
    if (Score >= 61) return WkdSbLevel_Malicious;
    if (Score >= 41) return WkdSbLevel_LikelyMalicious;
    if (Score >= 21) return WkdSbLevel_Suspicious;
    return WkdSbLevel_Clean;
}

/**************************************************/
/*               沙箱执行 (占位)                    */
/**************************************************/

NTSTATUS
IocSandbox_SubmitSample(
    _In_ PCWSTR SamplePath,
    _In_ ULONG  Timeout,
    _Out_ PULONG TaskId
    )
{
    /* 依赖缺失: Hyper-V/VMware 虚拟机基础设施 + 快照管理。
     * 接入时: 找空闲 VM → 还原快照 → 传输样本 → 执行监控 →
     * 超时回收 → 生成 Verdict。 */
    if (!SamplePath || !TaskId) return STATUS_INVALID_PARAMETER;
    *TaskId = 0;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
IocSandbox_GetVerdict(
    _In_ ULONG                  TaskId,
    _Out_ PWKD_SANDBOX_VERDICT Verdict
    )
{
    if (!Verdict) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Verdict, sizeof(*Verdict));
    Verdict->TaskState = WkdSbTask_Queued;
    UNREFERENCED_PARAMETER(TaskId);
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*               ML 分类 (占位)                     */
/**************************************************/

NTSTATUS
IocSandbox_MlClassify(
    _In_opt_ const FLOAT* Features,
    _In_ ULONG            FeatureCount,
    _Out_ PULONG          Verdict,
    _Out_ PFLOAT          Confidence
    )
{
    /* 依赖缺失: ONNX Runtime + PhantomCortex 模型。
     * 功能面覆盖：接口签名保留，返回 ML 未可用。 */
    UNREFERENCED_PARAMETER(Features);
    UNREFERENCED_PARAMETER(FeatureCount);
    if (Verdict) *Verdict = 0;
    if (Confidence) *Confidence = 0.0f;
    return STATUS_NOT_IMPLEMENTED;
}
