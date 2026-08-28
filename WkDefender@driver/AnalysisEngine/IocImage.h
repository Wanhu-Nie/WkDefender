#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Process/ProcessMonitor.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR */
#include "AnalysisEngine.h"

//
// IocDetectImage — 镜像加载 IOC 检测流水线（L1 检测层）
//
// 2026-08-08 L0/L1 边界重构：L0 回调已采集 PE 测量事实（WKD_MODULE_PE_FACTS）
// + ImageInfo 标志（文件级 SystemModule/KernelMode 入 WKD_MODULE，每映射
//   Unbacked/MachineMismatch 入视图 ViewFlags，2026-08-11）。
// 本函数从 Pair->SourceProcessId → wkdProcess->ModuleContext → PsLookupModuleInstanceByImageBaseLocked
// 读取事实，逐条检测判定并提交细分 TsIndicator_Image_* 指标。评分由
// dispatch Phase 4 TsSettleScores 统一结算，Phase 4.5 AeEvaluateVerdict 处置
// （浅层阻断：加载恶意镜像的进程评分达 Blocked 后经豁免校验被终止）。
//
// 检测范围（对齐 SS ImageNotify 全功能面，可死代码）：
//   1. 可疑路径加载（0x0A03 SuspiciousPath）
//   2. 系统 DLL 伪装（0x0A04 MasqueradingName）
//   3. typosquatting（0x0A05 Typosquatting）
//   4. 网络路径（0x0A06 NetworkPath）
//   5. 双扩展名（0x0A07 DoubleExtension）
//   6. 无背衬反射加载（0x0A08 PhantomDllUnbacked）
//   7. EP 不在代码段（0x0A09 EntrypointOutsideCode）
//   8. DLL 无导出（0x0A0A NoExports）
//   9. W^X 代码区段（复用 0x0A02 HollowingHeuristic）
//   10. 高熵区段（复用 0x0704 Reputation_SoftwarePacking）
//   11. 信息位（SystemModule/MachineMismatch，纯记录不上分）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocDetectImage(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PIMAGE_INFO ImageInfo
    );
