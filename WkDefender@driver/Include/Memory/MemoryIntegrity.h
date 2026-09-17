/**************************************************/
/*                                                    */
/*  WkDefender 内存完整性（Memory Integrity）         */
/*  检测子系统——对外公共头                           */
/*                                                    */
/*  【唯一对外入口】Memory 域之外的内核模块            */
/*  （Process\HollowingDetector、AnalysisEngine 等）   */
/*  访问内存 vs 磁盘文件比对公共能力时一律只允许       */
/*  包含本头，禁止直接包含                            */
/*  Memory\MemoryIntegrity.h（内部私有头）。          */
/*                                                    */
/*  架构分层（对齐 FileSystem / Process 域惯例）：    */
/*    Include\Memory\MemoryIntegrity.h   对外公共头   */
/*    Memory\MemoryIntegrity.{c,h}       实现 + 私有  */
/*                                                    */
/*  能力（对应 MITRE ATT&CK T1055 进程注入            */
/*  / T1186 Doppelganging / Ghosting 的映像完整性）： */
/*    - 专项比对：PhCompareImageWithFile              */
/*      （模块链节表驱动，可写节默认跳过防误报）      */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#ifndef _WC_INCLUDE_MEMORY_MEMORY_INTEGRITY_H_
#define _WC_INCLUDE_MEMORY_MEMORY_INTEGRITY_H_

#pragma once

#include <ntifs.h>
#include <ntddk.h>

#include "../Process/DefensiveEvasion.h"   /* PPH_DETECTOR（Config.CompareWritableSections 消费） */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 七、WKD_PROCESS 前向声明（对齐 DefensiveEvasion.h：不 typedef，避免与
 *      ProcessMonitor.h 的 PWKD_PROCESS 重复 typedef 触发 C2371）
 * ========================================================================== */
struct _WKD_PROCESS;

/* ============================================================================
 * 公共 API：专项比对
 * ========================================================================== */

/*++
 * PhCompareImageWithFile
 *   内存镜像与磁盘文件逐节比对（2026-09-13 迁自 Process\HollowingDetector，
 *   参数 WKD_PROCESS 化）：
 *     - 进程标识 / 镜像路径直接取自 WkdProcess->Core（权威副本），
 *       不再打开进程 / 不再 SeLocate 采集路径 / 不再 PEB 读取基址；
 *     - 映像基址 / 大小 / 节表取自模块链（WKD_MODULE_INSTANCE.ImageBase +
 *       WKD_MODULE.SizeOfImage + WKD_MODULE.Sections，L0 PeParser 已解析）；
 *     - 可写节（.data 等运行期合法写）按 Detector->Config.CompareWritableSections
 *       策略跳过 / 参与，防误报。
 *   调用前必须持有 WkdProcess 引用（分析期间不得释放）；无需句柄 / attach。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhCompareImageWithFile(
    _In_ PPH_DETECTOR Detector,             /* 检测器实例（Config 消费） */
    _In_ struct _WKD_PROCESS* WkdProcess,   /* WKD_PROCESS 权威副本 */
    _Out_ PBOOLEAN Match,                   /* 输出：镜像是否与文件一致 */
    _Out_opt_ PULONG MismatchOffset         /* 输出（可选）：首个不一致偏移 */
    );

#ifdef __cplusplus
}
#endif

#endif /* _WC_INCLUDE_MEMORY_MEMORY_INTEGRITY_H_ */