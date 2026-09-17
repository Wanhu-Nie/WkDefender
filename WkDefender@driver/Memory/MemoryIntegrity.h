/**************************************************/
/*                                                    */
/*  WkDefender 内存完整性——内部私有头               */
/*                                                    */
/*  【角色】仅供 MemoryIntegrity.c 实现与跨模块       */
/*  比对服务消费方（Process\HollowingDetector.c）     */
/*  引用。Memory 域之外的模块如需公共比对能力，        */
/*  一律只允许包含 Include\Memory\MemoryIntegrity.h。 */
/*                                                    */
/*  架构分层（对齐 FileSystem / Process 域惯例）：    */
/*    Include\Memory\MemoryIntegrity.h     对外公共头 */
/*    Memory\MemoryIntegrity.h（本文件）   内部私有头 */
/*    Memory\MemoryIntegrity.c             实现      */
/*                                                    */
/*  命名约定：Mi 前缀 = Memory Integrity 域；          */
/*  内部辅助一律 static，供 HollowingDetector          */
/*  跨模块消费的三个函数为本头声明。                   */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

#include "../Process/ProcessModuleTracker.h"   /* PWKD_MODULE_INSTANCE / WKD_MODULE_SECTION / WKD_MT_PE_SECTION_MASK_BITS */
#include "../Include/Process/DefensiveEvasion.h" /* PH_POOL_TAG_BUFFER / PH_MAX_SECTION_COMPARE_SIZE（公共常量复用） */

//
// 私有常量（2026-09-13 迁自 HollowingDetector 并更名）：
//   MI_HASH_CONCAT_LIMIT ← 原 PH_HASH_CONCAT_LIMIT（拼接哈希缓冲上限）；
//   MI_MIN_IMAGE_SIZE    ← 兼容路径最小映像比对长度（HollowingDetector
//     映像比对/入口点分析已迁模块链为主模块事实源，其原 PH_MIN_IMAGE_SIZE /
//     attach 探测路径已删除，2026-09-13；此处为内存域独立常量）；
//   单节上限复用公共 PH_MAX_SECTION_COMPARE_SIZE（64KB，DefensiveEvasion.h）。
//
#define MI_HASH_CONCAT_LIMIT            (128 * 1024)  /* 拼接哈希缓冲上限（节表驱动比对，2026-09-13） */
#define MI_MIN_IMAGE_SIZE               512           /* 兼容路径最小映像比对长度 */

C_ASSERT(PH_MAX_SECTION_COMPARE_SIZE <= (SIZE_T)MAXULONG);  /* L-2：ZwReadFile 的 ULONG 强转安全性 */

//
// 跨进程内存读取（MmCopyVirtualMemory 封装；pfnMmCopyVirtualMemory 由
// ExportParser 动态解析，见 Common\ExportParser.{c,h}）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MiReadProcessMemory(
    _In_ PEPROCESS Process,                         /* 目标进程 EPROCESS */
    _In_ PVOID BaseAddress,                         /* 源地址（进程虚拟地址） */
    _Out_writes_bytes_(Size) PVOID Buffer,          /* 目标缓冲区 */
    _In_ SIZE_T Size,                               /* 读取字节数 */
    _Out_opt_ PSIZE_T BytesRead                     /* 输出（可选）：实际读取字节数 */
    );

//
// 内存镜像与磁盘文件比对（节表驱动；无节表时降级全窗口兼容路径）
// 供 HollowingDetector（PhpAnalyzeImageComparison 探测路径 / PhAnalyzeWkdProcess
// 主路径）与 PhCompareImageWithFile 共用。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MiCompareMemoryWithFile(
    _In_ PEPROCESS Process,
    _In_ PVOID MemoryBase,
    _In_ SIZE_T MemorySize,
    _In_opt_ PWKD_MODULE_SECTION Sections,
    _In_ ULONG SectionCount,
    _In_ BOOLEAN CompareWritableSections,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset,
    _Out_opt_ PULONG ComparedSectionCount,
    _Out_opt_ PULONG SkippedSectionCount,
    _Out_opt_ PUCHAR MemoryHash,
    _Out_opt_ PUCHAR FileHash
    );

//
// 主模块定位：从 WKD_PROCESS 模块链查找主模块视图（2026-09-13 迁自
// HollowingDetector。优先按权威副本镜像路径匹配，fallback 到首个
// Exe 类型实例；持 ModuleContext 共享锁遍历，进程引用期内返回实例有效）
//
_IRQL_requires_max_(APC_LEVEL)
PWKD_MODULE_INSTANCE
MiLookupMainModule(
    _In_ PWKD_PROCESS WkdProcess,
    _In_opt_ PUNICODE_STRING ImagePath
    );