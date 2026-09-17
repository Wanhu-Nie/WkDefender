/*++
    Memory/MemoryRegionVerify.h - 定时器一致性校验器（MemoryRegion 校验引擎）

    Purpose:
        周期枚举各进程当前 VAD，与事件轨 RegionList 交叉比对，构成
        "基线快照（进程创建回调 Phase 0.1）→ 事件增量（SyscallHijack 内存 case）
        → 定时一致性校验"三阶段覆盖的第三阶段（2026-09-10 实施）。

        事件轨当前依赖 SmInitialize 启用的 ETW 劫持管道（WkdEntry.c 中已注释，
        预埋状态），校验器因此承担主力"兜底"职责：
          - 盲区补录：VAD 有而 RegionList 无 → MmpAddMemoryRegionToVirtualAddressSpace
            补录 + GapRegions/GapHighRisk 统计（盲区 RWX 计可疑操作）
          - 保护漂移修正：RegionList 记录的保护与当前 VAD 不一致 →
            MmpAnalyzeProtectionChange 语义修正 + W→X/→RWX 计可疑操作
          - 已释放清理：RegionList 有而 VAD 无（释放事件轨道缺失）→ 单点
            确认 State!=MEM_COMMIT 后 MmpRemoveMemoryRegionFromVirtualAddressSpace 摘除

        调度：Common/PeriodicTimer.h Thread 模式（PASSIVE_LEVEL 回调），
        周期 WKD_MEM_VERIFY_INTERVAL_MS=30s（1000~60000 限制内）；
        每周期至多 WKD_MEM_VERIFY_MAX_PROCS=256 进程（防霸占）。

        并发安全：
          - 进程收集：锁内 PsReferenceWkdProcess（链引用 +1），持有期间
            RefCount≥3（基础+链+校验），PspDestroyProcess（RefCount 归零触发）
            不可能并发 → MemoryRegionContext 不可能在校验期间被释放
          - 区域表：RegionLock（EX_PUSH_LOCK）保护，Phase1 共享锁清 ScanHit、
            Phase2 共享锁查找 + Mmp* 独占锁补录/修正、Phase3 独占锁收集/摘除
          - ScanHit 字段仅本模块写入（单定时器无并发），事件轨/VAD 工具不读

        统计：WKD_MEM_VERIFY_STATS（MvpGetStats 读取，当前仅 DbgPrint + 计数
        上报，告警通道随事件轨/ALPC 消息通道一并接入）。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include "../Process/ProcessMonitor.h"
#include "../Memory/MemoryRegion.h"

/* ============================================================================
 * 常量
 * ============================================================================ */

#define WKD_MEM_VERIFY_INTERVAL_MS      30000   // 校验周期（毫秒，限制 1000~60000）
#define WKD_MEM_VERIFY_MAX_PROCS        256     // 每周期最多校验进程数（防霸占，满则下轮补）
#define WKD_MEM_VERIFY_MAX_CANDIDATES   256     // 单进程候选释放上限（Phase3 收集数组）
#define WKD_MEM_VERIFY_MAX_VAD_SCAN     4096    // 单进程 VAD 枚举条目硬上限（防恶意无限 VAD）

/* ============================================================================
 * 统计结构
 * ============================================================================ */

typedef struct _WKD_MEM_VERIFY_STATS {
    volatile ULONG TotalRuns;            // 定时回调运行次数
    volatile ULONG ProcessesChecked;     // 累计校验进程数
    volatile ULONG GapRegions;           // 盲区补录（VAD 有 / RegionList 无）
    volatile ULONG GapHighRisk;          // 盲区高危（初始即 RWX）
    volatile ULONG ProtectionDrifts;     // 保护漂移修正次数
    volatile ULONG DriftSuspicious;      // 漂移可疑（W→X / →RWX / 初始 RWX，susp≥60）
    volatile ULONG FreedRegions;         // 已释放区域清理（事件轨残留）
    volatile ULONG FreedHighRisk;        // 清理的残留高风险节点
} WKD_MEM_VERIFY_STATS, *PWKD_MEM_VERIFY_STATS;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化校验引擎（DriverEntry，进程表就绪后调用：PmInitialize /
// PmEnumerateProcesses / CbProcessNotifyInitialize 之后）。
// 创建 Thread 模式周期定时器并启动；失败非致命（调用方记录并继续）。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MvpInitialize(
    VOID
    );

//
// 关闭校验引擎（DriverUnload 最前执行：排空定时器回调线程，阻止新激活）。
// 幂等安全；清理后定时器结构不可再使用。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MvpShutdown(
    VOID
    );

//
// 读取校验统计（快照复制，不持有锁）
//
_IRQL_requires_max_(APC_LEVEL)
VOID
MvpGetStats(
    _Out_ PWKD_MEM_VERIFY_STATS Stats
    );