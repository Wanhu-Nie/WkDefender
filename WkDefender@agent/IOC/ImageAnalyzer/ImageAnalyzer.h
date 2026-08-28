/**************************************************/
/*  WkDefender Agent — 统一镜像分析流水线 (门面)     */
/*                                                  */
/*  2026-08-15 新建。以 WKD_MODULE 为文件级静态分析  */
/*  结果权威副本，收敛三条镜像分析路径（消除重复     */
/*  解析，对齐驱动"全局不可变对象"模型）：            */
/*    ProcessCreate  → 建模块+分析（进程空壳，       */
/*                      exe 映射未发生，只读磁盘）   */
/*    ImageLoad      → PsHandleImageLoad 挂视图后分析    */
/*    ScanFileDirect → 按需文件扫描（PE 走模块表）   */
/*                                                  */
/*  三级分级（漏斗）：                              */
/*    Tier1 命中+实例化 — 模块三态                  */
/*      (DONE O(1) 复用 / IN_PROGRESS 等待 /        */
/*       NONE CAS 抢占)；非 PE 走独立分支不建模块    */
/*    Tier2 轻量快判   — 文件类型/欺骗/哈希 IOC 查询 */
/*      /豁免融合，零读全文件                       */
/*    Tier3 深度分析   — 六件套全量                  */
/*      (CertVerify/Lolbin/PeHeaders/Heuristic/     */
/*       Aggregate/Reputation)，每唯一镜像一次       */
/*                                                  */
/*  并发契约：AnalysisState 三态 + CompleteEvent     */
/*  （见 ProcessModule.h WKD_MODULE_ANALYSIS_*）。   */
/*  当前 Tier3 同步执行（沿用 ScanFileDirect 语义）， */
/*  状态机为未来异步化预留。                         */
/*                                                  */
/*  PEAnalyzer / Signature 保持独立能力域（被        */
/*  Exempts/MemoryScan/文档扫描等多处复用），本层     */
/*  仅编排不复制实现。                               */
/**************************************************/

#pragma once

#include "../IocTypes.h"

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    统一镜像文件分析入口。对 ImagePath 指向的文件执行
    三级分级流水线，输出文件级静态 IOC_SCAN_RESULT。

    调用语义：
      - ProcessCreate : ImageAnalyzer(exePath, cmdline, &r)
           进程空壳无映射，只读磁盘分析 exe；建模块（ImageSize
           未知传 0，宽松 Identity）；Cmdline 信号单独合并进 r
           （进程级，不写模块 FileResult）。
      - ImageLoad     : ImageAnalyzer(path, NULL, &r)
           PsHandleImageLoad 已挂视图，本调用命中模块 Done 则 O(1)。
      - ScanFileDirect: ImageAnalyzer(path, NULL, &r)
           无进程上下文；PE 文件也走模块表（全局镜像对象与
           进程无关，可作文件级权威副本）。

Arguments:
    ImagePath - 文件完整路径。
    Cmdline   - 可选进程命令行（仅 ProcessCreate 传；进程级
                信号，只合并进输出 Result，不写 FileResult）。
    Result    - 输出文件级静态分析结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocAnalyseImage(
    _In_ PCWSTR ImagePath,
    _In_opt_ PCWSTR CommandLine,
    _Out_ PIOC_SCAN_RESULT Result
    );

/* 异步 PE 深度分析工作线程生命周期（main.c 接线）：
 * 2026-08-18 阶段5。Initialize 启动单工作线程；Shutdown 停线程并
 * 释放未处理队列 pin。 */
NTSTATUS
IaAsyncInitialize(
    VOID
    );

VOID
IaAsyncShutdown(
    VOID
    );
