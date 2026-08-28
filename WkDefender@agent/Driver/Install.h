/**************************************************/
/*  WkDefender 驱动安装器 — 步骤 7 (runas 自提权)    */
/**************************************************/

/*
 * 职责：
 *   运行时安装并加载 WkDefender minifilter 驱动（管理员权限下）：
 *     - CreateServiceW(SERVICE_FILE_SYSTEM_DRIVER) 注册到 SCM；
 *     - 写 canonical "Instances" 注册表（与 INF 一致，FltMgr 读取）；
 *     - 校验 .sys 签名（WinVerifyTrust，开发期失败可降级告警）；
 *     - FilterLoad 加载 minifilter（而非 StartServiceW，minifilter 由 FltMgr 托管）。
 *   并提供 runas 自提权（ShellExecuteExW）以便普通权限启动的 agent 自动提权安装。
 *
 * 参考 PhantomSensor：
 *   src/PhantomCore/Service/ServiceInstaller.cpp（CreateServiceW/OpenSCManager 范式）
 *   迁移计划步骤 7（行 497-501、506-595）：FilterLoad 加载 + runas 自提权接管。
 *
 * 注意：本安装器写入的 Instances 注册表键须与 WkDefender@driver.inf 完全一致
 *   （ServiceName=WkDefender@driver，DefaultInstance="WkDefender Instance"，
 *    Altitude="385210"，Flags=0），否则 FltMgr 静默失效（计划风险第 6 条）。
 */

#pragma once

#include <windows.h>
#include <ntstatus.h>

/* 与计划 EnsureDriverReady 返回值约定一致：提权子进程已接管，原进程应直接退出 */
#ifndef STATUS_REBOOTED_FOR_INSTALL
#define STATUS_REBOOTED_FOR_INSTALL ((NTSTATUS)0xC0000227L)  /* STATUS_REBOOTED */
#endif

#define WKD_DRIVER_SERVICE_NAME   L"WkDefender@driver"
#define WKD_DRIVER_DISPLAY_NAME   L"WkDefender Mini-Filter Driver"
#define WKD_DRIVER_SYS_NAME       L"WkDefender@driver.sys"
#define WKD_DRIVER_INSTANCE_NAME  L"WkDefender Instance"
#define WKD_DRIVER_ALTITUDE       L"385210"

/*++
 * WkdIsElevated
 *   当前进程是否具管理员权限（IsUserAnAdmin）。
 *--*/
BOOLEAN WkdIsElevated(VOID);

/*++
 * WkdInstallAndLoadDriver
 *   完整安装并加载驱动（须管理员权限）：SCM 注册 + Instances 注册表 +
 *   签名校验 + FilterLoad。返回 STATUS_SUCCESS 表示驱动已就绪。
 *--*/
NTSTATUS WkdInstallAndLoadDriver(VOID);

/*++
 * WkdUninstallDriver
 *   FilterUnload + DeleteService + 删除 Instances 注册表。返回 STATUS_SUCCESS 表示已卸载。
 *--*/
NTSTATUS WkdUninstallDriver(VOID);

/*++
 * WkdRelaunchAsAdminForDriverInstall
 *   以 runas 提权重新启动自身并带 --install-driver 参数，同步等待其完成。
 *   返回 TRUE 表示已发起并等待结束（原进程应据 EnsureDriverReady 返回码退出）。
 *--*/
BOOLEAN WkdRelaunchAsAdminForDriverInstall(VOID);

/*++
 * EnsureDriverReady
 *   在 main() 最前调用。编排如下：
 *     - 若带 --install-driver：已是提权子进程 → 直接安装并加载 → 返回 SUCCESS
 *       （调用方应据参数识别为子进程并 exit，不重复初始化）。
 *     - 若未提权且无 --install-driver：发起 runas 提权子进程 → 返回
 *       STATUS_REBOOTED_FOR_INSTALL（调用方直接 exit）。
 *     - 若已提权（直接以管理员运行）：直接安装并加载 → 返回 SUCCESS。
 *   参数 Argc/Argv 来自 main。
 *--*/
NTSTATUS EnsureDriverReady(_In_ int Argc, _In_ char** Argv);
