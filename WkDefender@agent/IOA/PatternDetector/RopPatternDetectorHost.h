/**************************************************/
/*  WkDefender IOA — ROP 模式检测器宿主接线        */
/*                                                  */
/*  迁移自 ShadowStrike RopWiring                   */
/*  (RopWiring.cpp/.hpp)                            */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  SS RopWiring 是 ROPProtection 的服务层隔离垫片:  */
/*    InitROPProtection     => 单例 → Initialize →  */
/*                             Start                */
/*    ShutdownROPProtection => HasInstance 守卫 →   */
/*                             IsInitialized 守卫 → */
/*                             Shutdown             */
/*                                                  */
/*  本模块对齐上述生命周期边界, 以 RPD 模块 API     */
/*  (RopPatternDetector.h) 为唯一操作面:             */
/*    RpdHostInitialize     => RpdInitialize → 启动  */
/*                             就绪断言              */
/*    RpdHostShutdown       => RpdIsInitialized 守卫 */
/*                             → RpdShutdown         */
/*                                                  */
/*  与 SS 的对齐/裁剪 (注释就地标注):                */
/*    - 去 Instance/HasInstance (C 静态全局天然存在) */
/*    - 去 Utils::Logger 日志 (WkDefender 无          */
/*      log_manager, 失败语义靠返回值表达)           */
/*    - 去 kernel IPC 接线 (SS RegisterGenericHandler */
/*      订阅 FilterMessageType_MemoryAlert;          */
/*      WkDefender 无内核 IPC 通道, 内核告警由调用方 */
/*      转发到 RpdProcessKernelMemoryAlert)          */
/*    - C++ try/catch + noexcept → C 无异常语义,      */
/*      fail-safe 由返回值保证                       */
/*    - SS 隔离动机 (ROPProtection.hpp 的            */
/*      DetectionConfidence ODR 守卫跨头冲突)        */
/*      → C 无 ODR 问题, 本头仅依赖 DefendTypes      */
/*                                                  */
/*  接入状态: 独立模块 (死代码), 未挂接服务流水线。  */
/**************************************************/

#pragma once

#include "../../DefendTypes.h"

/**************************************************/
/*               宿主接线                           */
/**************************************************/

/*
 * RpdHostInitialize — 初始化并启动 ROP 模式检测器
 * (InitROPProtection):
 *  - 未初始化时以默认配置调用 RpdInitialize, 失败返回 FALSE
 *  - Start() 语义做启动就绪断言: 状态须为 Running,
 *    否则 fail-closed 返回 FALSE
 *  - 永不抛异常/永不崩溃; 失败仅以返回值表达
 */
BOOLEAN
RpdHostInitialize(VOID);

/*
 * RpdHostShutdown — 关闭 ROP 模式检测器
 * (ShutdownROPProtection):
 *  - 仅当模块已初始化时关闭; 未初始化直接返回
 *  - 绝不"为关闭而初始化"(对应 SS 绝不创建单例仅为关闭)
 */
VOID
RpdHostShutdown(VOID);