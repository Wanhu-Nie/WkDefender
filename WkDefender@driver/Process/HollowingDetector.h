/**************************************************/
/*                                                    */
/*  WkDefender 进程防御规避检测——内部私有头          */
/*                                                    */
/*  【角色】仅供 HollowingDetector.c 及其宿主          */
/*  Memory\MemoryMonitor.{c,h} 引用。进程域之外的     */
/*  内核模块访问本子系统公共 API/类型时，一律只允许   */
/*  包含 Include\Process\DefensiveEvasion.h。         */
/*                                                    */
/*  架构分层（对齐 FileSystem 域惯例）：              */
/*    Include\Process\DefensiveEvasion.h   对外公共头 */
/*    Process\HollowingDetector.h(本文件)  内部壳     */
/*    Process\HollowingDetector.c          实现      */
/*    Memory\MemoryMonitor.{c,h}           宿主编排  */
/*                                                    */
/*  【2026-09-13 迁移说明】                            */
/*  本头自 Memory/ 迁入 Process/ 进程域，其后公共导出 */
/*  （结构体/枚举/宏/函数声明）全部迁入               */
/*  Include\Process\DefensiveEvasion.h；本文件保留为  */
/*  内部兼容壳：仅 include 公共头。内部私有类型        */
/*  （PH_DETECTOR_INTERNAL 等）定义于 .c 实现文件，    */
/*  不对外暴露。                                      */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#pragma once

/* 对外公共导出（唯一入口）：
 * 类型：PH_HOLLOWING_TYPE / PH_INDICATORS / PH_ANALYSIS_RESULT /
 *       PH_DETECTOR / PH_DETECTION_CALLBACK / PH_STATISTICS
 * 常量：PH_POOL_TAG_* / PH_SCAN_TIMEOUT_MS /
 *       PH_MAX_SECTION_COMPARE_SIZE
 * 函数：PhInitialize / PhShutdown / PhAnalyzeWkdProcess /
 *       PsAnalyzeProcessHollowing / PsAnalyzeProcessHollowingAtCreation / PhQuickCheck /
 *       PhValidateEntryPoint /
 *       PhCheckForDoppelganging / PhCheckForGhosting /
 *       PhRegisterCallback / PhUnregisterCallback / PhFreeResult /
 *       PhGetStatistics
 * 注：PhCompareImageWithFile 已于 2026-09-13 迁入 Memory 域，
 *     公共声明见 Include\Memory\MemoryIntegrity.h。            */
#include "../Include/Process/DefensiveEvasion.h"