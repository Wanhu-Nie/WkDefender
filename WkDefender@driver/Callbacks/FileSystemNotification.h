/**************************************************/
/*                                                    */
/*  WkDefender 文件系统回调薄层——瘦身后导出面         */
/*                                                    */
/*  架构分层（2026-09-13 重构）：                       */
/*    Include\FileSystem.h          对外公共头         */
/*    FileSystem\FileSystem.h       内部私有头          */
/*    FileSystem\FileSystem.c       编排器             */
/*    FileSystem\*.c                分析能力模块        */
/*    Callbacks\FileSystemNotification.{c,h} 薄层      */
/*                                                    */
/*  本头只做一件事：include 对外公共头，使薄层 .c       */
/*  直接消费全部能力模块 API 与薄层导出声明             */
/*  （FsRegisterFilter/FsUnregisterFilter/             */
/*   FsSendYaraScanRequest/FsIsScannableExtension/     */
/*   FsIsCodeBearingExtension/WkdFsGetFilterHandle/     */
/*   WkdFspIsBootPhase）。                              */
/*                                                    */
/*  WKD_YARA_PORT_TAG 定义已迁往公共头，避免双处漂移。  */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#ifndef _WC_FILESYSTEM_CALLBACKS_H_
#define _WC_FILESYSTEM_CALLBACKS_H_

#include <fltkernel.h>
#include <ntddk.h>

#include "../Include/FileSystem.h"   /* 唯一对外公共头 */

#endif /* _WC_FILESYSTEM_CALLBACKS_H_ */