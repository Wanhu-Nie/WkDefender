/**************************************************/
/*                                                    */
/*  WkDefender 进程对象（WKD_PROCESS）公共查询接口    */
/*                                                    */
/*  WKD_PROCESS 完整定义位于 Process\ProcessMonitor.h */
/*  （本头仅依赖其前向声明，避免耦合 ProcessMonitor   */
/*   内部结构；包含顺序上先于 ProcessMonitor.h 亦安全）*/
/*                                                    */
/*  2026-09-13 新增：模块链公共查询接口下沉公共面， */
/*  供 HollowingDetector 等进程域消费方使用。          */
/*  本头提供的查询均为非锁版——内部自持               */
/*  ModuleContext 共享锁，调用方无需持锁。            */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#ifndef _WC_INCLUDE_PROCESS_WKDPROCESS_H_
#define _WC_INCLUDE_PROCESS_WKDPROCESS_H_

#include <ntifs.h>
#include <ntddk.h>

/* 前向声明（完整定义见 Process\ProcessMonitor.h 与
 * Process\ProcessModuleTracker.h；重复 typedef 同型，
 * C 标准允许，包含顺序先于两头部亦安全） */
typedef struct _WKD_PROCESS WKD_PROCESS, *PWKD_PROCESS;
typedef struct _WKD_MODULE_INSTANCE WKD_MODULE_INSTANCE, *PWKD_MODULE_INSTANCE;

/* ============================================================================
 * 主模块基址 / 模块实例查询（非锁版，内部自持 ModuleContext 共享锁）
 * ========================================================================== */

//
// 枚举 WkdProcess 模块链（ModuleList），返回 MainModule==TRUE 实例的映射基址。
//
// 主模块定义（2026-09-13）：进程挂载的第一个模块——
// PsModuleAttachProcessLocked 在模块链为空时挂载的实例即主模块
// （等价于进程主映像，进程创建后首个 Image 通知必然命中）。
//
// 非锁版（2026-09-13）：内部自持 ModuleContext 共享锁，调用方无需持锁；
// 允许 IRQL ≤ APC_LEVEL（EX_PUSH_LOCK 约束）。
//
// 返回值：
//   STATUS_SUCCESS     — 命中，*ImageBase 为主模块基址
//   STATUS_NOT_FOUND   — 未挂载任何模块 / 无主模块标记，*ImageBase 置 NULL
//   STATUS_INVALID_PARAMETER — 参数无效
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PsGetMainModuleImageBase(
    _In_ PWKD_PROCESS WkdProcess,
    _Out_ PVOID* ImageBase
    );

//
// 按映射基址查模块实例（非锁版，2026-09-13 新增）：
// 内部自持 ModuleContext 共享锁，再调用锁版原语
// PsLookupModuleInstanceByImageBaseLocked 遍历 ModuleList。
//
// 供无持锁上下文的调用方使用（如 HollowingDetector 各阶段函数），
// 与 PsGetMainModuleImageBase 同体系；允许 IRQL ≤ APC_LEVEL。
//
// 返回值：命中返回 WKD_MODULE_INSTANCE（MainModule 定位后取其 ImageBase
//   /Module->SizeOfImage / Module->Sections 等消费字段）；
//   WkdProcess / ImageBase 无效或未命中返回 NULL。调用方持模块引用时
//   实例生命周期受 ModuleContext 管理，返回后不要求继续持锁。
//
_IRQL_requires_max_(APC_LEVEL)
_Check_return_
_Ret_maybenull_
PWKD_MODULE_INSTANCE
PsLookupModuleInstanceByImageBase(
    _In_ PWKD_PROCESS WkdProcess,
    _In_ PVOID ImageBase
    );

#endif /* _WC_INCLUDE_PROCESS_WKDPROCESS_H_ */