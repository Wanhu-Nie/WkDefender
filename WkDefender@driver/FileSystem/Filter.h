/**************************************************/
/*  WkDefender 文件系统 Minifilter + YARA 扫描回路   */
/**************************************************/

#pragma once

#include <fltKernel.h>
#include <ntifs.h>

/*++
 * 模块职责：
 *   本模块实现 WkDefender 内核驱动的文件系统 minifilter 层，是迁移计划
 *   "步骤 2/步骤 4" 的落地载体。参考 PhantomSensor 成熟实现
 *   （ShadowStrike/PhantomSensor/PhantomSensor/Core/FilterRegistration.c 与
 *    Communication/CommPort.c），但**仅按计划范围裁剪实现**：
 *      - IRP_MJ_CREATE 的 Pre/Post：承载同步文件扫描回路 A（YARA 文件扫描）；
 *      - IRP_MJ_WRITE 的 Pre：CoW 备份（勒索回滚）+ 蜜罐 canary + 熵采样上送；
 *      - IRP_MJ_SET_INFORMATION 的 Pre：敏感文件删除/重命名保护 + 凭据硬链接
 *        阻断（T1003.003）+ 自保护 + 勒索窗口计数 + FBE 回滚 + 截断/属性监控
 *        上送（PreSetInfo 迁移 2026-08）；
 *      - IRP_MJ_CREATE_NAMED_PIPE 的 Pre：命名管道 C2/横向移动检测
 *        （NamedPipeMonitor 迁移 2026-08，阻断门控默认关）；
 *      - 其余 PhantomSensor 的回调（Cleanup/AcquireSection/USB 等）与 5 种
 *        context 注册**不照搬**，见各函数/结构处的"范围外"注释。
 *
 * 通信模型（DEC-02 = X1）：
 *   文件扫描使用**独立 FLT 通信端口**（FltCreateCommunicationPort），
 *   与现有 ALPC 主通道并存互不污染，便于调试。PreCreate 内经
 *   FltSendMessage 阻塞上送扫描请求（PASSIVE_LEVEL，MaxRetries=0、fail-open），
 *   agent 侧经 fltlib 客户端回 verdict。
 *--*/

/* 共享协议头（与 Agent YaraScanPort.h 共用，字段定义单源）。
 * 相对路径引用 Agent 项目 Common/YaraProtocol.h（两者共用同一协议结构）。 */
#include "../../WkDefender@agent/Common/YaraProtocol.h"

/* 池标签 */
#define WKD_FSF_POOL_TAG      'fSWK'  /* WkSf */
#define WKD_YARA_PORT_TAG     'pYWK'  /* WkYp */

/*++
 * FsInitialize
 *   注册 minifilter 并创建 YARA 专用 FLT 通信端口。
 *   在 WkdEntry DriverEntry 中于 NtfInitializeService 之后调用。
 *   必须在 PASSIVE_LEVEL 调用。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FsInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

/*++
 * FsCleanup
 *   卸载 minifilter、关闭通信端口、释放资源。
 *   在 WkdEntry DriverUnload 中逆序调用。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FsCleanup(
    _In_ PDRIVER_OBJECT DriverObject
    );

/*++
 * FsSendYaraScanRequest
 *   同步阻塞式文件扫描请求（回路 A 内核侧核心）。
 *   由 PreCreate 调用：构建 WKD_YARA_SCAN_REQUEST，经 FltSendMessage 阻塞发送，
 *   等待 agent 回 WKD_YARA_SCAN_VERDICT（或超时/fail-open 放行）。
 *   必须在 PASSIVE_LEVEL 调用（FltSendMessage 约束）。
 *   返回 WKD_YARA_SCAN_VERDICT（内含 Verdict 枚举 + Score 评分）。
 *   参考 PhantomSensor：CommPort.c ShadowStrikeBuildFileScanRequest +
 *        SbSendScanRequest（阻塞、MaxRetries=0、fail-open）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
WKD_YARA_SCAN_VERDICT
FsSendYaraScanRequest(
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG ProcessId
    );

/*++
 * FsIsScannableExtension
 *   判断文件扩展名是否属于可扫描类型（exe/dll/sys/... 等）。
 *   参考 PhantomSensor FilterRegistration.c ShadowStrikeIsScannable
 *   （纯 ASCII 大小写不敏感比较，DISPATCH_LEVEL 安全）。
 *   仅按计划范围收录主要可执行/脚本类型；PhantomSensor 的完整扩展名表
 *   本期未全量照搬，后期可按需扩充 g_FsScannableExtensions。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FsIsScannableExtension(
    _In_ PCUNICODE_STRING Extension
    );

/*++
 * WkdFsGetFilterHandle
 *   返回 minifilter 句柄。FileBackupEngine 等模块 FltCreateFileEx 需要非 NULL
 *   FilterHandle（Instance 可能为 NULL）。FilterHandle 运行时恒定，读无需加锁。
 *--*/
_IRQL_requires_max_(APC_LEVEL)
PFLT_FILTER
WkdFsGetFilterHandle(
    VOID
    );
