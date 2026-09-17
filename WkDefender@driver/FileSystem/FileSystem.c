/**************************************************/
/*                                                    */
/*  WkDefender 文件系统子系统——编排器                 */
/*                                                    */
/*  职责（2026-09-13 重构）：                          */
/*    统一调度 FileSystem 目录内 8 个能力模块           */
/*    （FileScan / USBDeviceControl /                  */
/*     ProcessFileContext / PostCreateContext /        */
/*     PostWrite / FileBackupEngine /           */
/*     NamedPipeMonitor / PreAcquireSection）与         */
/*    薄层（Callbacks\FileSystemNotification）的         */
/*    生命周期管理，并向子系统外部暴露统一服务          */
/*    （FsInitialize / FsCleanup / 备份回滚服务）。      */
/*                                                    */
/*  架构分层：                                         */
/*    Include\FileSystem.h          对外公共头         */
/*    FileSystem\FileSystem.h       内部私有头          */
/*    FileSystem\FileSystem.c       编排器(本文件)      */
/*    FileSystem\*.c                分析能力模块        */
/*    Callbacks\FileSystemNotification.{c,h} 薄层      */
/*                                                    */
/*  初始化顺序（经薄层 FsRegisterFilter 的              */
/*  StartFiltering 分界）：                            */
/*    FileScan → UDC → Pfcp → Poc → Pwc →             */
/*    薄层注册（minifilter+端口+StartFiltering）→       */
/*    Pas → FBE → NPM                                 */
/*                                                    */
/*  清理顺序（严格逆序）：                             */
/*    NPM → FBE → Pas → Pwc → Poc → Pfcp → Udc →      */
/*    FileScan → 薄层反注册（关端口+反注册）            */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#include <ntddk.h>
#include <fltkernel.h>

#include "FileSystem.h"   /* 内部私有头：include 公共头 + 内部结构（2026-09-13 重构） */

/**************************************************/
/*                   全局状态                      */
/**************************************************/

/* 子系统初始化位图（编排器内独享；各模块 Shutdown 自带 is-active 门控，
 * 位图仅用于失败路径的精确逆序回退与 DriverEntry 状态查询） */
#define FS_INIT_SCAN        0x00000001  /* WkdFsScanInitialize    成功 */
#define FS_INIT_UDC         0x00000002  /* WkdUdcInitialize       成功 */
#define FS_INIT_PFCP        0x00000004  /* WkdPfcpInitialize      成功 */
#define FS_INIT_POC         0x00000008  /* WkdPocInitialize       成功 */
#define FS_INIT_PWC         0x00000010  /* WkdPwcInitialize       成功 */
#define FS_INIT_FILTER      0x00000020  /* FsRegisterFilter       成功（薄层注册） */
#define FS_INIT_PAS         0x00000040  /* WkdPasInitialize       成功 */
#define FS_INIT_FBE         0x00000080  /* FbeInitialize          成功 */
#define FS_INIT_NPM         0x00000100  /* WkdNpmInitialize       成功 */

static volatile ULONG g_FsInitState = 0;

/**************************************************/
/*              FsInitialize / FsCleanup           */
/**************************************************/

/*++
 * FsInitialize
 *   文件系统子系统统一初始化（编排器入口）。
 *
 *   顺序说明（2026-09-13 重构，与薄层原 CbInitializeFileSystemNotification
 *   + WkdEntry 中 FbeInitialize/WkdNpmInitialize 三段拼接等价）：
 *     ① FileScan（蜜罐/速率/排除/进程退出回调）——与薄层无关的独立模块；
 *     ② UDC / Pfcp ——fault-tolerant 门控，当前保持注释禁用（未接入流水线）；
 *     ③ Poc / Pwc ——verdict 缓存与 post-write 检测；
 *     ④ FsRegisterFilter（薄层）：minifilter 注册 + YARA 端口 + StartFiltering；
 *     ⑤ WkdPasInitialize：StartFiltering 生效后初始化，回调经 WkdPasIsActive()
 *        门控安全跳过初始化窗口；
 *     ⑥ FbeInitialize：依赖薄层创建的 FilterHandle（FltCreateFileEx 需非 NULL）；
 *     ⑦ WkdNpmInitialize：依赖薄层注册的 IRP_MJ_CREATE_NAMED_PIPE 回调。
 *
 *   失败策略：各能力模块失败非致命（对应能力降级，不阻断驱动加载主流程）；
 *   仅薄层注册（FsRegisterFilter）失败视为子系统级失败——此时逆序回退已
 *   初始化的能力模块并返回错误，调用方（WkdEntry）不置 INIT_FS，卸载时
 *   不再触碰本子系统。
 *--*/
_Use_decl_annotations_
NTSTATUS
FsInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    ULONG initState = 0;

    g_FsInitState = 0;

    /* ① FileScan：静态/统计分析能力（蜜罐 canary/速率表/排除表/进程退出回调）。
     *    失败非致命：失去静态阻断与速率计数能力，过滤主流程仍可运行。 */
    status = WkdFsScanInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] WkdFsScanInitialize failed (non-fatal): 0x%X\n", status);
    } else {
        initState |= FS_INIT_SCAN;
    }

    /* ② USB 设备控制（只读卷写保护/autorun）：fail-safe 门控，未初始化放行。
     *    当前未接入流水线（薄层 InstanceSetup/PreCreate/PreWrite 回调对未
     *    初始化模块安全放行），保持注释禁用——与薄层原代码一致。 */
    //status = WkdUdcInitialize();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender] WkdUdcInitialize failed (non-fatal): 0x%X\n", status);
    //} else {
    //    initState |= FS_INIT_UDC;
    //}

    /* ②' 勒索行为评分（ProcessFileContext）：失败非致命（仅失去弱信号评分上报）。
     *     当前保持注释禁用——与薄层原代码一致。 */
    //status = WkdPfcpInitialize();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender] WkdPfcpInitialize failed (non-fatal): 0x%X\n", status);
    //} else {
    //    initState |= FS_INIT_PFCP;
    //}

    /* ③ PostCreate verdict 缓存模块：失败非致命
     *    （失去 verdict 缓存能力 → 退化为无缓存重扫，与迁移前行为一致） */
    status = WkdPocInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] WkdPocInitialize failed (non-fatal): 0x%X\n", status);
    } else {
        initState |= FS_INIT_POC;
    }

    /* ③' PostWrite 勒索行为检测：失败非致命
     *     （失去 post-write 行为检测/告警 → FspPostWrite 门控空转） */
    status = WkdPwcInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] WkdPwcInitialize failed (non-fatal): 0x%X\n", status);
    } else {
        initState |= FS_INIT_PWC;
    }

    /* ④ 薄层注册：minifilter + YARA 端口 + StartFiltering（子系统级关键路径）。
     *    失败 = 整个文件系统子系统不可用，逆序回退能力模块并返回错误。 */
    status = FsRegisterFilter(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] FsRegisterFilter failed: 0x%X (rolling back FileSystem)\n", status);
        goto FailRollback;
    }
    initState |= FS_INIT_FILTER;

    /* ⑤ 代码执行映射检测引擎：StartFiltering 生效后初始化，失败非致命
     *    （回调壳经 WkdPasIsActive() 状态门控安全跳过）。 */
    status = WkdPasInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] WkdPasInitialize failed (non-fatal): 0x%X\n", status);
    } else {
        initState |= FS_INIT_PAS;
    }

    /* ⑥ 勒索 CoW 备份/回滚引擎：依赖薄层 FilterHandle（FltCreateFileEx 需非 NULL）。
     *    StartFiltering 生效后回调可能先于 FbeInitialize 触发——FBE
     *    State!=2 时 FbepEnterOperation 返回 FALSE 安全跳过，无窗口期风险。
     *    初始化失败非致命（仅失去备份/回滚能力）。 */
    status = FbeInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] FbeInitialize failed (non-fatal): 0x%X\n", status);
    } else {
        initState |= FS_INIT_FBE;
    }

    /* ⑦ 命名管道监控：依赖薄层注册的 IRP_MJ_CREATE_NAMED_PIPE 回调。
     *    WkdNpmIsActive() 状态门控覆盖初始化窗口（回调先于 Initialize
     *    触发时安全跳过，对齐 FBE State 门控）。阻断默认关（Audit）。
     *    初始化失败非致命（仅失去命名管道 C2/冒充检测能力）。 */
    status = WkdNpmInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] WkdNpmInitialize failed (non-fatal): 0x%X\n", status);
    } else {
        initState |= FS_INIT_NPM;
    }

    g_FsInitState = initState;
    return STATUS_SUCCESS;

FailRollback:
    /* 逆序回退已成功初始化的能力模块（未含 NPM/FBE/Pas——未走到；未含
     * 薄层注册——注册本身失败，FltUnregisterFilter 由薄层内部 Cleanup 处理） */
    if (initState & FS_INIT_PWC)  WkdPwcShutdown();
    if (initState & FS_INIT_POC)  WkdPocShutdown();
    if (initState & FS_INIT_SCAN) WkdFsScanCleanup();
    g_FsInitState = 0;
    return status;
}

/*++
 * FsCleanup
 *   文件系统子系统统一卸载（编排器入口），严格逆序：
 *     NPM → FBE → Pas → Pwc → Poc → Pfcp → Udc → FileScan → 薄层反注册。
 *   各模块清理自带 is-active/is-initialized 门控（Shutdown 幂等），
 *   位图仅用于失败路径的精确回退，此处按全量逆序调用即可。
 *--*/
_Use_decl_annotations_
VOID
FsCleanup(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    /* 命名管道监控清理（先于 Pas/薄层反注册，回调仍引用其状态） */
    if (g_FsInitState & FS_INIT_NPM) {
        WkdNpmShutdown();
    }

    /* 勒索 CoW 备份/回滚引擎清理（先于薄层反注册，回调仍引用 FBE 状态） */
    if (g_FsInitState & FS_INIT_FBE) {
        FbeShutdown();
    }

    /* 代码执行映射检测引擎逆序清理（先于回调反注册，状态门控已置位） */
    if (g_FsInitState & FS_INIT_PAS) {
        WkdPasShutdown();
    }

    /* PostWrite 行为检测清理：反注册进程退出回调 + 清空 64 槽活动表 */
    if (g_FsInitState & FS_INIT_PWC) {
        WkdPwcShutdown();
    }

    /* PostCreate verdict 缓存清理 */
    if (g_FsInitState & FS_INIT_POC) {
        WkdPocShutdown();
    }

    /* 勒索行为评分（ProcessFileContext）清理（定时器/槽表） */
    if (g_FsInitState & FS_INIT_PFCP) {
        WkdPfcpShutdown();
    }

    /* USB 设备控制清理 */
    if (g_FsInitState & FS_INIT_UDC) {
        WkdUdcShutdown();
    }

    /* 静态分析能力模块清理：移除进程退出回调 + 释放蜜罐 canary + 重置活动表 */
    if (g_FsInitState & FS_INIT_SCAN) {
        WkdFsScanCleanup();
    }

    /* 薄层反注册：关闭 YARA 端口 + FltUnregisterFilter（最后执行） */
    if (g_FsInitState & FS_INIT_FILTER) {
        FsUnregisterFilter(DriverObject);
    }

    g_FsInitState = 0;
}

/**************************************************/
/*            备份服务（FBE 统一封装面）             */
/**************************************************/

/*++
 * FsBackupRollbackProcess
 *   按进程回滚勒索 CoW 备份（封装 FbeRollbackProcess）。
 *   供 ALPC SERVICE_ROLLBACK 调用。
 *--*/
_Use_decl_annotations_
FBE_ROLLBACK_RESULT
FsBackupRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    )
{
    return FbeRollbackProcess(ProcessId, FilesRestored);
}

/*++
 * FsBackupCommitProcess
 *   进程正常退出时丢弃其全部备份（封装 FbeCommitProcess）。
 *   由进程退出回调（ProcessNotification）调用。
 *--*/
_Use_decl_annotations_
VOID
FsBackupCommitProcess(
    _In_ HANDLE ProcessId
    )
{
    FbeCommitProcess(ProcessId);
}

/**************************************************/
/*                   文件尾                         */
/**************************************************/

/* ============================================================================
 * 敏感系统文件保护（2026-10 自 FileScan.c 迁入）
 *   原实现位于 FileSystem\FileScan.c，随 PreSetInformation 流水线提取一并
 *   调整归属：判定函数 WkdFsIsSensitiveSystemFile 与判定表 g_FsSensitivePaths
 *   迁入本协调文件（薄层/PreSetInformation 经公共头调用）；
 *   FspIsHardlinkSensitivePath / FspIsVolumeShadowCopyPath 则迁往
 *   FileSystem\PreSetInformation.c（本文件不再涉及）。
 *   表类型 WKD_FS_SENSITIVE_PATH 为文件内私有（无需入公共头）。
 * ========================================================================== */
typedef struct _WKD_FS_SENSITIVE_PATH {
    PCWSTR  Pattern;
    UCHAR   MatchMode;              /* 0=suffix, 1=contains */
    BOOLEAN BlockDelete;
    BOOLEAN BlockRename;
    BOOLEAN BlockHardLink;
} WKD_FS_SENSITIVE_PATH, *PWKD_FS_SENSITIVE_PATH;

static const WKD_FS_SENSITIVE_PATH g_FsSensitivePaths[] = {
    /* 注册表 hive - 后缀匹配 */
    { L"\\Windows\\System32\\config\\SAM",       0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SECURITY",  0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SYSTEM",    0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SOFTWARE",  0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\DEFAULT",   0, TRUE, TRUE, TRUE },

    /* 关键系统可执行 - 后缀匹配 */
    { L"\\Windows\\System32\\lsass.exe",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\csrss.exe",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\smss.exe",          0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\wininit.exe",       0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\winlogon.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\services.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\ntoskrnl.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\hal.dll",           0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\ntdll.dll",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\kernel32.dll",      0, TRUE, TRUE, FALSE },

    /* 驱动目录 - 包含匹配（block \drivers\ 下任意文件） */
    { L"\\Windows\\System32\\drivers\\",         1, TRUE, TRUE, FALSE },

    /* 引导文件 - 包含匹配 */
    { L"\\Windows\\Boot\\",                      1, TRUE, TRUE, FALSE },
    { L"\\EFI\\Microsoft\\Boot\\",               1, TRUE, TRUE, FALSE },

    /* 引导管理器 - 后缀匹配 */
    { L"\\bootmgr",                              0, TRUE, TRUE, FALSE },
    { L"\\BOOTMGR",                              0, TRUE, TRUE, FALSE },

    /* NTFS 元数据文件 - 后缀匹配 */
    { L"\\$MFT",                                 0, TRUE, TRUE, FALSE },
    { L"\\$MFTMirr",                             0, TRUE, TRUE, FALSE },
    { L"\\$LogFile",                             0, TRUE, TRUE, FALSE },
    { L"\\$Volume",                              0, TRUE, TRUE, FALSE },
    { L"\\$AttrDef",                             0, TRUE, TRUE, FALSE },
    { L"\\$Bitmap",                              0, TRUE, TRUE, FALSE },
    { L"\\$Boot",                                0, TRUE, TRUE, FALSE },
    { L"\\$BadClus",                             0, TRUE, TRUE, FALSE },
    { L"\\$Secure",                              0, TRUE, TRUE, FALSE },
    { L"\\$UpCase",                              0, TRUE, TRUE, FALSE },
    { L"\\$Extend",                              0, TRUE, TRUE, FALSE },

    { NULL, 0, FALSE, FALSE, FALSE }             /* sentinel */
};

/*++
 * WkdFsIsSensitiveSystemFile
 *   敏感系统文件判定（PreSetInfo.c g_SensitivePaths +
 *   PsipIsSensitiveSystemFile）。
 *   MatchMode：0=后缀精确匹配（边界校验）、1=包含匹配（路径分隔符边界校验）。
 *   normalized 路径以 \Device\HarddiskVolumeN\ 开头，目录类必须用包含匹配
 *   而非前缀匹配（SS 修复过该缺陷）。
 *   命中后按操作类型取 Block 位：Disposition→BlockDelete、Rename→BlockRename、
 *   Link→BlockHardLink（wkd 文件事件无 Link 类型，硬链接分支走
 *   FspIsHardlinkSensitivePath，PreSetInformation 模块）。
 *   仅命中时写回输出参数；未命中保持 *BlockXXX=FALSE。
 *--*/
_Use_decl_annotations_
BOOLEAN
WkdFsIsSensitiveSystemFile(
    PCUNICODE_STRING FileName,
    PBOOLEAN BlockDelete,
    PBOOLEAN BlockRename,
    PBOOLEAN BlockHardLink
    )
{
    ULONG i;
    UNICODE_STRING pattern;
    USHORT patternChars;
    USHORT fileChars;
    PWCHAR fileStart;
    LONG compareResult;

    if (BlockDelete) *BlockDelete = FALSE;
    if (BlockRename) *BlockRename = FALSE;
    if (BlockHardLink) *BlockHardLink = FALSE;

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {
        return FALSE;
    }

    fileChars = FileName->Length / sizeof(WCHAR);

    for (i = 0; g_FsSensitivePaths[i].Pattern != NULL; i++) {
        RtlInitUnicodeString(&pattern, g_FsSensitivePaths[i].Pattern);
        patternChars = pattern.Length / sizeof(WCHAR);

        if (patternChars > fileChars) {
            continue;
        }

        if (g_FsSensitivePaths[i].MatchMode == 1) {
            /* 包含匹配：仅在路径分隔符边界滑动窗口比较，防 C:\notWindows\ 误报 */
            USHORT maxOffset = fileChars - patternChars;
            USHORT offset;
            BOOLEAN found = FALSE;

            for (offset = 0; offset <= maxOffset; offset++) {
                if (offset > 0 && FileName->Buffer[offset - 1] != L'\\' &&
                    FileName->Buffer[offset - 1] != L':') {
                    continue;
                }

                UNICODE_STRING candidate;
                candidate.Buffer = FileName->Buffer + offset;
                candidate.Length = pattern.Length;
                candidate.MaximumLength = pattern.Length;

                if (RtlCompareUnicodeString(&candidate, &pattern, TRUE) == 0) {
                    found = TRUE;
                    break;
                }
            }

            if (found) {
                if (BlockDelete) *BlockDelete = g_FsSensitivePaths[i].BlockDelete;
                if (BlockRename) *BlockRename = g_FsSensitivePaths[i].BlockRename;
                if (BlockHardLink) *BlockHardLink = g_FsSensitivePaths[i].BlockHardLink;
                return TRUE;
            }
        } else {
            /* 后缀匹配 + 边界校验：模式以 '\' 开头则前导反斜杠即边界，否则前一字符须为 '\' 或 ':' */
            fileStart = FileName->Buffer + (fileChars - patternChars);

            UNICODE_STRING fileSuffix;
            fileSuffix.Buffer = fileStart;
            fileSuffix.Length = pattern.Length;
            fileSuffix.MaximumLength = pattern.Length;

            compareResult = RtlCompareUnicodeString(&fileSuffix, &pattern, TRUE);
            if (compareResult == 0) {
                BOOLEAN isBoundary = FALSE;

                if (fileStart == FileName->Buffer) {
                    isBoundary = TRUE;
                } else if (pattern.Buffer[0] == L'\\') {
                    isBoundary = TRUE;
                } else if (*(fileStart - 1) == L'\\' || *(fileStart - 1) == L':') {
                    isBoundary = TRUE;
                }

                if (isBoundary) {
                    if (BlockDelete) *BlockDelete = g_FsSensitivePaths[i].BlockDelete;
                    if (BlockRename) *BlockRename = g_FsSensitivePaths[i].BlockRename;
                    if (BlockHardLink) *BlockHardLink = g_FsSensitivePaths[i].BlockHardLink;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}