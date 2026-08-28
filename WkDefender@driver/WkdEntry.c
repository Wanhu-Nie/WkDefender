//#include "Common/Utils.h"
//#include "Common/HashSet.h"
//#include "Notification/MessageSync.h"
//#include "Notification/NotificationManager.h"
//#include "Process/ProcessMonitor.h"
//#include "Callbacks/ProcessNotify.h"

//#include "Callbacks/ObjectNotify.h"
//#include "Callbacks/ImageNotify.h"   /* 步骤3：镜像加载回调（独立模块，DEC-05） */
//#include "Object/ObjectManager.h"
//#include "Memory/MemorySignature.h"
//#include "Memory/AmsiBypassDetector.h"
//#include "Syscall/SyscallMonitor.h"
//#include "AnalysisEngine/AnalysisEngine.h"
//#include "AnalysisEngine/IocAppControl.h"
//#include "ThreatScoring/ThreatScoring.h"
//#include "Common/Exempts/Exempts.h"
//#include "Process/ProcessPairContext.h"
//#include "FileSystem/Filter.h"   /* 步骤2：minifilter + YARA FLT 端口（DEC-02=X1） */
//#include "FileSystem/FileBackupEngine.h"   /* FBE：勒索 CoW 备份/回滚（2026-08 迁移） */
//#include "FileSystem/NamedPipeMonitor.h"   /* 命名管道 C2/横向移动检测（2026-08 迁移） */
#include <ntifs.h>

/* ==================================================================
 * [能力开放阶段-1] 2026-08-10：基础框架验证通过后开放的核心监控能力
 * 已开放：Utils / MessageSync / ProcessPairContext / NotificationManager
 *        / AnalysisEngine / ThreatScoring / Exempts / ProcessMonitor
 *        / ProcessNotify / ImageNotify
 * 未开放：ThreadNotify / ObjectNotify / Fs(minifilter) / FBE / NPM
 *        / Ms(MemorySignature) / ABD / AC(AppControl) / Sm(Syscall ETW)
 * ================================================================== */
#include "Common/Utils.h"
#include "Notification/MessageSync.h"
#include "Process/ProcessPairContext.h"
#include "Notification/NotificationManager.h"
#include "Notification/AlpcService.h"
#include "AnalysisEngine/AnalysisEngine.h"
#include "ThreatScoring/ThreatScoring.h"
#include "Common/Exempts/Exempts.h"
#include "Process/ProcessMonitor.h"
#include "Callbacks/ProcessNotify.h"
#include "Callbacks/ImageNotify.h"
#include "Callbacks/ThreadNotify.h"

/* 子系统初始化标记 — 用于 DriverEntry 统一回退清理 */
#define INIT_NTF        0x00000001  /* NtfInitializeService */
#define INIT_AE         0x00000002  /* AeInitialize */
#define INIT_TS         0x00000004  /* TsInitialize */
#define INIT_EXEMPT     0x00000008  /* CoInitializeExempts */
#define INIT_FS         0x00000010  /* FsInitialize */
#define INIT_PM         0x00000020  /* PmInitialize */
#define INIT_CB_PROCESS 0x00000040  /* CbProcessNotifyInitialize */
#define INIT_CB_THREAD  0x00000080  /* CbThreadNotifyInitialize */
#define INIT_CB_OBJECT  0x00000100  /* CbObjectNotifyInitialize */
#define INIT_CB_IMAGE   0x00000200  /* CbInitializeImageNotify */
#define INIT_MS         0x00000400  /* MsInitialize */
#define INIT_SCM        0x00000800  /* SmInitialize */
#define INIT_ABD        0x00001000  /* AbdInitialize */
#define INIT_AC         0x00002000  /* IocAppControlInitialize */
#define INIT_FBE        0x00004000  /* FbeInitialize（勒索备份/回滚引擎） */
#define INIT_NPM        0x00008000  /* WkdNpmInitialize（命名管道 C2/冒充检测） */
#define INIT_MT         0x00010000  /* MtInitialize（全局镜像对象表） */

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] Driver unload ...\n");

    /* 按初始化的逆序清理 */
    //TsShutdown(WkdTsEngine);
    //WkdSyncCancelAll(&g_SyncMgr);
    //AeCleanup();
    //IocAppControlShutdown();
    //ScmCleanup();
    //MsCleanup();
    //AbdCleanup();
    //CbObjectNotifyCleanup();
    //CbThreadNotifyCleanup();
    //CbProcessNotifyCleanup();
    //PmCleanup();
    //NmCleanup();
    //ImgNotifyCleanup();         /* 步骤3：镜像加载回调逆序清理 */
    //WkdNpmShutdown();           /* NamedPipeMonitor：命名管道检测逆序清理（先于 FsCleanup，回调仍引用状态） */
    //FbeShutdown();              /* FBE：勒索备份/回滚引擎逆序清理（先于 FsCleanup，
    //                                回调仍引用 FBE 状态） */
    //FsCleanup(DriverObject);   /* 步骤2：minifilter + YARA FLT 端口逆序清理 */

    /* 清理 ALPC 通信服务（先停，杜绝卸载窗口的规则推送竞态） */
    AlpcCleanupService();

    /* 清理全局镜像对象表（先于进程清理；残留视图引用时内部跳过 free 防 bugcheck） */
    MtCleanup();

    /* 清理排除子系统（在 TsShutdown 之前、PmCleanup 之后） */
    ExemptsCleanup();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] Driver unloaded successfully.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
    NTSTATUS status;
    ULONG initFlags = 0;

    UNREFERENCED_PARAMETER(RegPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] Driver loading ...\n");
    DriverObject->DriverUnload = DriverUnload;

    /* 初始化全局 DriverObject 用于模块遍历 */
    UtSetDriverObject(DriverObject);

    /* 0. 初始化同步消息基础设施 */
    WkdSyncInitialize(&g_SyncMgr);

    /* 0.1 初始化进程对位图表 */
    WkdPairTableInitialize();

    /* 1. 通知管理器（最先初始化，其他模块依赖消息系统）
     *    注册 ALPC 转发回调（B1 修复），异步消息不再被丢弃 */
     status = NtfInitializeServiceWithCallback();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] NtfInitializeService failed: 0x%X\n", status);
        goto Cleanup;
    }
    initFlags |= INIT_NTF;

    /* 2. 分析引擎（IocEngine + IoaEngine） */
    status = AeInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] AeInitialize failed: 0x%X\n", status);
        goto Cleanup;
    }
    initFlags |= INIT_AE;

    /* 2.1 AppControl 执行策略引擎（AnalysisEngine 家族判定分区）
     *     默认 Audit 模式 + 门控关闭（IocAcEnabled()=FALSE，零行为变化）；
     *     规则表就绪，判定激活待 Agent 策略 / 规则推送通道。 */
    //status = IocAppControlInitialize();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
    //        "[WkDefender] IocAppControlInitialize failed: 0x%08X\n", status);
    //    goto Cleanup;
    //}
    //initFlags |= INIT_AC;

    /* 3. 威胁评分引擎 */
    status = TsInitialize(&WkdTsEngine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] TsInitialize failed: 0x%X\n", status);
        goto Cleanup;
    }
    initFlags |= INIT_TS;

    /* 2.1 排除子系统（在 PmInitialize 之前，进程创建回调需要 CoEvaluateProcessExemption）
     * 2026-08-10 恢复：Common\Exempts 重新引入并验证加载正常。 */
    status = CoInitializeExempts();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] CoInitializeExempts failed (non-fatal): 0x%X\n", status);
        /* 非致命：排除子系统不可用时所有进程走正常流程 */
    } else {
        initFlags |= INIT_EXEMPT;
    }

    /* 1.1 文件系统 minifilter + YARA 专用 FLT 端口（步骤2，DEC-02=X1）
     *     与 ALPC 主通道并存互不污染。失败不阻断加载（minifilter 非核心路径，
     *     文件扫描 fail-open，不影响其他检测能力）。 */
    //status = FsInitialize(DriverObject);
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender] FsInitialize failed (non-fatal): 0x%X\n", status);
    //} else {
    //    initFlags |= INIT_FS;

    //    /* 1.1.1 勒索 CoW 备份/回滚引擎（FBE 迁移 2026-08）。
    //     *     依赖 FsInitialize 创建的 FilterHandle（FltCreateFileEx 需非 NULL）。
    //     *     StartFiltering 生效后回调可能先于 FbeInitialize 触发——FBE
    //     *     State!=2 时 FbepEnterOperation 返回 FALSE 安全跳过，无窗口期风险。
    //     *     初始化失败非致命（仅失去备份/回滚能力）。 */
    //    status = FbeInitialize();
    //    if (!NT_SUCCESS(status)) {
    //        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //            "[WkDefender] FbeInitialize failed (non-fatal): 0x%X\n", status);
    //    } else {
    //        initFlags |= INIT_FBE;
    //    }

    //    /* 1.1.2 命名管道监控（NamedPipeMonitor 迁移 2026-08）。
    //     *     依赖 FsInitialize 注册的 IRP_MJ_CREATE_NAMED_PIPE 回调。
    //     *     WkdNpmIsActive() 状态门控覆盖初始化窗口（回调先于 Initialize
    //     *     触发时安全跳过，对齐 FBE State 门控）。阻断默认关（Audit）。
    //     *     初始化失败非致命（仅失去命名管道 C2/冒充检测能力）。 */
    //    status = WkdNpmInitialize();
    //    if (!NT_SUCCESS(status)) {
    //        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //            "[WkDefender] WkdNpmInitialize failed (non-fatal): 0x%X\n", status);
    //    } else {
    //        initFlags |= INIT_NPM;
    //    }
    //}

    /* 2. 进程监控器（进程追踪基础设施） */
    status = PmInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] PmInitialize failed: 0x%X\n", status);
        goto Cleanup;
    }
    initFlags |= INIT_PM;

    /* 3. 进程/线程回调注册 */
    status = CbProcessNotifyInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbProcessNotifyInitialize failed: 0x%X\n", status);
        goto Cleanup;
    }
    initFlags |= INIT_CB_PROCESS;

    /* 3.1 枚举已有进程填充全局进程表（回调已注册，并发创建不丢失） */
    status = PmEnumerateProcesses();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] PmEnumerateProcesses failed (non-fatal): 0x%X\n", status);
    }

    /* 3.1.1 全局镜像对象表（2026-08-11：须在 CbInitializeImageNotify 之前；
     *        PsFindOrCreateModule 依赖表，失败则禁用镜像监控，避免撞未初始化表） */
    status = MtInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] MtInitialize failed (image monitor disabled): 0x%X\n", status);
    } else {
        initFlags |= INIT_MT;

        /* 3.2 镜像加载回调（独立模块，DEC-05）：经 ALPC 异步上送 ImageLoad 给 agent
         *     触发机制 B 内存 YARA。非致命，失败仅失去镜像加载可见性。
         */
        status = CbInitializeImageNotify();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] CbInitializeImageNotify failed (non-fatal): 0x%X\n", status);
        } else {
            initFlags |= INIT_CB_IMAGE;
        }
    }

    /* 
     * 3.2 线程回调注册（独立于 CbProcessNotifyInitialize，检测跨进程线程创建/DLL注入） 
     * 其注册时机晚于3.1，确保当前所有进程均被记录
     */
    status = CbThreadNotifyInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] CbThreadNotifyInitialize failed (non-fatal): 0x%X\n", status);
        /* 非致命，继续运行但失去线程监控能力 */
    } else {
        initFlags |= INIT_CB_THREAD;
    }

    /* 4. Ob 回调（PreOperation 仅监控，非致命失败继续） */
    //status = CbObjectNotifyInitialize();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender] CbObjectNotifyInitialize failed (non-fatal): 0x%X\n", status);
    //    /* 非致命，继续运行但失去对象回调监控能力 */
    //} else {
    //    initFlags |= INIT_CB_OBJECT;
    //}

    /* 5. 内存签名扫描器（SyscallHijack 依赖） */
    //status = MsInitialize();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
    //        "[WkDefender] MsInitialize failed: 0x%X\n", status);
    //    goto Cleanup;
    //}
    //initFlags |= INIT_MS;

    /* 5.1 AMSI 绕过检测器（T1562.001）
     *     自注册镜像回调追踪 amsi.dll + 30s worker 周期扫描。
     *     非致命：失败仅失去 AMSI 绕过检测能力。 */
    //status = AbdInitialize();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender] AbdInitialize failed: 0x%X\n", status);
    //} else {
    //    initFlags |= INIT_ABD;
    //}

    /* 6. Syscall ETW 监控 */
    //status = SmInitialize();
    //if (!NT_SUCCESS(status)) {
    //   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
    //       "[WkDefender] SmInitialize failed: 0x%X\n", status);
    //   goto Cleanup;
    //}
    //initFlags |= INIT_SCM;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] All subsystems initialized successfully.\n");
    return STATUS_SUCCESS;

Cleanup:
    /* 逆序清理已成功初始化的子系统 */
    //if (initFlags & INIT_MS)       MsCleanup();
    //if (initFlags & INIT_ABD)      AbdCleanup();
    //if (initFlags & INIT_CB_OBJECT) CbObjectNotifyCleanup();
    //if (initFlags & INIT_CB_THREAD) CbThreadNotifyCleanup();
    //if (initFlags & INIT_CB_PROCESS) CbProcessNotifyCleanup();
    //if (initFlags & INIT_PM)       PmCleanup();
    //if (initFlags & INIT_FBE)      FbeShutdown();
    //if (initFlags & INIT_NPM)      WkdNpmShutdown();
    //if (initFlags & INIT_FS)       FsCleanup(DriverObject);
    //if (initFlags & INIT_CB_IMAGE) ImgNotifyCleanup();
    if (initFlags & INIT_EXEMPT)   ExemptsCleanup();
    if (initFlags & INIT_MT)       MtCleanup();
    //if (initFlags & INIT_TS)       TsShutdown(WkdTsEngine);
    //if (initFlags & INIT_AC)       IocAppControlShutdown();
    //if (initFlags & INIT_AE)       AeCleanup();
    //if (initFlags & INIT_NTF)      NmCleanup();

    return status;
}
