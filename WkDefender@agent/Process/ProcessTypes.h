/**************************************************/
/*  WkDefender Agent — 进程域核心类型               */
/*                                                  */
/*  进程域统一重构 (2026-08-15)：                    */
/*    - WKD_PROCESS  = WKD_PROCESS 改名 +      */
/*      合并 process_manager.h PROCESS_NODE         */
/*    - WKD_THREAD   = THREAD_NODE 升级，数据源      */
/*      WKD_MESSAGE_BODY_THREAD_CREATE              */
/*    - WKD_MODULE / WKD_MODULE_INSTANCE /          */
/*      WKD_MODULE_CONTEXT = 进程模块域（参照驱动    */
/*      ProcessModuleTracker，完整对象在 Process/    */
/*      ProcessModule.h 定义，本头仅指针前向声明）   */
/*                                                  */
/*  依赖约束：本头只依赖 DefendTypes.h + windows.h， */
/*  是进程域的纯净上游（IOA/Storage/Orchestrator     */
/*  反向依赖本头，禁止反向 include）。               */
/*                                                  */
/*  注意：WKD_PROCESS 内嵌 WKD_MODULE_CONTEXT（含    */
/*  CRITICAL_SECTION）+ LIST_ENTRY 指针，禁止对      */
/*  WKD_PROCESS 做全量 memcpy（字段级合并）。        */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               进程源枚举                         */
/*                                                  */
/*  区分驱动事件链与快照兜底链：                     */
/*    - Driver   : 驱动事件创建，GUID 有效、持久化   */
/*    - Snapshot : Toolhelp 快照兜底，GUID=零、      */
/*      不持久化、不产 IOA 事件；驱动事件到达同 PID  */
/*      时升级（赋 GUID+持久化）再进图。             */
/**************************************************/

typedef enum _WKD_PROCESS_SOURCE {
    WkdProcessSource_Driver = 0,
    WkdProcessSource_Snapshot,
} WKD_PROCESS_SOURCE, *PWKD_PROCESS_SOURCE;

/**************************************************/
/*               镜像类型                           */
/*                                                  */
/*  迁移自驱动 Callbacks/ImageNotify.h（消除循环     */
/*  依赖），驱动内消费不上送线格式。                 */
/**************************************************/

typedef enum _WKD_IMAGE_TYPE {
    WkdImageType_Unknown = 0,
    WkdImageType_Exe,
    WkdImageType_Dll,
    WkdImageType_Sys,             /* 内核驱动 */
    WkdImageType_Ocx,             /* ActiveX */
    WkdImageType_Cpl,             /* 控制面板 */
    WkdImageType_Scr,             /* 屏保 */
    WkdImageType_Drv,             /* 旧驱动 */
    WkdImageType_Efi,             /* EFI */
    WkdImageType_Max
} WKD_IMAGE_TYPE, *PWKD_IMAGE_TYPE;

/**************************************************/
/*            镜像文件级属性位域                    */
/*                                                  */
/*  对齐驱动 WKD_IMAGE_PROPERTIES：字段与 IMAGE_INFO */
/*  位域同构（SignatureLevel/Type 保留值非布尔化）。 */
/*  每映射属性（Unbacked 等）在 WKD_MODULE_INSTANCE:: */
/*  ViewFlags，不入全局对象。                       */
/**************************************************/

typedef union _WKD_IMAGE_PROPERTIES {
    struct {
        ULONG SystemModeImage       : 1;
        ULONG ImageSignatureLevel   : 4;  /* SE_SIGNING_LEVEL_*，保留值 */
        ULONG ImageSignatureType    : 3;  /* SE_IMAGE_SIGNATURE_TYPE，保留值 */
        ULONG ImagePartialMap       : 1;  /* 预留 */
    };
    ULONG PropertiesAsUlong;
} WKD_IMAGE_PROPERTIES, *PWKD_IMAGE_PROPERTIES;

/**************************************************/
/*            PE 测量事实（模块域，自有位域）        */
/*                                                  */
/*  对齐驱动 WKD_MODULE_PE_FACTS（自实现非复制，     */
/*  字段与 agent PE 分析结果映射）。深度分析结果      */
/*  （PE_INFO/节表）不常驻，用后即弃。           */
/**************************************************/

#define WKD_MT_PE_SECTION_MASK_BITS     96  /* SectionMask[3] = 96 区段 */

typedef struct _WKD_MODULE_PE_FACTS {
    struct {
        ULONG Valid : 1;                /* DOS+NT 签名校验通过 */
        ULONG Amd64 : 1;                /* Machine == AMD64 */
        ULONG IsDll : 1;
        ULONG IsDriver : 1;
        ULONG IsSystem : 1;
        ULONG EntryPointInCode : 1;     /* EP 落在可执行区段 */
        ULONG HasWxSection : 1;         /* 任意区段 EXECUTE|WRITE */
        ULONG HasNoExports : 1;         /* DLL 且导出目录 Size==0 */
        ULONG HasDotNet : 1;            /* COM_DIR 非零 */
        ULONG HasSecurityDirectory : 1; /* 安全目录非零 */
        ULONG HasTlsCallbacks : 1;      /* TLS 目录非零 */
    };

    USHORT  NumberOfSections;       /* 区段数（≤96） */
    ULONG   AddressOfEntryPoint;    /* 入口点 RVA */
    ULONG64 ImageBase;

    ULONG   SectionMask[3];         /* 区段特征位图（bit i = 第 i 区段 WX） */
    ULONG   TimeDateStamp;
    ULONG   CheckSum;
} WKD_MODULE_PE_FACTS, *PWKD_MODULE_PE_FACTS;

/**************************************************/
/*               前向声明                           */
/*                                                  */
/*  WKD_MODULE 完整定义（含深度分析结果）在          */
/*  Process/ProcessModule.h，依赖 IOC/PEAnalyzer。  */
/*  本头仅指针引用，保持依赖纯净。                   */
/**************************************************/

typedef struct _WKD_MODULE WKD_MODULE, *PWKD_MODULE;

/**************************************************/
/*   堆喷窗口聚合状态 (HeapSpray 迁移 2026-08)       */
/*                                                  */
/*  迁移自 IOA/IoaTypes.h WKD_HEAP_SPRAY_STATE       */
/*  （原 ShadowStrike HeapSpray 融合），随进程节点    */
/*  生命周期，进程域承载。                           */
/*  死代码: 消费方 IoaHeapSprayDetect 门控            */
/*  g_IoaHeapSprayEnabled=FALSE, 流水线未接入。       */
/**************************************************/

#define WKD_HS_PATTERN_SAMPLE_SIZE      256

typedef struct _WKD_HEAP_SPRAY_STATE {
    /* ── 窗口聚合计数 (对齐 SS HS_PROCESS_CONTEXT) ── */
    ULONG           AllocationCount;        /* 窗口内分配次数 */
    ULONG64         TotalAllocatedSize;     /* 窗口内总字节 */
    volatile LONG   AllocationsInWindow;    /* 当前窗口分配数 */
    LARGE_INTEGER   WindowStartTime;        /* 窗口起点 */
    ULONG           AlignedCount;           /* 对齐分配数 (地址 & 0xFFFF == 0) */
    ULONG           ExecCount;              /* 可执行保护分配数 */
    ULONG_PTR       LowestAddress;          /* 窗口内最低分配地址 */
    ULONG_PTR       HighestAddress;         /* 窗口内最高分配地址 */
    LARGE_INTEGER   LastAllocation;         /* 窗口内最后分配时间 */

    /* ── 最新一次内容采样 ── */
    UCHAR           PatternSample[WKD_HS_PATTERN_SAMPLE_SIZE];
    ULONG           PatternSampleSize;      /* 实际采样字节 (≤256) */
    ULONG           RepetitionScore;        /* 重复度 0-100 */
    ULONG           PatternHash;            /* FNV-1a */

    /* ── 堆喷状态 ── */
    WKD_HEAP_SPRAY_TYPE SuspectedType;
    ULONG           DetectionFlags;         /* WKD_HSF_* 位图 */
    /* 并发安全重构 2026-08-23：volatile 仅为满足 Interlocked 参数类型，
     * 原子语义来自 Interlocked* intrinc（写者经 InterlockedExchange 发布）。 */
    volatile LONG   SprayScore;             /* 0-1000 */
    volatile LONG   SprayInProgress;        /* 评分 ≥ 阈值时置位 */
    volatile LONG   SprayAlerted;           /* 已告警 (防重复告警) */
} WKD_HEAP_SPRAY_STATE, *PWKD_HEAP_SPRAY_STATE;

/**************************************************/
/*   WKD_PROCESS_BEHAVIOR_STATE — 进程级行为状态    */
/*                                                  */
/*  迁移自 IOA/IoaTypes.h（原 SS BehaviorAnalyzer    */
/*  ProcessBehaviorState 单进程累计模型）。           */
/*  作为进程事实随 WKD_PROCESS 迁入进程域，计数器     */
/*  驱动 SS 各"+N"评分; DetectionFlags 引用           */
/*  DefendTypes.h DEF_BEHAVIOR_FLAG_* (bit19+)。     */
/**************************************************/

typedef struct _WKD_PROCESS_BEHAVIOR_STATE {
    /* ── 进程级累计分 ── */
    /* 并发安全重构 2026-08-23：volatile 仅为满足 Interlocked 参数类型，
     * 写者经 InterlockedExchangeAdd 累加（IoaBehavior*Detect.c）。 */
    volatile LONG   MaliceScore;            /* 累计分 [0,100] */
    LARGE_INTEGER   LastFileEventTime;      /* 文件修改速率基准 */
    LARGE_INTEGER   LastUpdateTime;         /* 上次衰减时间 */

    /* ── 勒索 (IoaRansomwareDetect) ── */
    ULONG           HighEntropyWrites;      /* 高熵写次数 (entropy>=7.5) */
    ULONG           FilesDeleted;           /* 文件删除数 */
    ULONG           FileRenames;            /* 文件重命名数 */
    ULONG           ExtensionChanges;       /* 勒索扩展名变更数 */
    ULONG           ShadowCopyOps;          /* 卷影副本删除操作数 */
    ULONG           RansomNoteHits;         /* 勒索信模式命中 */
    ULONG           CanaryTouched;          /* Canary 蜜罐触碰 */

    /* ── C2 (IoaC2Detect) / 外渗 (IoaExfilDetect) ── */
    ULONG           BeaconPeriods;          /* 信标周期确认数 (CV<0.3) */
    ULONG           DgaDomains;             /* DGA 高熵域名数 */
    ULONG           ThreatIntelHits;        /* 情报域名命中 */
    ULONG           DnsQueries;             /* DNS 查询计数 */
    ULONG64         TotalBytesSent;         /* 累计出站字节 */
    BOOLEAN         ExfilCumulTriggered;    /* 累计外渗阈值已触发 */

    /* ── 横向 (IoaLateralDetect) ── */
    ULONG           RemoteServiceInstalls;  /* 远程服务创建 */
    ULONG           WmiExecHits;            /* WMI 远程执行 */
    ULONG           Port445;                /* SMB 445 连接 */
    ULONG           Port3389;               /* RDP 3389 连接 */
    ULONG           Port5985;               /* WinRM 5985/5986 连接 */

    /* ── 持久化 (IoaPersistenceDetect) ── */
    ULONG           PersistenceHits;        /* 持久化注册表路径命中 */
    ULONG           TaskCreates;            /* 计划任务创建 */
    ULONG           ServiceInstalls;        /* 服务安装 */
    ULONG           WmiSubscriptions;       /* WMI 事件订阅 */
    ULONG           BootConfigModifies;     /* 启动配置修改 */

    /* ── 凭据/规避 (IoaCredentialDetect / IoaEvasionDetect) ── */
    ULONG           CredentialTargetOpens;  /* 凭据目标进程被打开 */
    ULONG           TokenStealOps;          /* Token 窃取/复制 */
    ULONG           EvasionHits;            /* 规避尝试总数 */
    ULONG           LogClearOps;            /* 日志清除 */
    ULONG           TimestompOps;           /* 时间戳篡改 */
    ULONG           MasqueradeHits;         /* 脚本父+Temp 伪装 */

    /* ── 检测结论 (一次置位, 供告警/UI) ── */
    ULONG           DetectionFlags;         /* DEF_BEHAVIOR_FLAG_* (bit19+) */

    /* ── 堆喷 (IoaHeapSprayDetect) ── */
    WKD_HEAP_SPRAY_STATE HeapSpray;         /* 分配窗口聚合 + 内容采样 */
} WKD_PROCESS_BEHAVIOR_STATE, *PWKD_PROCESS_BEHAVIOR_STATE;

/**************************************************/
/*               线程节点                           */
/*                                                  */
/*  THREAD_NODE 升级（2026-08-15），字段对齐         */
/*  WKD_MESSAGE_BODY_THREAD_CREATE（WkDefenderHeader. */
/*  h），数据源=编排链回接（IoaObserve 线程分支）。    */
/*  不分配 GUID（自然键 = ThreadId + 所属进程），      */
/*  生命周期绑定 WKD_PROCESS，进程退出全部释放。       */
/**************************************************/

typedef struct _WKD_THREAD {
    LIST_ENTRY  ListEntry;            /* 挂 WKD_PROCESS::ThreadListHead */

    /* 核心标识 */
    HANDLE      ProcessId;              
    HANDLE      ThreadId;             /* 目标线程 ID (tTid) */
    HANDLE      CreatorProcessId;     /* 创建者进程 ID (sPid，来自 DEF_PAYLOAD) */
    HANDLE      CreatorThreadId;      /* 创建者线程 ID (sTid) */

    /* 线程入口 */
    PVOID       StartRoutine;         /* 线程入口地址 */
    PVOID       Argument;             /* NtCreateThreadEx Argument（未匹配=NULL） */
    ULONG       DesiredAccess;        /* NtCreateThreadEx DesiredAccess */
    ULONG       CreateFlags;          /* NtCreateThreadEx CreateFlags */

    /* 内存分析（对齐 PS TnpGetMemoryProtection） */
    ULONG       MemoryProtection;      /* 入口点内存保护 (PAGE_*) */
    ULONG       MemoryProtectionFlags; /* 保留 */

    /* 注入分析上下文（对齐 PS TnpAnalyzeThreadCreation） */
    ULONG       CreatorSessionId;     /* 创建者会话 ID */
    ULONG       TargetSessionId;      /* 目标进程会话 ID */
    ULONG       InjectIndicators;     /* WKD_MSG_INJECT_* 位图 */
    ULONG       InjectionScore;       /* 注入评分 0-1000 */
    ULONG       RiskLevel;            /* 风险等级 */

    /* 入口点原始字节（shellcode 模式匹配） */
    UCHAR       StartBytes[128];      /* 线程入口点前 128 字节 */
    ULONG       StartBytesSize;       /* 有效字节数 (0=未采集) */

    /* 生命周期 */
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;           /* 0=存活 */
    ULONG       Flags;                /* bit0=IsRemote, bit1=Create */

    /* ── IOC 区域 (单写者: IocObserveThread / IOA 只读, 禁止回写) ── */
    BOOLEAN     IoacUnbackedStart;     /* driver IsStartAddrBacked==FALSE (无模块背衬) */
    BOOLEAN     IoacUnusualEntry;      /* driver IsUnusualEntry==TRUE (异常入口, 未落已知模块) */
    BOOLEAN     IoacShellcodeSuspected; /* IocDetectShellcode 字节级命中 (异常入口线程确认) */
} WKD_THREAD, *PWKD_THREAD;

/**************************************************/
/*           进程模块上下文 + 映射视图               */
/*                                                  */
/*  WKD_MODULE_CONTEXT 内嵌 WKD_PROCESS（值类型，    */
/*  含 CRITICAL_SECTION）；WKD_MODULE_INSTANCE 是     */
/*  per-process 映射视图，经 PWKD_MODULE 串联全局     */
/*  唯一镜像对象（完整定义在 ProcessModule.h）。      */
/*  生命周期模型（参照驱动）：                       */
/*    RefCount = 表引用(1) + 视图引用 + pin           */
/*    进程退出先摘 orphan 链表再逐个 deref            */
/*                                                  */
/*  ViewFlags 位与驱动 WKD_IMG_IND_* 值对齐           */
/*  （PsHandleImageLoad 直接把 payload->ImageIndicators   */
/*  映射为视图级观测，防反射加载等跨进程误报污染       */
/*  全局文件级结果——对齐驱动决策 #2）。              */
/**************************************************/

/* 视图级观测位（值 = 驱动 ImageNotify.h IMG_INDICATOR_*） */
#define WKD_MODULE_VIEW_UNBACKED           0x00000400  /* 无背衬内存=反射加载 */
#define WKD_MODULE_VIEW_ENTRYPOINT_OUTSIDE 0x00000800
#define WKD_MODULE_VIEW_MACHINE_MISMATCH   0x00002000
#define WKD_MODULE_VIEW_MASQUERADING       0x00000002  /* MASQUERADING_DLL */
#define WKD_MODULE_VIEW_NETWORK_PATH       0x00000080
#define WKD_MODULE_VIEW_DOUBLE_EXTENSION   0x00000100
#define WKD_MODULE_VIEW_TYPOSQUATTING      0x00000200
#define WKD_MODULE_VIEW_SUSPICIOUS_PATH    0x00000001

typedef struct _WKD_MODULE_CONTEXT {
    LIST_ENTRY      ModuleList;       /* WKD_MODULE_INSTANCE::ListEntry */
    volatile LONG   ActiveModules;    /* 当前模块数（≤128）*/
    volatile LONG   TotalModules;
    ULONG           ProcessId;        /* 所属进程 PID */
    SRWLOCK         Lock;             /* 进程模块上下文读写锁（Exclusive=挂/摘/清场, Shared=遍历） */
} WKD_MODULE_CONTEXT, *PWKD_MODULE_CONTEXT;

/* 线程上下文（并发安全重构 2026-08-23，仿 WKD_MODULE_CONTEXT）：
 * 内嵌 WKD_PROCESS（值类型，含独立 SRWLOCK）；WKD_THREAD 是
 * per-process 线程实体，经 LIST_ENTRY 串联（完整定义在 ProcessThread.h）。
 * 生命周期与 ModuleContext 对齐：事件线程挂/摘线程实体持本锁，
 * 实例字段挂入后不被并发改写（WKD_THREAD 本身无锁）；
 * Context 惰性申请（指针 NULL=无线程），首次 PsThreadAttachProcess 经二次原子写分配。 */
typedef struct _WKD_THREAD_CONTEXT {
    LIST_ENTRY      ThreadList;       /* WKD_THREAD::ListEntry */
    volatile LONG   ActiveThreads;
    volatile LONG   TerminatedThreads;
    volatile LONG   TotalThreads;   
    HANDLE          ProcessId;        /* 所属进程 PID */
    SRWLOCK         Lock;             /* 进程线程上下文读写锁（Exclusive=挂/摘/清场, Shared=遍历） */
} WKD_THREAD_CONTEXT, *PWKD_THREAD_CONTEXT;

typedef struct _WKD_MODULE_INSTANCE {
    LIST_ENTRY   ListEntry;           /* 挂 ModuleContext::ModuleList */
    PVOID        ImageBase;           /* 映射基址（进程内唯一） */
    LARGE_INTEGER LoadTime;           /* 加载时间 */
    PWKD_MODULE  Module;              /* → 全局唯一对象 */
    ULONG        ViewFlags;           /* 每映射观测属性（WKD_MODULE_VIEW_*） */
    DEF_IOC_VERDICT ViewVerdict;      /* 视图级判定（反射加载等进程私有，对齐 0=Clean） */
    ULONG        ViewConfidence;      /* 视图级置信度 */
} WKD_MODULE_INSTANCE, *PWKD_MODULE_INSTANCE;

/**************************************************/
/*               进程节点 (聚合根)                  */
/*                                                  */
/*  WKD_PROCESS（IOA/IoaTypes.h）改名 +         */
/*  合并 process_manager.h PROCESS_NODE 有效字段。   */
/*  被因果图/谱系/处置/UI 共享，IOA 只引用不拥有。    */
/*                                                  */
/*  删除字段（死代码，2026-08-15 核验零读写）：       */
/*    IOA 侧: NodeType/Amd64/UserSid/UserSidSize/    */
/*      EventCount/SuspiciousEventCount/SiblingsLink/ */
/*      IocCheckTime/OutEdgeCount/InEdgeCount/        */
/*      FirstActivity/RefCount                       */
/*    PROCESS_NODE: AncestryScore/IsAppContainer/     */
/*      IsImmersive/UserSid[128]/HandleCount/         */
/*      EventCount/BlockedOperationCount/MemoryUsage/ */
/*      PeakMemoryUsage/UserTime/KernelTime/          */
/*      ExtraData[1024]                              */
/*                                                  */
/*  Status 语义拆分：Status=DEF_PROCESS_STATUS        */
/*  （IOA），MonitorFlags 承载 PROCESS_STATUS_* 的     */
/*  MONITORED/ISOLATED/THREAT 位（两者位值重叠，      */
/*  分字段避免碰撞）。                               */
/**************************************************/

/**************************************************/
/*   进程监视标志 (MonitorFlags 位，原 PROCESS_STATUS_* 的
 *   MONITORED/ISOLATED/THREAT 语义，与 DEF_PROCESS_STATUS
 *   位值分离避免碰撞)                               */
/**************************************************/

#define WKD_PROCESS_MONITOR_MONITORED   0x01
#define WKD_PROCESS_MONITOR_ISOLATED    0x02
#define WKD_PROCESS_MONITOR_THREAT      0x04

/* 前向声明：结构体内部 L369 引用自身指针（typedef 完整别名在文件尾部） */
typedef struct _WKD_PROCESS *PWKD_PROCESS;

/**************************************************/
/*   进程安全上下文 (对齐 driver WKD_PROCESS        */
/*   安全上下文分区的设计哲学)                      */
/*                                                  */
/*  进程固有静态结论聚合区：进程对创建时据此初始化    */
/*  <src,tgt> 基础画像。IOC 回归本义——"攻击的结果和  */
/*  痕迹"属进程互动产物挂 pair.IocContext；本区域只  */
/*  承载进程自身的固有结论。                        */
/*                                                  */
/*  ExeModule 只存指针不拷贝：证书/PE/声誉结论经      */
/*  #69 权威副本 WKD_MODULE::FileResult 取用，引用    */
/*  计数沿用 PsReferenceWkdModule/PsDereferenceWkdModule。 */
/*                                                  */
/*  Placeholder: 占位节点标记（2026-08-23 进程对创建 */
/*  上提重构）——懒建的最小节点仅含 PID/NodeId/Alive，*/
/*  真实事件到达时合并回填并清此位；下游消费方读到    */
/*  占位节点须跳过富化类逻辑。                       */
/**************************************************/

typedef struct _WKD_PROCESS_SECURITY_CONTEXT {
    DEF_IOC_VERDICT         IocVerdict;         /* IOC 引擎写入的进程固有判定 */
    ULONG                   IocConfidence;      /* 置信度 0-1000 */
    PWKD_MODULE             ExeModule;          /* 主镜像文件级权威副本（NULL=未分析） */
    BOOLEAN                 Placeholder;        /* TRUE=懒建占位节点，待真实事件回填 */
} WKD_PROCESS_SECURITY_CONTEXT, *PWKD_PROCESS_SECURITY_CONTEXT;

struct _WKD_PROCESS {
    /* === 标识 === */
    GUID                    NodeId;             /* 进程身份（跨事件/持久化/防复用）；快照节点=零 */
    HANDLE                  ProcessId;
    WKD_PROCESS_SOURCE      NodeSource;         /* Driver / Snapshot */
    PUNICODE_STRING         ImagePath;          /* 唯一字符串载体（替代 PROCESS_NODE WCHAR 数组） */
    PUNICODE_STRING         CommandLine;
    PUNICODE_STRING         ImageFileName;
    DEF_SHA256_HASH         ImageHash;          /* 主镜像哈希（模块域可回填） */

    /* === 安全属性 === */
    ULONG                   SessionId;
    ULONG                   IntegrityLevel;
    BOOLEAN                 IsElevated;
    BOOLEAN                 IsProtectedProcess;
    BOOLEAN                 IsSystemProcess;
    WCHAR                   UserName[64];       /* 富化（IocProcessEnrich） */
    WCHAR                   DomainName[64];
    ULONG                   ProcessCategory;    /* WKD_PROCESS_CATEGORY */
    BOOLEAN                 IsWow64;            /* 快照富化写 */
    ULONG                   SecurityFlags;      /* 驱动原始安全标志（IsProtectedProcess 源头） */

    /* === 生命周期 === */
    LONG                    RefCount;
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           ExitTime;
    DEF_PROCESS_STATUS      Status;             /* Running/Terminated */
    ULONG                   MonitorFlags;       /* bit0=MONITORED bit1=ISOLATED bit2=THREAT */
    ULONG                   ThreatLevel;        /* THREAT_LEVEL_* */
    BOOLEAN                 Alive;              /* 退出保留历史（Alive=FALSE） */
    LARGE_INTEGER           LastUpdateTime;     /* 快照刷新时戳 */

    /* === 谱系树结构 === */
    SRWLOCK                 GenealogyLock;
    LIST_ENTRY              ChildrenHead;
    LIST_ENTRY              ChildrenLink;
    ULONG                   TreeDepth;
    PWKD_PROCESS            Parent;             /* IoaCarsalGraph.c IsOrphan 读 */
    GUID                    ParentNodeId;       /* 谱系父节点 GUID */
    HANDLE                  ParentProcessId;          /* 原始 PPID（快照/事件两路写入） */
    WCHAR                   ParentImageName[256]; /* log_manager 读 */
    BOOLEAN                 IsOrphan;           /* 谱系: 孤儿进程 */
    BOOLEAN                 IsPpidSpoofed;      /* 谱系:PPID 欺骗 */
    BOOLEAN                 MetadataComplete;   /* 快照富化门控 */

    /* === 安全上下文 (进程固有静态结论, 2026-08-23 聚合) === */
    WKD_PROCESS_SECURITY_CONTEXT SecCtx;

    /* === 行为统计 === */
    /* 并发安全重构 2026-08-23：纯 |= 写者走 InterlockedOr，
     * 累加/覆盖写者走 InterlockedExchange/ExchangeAdd；
     * volatile 仅为满足 intrinsic 参数类型，原子语义来自 intrinc。 */
    volatile LONG           BehaviorFlags;
    volatile LONG           CumulativeRiskScore; /* GrbDecideLayer/PolicyEngine 读 */
    volatile LONG           IoaEventCount;       /* syscall 事件计数 */
    volatile LONG           SuspiciousBehaviorCount;
    WKD_PROCESS_BEHAVIOR_STATE BehaviorState;    /* 进程级行为状态（含 HeapSpray） */

    /* === 因果图关联 === */
    LARGE_INTEGER           LastActivity;        /* 持久化 last_seen */

    /* === 进程对双向关联 (PairContext 双向链) ===
     * 链头锁原则 (2026-08-25): Out/InPairListHead 的全部读写一律持
     * 本锁 — 遍历/摘除均不得借用 GenealogyLock (职责分离, 防跨域
     * 锁序纠缠)。 */
    SRWLOCK                 PairLinksLock;       /* 保护两条 pair 关联链 */
    LIST_ENTRY              OutPairListHead;
    LIST_ENTRY              InPairListHead;
    volatile LONG           OutPairCount;        /* 操作了多少不同目标 */
    volatile LONG           InPairCount;         /* 被多少不同源操作 */

    /* === 线程上下文 (惰性申请: 指针 NULL=无线程, 首次 PsThreadAttachProcess 经
     *   二次原子写分配; 释放于 PspDestroyWkdProcess 经 InterlockedExchangePointer) === */
    PWKD_THREAD_CONTEXT      ThreadContext;       /* 进程线程视图（含独立 SRWLOCK） */

    /* === 模块上下文 (惰性申请: 指针 NULL=无模块, 首次 PsModuleInstanceAttachProcess 分配;
     *   释放于 PspDestroyWkdProcess 经 InterlockedExchangePointer) === */
    PWKD_MODULE_CONTEXT      ModuleContext;       /* 进程模块视图 */

    /* === 链接 (树内) === */
    LIST_ENTRY              GlobalLink;          /* 全局链（历史代仍可遍历） */
};

/**************************************************/
/*               类型别名                           */
/**************************************************/

typedef struct _WKD_PROCESS WKD_PROCESS, *PWKD_PROCESS;
