/**************************************************/
/*  WkDefender IOA — ROP 代码复用攻击模式检测器      */
/*                                                  */
/*  迁移自 ShadowStrike ROPProtection               */
/*  (ROPProtection.cpp/.hpp, v3.0.0)                */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  能力面 (六大保护机制):                   */
/*    ├─ 影子栈 (软件 Shadow Stack, 逐线程槽位 +    */
/*    │    全局 LRU 淘汰, 返回地址压/弹校验)         */
/*    ├─ 返回地址校验 (VirtualQuery 可执行性 +       */
/*    │    CALL 前导指令 SEH 探测 + 影子栈交叉)      */
/*    ├─ 关键 API 保护 (21 项默认表, VirtualAlloc/   */
/*    │    VirtualProtect/CreateProcess/LoadLibrary…) */
/*    ├─ Gadget 链检测 (栈扫描 → 已知 pattern 表 +   */
/*    │    RET 结尾验证 → 链分析 → 置信度评分)       */
/*    ├─ JOP/COP 代码复用分类 (ROP/JOP/COP/SOP/      */
/*    │    BROP/COOP)                               */
/*    └─ CET 硬件集成 (CPUID 探测 + 进程级启用)      */
/*                                                  */
/*  与 SS 源码的对齐/裁剪 (注释就地标注):            */
/*    - 去 JSON 序列化 → 事件结构体直接输出          */
/*    - 去 AlertSystem/IPCManager/StackPivotDetector/ */
/*      SignatureStore 依赖 → 单一事件回调上报       */
/*    - 去 PushRopBlacklistToKernel (WkDefender 无   */
/*      内核 IPC 通道), 保留内核告警线格式与解析     */
/*    - 4 类回调合一为 RPD_DETECTED_CALLBACK          */
/*                                                  */
/*  接入状态: 独立模块 (死代码), 未挂接 IoaObserve   */
/*  事件流水线。调用方按需周期调用 RpdScanStackForRop */
/*  或各分析入口。                                   */
/**************************************************/

#pragma once

#include "../../DefendTypes.h"

/**************************************************/
/*               容量常量                           */
/*  ROPConstants (同类项中文化注释)。       */
/**************************************************/

#define RPD_VERSION_MAJOR              3
#define RPD_VERSION_MINOR              0
#define RPD_VERSION_PATCH              0

#define RPD_MAX_SHADOW_STACK_ENTRIES   4096        /* SS MAX_SHADOW_STACK_ENTRIES */
#define RPD_MAX_GADGET_CHAIN_LENGTH    256         /* SS MAX_GADGET_CHAIN_LENGTH */
#define RPD_MAX_PROTECTED_APIS         128         /* SS MAX_PROTECTED_APIS */
#define RPD_GADGET_SCAN_DEPTH          32          /* SS GADGET_SCAN_DEPTH */

/* RET 系列操作码 (SS ROPConstants) */
#define RPD_RET_OPCODE                 0xC3
#define RPD_RETN_OPCODE                0xC2
#define RPD_RETF_OPCODE                0xCB
#define RPD_RETFN_OPCODE               0xCA

/* 栈扫描单次读入上限 (SS ScanStackForRop: cap 8KB) */
#define RPD_MAX_STACK_SCAN_SIZE        8192
/* 栈扫描升级为链分析的最小 gadget 数 (SS MIN_ROP_GADGET_CHAIN_GADGETS) */
#define RPD_MIN_ROP_CHAIN_GADGETS      5
/* 链判完整的最小 gadget 数 (SS AnalyzeRopChain) */
#define RPD_MIN_COMPLETE_CHAIN_GADGETS 3
/* 内核链判完整的最小 gadget 数 (SS MIN_COMPLETE_KERNEL_CHAIN_GADGETS) */
#define RPD_MIN_COMPLETE_KERNEL_CHAIN  4
/* 影子栈返回地址容差 (JIT/trampoline, SS SHADOW_STACK_DIFF_TOLERANCE) */
#define RPD_SHADOW_STACK_TOLERANCE     0x1000

/* 全局线程影子栈槽位上限.
 * SS MAX_GLOBAL_THREAD_STACKS = MAX_SHADOW_STACK_ENTRIES=4096, 槽位
 * 随线程惰性创建且须动态分配, 对 C 静态化模块过度铺张; 此处收敛为
 * 256 槽 + LRU 淘汰, 语义不变。 */
#define RPD_MAX_THREAD_STACK_SLOTS     256

/* 检测历史环形容量 (SS MAX_HISTORY_SIZE) */
#define RPD_HISTORY_CAPACITY           1000
/* 进程模块缓存: 缓存 PID 上限 + TTL (SS MODULE_CACHE_TTL=30s, 无上限) */
#define RPD_MAX_CACHED_PIDS            16
#define RPD_MODULE_CACHE_TTL_MS        30000

/**************************************************/
/*               模块状态枚举                       */
/*  ModuleStatus (KED KedStatus 同构)。     */
/**************************************************/

typedef enum _RPD_STATUS {
    RpdStatus_Uninitialized = 0,
    RpdStatus_Initializing  = 1,
    RpdStatus_Running       = 2,
    RpdStatus_Paused        = 3,
    RpdStatus_Stopping      = 4,
    RpdStatus_Stopped       = 5,
    RpdStatus_Error         = 6
} RPD_STATUS;

/**************************************************/
/*               检测方法枚举                       */
/*  RopDetectionMethod (0-9)。              */
/**************************************************/

typedef enum _RPD_DETECTION_METHOD {
    RpdMethod_Unknown                = 0,
    RpdMethod_ShadowStackMismatch    = 1,    /* 影子栈返回不匹配      */
    RpdMethod_StackPointerOutOfBounds = 2,   /* RSP 超出有效范围      */
    RpdMethod_ReturnAddressInvalid   = 3,    /* 返回到不可执行区域    */
    RpdMethod_CallRetMismatch        = 4,    /* CALL/RET 不平衡       */
    RpdMethod_HeuristicGadgetScan    = 5,    /* 栈上 gadget 链        */
    RpdMethod_PatternMatch           = 6,    /* 已知 ROP 链签名       */
    RpdMethod_ApiReturnValidation    = 7,    /* API 返回校验失败      */
    RpdMethod_HardwareCET            = 8,    /* Intel CET 违规        */
    RpdMethod_KernelAlert            = 9     /* 内核 ROP 告警         */
} RPD_DETECTION_METHOD;

/**************************************************/
/*               Gadget 类型枚举                    */
/*  GadgetType。                            */
/**************************************************/

typedef enum _RPD_GADGET_TYPE {
    RpdGadget_Unknown       = 0,
    RpdGadget_Ret           = 1,    /* RET 结尾       */
    RpdGadget_RetN          = 2,    /* RET N 结尾     */
    RpdGadget_Jmp           = 3,    /* JOP gadget     */
    RpdGadget_Call          = 4,    /* COP gadget     */
    RpdGadget_Syscall       = 5,    /* SYSCALL gadget */
    RpdGadget_Int           = 6     /* INT gadget     */
} RPD_GADGET_TYPE;

/**************************************************/
/*               代码复用攻击类型                   */
/*  CodeReuseType。                         */
/**************************************************/

typedef enum _RPD_ATTACK_TYPE {
    RpdAttack_Unknown = 0,
    RpdAttack_ROP     = 1,    /* 面向返回编程          */
    RpdAttack_JOP     = 2,    /* 面向跳转编程          */
    RpdAttack_COP     = 3,    /* 面向调用编程          */
    RpdAttack_SOP     = 4,    /* 面向 sigreturn 编程   */
    RpdAttack_BROP    = 5,    /* 盲 ROP               */
    RpdAttack_COOP    = 6     /* 伪造对象编程          */
} RPD_ATTACK_TYPE;

/**************************************************/
/*               受保护 API 分类                    */
/*  ProtectedApiCategory。                  */
/**************************************************/

typedef enum _RPD_API_CATEGORY {
    RpdApiCat_Unknown           = 0,
    RpdApiCat_MemoryAllocation  = 1,    /* VirtualAlloc, HeapAlloc */
    RpdApiCat_MemoryProtection  = 2,    /* VirtualProtect          */
    RpdApiCat_ProcessCreation   = 3,    /* CreateProcess           */
    RpdApiCat_ThreadCreation    = 4,    /* CreateThread, CreateRemoteThread */
    RpdApiCat_DllLoading        = 5,    /* LoadLibrary             */
    RpdApiCat_CodeExecution     = 6,    /* ShellExecute, WinExec   */
    RpdApiCat_FileOperations    = 7,    /* CreateFile 危险操作     */
    RpdApiCat_RegistryAccess    = 8,    /* 注册表操作              */
    RpdApiCat_NetworkOperations = 9     /* Socket, Connect         */
} RPD_API_CATEGORY;

/**************************************************/
/*               检测置信度枚举                     */
/*  DetectionConfidence。                   */
/**************************************************/

typedef enum _RPD_CONFIDENCE {
    RpdConf_Unknown   = 0,
    RpdConf_Low       = 1,
    RpdConf_Medium    = 2,
    RpdConf_High      = 3,
    RpdConf_VeryHigh  = 4,
    RpdConf_Confirmed = 5
} RPD_CONFIDENCE;

/* 置信度 → 分数换算 (SS 栈扫描映射: Confirmed=95/VeryHigh=80/High=65/Medium=45/Low=25) */
#define RPD_CONFIDENCE_SCORE(Level)                     \
    (((Level) == RpdConf_Confirmed) ? 95 :              \
     ((Level) == RpdConf_VeryHigh)  ? 80 :              \
     ((Level) == RpdConf_High)      ? 65 :              \
     ((Level) == RpdConf_Medium)    ? 45 : 25)

/**************************************************/
/*           内核 ↔ 用户二进制线结构                */
/*  KernelRopGadgetEntry / KernelRopAlert     */
/*  Payload (FilterMessageType_MemoryAlert 的 ABI    */
/*  稳定线格式, 内核 ROPDetector 原样打包发送)。     */
/*                                                  */
/*  SS 侧 static_assert:                            */
/*    sizeof(KernelRopGadgetEntry) == 45            */
/*    sizeof(KernelRopAlertPayload) == 334          */
/*  C 无编译期静态断言, ABI 大小以注释约定,          */
/*  修改字段时必须同步内核驱动与用户解析器。         */
/**************************************************/

#pragma pack(push, 1)

/* 单 gadget 数据, 附加于告警载荷尾部 */
typedef struct _RPD_KERNEL_ROP_GADGET_ENTRY {
    UINT64  GadgetAddress;          /* gadget 虚拟地址           */
    ULONG   GadgetType;             /* ROP_GADGET_TYPE 内核枚举值 */
    ULONG   GadgetSize;             /* gadget 字节数             */
    ULONG   DangerScore;            /* 0-100 内核危险度评分      */
    UCHAR   IsPrivileged;           /* 需提升权限                */
    ULONG   RegistersModified;      /* 被修改寄存器位掩码        */
    UINT64  StackOffset;            /* 相对链基址的栈偏移        */
    UINT64  StackValue;             /* 该栈槽位内容              */
    ULONG   Index;                  /* 链内位置                  */
} RPD_KERNEL_ROP_GADGET_ENTRY, *PRPD_KERNEL_ROP_GADGET_ENTRY;

/* FilterMessageType_MemoryAlert ROP 载荷定长头.
 * 其后紧邻 GadgetCount 个 RPD_KERNEL_ROP_GADGET_ENTRY。 */
typedef struct _RPD_KERNEL_ROP_ALERT {
    ULONG   ProcessId;              /* 内核 HANDLE 截断为 ULONG */
    ULONG   ThreadId;               /* 内核 HANDLE 截断为 ULONG */
    UCHAR   ChainDetected;          /* 非零 = 已确认 ROP 链     */
    ULONG   AttackType;             /* ROP_ATTACK_TYPE 值       */
    ULONG   ConfidenceScore;        /* 0-100                    */
    ULONG   SeverityScore;          /* 0-100                    */
    UINT64  StackBase;              /* 线程栈基址 (高地址)      */
    UINT64  StackLimit;             /* 线程栈下限 (低地址)      */
    UINT64  CurrentSp;              /* 检测时刻栈指针           */
    ULONG   ChainLength;            /* 链内 gadget 数           */
    ULONG   UniqueGadgets;          /* 去重后 gadget 地址数     */
    UCHAR   StackPivotDetected;     /* 非零 = 链含栈迁移        */
    UINT64  PivotSource;            /* 迁移前 RSP               */
    UINT64  PivotDestination;       /* 迁移后 RSP               */
    UCHAR   PayloadInferred;        /* 非零 = 载荷已推断        */
    UCHAR   MayExecuteCode;         /* 链可能触发代码执行       */
    UCHAR   MayDisableDefenses;     /* 链可能禁用安全软件       */
    UCHAR   MayEscalatePrivileges;  /* 链可能提权               */
    ULONG   GadgetCount;            /* 尾部 gadget 结构数量     */
    CHAR    PayloadDescription[256];/* 内核描述 (NUL 结尾)      */
} RPD_KERNEL_ROP_ALERT, *PRPD_KERNEL_ROP_ALERT;

#pragma pack(pop)

/**************************************************/
/*               Gadget 信息结构                    */
/*  GadgetInfo, 字节缓冲定长化。            */
/**************************************************/

typedef struct _RPD_GADGET_INFO {
    UINT64          Address;            /* gadget 地址              */
    RPD_GADGET_TYPE Type;               /* gadget 类型              */
    ULONG           Length;             /* gadget 长度              */
    USHORT          StackAdjustment;    /* RET N 栈调整值           */
    WCHAR           ModuleName[DEF_MAX_IMAGE_NAME]; /* 所属模块名   */
    UINT64          ModuleOffset;       /* 模块内偏移               */
    BOOLEAN         IsAslrDependent;    /* 依赖 ASLR                */
    UCHAR           GadgetBytes[RPD_GADGET_SCAN_DEPTH]; /* 原始字节 */
    UCHAR           ByteCount;          /* 有效字节数               */
} RPD_GADGET_INFO, *PRPD_GADGET_INFO;

/**************************************************/
/*               ROP 链信息结构                     */
/*  RopChainInfo (摘要字段), gadget 明细    */
/*  由调用方缓冲逐项输出。                          */
/**************************************************/

typedef struct _RPD_CHAIN_INFO {
    UINT64          ChainId;            /* 链 ID (自增序号, 替代 SS 字符串) */
    UINT64          ChainStartAddress;  /* 链起始栈地址            */
    ULONG           ChainLength;        /* gadget 数               */
    ULONG           TotalBytes;         /* 总字节数                */
    RPD_ATTACK_TYPE AttackType;         /* 攻击类型                */
    WCHAR           PayloadType[64];    /* 推断载荷类型            */
    WCHAR           TargetFunction[64]; /* 识别到的目标函数        */
    WCHAR           SignatureMatch[64]; /* 签名命中 (如有)         */
    BOOLEAN         IsCompleteChain;    /* 链完整                  */
    BOOLEAN         UsesKnownSequence;  /* 命中已知 gadget 序列    */
    RPD_CONFIDENCE  Confidence;         /* 置信度                  */
} RPD_CHAIN_INFO, *PRPD_CHAIN_INFO;

/**************************************************/
/*               受保护 API 信息                    */
/*  ProtectedApiInfo (API 名本质为 ASCII,   */
/*  按 SS 语义以 CHAR 存储)。                       */
/**************************************************/

typedef struct _RPD_PROTECTED_API_INFO {
    CHAR            ApiName[64];        /* API 名                  */
    RPD_API_CATEGORY Category;          /* 分类                    */
    UINT64          Address;            /* 函数地址                */
    BOOLEAN         IsHooked;           /* 是否已挂钩              */
    UINT64          HookAddress;        /* 挂钩地址                */
    ULONG           CallCount;          /* 调用计数 (锁保护)       */
    ULONG           BlockCount;         /* 拦截计数 (锁保护)       */
} RPD_PROTECTED_API_INFO, *PRPD_PROTECTED_API_INFO;

/**************************************************/
/*               检测事件结构                       */
/*  RopEvent 核心字段, 去 JSON 序列化。      */
/**************************************************/

typedef struct _RPD_EVENT {
    ULONG               EventId;            /* 全局自增序号 (替代 SS 字符串 ID) */
    ULONG               ProcessId;
    ULONG               ThreadId;
    WCHAR               ProcessName[DEF_MAX_IMAGE_NAME];
    WCHAR               ProcessPath[DEF_MAX_PATH * 2];

    RPD_DETECTION_METHOD Method;            /* 检测方法              */
    WCHAR               ApiFunction[64];    /* API 边界函数名 (如有) */

    UINT64              InstructionPointer; /* 指令指针              */
    UINT64              StackPointer;       /* 栈指针                */
    UINT64              ExpectedReturn;     /* 影子栈期望返回地址    */
    UINT64              ActualReturn;       /* 实际返回地址          */

    /* 链摘要 (链检测时填充) */
    UINT64              ChainStartAddress;
    ULONG               ChainLength;
    ULONG               ChainTotalBytes;
    RPD_ATTACK_TYPE     AttackType;
    BOOLEAN             IsCompleteChain;
    BOOLEAN             UsesKnownSequence;

    RPD_CONFIDENCE      Confidence;         /* 置信度等级            */
    ULONG               ConfidenceScore;    /* 置信度分数 [0,100]    */
    BOOLEAN             WasBlocked;         /* 是否触发拦截          */
    BOOLEAN             ProcessTerminated;  /* 是否终止进程          */

    LARGE_INTEGER       Timestamp;
    WCHAR               Details[512];       /* 人类可读细节 (宽字符) */
} RPD_EVENT, *PRPD_EVENT;

/**************************************************/
/*               配置结构                           */
/*  ROPProtectionConfiguration 核心开关。   */
/*  去除 protectedApis/excludedProcesses 动态表     */
/*  (默认 API 表内置, 排除列表由调用侧把关)。       */
/**************************************************/

typedef struct _RPD_CONFIG {
    BOOLEAN         EnableShadowStack;      /* 脚本影子栈开关   */
    BOOLEAN         EnableApiReturnValidation; /* API 返回校验   */
    BOOLEAN         EnableGadgetScan;       /* 栈 gadget 扫描   */
    BOOLEAN         BlockOnDetection;       /* 检测即拦截       */
    BOOLEAN         TerminateOnConfirmed;   /* 确认攻击即终止   */
    ULONG           MaxShadowStackDepth;    /* 影子栈深度上限   */
} RPD_CONFIG, *PRPD_CONFIG;

#define RPD_DEFAULT_CONFIG                                              \
    { TRUE, TRUE, TRUE, TRUE, TRUE, RPD_MAX_SHADOW_STACK_ENTRIES }

/**************************************************/
/*               统计结构                           */
/*  ROPStatisticsSnapshot (byMethod 10 槽   */
/*  对应 RPD_DETECTION_METHOD 0-9)。                */
/**************************************************/

typedef struct _RPD_STATISTICS {
    volatile LONG   ApiCallsValidated;      /* API 校验次数      */
    volatile LONG   ShadowStackPushes;      /* 影子栈压栈次数    */
    volatile LONG   ShadowStackPops;        /* 影子栈弹栈次数    */
    volatile LONG   ShadowStackMismatches;  /* 影子栈失配次数    */
    volatile LONG   RopChainsDetected;      /* ROP 链命中次数    */
    volatile LONG   JopChainsDetected;      /* JOP 链命中次数    */
    volatile LONG   GadgetsIdentified;      /* 识别 gadget 数    */
    volatile LONG   AttacksBlocked;         /* 拦截次数          */
    volatile LONG   ProcessesTerminated;    /* 终止进程数        */
    volatile LONG   ByMethod[10];           /* 按检测方法计数    */
    ULONG           UptimeSeconds;          /* 启动后运行秒数    */
} RPD_STATISTICS, *PRPD_STATISTICS;

/**************************************************/
/*               检测回调                           */
/**************************************************/

typedef VOID (*RPD_DETECTED_CALLBACK)(
    _In_    const RPD_EVENT* Event,
    _In_opt_ PVOID          Context
    );

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
RpdInitialize(
    _In_opt_ const RPD_CONFIG* Config          /* NULL = RPD_DEFAULT_CONFIG */
    );

VOID
RpdShutdown(VOID);

BOOLEAN
RpdIsInitialized(VOID);

RPD_STATUS
RpdGetStatus(VOID);

PCSTR
RpdGetVersionString(VOID);

/**************************************************/
/*               API 保护                          */
/**************************************************/

/*
 * RpdValidateApiCall — 校验当前进程一次 API 调用的返回地址
 * (ValidateApiCall 单参重载, 供进程内 hook 使用):
 *  - 拒绝保留区/内核区地址
 *  - VirtualQuery 验证目标为已提交可执行内存
 *  - RWX 标记为可疑 (不硬拦, JIT 合法使用)
 *  - 可选: 返回地址前导指令须为 CALL 编码 (SEH 探测)
 */
BOOLEAN
RpdValidateApiCall(
    _In_ UINT64 ReturnAddress
    );

BOOLEAN
RpdValidateApiCallEx(
    _In_ UINT64  ReturnAddress,
    _In_ PCSTR   ApiName,
    _In_ ULONG   ProcessId,
    _In_ ULONG   ThreadId
    );

NTSTATUS
RpdProtectApi(
    _In_ PCSTR           ApiName,
    _In_ RPD_API_CATEGORY Category
    );

VOID
RpdUnprotectApi(
    _In_ PCSTR ApiName
    );

ULONG
RpdGetProtectedApis(
    _Out_writes_to_opt_(MaxInfos, *pReturned) PRPD_PROTECTED_API_INFO Infos,
    _In_                               ULONG                   MaxInfos,
    _Out_opt_                          PULONG                  pReturned
    );

/**************************************************/
/*               影子栈                            */
/**************************************************/

VOID
RpdShadowStackPush(
    _In_ ULONG   ThreadId,
    _In_ UINT64  ReturnAddress,
    _In_ UINT64  CallSite
    );

BOOLEAN
RpdShadowStackPop(
    _In_ ULONG  ThreadId,
    _In_ UINT64 ExpectedReturn
    );

VOID
RpdShadowStackClear(
    _In_ ULONG ThreadId
    );

ULONG
RpdGetShadowStackDepth(
    _In_ ULONG ThreadId
    );

/**************************************************/
/*               Gadget 分析                       */
/**************************************************/

/*
 * RpdScanStackForRop — 读取目标进程栈内存并检测 ROP 链
 * (ScanStackForRop):
 *  - 读取上限 8KB
 *  - 逐 qword 提取候选地址, 验证可读可执行区 + RET 结尾 + pattern 表
 *  - 命中 >= RPD_MIN_ROP_CHAIN_GADGETS 时升级为链分析
 *  - 命中事件写入调用方缓冲并经回调上报 (不丢事件)
 *  - 返回本轮命中事件总数。
 */
ULONG
RpdScanStackForRop(
    _In_                               ULONG      ProcessId,
    _In_                               UINT64     StackPointer,
    _In_                               ULONG      ScanSize,
    _Out_writes_to_opt_(MaxEvents, *pReturned) PRPD_EVENT Events,
    _In_                               ULONG      MaxEvents,
    _Out_opt_                          PULONG     pReturned
    );

/*
 * RpdAnalyzeRopChain — 分析潜在 ROP 链 (AnalyzeRopChain):
 * 从 ChainStart 起读取至多 MaxGadgets 个栈 qword, 逐项识别 gadget,
 * 填充链摘要与 gadget 明细 (gadget 数受调用方缓冲上限约束)。
 */
NTSTATUS
RpdAnalyzeRopChain(
    _In_                               ULONG          ProcessId,
    _In_                               UINT64         ChainStart,
    _In_                               ULONG          MaxGadgets,
    _Out_                              PRPD_CHAIN_INFO  ChainInfo,
    _Out_writes_to_opt_(MaxGadgets, *pReturned) PRPD_GADGET_INFO Gadgets,
    _Out_opt_                          PULONG         pGadgetCount
    );

/*
 * RpdIdentifyGadget — 识别指定地址上的 gadget (IdentifyGadget):
 * 验证可读可执行区, 读取扫描窗口字节, 匹配 RET 系列操作码,
 * 提取 RET N 栈调整值与模块归属。
 */
NTSTATUS
RpdIdentifyGadget(
    _In_  ULONG          ProcessId,
    _In_  UINT64         Address,
    _Out_ PRPD_GADGET_INFO OutInfo
    );

/*
 * RpdDisassembleGadget — 简单反汇编 (DisassembleGadget,
 * 支持子集: REX 前缀/POP/PUSH/RET 系列/NOP/XCHG/83 组/MOV/
 * JMP/CALL/FF 组/SYSCALL/INT/LEAVE, 其余输出 DB 伪指令)。
 * 输出为 ASCII 多行文本 (逐指令 \r\n), std::string 语义。
 */
ULONG
RpdDisassembleGadget(
    _In_reads_(ByteCount) const UCHAR*  Bytes,
    _In_                          ULONG   ByteCount,
    _In_                          UINT64  BaseAddress,
    _Out_writes_(BufChars)        PCHAR   Out,
    _In_                          ULONG   BufChars
    );

/**************************************************/
/*               进程保护                           */
/**************************************************/

BOOLEAN
RpdProtectProcess(
    _In_ ULONG ProcessId
    );

VOID
RpdUnprotectProcess(
    _In_ ULONG ProcessId
    );

BOOLEAN
RpdIsProcessProtected(
    _In_ ULONG ProcessId
    );

ULONG
RpdGetProtectedProcesses(
    _Out_writes_(MaxPids) PULONG Pids,
    _In_                  ULONG  MaxPids
    );

/**************************************************/
/*               硬件特性 (CET)                    */
/**************************************************/

BOOLEAN
RpdIsHardwareCetAvailable(VOID);

BOOLEAN
RpdIsHardwareCetEnabled(
    _In_ ULONG ProcessId
    );

BOOLEAN
RpdEnableHardwareCet(
    _In_ ULONG ProcessId
    );

/**************************************************/
/*               内核集成                           */
/*  WkDefender agent 无内核 IPC 通道 (SS IPCManager) */
/*  已裁掉 PushRopBlacklistToKernel; 本入口供调用方 */
/*  把 FilterMessageType_MemoryAlert 载荷转发解析。  */
/**************************************************/

VOID
RpdProcessKernelMemoryAlert(
    _In_ ULONG  MsgType,
    _In_reads_bytes_(PayloadSize) const VOID* Payload,
    _In_ ULONG  PayloadSize
    );

/**************************************************/
/*               统计 / 历史                        */
/**************************************************/

VOID
RpdGetStatistics(
    _Out_ PRPD_STATISTICS Stats
    );

VOID
RpdResetStatistics(VOID);

/*
 * RpdGetRecentDetections — 取最近检测事件 (环形历史,
 * 最新的在前, GetRecentDetections 倒序语义)。
 */
ULONG
RpdGetRecentDetections(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PRPD_EVENT Events,
    _In_                               ULONG      MaxEvents,
    _Out_opt_                          PULONG     pReturned
    );

BOOLEAN
RpdSelfTest(VOID);

/**************************************************/
/*               回调                              */
/**************************************************/

VOID
RpdRegisterCallback(
    _In_opt_ RPD_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    );

/**************************************************/
/*               工具函数                           */
/**************************************************/

PCSTR
RpdGetDetectionMethodName(
    _In_ RPD_DETECTION_METHOD Method
    );

PCSTR
RpdGetAttackTypeName(
    _In_ RPD_ATTACK_TYPE Type
    );

PCSTR
RpdGetGadgetTypeName(
    _In_ RPD_GADGET_TYPE Type
    );

PCSTR
RpdGetApiCategoryName(
    _In_ RPD_API_CATEGORY Category
    );

BOOLEAN
RpdIsReturnInstruction(
    _In_ UCHAR Opcode
    );

BOOLEAN
RpdIsJumpInstruction(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG  ByteCount
    );

BOOLEAN
RpdIsCallInstruction(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG  ByteCount
    );