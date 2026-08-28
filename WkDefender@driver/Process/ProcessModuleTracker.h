/**************************************************/
/*  WkDefender — 进程模块追踪子系统                  */
/*  参考 PhantomSensor ImageNotify.c                 */
/*  IMG_PROCESS_MODULES / IMG_MODULE_ENTRY           */
/*                                                   */
/*  每个 WKD_PROCESS 嵌入一个 PWKD_MODULE_CONTEXT，   */
/*  记录该进程加载的所有模块。                         */
/*                                                   */
/*  2026-08-11 全局镜像对象重构：                     */
/*    - 新增全局唯一 WKD_MODULE 对象（每唯一镜像一个， */
/*      内容固有数据只解析/存储一次）                  */
/*    - WKD_MODULE_CONTEXT 条目瘦身为映射实例视图，    */
/*      经 PWKD_MODULE 指针串联全局对象                */
/*    - 并发模型：RefCount = 表引用(1) + 视图引用 +    */
/*      pin；ShouldRemove double-check 保证摘表原子性  */
/*                                                   */
/*  2026-08-11 全量重构完成（S1-S5）：                 */
/*    旧 WKD_MODULE_INSTANCE 字段（ModulePath/PeFacts/    */
/*    ImageProperties/SectionInfo/Hash）与旧 Mt API     */
/*   （MtAddModuleEx/MtAddModule/MtFindModuleByPath）   */
/*    已删除，仅保留新流。                             */
/**************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Common/DynamicArray.h"
#include "../Common/HashMap.h"

//
// 前向声明（WKD_PROCESS 定义于 ProcessMonitor.h，反向包含会成环；
// Ps* 模块 API 以 PWKD_PROCESS 为参数时依赖此前向声明）
//
typedef struct _WKD_PROCESS *PWKD_PROCESS;

//
// 池标记
//
#define WKD_MT_POOL_TAG     'tMWK'      /* WkMt — Module Tracker */
#define WKD_MT_POOL_ENTRY   'eMWK'      /* WkMe — Module Entry  */
#define WKD_MT_MODULE_TAG   'dMWK'      /* WkMd — WKD_MODULE 对象 */

//
// 限制
//
#define MAX_MODULES_PER_PROCESS      128

//
// 全局唯一镜像对象表
//
#define WKD_MODULE_TABLE_BUCKETS        128
#define WKD_MODULE_TABLE_MAX_ENTRIES    16384   /* 防无界增长（.NET 临时程序集等） */

//
// 区段特征位图：bit i 置位 = 第 i 区段 (EXECUTE | WRITE)，最多 96 区段（SectionMask[3]）
//
#define WKD_MT_PE_SECTION_MASK_BITS     96

//
// PE 测量事实（L0 镜像回调采集，L1 IocImage 检测消费）
// ★ PeParser.h WKD_PE_PARSE_CONTEXT.Facts 的类型即此结构，不能删除。
// 熵已移除：hash/熵计算全部归 agent（2026-08-09 镜像职责收敛）。
//
typedef struct _WKD_MODULE_PE_FACTS {
    struct {
        ULONG Valid : 1;                // DOS+NT 签名校验通过
        ULONG Amd64 : 1;                // Machine == AMD64
        ULONG IsDll : 1;
        ULONG IsDriver : 1;
        ULONG IsSystem : 1;
        ULONG EntryPointInCode : 1;     // EP 落在可执行区段
        ULONG HasWxSection : 1;         // 任意区段 EXECUTE|WRITE（SelfModifying）
        ULONG HasNoExports : 1;         // DLL 且导出目录 Size==0
        ULONG HasDotNet : 1;            // COM_DIR 非零
        ULONG HasSecurityDirectory : 1; // 安全目录非零
        ULONG HasTlsCallbacks : 1;      // TLS 目录非零
    };                              

    USHORT  NumberOfSections;       // 区段数（≤96）
    ULONG   AddressOfEntryPoint;    // 入口点 RVA
    ULONG64 ImageBase;
    
    ULONG   SectionMask[3];         // 区段特征位图（bit i = 第 i 区段 WX）
    ULONG   TimeDateStamp;
    ULONG   CheckSum;
} WKD_MODULE_PE_FACTS, *PWKD_MODULE_PE_FACTS;

//
// 单节明细（全局 WKD_MODULE 节集元素，动态数组存储）
//
typedef struct _WKD_MODULE_SECTION {
    WCHAR Name[8];                // 节名（IMAGE_SECTION_HEADER.Name，8 字节含 NUL）
    ULONG VirtualSize;            // Misc.VirtualSize
    ULONG VirtualAddress;         // VirtualAddress（RVA，内存偏移）
    ULONG SizeOfRawData;          // SizeOfRawData
    ULONG Characteristics;        // 节属性位
} WKD_MODULE_SECTION, *PWKD_MODULE_SECTION;

// 镜像文件级属性位域（WKD_MODULE::ImageProperties；L0 回调 PspAnalyzeImageProperties 直填）
// 2026-08-12：与 IMAGE_INFO 位域同构，字段一一对应直拷（SignatureLevel/Type 保留值，非布尔化）。
// 每映射属性（Unbacked 等）在 WKD_MODULE_INSTANCE::ViewFlags，不入全局对象。
typedef union _WKD_IMAGE_PROPERTIES {
    struct {
        ULONG SystemModeImage       : 1;
        ULONG ImageSignatureLevel   : 4;  // SE_SIGNING_LEVEL_*，保留值
        ULONG ImageSignatureType    : 3;  // SE_IMAGE_SIGNATURE_TYPE，保留值
        ULONG ImagePartialMap       : 1;  // 预留
    };
    ULONG PropertiesAsUlong;
} WKD_IMAGE_PROPERTIES, *PWKD_IMAGE_PROPERTIES;

//
// 镜像类型细分（驱动内消费，不上送线格式）
// 对齐 PS IMG_TYPE。2026-08-08 迁自 Callbacks/ImageNotify.h（消除循环依赖）。
// 2026-08-12 前移：WKD_MODULE::ImageType 使用本枚举，定义必须先于结构体。
//
typedef enum _WKD_IMAGE_TYPE {
    WkdImageType_Unknown = 0,
    WkdImageType_Exe,
    WkdImageType_Dll,
    WkdImageType_Sys,             // 内核驱动
    WkdImageType_Ocx,             // ActiveX
    WkdImageType_Cpl,             // 控制面板
    WkdImageType_Scr,             // 屏保
    WkdImageType_Drv,             // 旧驱动
    WkdImageType_Efi,             // EFI
    WkdImageType_Max
} WKD_IMAGE_TYPE, *PWKD_IMAGE_TYPE;

//
// 全局唯一镜像对象。发布（入表）后除 RefCount 外全部字段不可变：
//   - 构造期由创建线程独占填写，CoInsertHashMap 成功即对外可见；
//   - 读者须先 pin（PsFindOrCreateModule / CoLookupHashMapEntry 命中
//     Reference 自动 +1），或经持有视图引用的进程上下文访问，
//     以生命周期保证读不撕裂。
//   - 无需内容锁：发布后不可变 + RefCount 用 Interlocked（2026-08-11）。
//
typedef struct _WKD_MODULE {
    /* === 引用与生命周期 === */
    volatile LONG       RefCount;        // 表引用(1) + 视图引用 + 查找 pin
    BOOLEAN             InTable;         // 已入表（调试/释放路径判读；桶锁内写）
    BOOLEAN             Trusted;
    UCHAR               Reserved0[2];

    WKD_IMAGE_TYPE      ImageType;

    /* === 身份（防 TOCTOU：同路径文件被替换后重载） === */
    SIZE_T              ImageSize;       // 首见映射大小（Identity，与 IMAGE_INFO.ImageSize 同源）
    LARGE_INTEGER       LastWriteTime;   // 文件末写时间（本轮 0，预留扩展）

    /* === 路径（嵌入式 UNICODE_STRING + 尾随缓冲，一次分配；= 表 key） === */
    PUNICODE_STRING      ImagePath;

    /* === PE 解析标准事实（内嵌一份；PeParser 核心耦合类型） === */
    WKD_MODULE_PE_FACTS Facts;

    /* === OnNtHeader 三字段（Facts 不含，须单独保存） === */
    ULONG               SectionAlignment; // WKD_PE_OPT_OFFSET(Ctx, SectionAlignment)
    ULONG               FileAlignment;    // WKD_PE_OPT_OFFSET(Ctx, FileAlignment)
    ULONG               SizeOfImage;      // WKD_PE_OPT_OFFSET(Ctx, SizeOfImage)

    /* === 节集（动态数组；发布后只读，一次 DaEnsureCapacity 到位） === */
    WKD_DYNAMIC_ARRAY   Sections;         // 元素 = WKD_MODULE_SECTION

    /* === ImageInfo 文件级标志（直填：PspAnalyzeImageProperties 位域直写，无位图中转） === */
    WKD_IMAGE_PROPERTIES ImageProperties;

    PFILE_OBJECT        FileObject;
} WKD_MODULE, *PWKD_MODULE;

//
// 单条模块条目（映射实例视图，对齐 PS IMG_MODULE_ENTRY）
// 2026-08-11 瘦身：内容固有数据（事实/节/路径/文件级标志）全部上提全局
// WKD_MODULE，本结构仅保留 per-process 映射实例信息。
//
typedef struct _WKD_MODULE_INSTANCE {
    LIST_ENTRY          ListEntry;
    PVOID               ImageBase;
    LARGE_INTEGER       LoadTime;
    PWKD_MODULE         Module;          /* → 全局唯一对象（事实/节/路径/文件级标志） */
} WKD_MODULE_INSTANCE, *PWKD_MODULE_INSTANCE;

//
// 进程模块追踪上下文（对齐 PS IMG_PROCESS_MODULES）
// Lock：EX_PUSH_LOCK（2026-08-12 自旋锁迁移）——
//   读路径共享锁（PsLookupModuleInstanceByImageBaseLocked），写路径独占锁（Add/Destroy）。
//   IRQL 硬约束：仅允许 ≤ APC_LEVEL 获取；引入 DPC/高 IRQL 回调查询前必须回退自旋锁。
//
typedef struct _WKD_MODULE_CONTEXT {
    /* 上下文推锁 (2026-08-25 锁下沉: 自 WKD_PROCESS.Lock 迁入)
     * 规则: ModuleList 链头必须持本锁访问 (读共享/写独占);
     * ActiveModules 走 Interlocked 原子 */
    EX_PUSH_LOCK        Lock;

    LIST_ENTRY          ModuleList;         // WKD_MODULE_INSTANCE::ListEntry 链表头
    volatile ULONG      ActiveModules;      // 当前模块数
    HANDLE              ProcessId;          // 所属进程 PID
} WKD_MODULE_CONTEXT, *PWKD_MODULE_CONTEXT;

//
// ======================================================================
// 函数声明
// ======================================================================
//

//
// 全局模块表（每唯一镜像一个 WKD_MODULE，key = 归一化小写路径字节）
//
extern WKD_HASH_MAP g_WkdModuleTable;

//
// 初始化全局模块表（DriverEntry，须在 CbInitializeImageNotify 之前）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MtInitialize(
    VOID
    );

//
// 清理全局模块表（DriverUnload，先移除镜像回调）
// 注意：CoFreeHashMap 不调 Dereference，直接 Free 会泄漏模块对象；
// 卸载路径残留视图引用时 ShouldRemove 拒绝（尽力而为，与现有卸载清理策略对齐）。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MtCleanup(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PsFindOrCreateModule(
    _In_ PCUNICODE_STRING ImagePath,
    _In_ const PIMAGE_INFO ImageInfo,
    _Out_ PWKD_MODULE* Module,
    _Out_opt_ PBOOLEAN Existing
    );

//
// 递增模块引用（视图挂接 / pin）
//
FORCEINLINE
LONG
PsReferenceWkdModule(
    _In_ PWKD_MODULE Module
    )
{
    return InterlockedIncrement(&Module->RefCount);
}

//
// 递减模块引用。归零前最后视图释放（RefCount==1 仅剩表引用）→
// ShouldRemove double-check 摘表 → 锁外释放。无延迟释放（决策 #3）。
//
_IRQL_requires_(PASSIVE_LEVEL)
LONG
PsDereferenceWkdModule(
    _Inout_ PWKD_MODULE Module
    );

//
// 挂接映射实例视图到进程模块上下文（Module 须已 pin；ImageBase 去重由调用方保证）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PsModuleAttachProcessLocked(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Inout_ PWKD_MODULE Module,
    _In_ PVOID ImageBase,
    _Out_opt_ PWKD_MODULE_INSTANCE* Instance
    );

//
// 分配并初始化模块追踪上下文（建议前移到进程创建路径，消除惰性初始化竞态）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PsAllocateModuleContext(
    _Inout_ PWKD_PROCESS WkdProcess
    );

//
// 销毁模块追踪上下文（进程终止时调用；遍历视图 PsDereferenceWkdModule）
// ★ 2026-08-11 注解降级 PASSIVE（新实现经 PsDereferenceWkdModule 触发 CoRemoveHashMapEntry，
//    max APC_LEVEL）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PsDestroyWkdModuleContext(
    _In_ PWKD_PROCESS WkdProcess
    );

//
// 按基址查找模块（返回瘦视图；调用方须保证进程存活期间使用）
//
_IRQL_requires_max_(APC_LEVEL)
PWKD_MODULE_INSTANCE
PsLookupModuleInstanceByImageBaseLocked(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ PVOID ImageBase
    );

//
// 地址包含查询（新增，对齐 SS TnpFindModuleForAddress，改用 WKD_MODULE 全局表替代 PEB 遍历）。
// 遍历目标进程 ModuleContext->ModuleList，判定 Address 是否落在某模块 [ImageBase, +ImageSize) 内。
// 全程内核数据结构，无用户态地址访问、无 ProbeForRead/SEH（本质优于 PEB 版）。
// 约定：调用方须已持有 ModuleContext 共享锁（EX_PUSH_LOCK，≤APC_LEVEL），
//       与 PsLookupModuleInstanceByImageBaseLocked 一致；返回命中实例（含 Module 指针），
//       未命中返回 NULL。ModuleBase/ModuleSize/ModulePath 可选回传。
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PsLookupWkdModuleContainingAddress(
    _In_ PWKD_PROCESS WkdProcess,
    _In_ PVOID Address,
    _Outptr_ PWKD_MODULE_INSTANCE* Instance
    );
