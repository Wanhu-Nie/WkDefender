/**************************************************/
/*  WkDefender — 统一 PE 解析核心（PeParser）        */
/*                                                  */
/*  2026-08-08 新建：统一 Driver 侧 PE 解析模板，     */
/*  融合 PhantomSensor 9 解析点 + wkd 4 解析点的     */
/*  边界校验，集 7 种 e_lfanew 写法之长。            */
/*                                                  */
/*  输入 <PVOID data, SIZE_T dataSize>，解析上下文    */
/*  内嵌回调集承载消费者功能；标准事实               */
/*  WKD_MODULE_PE_FACTS 核心恒填充，L1 IocImage      */
/*  消费零改动。                                    */
/**************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include "../Process/ProcessModuleTracker.h"

//
// 解析标志
//
#define WKD_PE_FLAG_NONE            0x00000000
#define WKD_PE_FLAG_DIRECTORIES     0x00000002  // 触发 OnDirectory
#define WKD_PE_FLAG_SECTION_CONTENT 0x00000004  // 触发 OnSectionContent
// WKD_PE_FLAG_ENTROPY(0x1) 已移除 —— 熵计算归 agent（2026-08-09 镜像职责收敛），
// 保留 WkdPeEntropyWkd 通用熵工具（独立调用方使用）。

//
// 上限常量
//
#define WKD_PE_MAX_SECTIONS_DEFAULT 96          // 节数上限（对齐各解析点）
#define WKD_PE_MAX_ENTROPY_SCAN     256         // 每节熵采样上限（对齐 ImgpParsePeFacts）
#define WKD_PE_MAX_HEADER_OFFSET    4096        // e_lfanew 硬顶（WKD_IMG_PE_HEADER_MAX）
#define WKD_PE_MAX_REMAP_SIZE       (16 * 1024 * 1024)  // file→image 重排 SizeOfImage 上限（对齐 NI_MAX_NTDLL_SIZE）

/**************************************************/
/*                  模式与解析上下文               */
/**************************************************/

//
// 布局模式：Image=镜像布局（RVA 直接加基址寻址）；
//           File=文件布局（RVA 经节表转 PointerToRawData）。
//
typedef enum _WKD_PE_ACCESS_MODE {
    WkdPeMode_Image = 0,
    WkdPeMode_File  = 1,
    WkdPeMode_Max
} WKD_PE_ACCESS_MODE, *PWKD_PE_ACCESS_MODE;

typedef struct _WKD_PE_PARSE_CONTEXT WKD_PE_PARSE_CONTEXT, *PWKD_PE_PARSE_CONTEXT;

/**************************************************/
/*                    回调集                       */
/**************************************************/

//
// 阶段回调契约：
//   返回 STATUS_SUCCESS            → 继续；
//   返回 STATUS_NO_MORE_ENTRIES    → 优雅停环（"找到即停"，整体仍 SUCCESS）；
//   返回其他 NTSTATUS              → 中止并向上传播。
//   回调在核心 SEH 保护内调用，可经 Ctx 读已解析的内部态。
//
typedef NTSTATUS (*WKD_PE_NT_HEADER_CALLBACK)(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PIMAGE_NT_HEADERS NtHeaders,
    _In_opt_ PVOID UserCtx
    );

typedef NTSTATUS (*WKD_PE_DIRECTORY_CALLBACK)(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    ULONG Index,
    _In_    PIMAGE_DATA_DIRECTORY Directory,
    _In_opt_ PVOID UserCtx
    );

typedef NTSTATUS (*WKD_PE_SECTION_CALLBACK)(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PIMAGE_SECTION_HEADER Section,
    _In_    ULONG Index,
    _In_opt_ PVOID UserCtx
    );

typedef NTSTATUS (*WKD_PE_SECTION_CONTENT_CALLBACK)(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PVOID Ptr,
    _In_    SIZE_T Size,
    _In_    PVOID UserCtx
    );

typedef NTSTATUS (*WKD_PE_COMPLETE_CALLBACK)(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_opt_ PVOID UserCtx
    );

typedef struct _WKD_PE_CALLBACKS {
    WKD_PE_NT_HEADER_CALLBACK       OnNtHeader;         // 签名+节表边界+Magic 分支全过后、填 Facts 前
    WKD_PE_DIRECTORY_CALLBACK       OnDirectory;        // 逐数据目录项（需置 WKD_PE_FLAG_DIRECTORIES）
    WKD_PE_SECTION_CALLBACK         OnSection;          // 节循环内（WX/EP/熵增量更新 Facts 后）
    WKD_PE_SECTION_CONTENT_CALLBACK OnSectionContent;   // 每节内容指针（需置 WKD_PE_FLAG_SECTION_CONTENT）
    WKD_PE_COMPLETE_CALLBACK        OnComplete;         // 头部有效后、返回前必调
} WKD_PE_CALLBACKS, *PWKD_PE_CALLBACKS;

/**************************************************/
/*                  解析上下文                     */
/**************************************************/

typedef struct _WKD_PE_PARSE_CONTEXT {
    PVOID               Data;           // 输入缓冲/基址
    SIZE_T              DataSize;       // 缓冲大小
    ULONG               Mode;           // WKD_PE_ACCESS_MODE
    ULONG               Flags;          // WKD_PE_FLAG_*
    ULONG               MaxSections;    // 节数上限（0 → 默认 96）
    WKD_MODULE_PE_FACTS Facts;          // 标准事实（核心恒填充，先清零）

    WKD_PE_CALLBACKS    Callbacks;      // 阶段回调（全部可选）
    PVOID               CallbackContext;// 消费者私有上下文（随回调 UserCtx 透传）

    /* === 内部态（回调只读） === */
    PIMAGE_NT_HEADERS       NtHeaders;  // NT 头（已校验）
    PIMAGE_SECTION_HEADER   Sections;   // 节表首指针（已校验边界）
    union {
        PIMAGE_OPTIONAL_HEADER32 Opt32; // Magic==PE32 时有效
        PIMAGE_OPTIONAL_HEADER64 Opt64; // Magic==PE32+ 时有效
    };
    USHORT              Magic;          // IMAGE_NT_OPTIONAL_HDR32/64_MAGIC
    ULONG               SectionCount;   // 已解析节数
    ULONG               DirectoryEntries;       // min(NumberOfRvaAndSizes, 16)
} WKD_PE_PARSE_CONTEXT, *PWKD_PE_PARSE_CONTEXT;

//
// 位宽感知的 OptionalHeader 字段读取（32/64 统一，消除硬编码位宽）。
// Field 须为 ULONG/USHORT 类型成员；DataDirectory 用 WKD_PE_OPT_DIR。
//
#define WKD_PE_OPT_OFFSET(Ctx, Field)                              \
    (((Ctx)->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?             \
        (ULONG)(Ctx)->Opt32->Field : (ULONG)(Ctx)->Opt64->Field)

#define WKD_PE_OPT_DIR(Ctx, Index)                                 \
    (((Ctx)->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?             \
        (Ctx)->Opt32->DataDirectory[(Index)] :                     \
        (Ctx)->Opt64->DataDirectory[(Index)])

/**************************************************/
/*                  函数声明                       */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoParsePe(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx
    );

//
// 布局感知寻址：把 RVA 解析为数据缓冲内有效指针。
//   - Image 模式：ptr = Data + Rva（校验 Rva <= DataSize）
//   - File 模式：先经 WkdPeRvaToFileOffset 转偏移
//   BoundedSize 返回实际可安全读取的字节数（受 Size 与 DataSize 双夹）。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPeGetDataAtRva(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    ULONG Rva,
    _In_    SIZE_T Size,
    _Outptr_ PVOID* Ptr,
    _Out_opt_ PSIZE_T BoundedSize
    );

//
// RVA → 文件偏移（仅 File 模式有意义）。返回 0 兼作失败哨兵
// （遍历节表，RVA 未落入任何节或偏移溢出时返回 0）。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WkdPeRvaToFileOffset(
    _In_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_ ULONG Rva
    );

//
// 导出解析（Amsi 能力）：按名解析导出函数。
// 内封目录整界校验 / 名字·函数数 1M 上限 / SIZE_T 乘法逐表越界 /
// strnlen 防越界 / ordinal 界校验。
//
typedef struct _WKD_PE_EXPORT_ENTRY {
    ULONG   Rva;            // 函数 RVA（0=未解析）
    ULONG   Ordinal;        // 导出序数索引
    ULONG   FileOffset;     // File 模式下函数文件偏移（Image 模式为 0）
} WKD_PE_EXPORT_ENTRY, *PWKD_PE_EXPORT_ENTRY;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPeResolveExport(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PCSTR Name,
    _Out_   PWKD_PE_EXPORT_ENTRY Out
    );

//
// file→image 布局重排（NtdllIntegrity 能力，死代码预留，冷路径）：
// 分配并清零 SizeOfImage 镜像缓冲，SizeOfHeaders 双夹拷贝头部，
// 逐节 copySize 截断搬移到 VirtualAddress。调用方须用
// WKD_PE_REMAP_TAG 释放 ImageBuffer。
//
#define WKD_PE_REMAP_TAG   'mRPW'

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPeRemapFileToImage(
    _In_  PVOID FileData,
    _In_  SIZE_T FileSize,
    _Out_ PVOID* ImageBuffer,
    _Out_ PSIZE_T ImageSize
    );

//
// 熵双变体（核心内置）：
//   - WkdPeEntropyWkd      — wkd 简化熵（uniqueFactor+distFactor，0-1000），
//                            与现 ImgpParsePeFacts 内联实现逐字节一致，入 Facts/线格式。
//   - WkdPeEntropyShannon  — PS 语义 Shannon 近似（prob*10000/Size + 右移 logApprox，
//                            clamp 800），供 PS 回调。
// 调用方须保证 Data 可读（SEH 外调用时自担）。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WkdPeEntropyWkd(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WkdPeEntropyShannon(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

//
// 粗分类（FileUtils 能力）：非 PE 返回 STATUS_SUCCESS 且 IsPe=FALSE（不报错语义）。
//
typedef struct _WKD_PE_CLASSIFY {
    BOOLEAN IsPe;
    BOOLEAN Amd64;
    BOOLEAN IsDll;
    BOOLEAN IsDriver;
    USHORT  Subsystem;
} WKD_PE_CLASSIFY, *PWKD_PE_CLASSIFY;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPeClassify(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PE_CLASSIFY Out
    );

//
// 用户可执行地址域判定（对齐 CSA_MIN_VALID_USER_ADDRESS 0x10000 上限 0x7FFFFFFFFFFF）。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdPeIsUserExecutableRange(
    _In_ PVOID Address
    );
