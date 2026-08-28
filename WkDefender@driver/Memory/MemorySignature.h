#pragma once
#include "../Common/Constants.h"

//
// 模块名称：内存签名管理模块 (MemorySignature)
// 功能描述：提供内存签名的生命周期管理，包括注册、卸载、预编译等
// 主要用途：
//   - 统一管理所有内存签名的注册和注销
//   - 自动处理签名的预编译和资源分配
//   - 支持一次性签名和持久化签名的分类管理
//   - 提供签名查询和批量清理功能
// 使用示例：
//   // 1. 初始化签名管理器（驱动加载时）
//   NTSTATUS status = MsInitialize();
//   
//   // 2. 注册持久化签名（频繁使用）- 方法1：使用辅助宏
//   WKD_MEMORY_SIGNATURE* pSig = NULL;
//   UCHAR pattern[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00 };
//   UCHAR mask[] =    { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
//   WKD_MEMORY_SIGNATURE_DEFINE sigDef = WKD_SIGNATURE_DEFINE_INIT("Ntoskrnl_Pattern_1", 7);
//   RtlCopyMemory(sigDef.Pattern, pattern, 7);
//   RtlCopyMemory(sigDef.Mask, mask, 7);
//   status = MsRegisterSignature(&sigDef, WkdMemorySignaturePersistent, &pSig);
//   
//   // 方法2：直接初始化数组
//   static const WKD_MEMORY_SIGNATURE_DEFINE sigDef2 = {
//       "Ntoskrnl_Pattern_2",
//       {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00},
//       {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
//       7
//   };
//   status = MsRegisterSignature(&sigDef2, WkdMemorySignaturePersistent, &pSig);
//   
//   // 3. 使用签名进行扫描
//   WKD_SCAN_RESULT result;
//   status = MmScanSection(ntBase, ".text", pSig, &result);
//   
//   // 4. 清理所有签名（驱动卸载时）
//   MsCleanupAllSignatures();
//

#define WKD_MEMORY_SIGNATURE_PATTERN_MAX_SIZE 32
#define WKD_MEMORY_SIGNATURE_NAME_MAX_SIZE 64

//
// 辅助宏：简化签名定义初始化
// 使用示例：
//   WKD_MEMORY_SIGNATURE_DEFINE sigDef = 
//       WKD_SIGNATURE_DEFINE_INIT("MySignature", 7);
//   RtlCopyMemory(sigDef.Pattern, myPattern, 7);
//   RtlCopyMemory(sigDef.Mask, myMask, 7);
//
#define WKD_SIGNATURE_DEFINE_INIT(name, length) \
    { (name), {0}, {0}, (length) }

typedef struct _WKD_MEMORY_SIGNATURE_DEFINE {
    PCSTR Name;
    BYTE Pattern[WKD_MEMORY_SIGNATURE_PATTERN_MAX_SIZE];
    BYTE Mask[WKD_MEMORY_SIGNATURE_PATTERN_MAX_SIZE];
    SIZE_T Length;
} WKD_MEMORY_SIGNATURE_DEFINE, * PWKD_MEMORY_SIGNATURE_DEFINE;

//
// 签名类型枚举
//
typedef enum _WKD_SIGNATURE_TYPE {
    WkdMemorySignatureTemporary = 0,     // 临时签名：一次性使用，不预编译
    WkdMemorySignaturePersistent = 1     // 持久化签名：频繁使用，需要预编译
} WKD_SIGNATURE_TYPE;

//
// 内存签名核心结构定义
// 包含签名的核心数据和优化字段
//
typedef struct _WKD_MEMORY_SIGNATURE {
    
    // === 核心数据 ===
    UCHAR Name[WKD_MEMORY_SIGNATURE_NAME_MAX_SIZE];  // 签名名称（用于调试和查询）
    BYTE Pattern[WKD_MEMORY_SIGNATURE_PATTERN_MAX_SIZE];   // 特征码字节数组
    BYTE Mask[WKD_MEMORY_SIGNATURE_PATTERN_MAX_SIZE];      // 掩码数组（0xFF表示精确匹配，0x00表示通配符）
    SIZE_T Length;             // 特征码长度

    // === 优化字段：预编译的匹配信息 ===
    PUCHAR ExactPattern;      // 提取的精确匹配字节序列（去除通配符）
    PUCHAR ExactPositions;    // 精确匹配字节在原Pattern中的位置索引
    ULONG ExactCount;         // 精确匹配字节的数量
    BOOLEAN IsPrecompiled;    // 是否已预编译

    // === 快速过滤字段：用于跳过大量不匹配位置 ===
    UCHAR FirstExactByte;     // 第一个精确匹配字节的值（用于快速筛选）
    BOOLEAN HasFirstByte;     // 是否存在第一个精确字节
} WKD_MEMORY_SIGNATURE, * PWKD_MEMORY_SIGNATURE;

//
// 签名管理结构
// 封装 WKD_MEMORY_SIGNATURE 并添加管理元数据
//
typedef struct _WKD_MEMORY_SIGNATURE_EX {
    LIST_ENTRY ListEntry;           // 链表节点，用于管理所有注册的签名
    
    // === 核心数据（嵌入到起始位置便于访问）===
    WKD_MEMORY_SIGNATURE Core;      // 签名核心数据（包含名称、特征码和优化字段）
    
    // === 管理信息 ===
    ULONG SignatureId;              // 签名唯一ID
    WKD_SIGNATURE_TYPE Type;        // 签名类型
    volatile LONG ReferenceCount;   // 引用计数（原子操作，防止 UAF）
    volatile LONG UsageCount;       // 使用次数（记录签名被使用的总次数）
    LARGE_INTEGER RegisterTime;     // 注册时间
    LARGE_INTEGER LastUsedTime;     // 最后使用时间
} WKD_MEMORY_SIGNATURE_EX, * PWKD_MEMORY_SIGNATURE_EX;

//
// 签名管理器上下文
//
typedef struct _WKD_SIGNATURE_MANAGER {
    LIST_ENTRY SignatureList;       // 已注册签名链表
    KSPIN_LOCK Lock;                // 保护链表的自旋锁
    ULONG NextSignatureId;          // 下一个可用的签名ID
    ULONG TotalSignatures;          // 当前注册的签名总数
    ULONG PersistentCount;          // 持久化签名数量
    ULONG TemporaryCount;           // 临时签名数量
} WKD_SIGNATURE_MANAGER, * PWKD_SIGNATURE_MANAGER;

//
// 初始化签名管理器
// 在驱动加载时调用一次
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsInitialize(
    VOID
    );

//
// 清理签名管理器
// 在驱动卸载时调用，释放所有签名资源
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsCleanup(
    VOID
    );

//
// 注册新的内存签名
// 
// Parameters:
//   Name - 签名名称（用于调试和查询）
//   Pattern - 特征码字节数组
//   Mask - 掩码数组（0xFF表示精确匹配，0x00表示通配符）
//   Length - 特征码长度
//   Type - 签名类型（临时或持久化）
//   OutSignature - 输出参数，返回注册后的签名指针
//
// Returns:
//   STATUS_SUCCESS - 注册成功
//   STATUS_INSUFFICIENT_RESOURCES - 内存不足
//   STATUS_INVALID_PARAMETER - 参数无效
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsRegisterSignature(
    _In_ PWKD_MEMORY_SIGNATURE_DEFINE SignatureDefine,
    _In_ WKD_SIGNATURE_TYPE Type,
    _Out_ PWKD_MEMORY_SIGNATURE* Signature
    );

//
// 注销指定的内存签名
// 释放签名占用的所有资源（包括预编译数据）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsUnregisterSignature(
    _In_ PWKD_MEMORY_SIGNATURE Signature
    );

//
// 根据名称查找已注册的签名
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MEMORY_SIGNATURE
MsFindSignatureByName(
    _In_ PCHAR Name
    );

//
// 根据ID查找已注册的签名
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MEMORY_SIGNATURE
MsFindSignatureById(
    _In_ ULONG SignatureId
    );

//
// 预编译指定的签名
// 对于持久化签名，通常在注册时自动调用
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsPrecompileSignature(
    _Inout_ PWKD_MEMORY_SIGNATURE Signature
    );

//
// 清理所有已注册的签名
// 驱动卸载时调用，确保无内存泄漏
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsCleanupAllSignatures(
    VOID
    );

//
// 获取签名统计信息
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsGetStatistics(
    _Out_ PULONG TotalCount,
    _Out_ PULONG PersistentCount,
    _Out_ PULONG TemporaryCount
    );

