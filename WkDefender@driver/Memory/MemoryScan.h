#pragma once
#include "../Common/Constants.h"
#include "MemorySignature.h"
//
// 模块名称：内存扫描模块 (MemoryScan)
// 功能描述：提供基于特征码的PE内存扫描功能
// 主要用途：
//   - 获取内核模块基地址（如ntoskrnl.exe）
//   - 解析PE结构并定位指定节区
//   - 在节区内进行特征码模式匹配
// 使用示例：
//   // 1. 获取ntoskrnl基地址
//   PVOID ntBase = UtGetNtoskrnlBase();
//   
//   // 2. 定义特征码（建议使用签名管理器注册）
//   WKD_SIGNATURE_PATTERN* pSig = NULL;
//   NTSTATUS status = MsRegisterSignature(
//       "MyPattern", pattern, mask, length, 
//       SignatureTypePersistent, &pSig);
//   
//   // 3. 执行扫描
//   WKD_SCAN_RESULT result;
//   status = MmScanSection(ntBase, ".text", pSig, &result);
//



//
// PE节区信息结构
//
typedef struct _WKD_SECTION_INFO {
    PVOID BaseAddress;        // 节区基地址
    ULONG Size;               // 节区大小
    CHAR Name[8];             // 节区名称
} WKD_SECTION_INFO, * PWKD_SECTION_INFO;

//
// 内存扫描结果
//
typedef struct _WKD_SCAN_RESULT {
    PVOID MatchAddress;       // 匹配地址
    ULONG MatchOffset;        // 相对于扫描起始地址的偏移
    BOOLEAN Found;            // 是否找到匹配
} WKD_SCAN_RESULT, * PWKD_SCAN_RESULT;

//
// 注意：签名的生命周期管理（注册、注销、预编译）已统一由 MemorySignature 模块负责
// - 请使用 MsRegisterSignature() 注册签名（自动尝试预编译）
// - 请使用 MsUnregisterSignature() 注销签名（自动释放预编译资源）
// - 内部辅助函数 MspFreePrecompiledPattern() 不对外暴露
//

//
// 解析PE文件获取指定节区信息
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmParsePeSection(
    _In_ PVOID ImageBase,
    _In_ PCHAR SectionName,
    _Out_ PWKD_SECTION_INFO SectionInfo
    );

//
// 在指定节区内进行特征码扫描（粗粒度）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmScanSection(
    _In_ PVOID ImageBase,
    _In_ PCHAR SectionName,
    _In_ PWKD_MEMORY_SIGNATURE Signature,
    _Out_ PWKD_SCAN_RESULT ScanResult
    );

//
// 在指定地址范围内进行特征码扫描（细粒度）
// 适用于已知函数地址或特定内存区域的扫描
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmScanMemoryRange(
    _In_ PVOID StartAddress,            // 扫描起始地址
    _In_opt_ SIZE_T RangeSize,          // 扫描范围大小
    _In_ PWKD_MEMORY_SIGNATURE Signature,
    _Out_ PWKD_SCAN_RESULT ScanResult
    );


