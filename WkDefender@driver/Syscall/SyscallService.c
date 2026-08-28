#include "SyscallService.h"
#include "../Common/Utils.h"
#include "../Memory/MemorySignature.h"
#include "../Memory/MemoryScan.h"
#define IA32_LSTAR 0xC0000082

//
// 全局 SSDT 指针（通过 KeServiceDescriptorTable 获取）
//

static PVOID WkdSystemServiceDescriptorTable = NULL;

//
// 系统调用栈扩展判断表
// 某些系统调用会导致内核栈扩展，需要额外的空间
// 这里列出常见的需要栈扩展的系统调用号示例
//
static const ULONG g_StackExpendSyscalls[] = {
    0x00,  // NtAcceptConnectPort
    0x01,  // NtAccessCheck
    // ... 可以根据实际需要添加更多系统调用号
};

static const ULONG g_StackExpendSyscallCount = 
    sizeof(g_StackExpendSyscalls) / sizeof(g_StackExpendSyscalls[0]);



// .text:0000000140412584                           KiSystemServiceRepeat
// .text:0000000140412584 4C 8D 15 35 F3 9E 00      lea     r10, KeServiceDescriptorTable
// .text:000000014041258B 4C 8D 1D AE A4 8E 00      lea     r11, KeServiceDescriptorTableShadow
const WKD_MEMORY_SIGNATURE_DEFINE WkdMemorySignature_KeServiceDescriptorTable = {
    "KeServiceDescriptorTable",
     {0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x1D},
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF},
     10
};



//
// 判断内核栈是否扩展
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SsIsKernelStackExpanded(
    _In_ ULONG SyscallNumber
    )
{
    ULONG i = 0;

    // 遍历栈扩展系统调用列表
    for (i = 0; i < g_StackExpendSyscallCount; i++) {
        if (g_StackExpendSyscalls[i] == SyscallNumber) {
            return TRUE;
        }
    }

    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
PVOID SsGetSsdtBase(
    VOID
    )
{
    NTSTATUS status;
    PWKD_MEMORY_SIGNATURE sigKeServiceDescriptorTable = NULL;
    WKD_SCAN_RESULT scanResult;
    PVOID base = NULL;

    if (WkdSystemServiceDescriptorTable) {
        return WkdSystemServiceDescriptorTable;
    }

    // Windows 10 1803+ 默认启用 KVA Shadow，导致 IA32_LSTAR 指向 KiSystemCall64Shadow 而非原始函数 KiSystemCall64
    status = MsRegisterSignature(
        &WkdMemorySignature_KeServiceDescriptorTable,
        WkdMemorySignatureTemporary,
        &sigKeServiceDescriptorTable
    );

    status = MmScanSection(UtGetNtoskrnlBase(), ".text", sigKeServiceDescriptorTable, &scanResult);
    if (scanResult.Found) {
        base = scanResult.MatchAddress;
        base = *(PVOID*)(*(PULONG32)((ULONG64)base + 3) + (ULONG64)base + 7);
        InterlockedCompareExchangePointer(
            (PVOID volatile*)&WkdSystemServiceDescriptorTable,
            base,
            NULL
        );
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] SSDT: 0x%p\n", WkdSystemServiceDescriptorTable);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Get SSDT failed.\n");
        DbgBreakPoint();
    }

    return WkdSystemServiceDescriptorTable;
}