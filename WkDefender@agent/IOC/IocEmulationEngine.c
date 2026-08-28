/**************************************************/
/*  WkDefender IOC 引擎 — 模拟执行骨架实现          */
/**************************************************/

#include "IocEmulationEngine.h"

#include <stdio.h>
#include <string.h>
#include <ntstatus.h>

/**************************************************/
/*               OEP 启发式检测                     */
/**************************************************/

BOOLEAN
IocEmu_DetectOEP(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_opt_ PULONG OepOffset
    )
{
    SIZE_T i;

    if (!Buf || Len < 8) return FALSE;
    if (OepOffset) *OepOffset = 0;

    for (i = 0; i + 4 < Len; i++) {
        /* push ebp; mov ebp, esp   (55 8B EC) */
        if (Buf[i] == 0x55 && Buf[i + 1] == 0x8B && Buf[i + 2] == 0xEC) {
            if (OepOffset) *OepOffset = (ULONG)i;
            return TRUE;
        }
        /* mov edi, edi; push ebp; mov ebp, esp (8B FF 55 8B EC) */
        if (Buf[i] == 0x8B && Buf[i + 1] == 0xFF && Buf[i + 2] == 0x55 &&
            Buf[i + 3] == 0x8B && Buf[i + 4] == 0xEC) {
            if (OepOffset) *OepOffset = (ULONG)i + 2;
            return TRUE;
        }
        /* 64 位: sub rsp, imm8 (48 83 EC xx) */
        if (Buf[i] == 0x48 && Buf[i + 1] == 0x83 && Buf[i + 2] == 0xEC) {
            if (OepOffset) *OepOffset = (ULONG)i;
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*               API 分类                           */
/**************************************************/

NTSTATUS
IocEmu_CategorizeApi(
    _In_ PCWSTR DllName,
    _In_opt_ PCWSTR FuncName,
    _Out_ PWKD_EMU_API_CATEGORY Category
    )
{
    if (!DllName || !Category) return STATUS_INVALID_PARAMETER;
    *Category = WkdEmuApi_Unknown;

    if (wcsstr(DllName, L"ws2_32") || wcsstr(DllName, L"wininet") ||
        wcsstr(DllName, L"winhttp") || wcsstr(DllName, L"urlmon")) {
        *Category = WkdEmuApi_Network;
    } else if (wcsstr(DllName, L"advapi32")) {
        *Category = WkdEmuApi_Registry;
    } else if (wcsstr(DllName, L"crypt32") || wcsstr(DllName, L"bcrypt")) {
        *Category = WkdEmuApi_Crypto;
    } else if (wcsstr(DllName, L"kernel32") || wcsstr(DllName, L"ntdll")) {
        if (FuncName) {
            if (wcsstr(FuncName, L"CreateFile") || wcsstr(FuncName, L"WriteFile") ||
                wcsstr(FuncName, L"ReadFile") || wcsstr(FuncName, L"DeleteFile")) {
                *Category = WkdEmuApi_FileSystem;
            } else if (wcsstr(FuncName, L"Process") || wcsstr(FuncName, L"Thread") ||
                       wcsstr(FuncName, L"ShellExecute") || wcsstr(FuncName, L"WinExec")) {
                *Category = WkdEmuApi_Process;
            } else if (wcsstr(FuncName, L"Virtual") || wcsstr(FuncName, L"Heap")) {
                *Category = WkdEmuApi_Memory;
            } else if (wcsstr(FuncName, L"GetSystem") || wcsstr(FuncName, L"GetVersion") ||
                       wcsstr(FuncName, L"GetComputer")) {
                *Category = WkdEmuApi_SystemInfo;
            } else {
                *Category = WkdEmuApi_SystemInfo;
            }
        }
    } else if (wcsstr(DllName, L"user32")) {
        *Category = WkdEmuApi_SystemInfo;
    } else if (wcsstr(DllName, L"shell32")) {
        *Category = WkdEmuApi_Process;
    } else if (wcsstr(DllName, L"secur32") || wcsstr(DllName, L"sspicli")) {
        *Category = WkdEmuApi_Security;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               API 严重性评估                     */
/**************************************************/

NTSTATUS
IocEmu_AssessApiSeverity(
    _In_ PCWSTR DllName,
    _In_ PCWSTR FuncName,
    _Out_ PWKD_EMU_API_SEVERITY Severity
    )
{
    if (!DllName || !FuncName || !Severity) return STATUS_INVALID_PARAMETER;
    *Severity = WkdEmuSev_Benign;

    /* 注入/内存写/远程执行 → Critical */
    if (wcsstr(FuncName, L"CreateRemoteThread") ||
        wcsstr(FuncName, L"NtCreateThreadEx") ||
        wcsstr(FuncName, L"WriteProcessMemory") ||
        wcsstr(FuncName, L"NtWriteVirtualMemory") ||
        wcsstr(FuncName, L"QueueUserAPC") ||
        wcsstr(FuncName, L"SetThreadContext")) {
        *Severity = WkdEmuSev_Critical;
    } else if (wcsstr(FuncName, L"VirtualAllocEx") ||
               wcsstr(FuncName, L"VirtualProtectEx") ||
               wcsstr(FuncName, L"VirtualAlloc") ||
               wcsstr(FuncName, L"LoadLibrary") ||
               wcsstr(FuncName, L"GetProcAddress") ||
               wcsstr(FuncName, L"AdjustToken") ||
               wcsstr(FuncName, L"OpenProcess")) {
        *Severity = WkdEmuSev_High;
    } else if (wcsstr(FuncName, L"RegSetValue") ||
               wcsstr(FuncName, L"CreateService") ||
               wcsstr(FuncName, L"ShellExecute") ||
               wcsstr(FuncName, L"WinExec") ||
               wcsstr(FuncName, L"CreateProcess") ||
               wcsstr(FuncName, L"InternetOpen") ||
               wcsstr(FuncName, L"HttpSendRequest")) {
        *Severity = WkdEmuSev_Medium;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               模拟执行 (占位)                    */
/**************************************************/

NTSTATUS
IocEmu_EmulatePE(
    _In_ const BYTE*     Buf,
    _In_ SIZE_T          Len,
    _Out_ PWKD_EMU_RESULT Result
    )
{
    /* 依赖缺失: WHP/Unicorn/PhantomEmulator 模拟器后端。
     * 接入 PeUnpack 静态解包时，此函数填充解包字段后返回。 */
    if (!Buf || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    Result->State = WkdEmuState_Uninitialized;
    return STATUS_NOT_IMPLEMENTED;
}
