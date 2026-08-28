/**************************************************/
/*  WkDefender IOC — 注册表注入向量检测实现          */
/**************************************************/

#include "IocRegistryVector.h"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

/**************************************************/
/*               常量 (注册表路径)                   */
/**************************************************/

#define IRV_WINDOWS_KEY     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define IRV_IFEO_KEY        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define IRV_APPINIT_VALUE   L"AppInit_DLLs"
#define IRV_LOADAPPINIT     L"LoadAppInit_DLLs"
#define IRV_DEBUGGER        L"Debugger"
#define IRV_GLOBALFLAG      L"GlobalFlag"
#define IRV_VERIFIERDLLS    L"VerifierDlls"

/**************************************************/
/*               内部辅助                           */
/**************************************************/

/* 读 REG_DWORD 值; 返回是否成功读到 */
static
BOOLEAN
IrvpReadDword(
    _In_ HKEY Root,
    _In_ PCWSTR SubKey,
    _In_ PCWSTR Value,
    _In_ REGSAM Access,
    _Out_ PDWORD Out
    )
{
    HKEY hKey;
    DWORD data = 0;
    DWORD size = sizeof(data);
    DWORD type = 0;
    LONG rc;

    if (!Out) {
        return FALSE;
    }
    *Out = 0;

    rc = RegOpenKeyExW(Root, SubKey, 0, KEY_READ | Access, &hKey);
    if (rc != ERROR_SUCCESS) {
        return FALSE;
    }
    rc = RegQueryValueExW(hKey, Value, NULL, &type, (LPBYTE)&data, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_DWORD) {
        return FALSE;
    }
    *Out = data;
    return TRUE;
}

/* 读 REG_SZ 值 (非空才返回 TRUE); 保证 NUL 结尾 */
static
BOOLEAN
IrvpReadString(
    _In_ HKEY Root,
    _In_ PCWSTR SubKey,
    _In_ PCWSTR Value,
    _In_ REGSAM Access,
    _Out_writes_(BufSize) WCHAR* Out,
    _In_ ULONG BufSize
    )
{
    HKEY hKey;
    DWORD size = BufSize * sizeof(WCHAR);
    DWORD type = 0;
    LONG rc;

    if (!Out || BufSize == 0) {
        return FALSE;
    }
    Out[0] = L'\0';

    rc = RegOpenKeyExW(Root, SubKey, 0, KEY_READ | Access, &hKey);
    if (rc != ERROR_SUCCESS) {
        return FALSE;
    }
    rc = RegQueryValueExW(hKey, Value, NULL, &type, (LPBYTE)Out, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_SZ) {
        Out[0] = L'\0';
        return FALSE;
    }
    Out[BufSize - 1] = L'\0';   /* RegQueryValueExW 可能不补 NUL */
    return (Out[0] != L'\0');
}

/* 填写一条向量记录的公共字段 */
static
VOID
IrvpFillVector(
    _Out_ PWKD_REGISTRY_VECTOR Vec,
    _In_ WKD_REG_VECTOR_TYPE Type,
    _In_ PCWSTR RegistryPath,
    _In_ PCWSTR ValueName,
    _In_ BOOLEAN Enabled,
    _In_ BOOLEAN Suspicious,
    _In_ PCWSTR Reason
    )
{
    RtlZeroMemory(Vec, sizeof(*Vec));
    Vec->Type = Type;
    Vec->IsEnabled = Enabled;
    Vec->IsSuspicious = Suspicious;
    if (RegistryPath) {
        wcsncpy_s(Vec->RegistryPath, IRV_PATH_BUFFER_MAX, RegistryPath, _TRUNCATE);
    }
    if (ValueName) {
        wcsncpy_s(Vec->ValueName, 64, ValueName, _TRUNCATE);
    }
    if (Reason) {
        wcsncpy_s(Vec->Reason, 256, Reason, _TRUNCATE);
    }
}

/**************************************************/
/*               函数实现                           */
/**************************************************/

ULONG
IrvCheckAppInitDlls(
    _Out_writes_to_(*Count, *Count) PWKD_REGISTRY_VECTOR Vectors,
    _In_ ULONG Max,
    _Out_opt_ PULONG Count
    )
/*++
Routine Description:
    检查 AppInit_DLLs 注册表注入向量 (64 位 + WoW64 双视图)。

    AppInit_DLLs 由 HKLM\...\Windows 键的 AppInit_DLLs / LoadAppInit_DLLs
    控制, 是 T1546.010 持久化注入向量。LoadAppInit_DLLs=1 且配置了 DLL
    才真正生效。

Arguments:
    Vectors - 输出向量数组 (必填)。
    Max     - 数组容量。
    Count   - 实际写入条数 (可为 NULL)。

Return Value:
    写入的向量条数。
--*/
{
    ULONG written = 0;
    DWORD load64 = 0;
    DWORD load32 = 0;

    if (!Vectors || Max == 0) {
        if (Count) *Count = 0;
        return 0;
    }

    /* 64 位视图 */
    IrvpReadDword(HKEY_LOCAL_MACHINE, IRV_WINDOWS_KEY, IRV_LOADAPPINIT,
                  KEY_WOW64_64KEY, &load64);
    if (IrvpReadString(HKEY_LOCAL_MACHINE, IRV_WINDOWS_KEY, IRV_APPINIT_VALUE,
                       KEY_WOW64_64KEY, Vectors[written].DllPath,
                       IRV_DLL_BUFFER_MAX)) {
        if (written < Max) {
            IrvpFillVector(&Vectors[written], WkdRv_AppInitDlls,
                           IRV_WINDOWS_KEY, IRV_APPINIT_VALUE,
                           (load64 != 0), (load64 != 0),
                           (load64 != 0)
                               ? L"AppInit_DLLs 已配置且启用 (LoadAppInit_DLLs=1)"
                               : L"AppInit_DLLs 已配置但未启用 (LoadAppInit_DLLs=0)");
            written++;
        }
    }

    /* WoW64 (32 位) 视图 */
    if (written < Max) {
        IrvpReadDword(HKEY_LOCAL_MACHINE, IRV_WINDOWS_KEY, IRV_LOADAPPINIT,
                      KEY_WOW64_32KEY, &load32);
        if (IrvpReadString(HKEY_LOCAL_MACHINE, IRV_WINDOWS_KEY, IRV_APPINIT_VALUE,
                           KEY_WOW64_32KEY, Vectors[written].DllPath,
                           IRV_DLL_BUFFER_MAX)) {
            IrvpFillVector(&Vectors[written], WkdRv_AppInitDllsWoW64,
                           IRV_WINDOWS_KEY, IRV_APPINIT_VALUE,
                           (load32 != 0), (load32 != 0),
                           (load32 != 0)
                               ? L"WoW64 AppInit_DLLs 已配置且启用"
                               : L"WoW64 AppInit_DLLs 已配置但未启用");
            written++;
        }
    }

    if (Count) *Count = written;
    return written;
}

ULONG
IrvCheckIfeo(
    _Out_writes_to_(*Count, *Count) PWKD_REGISTRY_VECTOR Vectors,
    _In_ ULONG Max,
    _Out_opt_ PULONG Count
    )
/*++
Routine Description:
    检查 Image File Execution Options 注入向量。

    枚举 HKLM\...\Image File Execution Options 全部子键, 检测:
      - Debugger 值 (经典 IFEO 劫持, 恶意可劫持目标进程启动);
      - GlobalFlag + VerifierDlls (Application Verifier 滥用).

Arguments:
    Vectors - 输出向量数组 (必填)。
    Max     - 数组容量。
    Count   - 实际写入条数 (可为 NULL)。

Return Value:
    写入的向量条数。
--*/
{
    HKEY hIfeo;
    ULONG written = 0;
    DWORD index = 0;
    LONG rc;

    if (!Vectors || Max == 0) {
        if (Count) *Count = 0;
        return 0;
    }

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, IRV_IFEO_KEY, 0,
                       KEY_READ | KEY_WOW64_64KEY, &hIfeo);
    if (rc != ERROR_SUCCESS) {
        if (Count) *Count = 0;
        return 0;
    }

    for (index = 0; written < Max; index++) {
        WCHAR subKey[IRV_PATH_BUFFER_MAX];
        WCHAR fullPath[IRV_PATH_BUFFER_MAX + 64];
        WCHAR debugger[IRV_DLL_BUFFER_MAX];
        WCHAR verifierDlls[IRV_DLL_BUFFER_MAX];
        DWORD subKeySize = IRV_PATH_BUFFER_MAX;

        rc = RegEnumKeyExW(hIfeo, index, subKey, &subKeySize,
                           NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (rc != ERROR_SUCCESS) {
            continue;
        }

        _snwprintf_s(fullPath, ARRAYSIZE(fullPath), _TRUNCATE,
                     L"%s\\%s", IRV_IFEO_KEY, subKey);

        /* Debugger 劫持 */
        if (IrvpReadString(HKEY_LOCAL_MACHINE, fullPath, IRV_DEBUGGER,
                           KEY_WOW64_64KEY, debugger, IRV_DLL_BUFFER_MAX)) {
            IrvpFillVector(&Vectors[written], WkdRv_IfeoDebugger,
                           fullPath, IRV_DEBUGGER, TRUE, TRUE,
                           L"IFEO Debugger 劫持配置");
            wcsncpy_s(Vectors[written].DllPath, IRV_DLL_BUFFER_MAX,
                      debugger, _TRUNCATE);
            written++;
            if (written >= Max) {
                break;
            }
        }

        /* GlobalFlag + VerifierDlls */
        {
            HKEY hSub;
            DWORD globalFlag = 0;
            DWORD flagSize = sizeof(globalFlag);
            DWORD type = 0;

            rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath, 0,
                               KEY_READ | KEY_WOW64_64KEY, &hSub);
            if (rc == ERROR_SUCCESS) {
                rc = RegQueryValueExW(hSub, IRV_GLOBALFLAG, NULL, &type,
                                      (LPBYTE)&globalFlag, &flagSize);
                if (rc == ERROR_SUCCESS && type == REG_DWORD && globalFlag != 0) {
                    DWORD verifierLen = IRV_DLL_BUFFER_MAX * sizeof(WCHAR);

                    rc = RegQueryValueExW(hSub, IRV_VERIFIERDLLS, NULL, &type,
                                          (LPBYTE)verifierDlls, &verifierLen);
                    if (rc == ERROR_SUCCESS && type == REG_SZ) {
                        verifierDlls[IRV_DLL_BUFFER_MAX - 1] = L'\0';
                        if (verifierDlls[0] != L'\0' && written < Max) {
                            IrvpFillVector(&Vectors[written],
                                           WkdRv_IfeoVerifierDlls,
                                           fullPath, IRV_VERIFIERDLLS,
                                           TRUE, TRUE,
                                           L"IFEO Application Verifier DLL 滥用");
                            wcsncpy_s(Vectors[written].DllPath, IRV_DLL_BUFFER_MAX,
                                      verifierDlls, _TRUNCATE);
                            written++;
                        }
                    }
                }
                RegCloseKey(hSub);
            }
        }
    }

    RegCloseKey(hIfeo);
    if (Count) *Count = written;
    return written;
}

ULONG
IrvCheckAll(
    _Out_writes_to_(*Count, *Count) PWKD_REGISTRY_VECTOR Vectors,
    _In_ ULONG Max,
    _Out_opt_ PULONG Count
    )
/*++
Routine Description:
    全量注册表注入向量检查 (AppInit_DLLs + IFEO)。

Arguments:
    Vectors - 输出向量数组 (必填)。
    Max     - 数组容量。
    Count   - 实际写入条数 (可为 NULL)。

Return Value:
    写入的向量条数。
--*/
{
    ULONG total = 0;
    ULONG subCount = 0;

    if (!Vectors || Max == 0) {
        if (Count) *Count = 0;
        return 0;
    }

    total += IrvCheckAppInitDlls(Vectors, Max, &subCount);
    if (total < Max) {
        total += IrvCheckIfeo(Vectors + total, Max - total, &subCount);
    }

    if (Count) *Count = total;
    return total;
}
