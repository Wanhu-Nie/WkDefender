/**************************************************/
/*  WkDefender 驱动安装器 — 步骤 7 实现 (runas 自提权) */
/**************************************************/

#include "Install.h"
#include <shlobj.h>
#include <stdio.h>
#include <shellapi.h>
#include <fltUser.h>
#include <wintrust.h>

/* ntstatus.h 在某些 SDK C 配置下不定义 NT_SUCCESS 宏，自行兜底 */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")

/* 生产环境应置 1 强制要求 .sys 签名；开发期置 0（仅告警） */
#define WKD_REQUIRE_SIGNATURE  0

/* .sys 预期路径：System32\drivers\WkDefender@driver.sys */
static VOID WkdGetDriverSysPath(_Out_ WCHAR Path[MAX_PATH])
{
    UINT n = GetSystemDirectoryW(Path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { Path[0] = L'\0'; return; }
    if (Path[n - 1] != L'\\') wcscat_s(Path, MAX_PATH, L"\\");
    wcscat_s(Path, MAX_PATH, L"drivers\\");
    wcscat_s(Path, MAX_PATH, WKD_DRIVER_SYS_NAME);
}

/* 校验 .sys 数字签名（WinVerifyTrust）。返回 TRUE=签名有效 */
static BOOLEAN WkdVerifyDriverSignature(_In_ LPCWSTR SysPath)
{
    WINTRUST_FILE_INFO fileInfo;
    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = SysPath;
    fileInfo.hFile = NULL;

    /* WINTRUST_ACTION_GENERIC_VERIFY_V2 在一些 SDK C 编译下未声明，定义 GUID 字面量 */
    static const GUID kWinTrustGenericVerifyV2 =
        { 0x00AAC56B, 0xCD44, 0x11d0, { 0x8C, 0xC2, 0x00, 0x80, 0xC7, 0x39, 0xE2, 0x5B } };
    GUID policyGUID = kWinTrustGenericVerifyV2;
    WINTRUST_DATA wtd;
    RtlZeroMemory(&wtd, sizeof(wtd));
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwProvFlags = WTD_SAFER_FLAG;

    LONG res = WinVerifyTrust(NULL, &policyGUID, &wtd);
    return (res == ERROR_SUCCESS);
}

/* 写 canonical Instances 注册表（与 INF 一致） */
static NTSTATUS WkdWriteInstancesRegistry(VOID)
{
    HKEY svcKey = NULL;
    LONG lr = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\" WKD_DRIVER_SERVICE_NAME,
        0, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, &svcKey);
    if (lr != ERROR_SUCCESS) return STATUS_ACCESS_DENIED;

    HKEY instKey = NULL;
    lr = RegCreateKeyExW(svcKey, L"Instances", 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &instKey, NULL);
    if (lr == ERROR_SUCCESS) {
        RegSetValueExW(instKey, L"DefaultInstance", 0, REG_SZ,
                       (const BYTE*)WKD_DRIVER_INSTANCE_NAME,
                       (DWORD)(wcslen(WKD_DRIVER_INSTANCE_NAME) + 1) * sizeof(WCHAR));
        RegCloseKey(instKey);
    }

    WCHAR subKey[256];
    _snwprintf_s(subKey, ARRAYSIZE(subKey), _TRUNCATE,
                 L"Instances\\%s", WKD_DRIVER_INSTANCE_NAME);
    HKEY subKeyH = NULL;
    lr = RegCreateKeyExW(svcKey, subKey, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &subKeyH, NULL);
    if (lr == ERROR_SUCCESS) {
        RegSetValueExW(subKeyH, L"Altitude", 0, REG_SZ,
                       (const BYTE*)WKD_DRIVER_ALTITUDE,
                       (DWORD)(wcslen(WKD_DRIVER_ALTITUDE) + 1) * sizeof(WCHAR));
        DWORD flags = 0;
        RegSetValueExW(subKeyH, L"Flags", 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags));
        RegCloseKey(subKeyH);
    }
    RegCloseKey(svcKey);
    return STATUS_SUCCESS;
}

BOOLEAN
WkdIsElevated(
    VOID
    )
{
    return (BOOLEAN)IsUserAnAdmin();
}

NTSTATUS WkdInstallAndLoadDriver(VOID)
{
    WCHAR sysPath[MAX_PATH];
    WkdGetDriverSysPath(sysPath);
    if (GetFileAttributesW(sysPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[Install] Driver sys not found: %ls\n", sysPath);
        printf("[Install] Please build/place WkDefender@driver.sys under drivers\\ first.\n");
        return STATUS_NOT_FOUND;
    }

    /* 签名校验（开发期降级） */
    if (!WkdVerifyDriverSignature(sysPath)) {
        printf("[Install] WARNING: driver signature invalid: %ls\n", sysPath);
#if WKD_REQUIRE_SIGNATURE
        return STATUS_INVALID_SIGNATURE;
#else
        printf("[Install] (dev) continuing without valid signature...\n");
#endif
    }

    /* SCM 注册 FILE_SYSTEM_DRIVER */
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        printf("[Install] OpenSCManager failed: %u\n", GetLastError());
        return STATUS_ACCESS_DENIED;
    }

    SC_HANDLE hSvc = CreateServiceW(
        hSCM, WKD_DRIVER_SERVICE_NAME, WKD_DRIVER_DISPLAY_NAME,
        SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        sysPath, L"FSFilter Anti-Virus", NULL, NULL, NULL, NULL);
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hSvc = OpenServiceW(hSCM, WKD_DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
            printf("[Install] Service already exists, reusing.\n");
        } else {
            printf("[Install] CreateService failed: %u\n", err);
            CloseServiceHandle(hSCM);
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* 写 canonical Instances（FltMgr 加载必需） */
    WkdWriteInstancesRegistry();

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    /* 加载 minifilter（FilterLoad，而非 StartServiceW） */
    HRESULT hr = FilterLoad(WKD_DRIVER_SERVICE_NAME);
    if (FAILED(hr)) {
        printf("[Install] FilterLoad failed: 0x%08X (driver not loaded)\n", hr);
        /* 兜底：尝试 StartServiceW 加载 .sys 映像 */
        hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (hSCM) {
            hSvc = OpenServiceW(hSCM, WKD_DRIVER_SERVICE_NAME, SERVICE_START);
            if (hSvc) {
                if (StartServiceW(hSvc, 0, NULL))
                    printf("[Install] StartServiceW fallback succeeded.\n");
                CloseServiceHandle(hSvc);
            }
            CloseServiceHandle(hSCM);
        }
        if (FAILED(hr)) return STATUS_UNSUCCESSFUL;
    }

    printf("[Install] Driver installed and loaded: %ls\n", WKD_DRIVER_SERVICE_NAME);
    return STATUS_SUCCESS;
}

NTSTATUS WkdUninstallDriver(VOID)
{
    /* 先卸载 minifilter */
    FilterUnload(WKD_DRIVER_SERVICE_NAME);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, WKD_DRIVER_SERVICE_NAME,
                                      DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS status;
            if (ControlService(hSvc, SERVICE_CONTROL_STOP, &status)) {
                /* stopped */
            }
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    /* 删除 Instances 注册表 */
    HKEY svcKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\" WKD_DRIVER_SERVICE_NAME,
            0, KEY_CREATE_SUB_KEY | DELETE, &svcKey) == ERROR_SUCCESS) {
        RegDeleteTreeW(svcKey, L"Instances");
        RegCloseKey(svcKey);
    }
    printf("[Install] Driver uninstalled.\n");
    return STATUS_SUCCESS;
}

BOOLEAN
WkdRelaunchAsAdminForDriverInstall(
    VOID
    )
{
    WCHAR selfPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, selfPath, MAX_PATH) == 0) return FALSE;

    SHELLEXECUTEINFOW sei;
    RtlZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = selfPath;
    sei.lpParameters = L"--install-driver";
    sei.nShow = SW_SHOW;

    if (!ShellExecuteExW(&sei)) {
        printf("[Install] runas relaunch failed: %u\n", GetLastError());
        return FALSE;
    }

    /* 同步等待提权子进程完成安装 */
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    }
    return TRUE;
}

NTSTATUS
EnsureDriverReady(
    _In_ int Argc, 
    _In_ char** Argv
    )
{
    /* 解析 --install-driver（提权子进程标识） */
    BOOLEAN installArg = FALSE;

    for (int i = 1; i < Argc; i++) {
        if (_stricmp(Argv[i], "--install-driver") == 0) { installArg = TRUE; break; }
    }

    if (installArg) {
        /* 提权子进程：直接安装并加载，完成后退出（不重复初始化）。
         * 返回 STATUS_REBOOTED_FOR_INSTALL 使 main 统一 exit（与"未提权原进程
         * 发 runas 后退出"同码），避免子进程再启动第二个 agent 实例竞争 ALPC。 */
        printf("[Install] Elevated child: installing driver...\n");
        NTSTATUS st = WkdInstallAndLoadDriver();
        if (!NT_SUCCESS(st)) {
            printf("[Install] Driver install failed: 0x%X\n", st);
            getchar();
        }
        return STATUS_REBOOTED_FOR_INSTALL;
    }

    if (!WkdIsElevated()) {
        /* 未提权：发起 runas 提权子进程接管安装，原进程退出 */
        printf("[Install] Not elevated. Relaunching as admin for driver install...\n");
        WkdRelaunchAsAdminForDriverInstall();
        return STATUS_REBOOTED_FOR_INSTALL;   /* 原进程据此 exit */
    }

    /* 已管理员：直接安装并加载，继续初始化 */
    NTSTATUS st = WkdInstallAndLoadDriver();
    if (!NT_SUCCESS(st)) {
        printf("[Install] Driver install failed: 0x%X (continuing without kernel YARA)\n", st);
        /* 非致命：agent 仍可运行用户态机制 B，仅文件扫描回路 A 不可用 */
    }
    return STATUS_SUCCESS;
}
