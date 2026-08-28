/**************************************************/
/*  WkDefender Common — 路径规范化与系统路径判定实现  */
/**************************************************/

#include "PathUtil.h"
#include <string.h>
#include <wchar.h>

/**************************************************/
/*               内部辅助                           */
/**************************************************/

/* 大小写不敏感前缀比较 */
static
BOOLEAN
PathpPrefixEquals(
    _In_ PCWSTR Str,
    _In_ PCWSTR Prefix
    )
{
    return _wcsnicmp(Str, Prefix, wcslen(Prefix)) == 0;
}

/* 就地转小写 */
static
VOID
PathpToLowerInPlace(
    _Inout_ WCHAR* Str
    )
{
    for (; *Str != L'\0'; Str++) {
        *Str = (WCHAR)towlower(*Str);
    }
}

/* 驱动号映射: \Device\HarddiskVolumeN → 盘符 (首次使用构建缓存) */

typedef struct _PATHP_DRIVE_ENTRY {
    WCHAR DevicePath[PATHP_PATH_BUFFER_MAX];
    WCHAR DriveLetter[4];               /* 如 "C:" */
} PATHP_DRIVE_ENTRY;

static PATHP_DRIVE_ENTRY g_PathpDriveTable[26];
static ULONG g_PathpDriveCount = 0;
static BOOLEAN g_PathpDriveInit = FALSE;

static
VOID
PathpBuildDriveTable(
    VOID
    )
{
    WCHAR drives[512];
    WCHAR devicePath[PATHP_PATH_BUFFER_MAX];
    DWORD driveCount = GetLogicalDriveStringsW(512, drives);
    DWORD pos = 0;

    g_PathpDriveCount = 0;
    while (pos < driveCount && drives[pos] != L'\0' &&
           g_PathpDriveCount < ARRAYSIZE(g_PathpDriveTable)) {
        WCHAR* drive = &drives[pos];
        WCHAR letter[4] = { drive[0], drive[1], L'\0' };    /* "C:" */
        DWORD len = QueryDosDeviceW(letter, devicePath, PATHP_PATH_BUFFER_MAX);

        if (len > 0 && len < PATHP_PATH_BUFFER_MAX) {
            PathpToLowerInPlace(devicePath);
            wcsncpy_s(g_PathpDriveTable[g_PathpDriveCount].DevicePath,
                      PATHP_PATH_BUFFER_MAX, devicePath, _TRUNCATE);
            wcsncpy_s(g_PathpDriveTable[g_PathpDriveCount].DriveLetter,
                      4, letter, _TRUNCATE);
            g_PathpDriveCount++;
        }
        pos += (DWORD)wcslen(drive) + 1;
    }
    g_PathpDriveInit = TRUE;
}

/* 查找设备前缀对应盘符; 未找到返回 FALSE */
static
BOOLEAN
PathpResolveDevicePrefix(
    _In_ PCWSTR DevicePrefix,
    _Out_writes_(4) WCHAR* DriveOut
    )
{
    ULONG i;

    if (!g_PathpDriveInit) {
        PathpBuildDriveTable();
    }
    for (i = 0; i < g_PathpDriveCount; i++) {
        if (PathpPrefixEquals(DevicePrefix, g_PathpDriveTable[i].DevicePath)) {
            wcsncpy_s(DriveOut, 4, g_PathpDriveTable[i].DriveLetter, _TRUNCATE);
            return TRUE;
        }
    }
    return FALSE;
}

/* 系统 DLL 名单 (搜索顺序劫持 / 仿冒检测共用) */
static const WCHAR* const g_PathpSystemDllNames[] = {
    L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
    L"user32.dll", L"gdi32.dll", L"advapi32.dll",
    L"ole32.dll", L"shell32.dll", L"combase.dll",
    L"msvcrt.dll", L"ws2_32.dll", L"wininet.dll"
};

/* 系统路径缓存 (首次使用构建) */

typedef struct _PATHP_SYSTEM_PATHS {
    WCHAR SystemDir[PATHP_PATH_BUFFER_MAX];
    WCHAR WindowsDir[PATHP_PATH_BUFFER_MAX];
    WCHAR TempDir[PATHP_PATH_BUFFER_MAX];
    WCHAR UserProfile[PATHP_PATH_BUFFER_MAX];
} PATHP_SYSTEM_PATHS;

static PATHP_SYSTEM_PATHS g_PathpPaths;
static BOOLEAN g_PathpPathsInit = FALSE;

static
VOID
PathpInitSystemPaths(
    VOID
    )
{
    WCHAR buf[MAX_PATH];

    if (GetSystemDirectoryW(buf, MAX_PATH) > 0) {
        WkdNormalizePath(buf, g_PathpPaths.SystemDir, PATHP_PATH_BUFFER_MAX);
    }
    if (GetWindowsDirectoryW(buf, MAX_PATH) > 0) {
        WkdNormalizePath(buf, g_PathpPaths.WindowsDir, PATHP_PATH_BUFFER_MAX);
    }
    if (GetTempPathW(MAX_PATH, buf) > 0) {
        WkdNormalizePath(buf, g_PathpPaths.TempDir, PATHP_PATH_BUFFER_MAX);
    }
    if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH) > 0) {
        WkdNormalizePath(buf, g_PathpPaths.UserProfile, PATHP_PATH_BUFFER_MAX);
    }
    g_PathpPathsInit = TRUE;
}

/* Levenshtein 编辑距离 (输入长度上限 64, 长度差快路径) */
static
SIZE_T
PathpLevenshtein(
    _In_ PCWSTR S1,
    _In_ PCWSTR S2
    )
{
    const SIZE_T MAX_LEN = PATHP_LEVENSHTEIN_MAX;
    SIZE_T d[PATHP_LEVENSHTEIN_MAX + 1][PATHP_LEVENSHTEIN_MAX + 1];
    SIZE_T len1 = wcslen(S1);
    SIZE_T len2 = wcslen(S2);
    SIZE_T i;
    SIZE_T j;

    if (len1 > MAX_LEN) len1 = MAX_LEN;
    if (len2 > MAX_LEN) len2 = MAX_LEN;

    /* 长度差超过 3 不可能在 2 以内, 直接返回 */
    if (len1 > len2 + 3 || len2 > len1 + 3) {
        return (len1 > len2) ? len1 : len2;
    }

    for (i = 0; i <= len1; i++) d[i][0] = i;
    for (j = 0; j <= len2; j++) d[0][j] = j;

    for (i = 1; i <= len1; i++) {
        for (j = 1; j <= len2; j++) {
            SIZE_T cost = (towlower(S1[i - 1]) == towlower(S2[j - 1])) ? 0 : 1;
            SIZE_T del = d[i - 1][j] + 1;
            SIZE_T ins = d[i][j - 1] + 1;
            SIZE_T sub = d[i - 1][j - 1] + cost;
            SIZE_T m = (del < ins) ? del : ins;

            d[i][j] = (m < sub) ? m : sub;
        }
    }
    return d[len1][len2];
}

/**************************************************/
/*               函数实现                           */
/**************************************************/

NTSTATUS
WkdNormalizePath(
    _In_ PCWSTR Path,
    _Out_writes_(OutLen) WCHAR* Out,
    _In_ ULONG OutLen
    )
/*++
Routine Description:
    将 NT/设备/扩展前缀路径规范化为标准 Win32 路径 (小写, 无尾斜杠)。

    处理:
      1. 去除 \\?\ / \??\ / \\.\ 前缀;
      2. \SystemRoot\ 解析为 Windows 目录;
      3. \Device\HarddiskVolumeN\ 经 QueryDosDevice 映射为盘符;
      4. '/' 统一为 '\';
      5. 拆分组件, 规范 . 与 .. (不越过根);
      6. 统一小写; 7. 去除尾斜杠。

Arguments:
    Path    - 输入路径 (可为 NT 风格或 Win32 风格)。
    Out     - 输出缓冲区 (必填)。
    OutLen  - 输出缓冲区容量 (WCHAR 数, 含结尾 NUL)。

Return Value:
    STATUS_SUCCESS; STATUS_BUFFER_TOO_SMALL; STATUS_INVALID_PARAMETER。
--*/
{
    WCHAR work[PATHP_PATH_BUFFER_MAX];
    WCHAR parts[32][PATHP_PATH_BUFFER_MAX];
    ULONG partCount = 0;
    SIZE_T len;
    ULONG idx;
    BOOLEAN isUNC;
    WCHAR* tok;
    WCHAR* save = NULL;

    if (!Path || !Out || OutLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    len = wcslen(Path);
    if (len >= PATHP_PATH_BUFFER_MAX) {
        len = PATHP_PATH_BUFFER_MAX - 1;
    }
    wcsncpy_s(work, PATHP_PATH_BUFFER_MAX, Path, len);
    work[len] = L'\0';

    /* 1. 去扩展/设备前缀 */
    if (PathpPrefixEquals(work, L"\\\\?\\") ||
        PathpPrefixEquals(work, L"\\??\\") ||
        PathpPrefixEquals(work, L"\\\\.\\")) {
        len = wcslen(work);
        if (len > 4) {
            memmove(work, work + 4, (len - 4 + 1) * sizeof(WCHAR));
        }
    }

    /* 2. \SystemRoot\ → Windows 目录 */
    if (PathpPrefixEquals(work, L"\\SystemRoot\\")) {
        WCHAR winDir[MAX_PATH];
        WCHAR rest[PATHP_PATH_BUFFER_MAX];
        if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
            wcsncpy_s(rest, PATHP_PATH_BUFFER_MAX, work + 12, _TRUNCATE);
            _snwprintf_s(work, PATHP_PATH_BUFFER_MAX, _TRUNCATE,
                         L"%ls\\%ls", winDir, rest);
        }
    }

    /* 3. \Device\HarddiskVolumeN\ → 盘符 */
    if (PathpPrefixEquals(work, L"\\Device\\HarddiskVolume")) {
        const SIZE_T kDevPrefixLen = wcslen(L"\\Device\\HarddiskVolume");
        SIZE_T volEnd = kDevPrefixLen;
        len = wcslen(work);

        while (volEnd < len && work[volEnd] >= L'0' && work[volEnd] <= L'9') {
            volEnd++;
        }
        if (volEnd > kDevPrefixLen && volEnd < len && work[volEnd] == L'\\') {
            WCHAR devicePrefix[PATHP_PATH_BUFFER_MAX];
            WCHAR drive[4];
            WCHAR rest[PATHP_PATH_BUFFER_MAX];

            wcsncpy_s(devicePrefix, PATHP_PATH_BUFFER_MAX, work, volEnd);
            devicePrefix[volEnd] = L'\0';
            PathpToLowerInPlace(devicePrefix);

            if (PathpResolveDevicePrefix(devicePrefix, drive)) {
                wcsncpy_s(rest, PATHP_PATH_BUFFER_MAX, work + volEnd, _TRUNCATE);
                _snwprintf_s(work, PATHP_PATH_BUFFER_MAX, _TRUNCATE,
                             L"%ls%ls", drive, rest);
            }
        }
    }

    /* 4. '/' → '\' */
    for (idx = 0; work[idx] != L'\0'; idx++) {
        if (work[idx] == L'/') {
            work[idx] = L'\\';
        }
    }

    /* 5. 拆分组件, 规范 . / .. */
    isUNC = (work[0] == L'\\' && work[1] == L'\\');
    partCount = 0;
    save = NULL;

    for (tok = wcstok_s(work, L"\\", &save);
         tok != NULL;
         tok = wcstok_s(NULL, L"\\", &save)) {
        if (tok[0] == L'\0' || wcscmp(tok, L".") == 0) {
            continue;
        }
        if (wcscmp(tok, L"..") == 0) {
            /* 不越过根 (盘符/UNC 服务器) */
            if (partCount > 1) {
                partCount--;
            }
            continue;
        }
        if (partCount >= ARRAYSIZE(parts)) {
            break;      /* 深度防护 */
        }
        wcsncpy_s(parts[partCount], PATHP_PATH_BUFFER_MAX, tok, _TRUNCATE);
        partCount++;
    }

    /* 6. 重组 + 小写 + 去尾斜杠 */
    {
        WCHAR result[PATHP_PATH_BUFFER_MAX];
        ULONG o = 0;
        ULONG i;

        if (isUNC) {
            result[o++] = L'\\';
            result[o++] = L'\\';
        }
        for (i = 0; i < partCount; i++) {
            SIZE_T segLen = wcslen(parts[i]);

            if (o > (isUNC ? 2 : 0)) {
                result[o++] = L'\\';
            }
            if (o + segLen + 1 >= PATHP_PATH_BUFFER_MAX) {
                break;
            }
            wcscpy_s(&result[o], PATHP_PATH_BUFFER_MAX - o, parts[i]);
            o += (ULONG)segLen;
        }
        result[o] = L'\0';
        wcscpy_s(work, PATHP_PATH_BUFFER_MAX, result);
    }

    PathpToLowerInPlace(work);

    len = wcslen(work);
    if (len > 3 && work[len - 1] == L'\\') {
        work[len - 1] = L'\0';
    }

    if (wcslen(work) + 1 > OutLen) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    wcscpy_s(Out, OutLen, work);
    return STATUS_SUCCESS;
}

BOOLEAN
WkdIsSystemDirectory(
    _In_ PCWSTR Path
    )
/*++
Routine Description:
    判定路径是否位于系统目录 (system32) 或 Windows 目录下。

Arguments:
    Path - 输入路径。

Return Value:
    TRUE 表示位于系统/Windows 目录。
--*/
{
    WCHAR norm[PATHP_PATH_BUFFER_MAX];

    if (!Path) {
        return FALSE;
    }
    if (WkdNormalizePath(Path, norm, PATHP_PATH_BUFFER_MAX) != STATUS_SUCCESS) {
        return FALSE;
    }
    if (!g_PathpPathsInit) {
        PathpInitSystemPaths();
    }
    return (g_PathpPaths.SystemDir[0] != L'\0' &&
            PathpPrefixEquals(norm, g_PathpPaths.SystemDir)) ||
           (g_PathpPaths.WindowsDir[0] != L'\0' &&
            PathpPrefixEquals(norm, g_PathpPaths.WindowsDir));
}

BOOLEAN
WkdIsTempDirectory(
    _In_ PCWSTR Path
    )
/*++
Routine Description:
    判定路径是否位于临时目录: 环境 TEMP 前缀, 或路径含 \temp\ / \tmp\ 段。

Arguments:
    Path - 输入路径。

Return Value:
    TRUE 表示位于临时目录。
--*/
{
    WCHAR norm[PATHP_PATH_BUFFER_MAX];

    if (!Path) {
        return FALSE;
    }
    if (WkdNormalizePath(Path, norm, PATHP_PATH_BUFFER_MAX) != STATUS_SUCCESS) {
        return FALSE;
    }
    if (!g_PathpPathsInit) {
        PathpInitSystemPaths();
    }
    return (g_PathpPaths.TempDir[0] != L'\0' &&
            PathpPrefixEquals(norm, g_PathpPaths.TempDir)) ||
           wcsstr(norm, L"\\temp\\") != NULL ||
           wcsstr(norm, L"\\tmp\\") != NULL;
}

BOOLEAN
WkdIsUserProfilePath(
    _In_ PCWSTR Path
    )
/*++
Routine Description:
    判定路径是否位于用户配置文件目录下。

Arguments:
    Path - 输入路径。

Return Value:
    TRUE 表示位于用户配置文件目录。
--*/
{
    WCHAR norm[PATHP_PATH_BUFFER_MAX];

    if (!Path) {
        return FALSE;
    }
    if (WkdNormalizePath(Path, norm, PATHP_PATH_BUFFER_MAX) != STATUS_SUCCESS) {
        return FALSE;
    }
    if (!g_PathpPathsInit) {
        PathpInitSystemPaths();
    }
    return g_PathpPaths.UserProfile[0] != L'\0' &&
           PathpPrefixEquals(norm, g_PathpPaths.UserProfile);
}

BOOLEAN
WkdIsMasquerading(
    _In_ PCWSTR DllName
    )
/*++
Routine Description:
    DLL 文件名是否仿冒系统 DLL: 名称长度 ≤ 32, 与任一系统 DLL 名的
    Levenshtein 距离在 (0, 2] 区间, 且非精确命中。

Arguments:
    DllName - DLL 文件名 (不含路径)。

Return Value:
    TRUE 表示判定为仿冒系统 DLL 名。
--*/
{
    WCHAR lowerName[PATHP_MASQUERADE_MAX_LEN + 1];
    SIZE_T nameLen;
    ULONG i;

    if (!DllName) {
        return FALSE;
    }
    nameLen = wcslen(DllName);
    if (nameLen == 0 || nameLen > PATHP_MASQUERADE_MAX_LEN) {
        return FALSE;
    }

    for (i = 0; i < nameLen; i++) {
        lowerName[i] = (WCHAR)towlower(DllName[i]);
    }
    lowerName[nameLen] = L'\0';

    for (i = 0; i < ARRAYSIZE(g_PathpSystemDllNames); i++) {
        SIZE_T dist;

        if (wcscmp(lowerName, g_PathpSystemDllNames[i]) == 0) {
            return FALSE;       /* 精确命中不算仿冒 */
        }
        dist = PathpLevenshtein(lowerName, g_PathpSystemDllNames[i]);
        if (dist > 0 && dist <= 2) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
WkdIsSystemDllName(
    _In_ PCWSTR DllName
    )
/*++
Routine Description:
    DLL 文件名是否精确命中系统 DLL 名单 (搜索顺序劫持判定用)。

Arguments:
    DllName - DLL 文件名 (不含路径)。

Return Value:
    TRUE 表示命中系统 DLL 名单。
--*/
{
    WCHAR lowerName[PATHP_MASQUERADE_MAX_LEN + 1];
    SIZE_T nameLen;
    ULONG i;

    if (!DllName) {
        return FALSE;
    }
    nameLen = wcslen(DllName);
    if (nameLen == 0 || nameLen > PATHP_MASQUERADE_MAX_LEN) {
        return FALSE;
    }

    for (i = 0; i < nameLen; i++) {
        lowerName[i] = (WCHAR)towlower(DllName[i]);
    }
    lowerName[nameLen] = L'\0';

    for (i = 0; i < ARRAYSIZE(g_PathpSystemDllNames); i++) {
        if (wcscmp(lowerName, g_PathpSystemDllNames[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}
