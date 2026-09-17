/**************************************************/
/*  WkDefender Agent — 注册表保护引擎 (RG)         */
/*  纯 C 移植自 ShadowStrike RegistryProtection.cpp */
/*                                                 */
/*  结构域：                                        */
/*    1  包含 / 宏 / 类型                           */
/*    2  内部结构 (引擎对象/键值条目/回调槽)         */
/*    3  前向声明                                   */
/*    4  工具函数域                                 */
/*    5  快照域 (内部辅助)                          */
/*    6  事件 / 统计 / 历史域                       */
/*    7  键保护域                                   */
/*    8  值保护域                                   */
/*    9  操作过滤域                                 */
/*   10  完整性域                                   */
/*   11  快照 / 回滚域 (公开)                       */
/*   12  白名单域                                   */
/*   13  生命周期 / 配置域                          */
/*   14  自检 / 报告 / 名称工具域                    */
/*   15  内核桥 (留桩)                              */
/**************************************************/

#include "RegistryProtection.h"
#include "../Common/BCrypUtils.h"                    /* IocScanner_ComputeBufferSha256 → DEF_SHA256_HASH */
#include "../IOC/IocTypes.h"                         /* DEF_CERT_STATUS */
#include "../IOC/Signature/SignatureVerifier.h"      /* IocVerifySignature (白名单验签) */
#include <sddl.h>                                    /* SDDL 解析 (RpHardenKeyDACL) */
#include <strsafe.h>

#include <winternl.h>    /* NTSTATUS / UNICODE_STRING (进程枚举) */

/**************************************************/
/*  1  宏 / 引擎状态                              */
/**************************************************/

/* 引擎状态机 (枚举 EngineState / State) */
#define RG_STATE_UNINITIALIZED  0
#define RG_STATE_INITIALIZED    1
#define RG_STATE_RUNNING        2
#define RG_STATE_STOPPING       3
#define RG_STATE_STOPPED        4

/* 统计原子宏 (引擎单例 RgP 全局) */
#define RgStatsInc(field) \
    InterlockedIncrement64(&RgP->Stats.field)
#define RgStatsAdd(field, n) \
    InterlockedExchangeAdd64((volatile LONG64*)&RgP->Stats.field, (LONG64)(n))
#define RgStatsSet(field, v) \
    InterlockedExchange64((volatile LONG64*)&RgP->Stats.field, (LONG64)(v))
#define RgReadStats(field) \
    InterlockedOr64((volatile LONG64*)&RgP->Stats.field, 0)

/* 调试输出 (AccessControl 无统一日志宏, 沿用 OutputDebugStringW 惯例) */
#define RG_DBG_FMT         L"[RG] %ls"
#define RgDbgPrint(fmt, ...)                              \
    do {                                                  \
        WCHAR _msg_[1024];                                \
        StringCchPrintfW(_msg_, 1024, fmt, __VA_ARGS__);  \
        OutputDebugStringW(_msg_);                        \
    } while (0)

/* SHA256 静态断言: WkD 的 DEF_SHA256_SIZE 必须容纳 RG_SHA256_SIZE */
#if defined(DEF_SHA256_SIZE)
_STATIC_ASSERT(DEF_SHA256_SIZE >= RG_SHA256_SIZE);
#endif

/**************************************************/
/*  2  内部结构                                    */
/**************************************************/

/* 键条目: 公开信息 + 快照缓冲 (C 化 std::unordered_map 键表行) */
typedef struct _RG_KEY_ENTRY {
    RG_PROTECTED_KEY        Public;                 /* 对外可见信息 */
    PRG_KEY_SNAPSHOT        Snapshots;              /* 动态数组, 容量 MaxSnapshotsPerKey */
    ULONG                   SnapshotCount;
    ULONG                   NextSnapshotVersion;    /* 版本号单调递增 (SS snapshotVersion 计数) */
} RG_KEY_ENTRY, * PRG_KEY_ENTRY;

/* 值条目: 公开信息 + 期望数据 (SS ProtectedValue::expectedData, 不对外导出) */
typedef struct _RG_VALUE_ENTRY {
    RG_PROTECTED_VALUE      Public;
    PVOID                   ExpectedData;           /* malloc */
    ULONG                   ExpectedDataSize;
} RG_VALUE_ENTRY, * PRG_VALUE_ENTRY;

/* 回调槽 (白名单模式: 数组 + 回调 ID) */
typedef struct _RG_EVENT_SLOT {
    ULONG64                 Id;
    RG_EVENT_CALLBACK       Callback;
    PVOID                   Context;
} RG_EVENT_SLOT, * PRG_EVENT_SLOT;

typedef struct _RG_INTEGRITY_SLOT {
    ULONG64                 Id;
    RG_INTEGRITY_CALLBACK   Callback;
    PVOID                   Context;
} RG_INTEGRITY_SLOT, * PRG_INTEGRITY_SLOT;

typedef struct _RG_VALUE_CHANGE_SLOT {
    ULONG64                 Id;
    RG_VALUE_CHANGE_CALLBACK Callback;
    PVOID                   Context;
} RG_VALUE_CHANGE_SLOT, * PRG_VALUE_CHANGE_SLOT;

/* 引擎对象 (单例) */
typedef struct _RG_ENGINE_INTERNAL {
    volatile LONG           State;                          /* RG_STATE_* */
    SRWLOCK                 Lock;                           /* 全部表/回调/历史/配置 */
    HANDLE                  StopEvent;
    HANDLE                  MonitorThread;
    RG_CONFIGURATION        Config;

    RG_KEY_ENTRY            Keys[RG_MAX_PROTECTED_KEYS];
    ULONG                   KeyCount;

    RG_VALUE_ENTRY          Values[RG_MAX_PROTECTED_VALUES];
    ULONG                   ValueCount;

    WCHAR                   Whitelist[RG_MAX_WHITELIST][MAX_PATH];
    ULONG                   WhitelistCount;

    RG_OPERATION_DECISION_CALLBACK  DecisionCallback;
    PVOID                           DecisionContext;

    RG_EVENT_SLOT           EventSlots[RG_MAX_CALLBACKS];
    RG_INTEGRITY_SLOT       IntegritySlots[RG_MAX_CALLBACKS];
    RG_VALUE_CHANGE_SLOT    ChangeSlots[RG_MAX_CALLBACKS];

    RG_PROTECTION_EVENT     History[RG_MAX_BLOCKED_OPERATIONS_LOG];
    ULONG                   HistoryHead;                    /* 下一写入槽 (环形) */
    ULONG                   HistoryCount;

    ULONGLONG               EventIdCounter;                 /* Interlocked64 */
    ULONGLONG               CallbackIdCounter;

    RG_PROTECTION_STATISTICS Stats;
    LARGE_INTEGER           LastIntegrityCheckQpc;          /* 节流基准 (QPC 单调) */
} RG_ENGINE_INTERNAL, * PRG_ENGINE_INTERNAL;

/* 默认保护键 13 条 (DEFAULT_PROTECTED_KEYS 原文;
 * 注册为 Full + includeSubkeys=true, L290-296 语义) */
static const WCHAR* const RgDefaultProtectedKeys[RG_DEFAULT_PROTECTED_KEY_COUNT] = {
    L"HKLM\\SOFTWARE\\ShadowStrike",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikePhantomService",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeDriver",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"HKCU\\SOFTWARE\\ShadowStrike",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\ShadowStrikePhantomService",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ShadowStrikePhantomService",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ShadowStrikePhantomService.exe",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ShadowStrikeUI.exe",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ShadowStrikeUpdater.exe"
};

/* 默认白名单 (L304-306: 三个自身进程, 名称匹配 + 数字签名双重校验) */
static const WCHAR* const RgDefaultWhitelistedProcesses[3] = {
    L"ShadowStrikePhantomService.exe",
    L"ShadowStrikeUI.exe",
    L"ShadowStrikeUpdater.exe"
};

/* 全局单例 */
static PRG_ENGINE_INTERNAL RgP = NULL;

/**************************************************/
/*  3  前向声明                                    */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID RgLockExclusive(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID RgUnlockExclusive(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID RgLockShared(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID RgUnlockShared(VOID);

static LARGE_INTEGER RgNow(VOID);                    /* FILETIME (1601 epoch, 100ns) */
static LARGE_INTEGER RgQpcNow(VOID);                 /* QueryPerformanceCounter 单调 */

static PCWSTR RgNormalizeKeyPathImpl(_In_ PCWSTR KeyPath, _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out);
static HKEY RgParseRootKeyImpl(_In_ PCWSTR KeyPath);
static NTSTATUS RgGetSubkeyPathImpl(_In_ PCWSTR FullPath, _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out);
static BOOLEAN RgKeyPathEquals(_In_ PCWSTR A, _In_ PCWSTR B);
static BOOLEAN RgIsAncestorKeyPath(_In_ PCWSTR Parent, _In_ PCWSTR Child);

static BOOLEAN RgComputeSha256(_In_reads_bytes_(Size) const UCHAR* Buffer, _In_ ULONG Size, _Out_writes_(RG_SHA256_SIZE) PUCHAR Hash);
static NTSTATUS RgReadValueData(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName, _Outptr_ PVOID* Data, _Out_ PULONG DataSize, _Out_ PRG_REGISTRY_VALUE_TYPE Type);
static NTSTATUS RgBuildCompositePath(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName, _Out_writes_(RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH) PWSTR Out);
static LONG RgFindKeyIndex(_In_ PCWSTR KeyNorm);
static LONG RgFindKeyAncestorIndex(_In_ PCWSTR KeyNorm);
static LONG RgFindValueIndex(_In_ PCWSTR CompositePath);

static ULONG RgBlockedOpsForType(_In_ const RG_KEY_ENTRY* Entry);
static BOOLEAN RgIsValueProtectedByEntryLocked(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName);
static BOOLEAN RgValidateValue(_In_ PCWSTR KeyNorm, _In_ PRG_VALUE_ENTRY Entry);

static VOID RgFreeSnapshotValues(_In_ PRG_KEY_SNAPSHOT Snapshot);
static VOID RgFreeKeySnapshots(_In_ PRG_KEY_ENTRY Entry);
static NTSTATUS RgPushSnapshot(_In_ PCWSTR KeyNorm, _In_ PRG_KEY_SNAPSHOT Snapshot);
static NTSTATUS RgSnapshotDeepCopy(_Out_ PRG_KEY_SNAPSHOT Dst, _In_ const RG_KEY_SNAPSHOT* Src);

static VOID RgDispatchEvent(_In_ const RG_PROTECTION_EVENT* Event);
static VOID RgDispatchIntegrityCallback(_In_ PCWSTR KeyNorm, _In_ RG_INTEGRITY_STATUS Status);
static VOID RgDispatchValueChange(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName,
    _In_reads_bytes_opt_(OldSize) const UCHAR* OldData, _In_ ULONG OldSize,
    _In_reads_bytes_opt_(NewSize) const UCHAR* NewData, _In_ ULONG NewSize);
static VOID RgNoteEvent(_In_ ULONG Type, _In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName,
    _In_ ULONG Operation, _In_ RG_OPERATION_DECISION Decision, _In_ ULONG Response,
    _In_ BOOLEAN WasBlocked, _In_ BOOLEAN WasRolledBack, _In_ PCSTR Description);

static PWSTR RgGetProcessNameByPid(_In_ ULONG ProcessId, _Out_writes_(MAX_PATH) PWSTR Name, _In_ ULONG NameCch);
static BOOLEAN RgGetProcessPathByPid(_In_ ULONG ProcessId, _Out_writes_(MAX_PATH) PWSTR Path, _In_ ULONG PathCch);
static BOOLEAN RgIsWhitelistedLocked(_In_ PCWSTR ProcessName);
static BOOLEAN RgIsProcessWhitelisted(_In_ ULONG ProcessId, _Out_writes_(MAX_PATH) PWSTR ProcessNameOut);

static DWORD WINAPI RgMonitorThreadMain(_In_ PVOID Parameter);
static VOID RgPerformIntegrityCheck(VOID);
static NTSTATUS RgStartMonitoring(VOID);
static VOID RgStopMonitoring(VOID);

static NTSTATUS RgCreateEngine(VOID);
static VOID RgResetEngine(VOID);

/**************************************************/
/*  4  工具函数域                                  */
/**************************************************/

/*++ 锁封装 --*/
static VOID RgLockExclusive(VOID) { if (RgP) AcquireSRWLockExclusive(&RgP->Lock); }
static VOID RgUnlockExclusive(VOID) { if (RgP) ReleaseSRWLockExclusive(&RgP->Lock); }
static VOID RgLockShared(VOID) { if (RgP) AcquireSRWLockShared(&RgP->Lock); }
static VOID RgUnlockShared(VOID) { if (RgP) ReleaseSRWLockShared(&RgP->Lock); }

/*++ 时间: FILETIME 语义 (chrono system_clock 输出侧) --*/
static LARGE_INTEGER RgNow(VOID)
{
    LARGE_INTEGER t;
    GetSystemTimeAsFileTime((LPFILETIME)&t);
    return t;
}

/*++ 时间: QPC 单调 (键/快照节流与排序) --*/
static LARGE_INTEGER RgQpcNow(VOID)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t;
}

/*++
Routine Description:
    键路径规范化 (normalizeKeyPath):
    根键前缀识别 → 输出 "HKLM\\..." 形式, 子键小写折叠, 去除尾部反斜杠。
    注册表键名不区分大小写, 折叠后统一比较; 值名区分大小写不做折叠。

Return Value:
    Out 或 NULL (无效根/过长)。
--*/
static PCWSTR RgNormalizeKeyPathImpl(_In_ PCWSTR KeyPath, _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out)
{
    HKEY root;
    PCWSTR sub;
    SIZE_T subLen;

    if (KeyPath == NULL || Out == NULL) {
        return NULL;
    }

    root = RgParseRootKeyImpl(KeyPath);
    if (root == NULL) {
        return NULL;
    }

    /* 定位根键前缀尾部 (双反斜杠后) */
    sub = wcschr(KeyPath, L'\\');
    if (sub == NULL) {
        /* 仅根键本身: "HKLM" */
        StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, KeyPath);
        return Out;
    }
    sub = sub + 1; /* 跳过 '\' */

    subLen = wcslen(sub);
    if (subLen >= (RG_MAX_KEY_PATH_LENGTH - 8)) { /* 留足前辍与尾0 */
        return NULL;
    }

    /* 前缀规范为 SS 形式 (原样大小写, 如 HKLM/HKCU) */
    if (root == HKEY_LOCAL_MACHINE) {
        StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, L"HKLM");
    } else if (root == HKEY_CURRENT_USER) {
        StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, L"HKCU");
    } else if (root == HKEY_CLASSES_ROOT) {
        StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, L"HKCR");
    } else if (root == HKEY_USERS) {
        StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, L"HKU");
    } else if (root == HKEY_CURRENT_CONFIG) {
        StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, L"HKCC");
    } else {
        return NULL;
    }
    StringCchCatW(Out, RG_MAX_KEY_PATH_LENGTH, L"\\");

    /* 追加子键 (小写折叠) 并去尾反斜杠 */
    {
        WCHAR folded[RG_MAX_KEY_PATH_LENGTH];
        SIZE_T i;
        SIZE_T len = subLen;

        for (i = 0; i < len; i++) {
            folded[i] = (WCHAR)towlower(sub[i]);
        }
        /* 去除尾部反斜杠 */
        while (len > 0 && folded[len - 1] == L'\\') {
            len--;
        }
        folded[len] = L'\0';

        StringCchCatW(Out, RG_MAX_KEY_PATH_LENGTH, folded);
    }

    return Out;
}

/*++
Routine Description:
    键路径根键解析 (parseRootKey)。支持五种前缀大写形式, 大小写不敏感。

Return Value:
    HKEY 常量或 NULL。
--*/
static HKEY RgParseRootKeyImpl(_In_ PCWSTR KeyPath)
{
    if (KeyPath == NULL || KeyPath[0] == L'\0') {
        return NULL;
    }

    if (_wcsnicmp(KeyPath, L"HKLM", 4) == 0) {
        return HKEY_LOCAL_MACHINE;
    }
    if (_wcsnicmp(KeyPath, L"HKCU", 4) == 0) {
        return HKEY_CURRENT_USER;
    }
    if (_wcsnicmp(KeyPath, L"HKCR", 4) == 0) {
        return HKEY_CLASSES_ROOT;
    }
    if (_wcsnicmp(KeyPath, L"HKU", 3) == 0) {
        return HKEY_USERS;
    }
    if (_wcsnicmp(KeyPath, L"HKCC", 4) == 0) {
        return HKEY_CURRENT_CONFIG;
    }
    return NULL;
}

/*++ 子键路径提取 ("HKLM\\A\\B" → "A\\B") --*/
static NTSTATUS RgGetSubkeyPathImpl(_In_ PCWSTR FullPath, _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out)
{
    PCWSTR sub;

    if (FullPath == NULL || Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgParseRootKeyImpl(FullPath) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    sub = wcschr(FullPath, L'\\');
    if (sub == NULL) {
        Out[0] = L'\0';
        return STATUS_SUCCESS;
    }
    sub = sub + 1; /* 跳过 '\' */

    if (wcslen(sub) >= RG_MAX_KEY_PATH_LENGTH) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    StringCchCopyW(Out, RG_MAX_KEY_PATH_LENGTH, sub);
    return STATUS_SUCCESS;
}

/*++ 已规范化路径比较 (子键大小写不敏感) --*/
static BOOLEAN RgKeyPathEquals(_In_ PCWSTR A, _In_ PCWSTR B)
{
    if (A == NULL || B == NULL) {
        return FALSE;
    }
    return (_wcsicmp(A, B) == 0);
}

/*++ 祖先链判定: Parent 是否 Child 的祖先 (含子键保护语义).
    已规范化输入, 边界需落在 '\' 上, 防 "HKCU\a\bb" 误配 "HKCU\a\b"。 --*/
static BOOLEAN RgIsAncestorKeyPath(_In_ PCWSTR Parent, _In_ PCWSTR Child)
{
    SIZE_T parentLen;

    if (Parent == NULL || Child == NULL) {
        return FALSE;
    }

    parentLen = wcslen(Parent);
    if (parentLen == 0) {
        return FALSE;
    }

    /* Parent + '\' + 子串 */
    if (_wcsnicmp(Parent, Child, (size_t)parentLen) != 0) {
        return FALSE;
    }
    if (Child[parentLen] != L'\\') {
        return FALSE;
    }
    /* 排除完全相等 (相等属于直接命中) */
    return (Child[parentLen + 1] != L'\0');
}

/*++ 哈希计算入口 (包装 BCrypUtils) --*/
static BOOLEAN RgComputeSha256(_In_reads_bytes_(Size) const UCHAR* Buffer, _In_ ULONG Size, _Out_writes_(RG_SHA256_SIZE) PUCHAR Hash)
{
    DEF_SHA256_HASH digest;

    if (Buffer == NULL && Size > 0) {
        return FALSE;
    }
    ZeroMemory(&digest, sizeof(digest));
    if (!IocScanner_ComputeBufferSha256(Buffer, Size, &digest)) {
        return FALSE;
    }
    RtlCopyMemory(Hash, digest.Data, RG_SHA256_SIZE);
    return TRUE;
}

/*++
Routine Description:
    读取注册表值数据 (动态分配, 调用方 free)。
    ReadValueAndComputeHash 的 1MB 安全上限护栏。

Return Value:
    NTSTATUS。*Data 为 malloc 缓冲或 NULL(空值 DataSize=0)。
--*/
static NTSTATUS RgReadValueData(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName, _Outptr_ PVOID* Data, _Out_ PULONG DataSize, _Out_ PRG_REGISTRY_VALUE_TYPE Type)
{
    HKEY root;
    WCHAR sub[RG_MAX_KEY_PATH_LENGTH];
    HKEY hKey;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG size = 0;
    ULONG type = REG_NONE;
    PVOID buffer = NULL;
    LONG lerr;

    if (KeyNorm == NULL || ValueName == NULL || Data == NULL || DataSize == NULL || Type == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Data = NULL;
    *DataSize = 0;

    root = RgParseRootKeyImpl(KeyNorm);
    if (root == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(RgGetSubkeyPathImpl(KeyNorm, sub))) {
        return STATUS_INVALID_PARAMETER;
    }

    lerr = RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE, &hKey);
    if (lerr != ERROR_SUCCESS) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    /* 首查长度 */
    lerr = RegQueryValueExW(hKey, ValueName, NULL, &type, NULL, &size);
    if (lerr != ERROR_SUCCESS) {
        status = (lerr == ERROR_FILE_NOT_FOUND) ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_UNSUCCESSFUL;
        RegCloseKey(hKey);
        return status;
    }

    /* 1MB 安全上限 (MAX_VALUE_DATA_SIZE) */
    if (size > RG_MAX_VALUE_DATA_SIZE) {
        RgDbgPrint(RG_DBG_FMT, L"value data too large: %ls\\%ls (%lu bytes, cap %u)",
            KeyNorm, ValueName, size, RG_MAX_VALUE_DATA_SIZE);
        RegCloseKey(hKey);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (size > 0) {
        buffer = malloc(size);
        if (buffer == NULL) {
            RegCloseKey(hKey);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        lerr = RegQueryValueExW(hKey, ValueName, NULL, &type, buffer, &size);
        if (lerr != ERROR_SUCCESS) {
            free(buffer);
            RegCloseKey(hKey);
            return STATUS_UNSUCCESSFUL;
        }
    }

    RegCloseKey(hKey);

    *Data = buffer;
    *DataSize = size;
    *Type = (RG_REGISTRY_VALUE_TYPE)type;
    return STATUS_SUCCESS;
}

/*++ 复合路径: "KeyNorm\\ValueName" (值表定位键) --*/
static NTSTATUS RgBuildCompositePath(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName, _Out_writes_(RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH) PWSTR Out)
{
    if (KeyNorm == NULL || ValueName == NULL || Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (StringCchPrintfW(Out, RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH, L"%ls\\%ls", KeyNorm, ValueName) != S_OK) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    return STATUS_SUCCESS;
}

/*++ 键表定位 (直接命中; 未找到返回 -1) --*/
static LONG RgFindKeyIndex(_In_ PCWSTR KeyNorm)
{
    ULONG i;
    if (!RgP) {
        return -1;
    }
    for (i = 0; i < RgP->KeyCount; i++) {
        if (RgKeyPathEquals(RgP->Keys[i].Public.NormalizedPath, KeyNorm)) {
            return (LONG)i;
        }
    }
    return -1;
}

/*++ 键表定位 (祖先链: includeSubkeys 父键命中; 未找到返回 -1) --*/
static LONG RgFindKeyAncestorIndex(_In_ PCWSTR KeyNorm)
{
    ULONG i;
    if (!RgP) {
        return -1;
    }
    for (i = 0; i < RgP->KeyCount; i++) {
        if (RgP->Keys[i].Public.IncludeSubkeys &&
            RgIsAncestorKeyPath(RgP->Keys[i].Public.NormalizedPath, KeyNorm)) {
            return (LONG)i;
        }
    }
    return -1;
}

/*++ 值表定位 (复合路径; 未找到返回 -1) --*/
static LONG RgFindValueIndex(_In_ PCWSTR CompositePath)
{
    ULONG i;
    if (!RgP) {
        return -1;
    }
    for (i = 0; i < RgP->ValueCount; i++) {
        if (_wcsicmp(RgP->Values[i].Public.KeyPath, CompositePath) == 0) {
            return (LONG)i;
        }
    }
    return -1;
}

/*++ 键类型 → 阻断操作位图 (GetBlockedOperationsForType) --*/
static ULONG RgBlockedOpsForType(_In_ const RG_KEY_ENTRY* Entry)
{
    const RG_PROTECTED_KEY* key;
    if (Entry == NULL) {
        return 0;
    }
    key = &Entry->Public;

    switch (key->Type) {
    case RgKeyTypeReadOnly:
        /* 允许读, 阻断全部修改/删除/加固类 */
        return RgOpSetValue | RgOpDeleteValue | RgOpCreateKey | RgOpDeleteKey |
            RgOpRenameKey | RgOpSetKeySecurity | RgOpLoadKey | RgOpUnloadKey |
            RgOpSaveKey | RgOpRestoreKey;

    case RgKeyTypeNoDelete:
        return RgOpDeleteKey;

    case RgKeyTypeNoModify:
        return RgOpSetValue | RgOpDeleteValue | RgOpCreateKey | RgOpDeleteKey |
            RgOpRenameKey | RgOpSetKeySecurity | RgOpLoadKey | RgOpUnloadKey |
            RgOpSaveKey | RgOpRestoreKey;

    case RgKeyTypeFull:
        return RgOpSetValue | RgOpDeleteValue | RgOpCreateKey | RgOpDeleteKey |
            RgOpRenameKey | RgOpSetKeySecurity | RgOpLoadKey | RgOpUnloadKey |
            RgOpSaveKey | RgOpRestoreKey;

    case RgKeyTypeValuesOnly:
        return 0;   /* 键级操作放行, 值级由值表判定 */

    case RgKeyTypeCustom:
        return key->BlockedOperations;

    default:
        return 0;
    }
}

/*++ 值保护判定 (调用方持锁; 复合路径比较) --*/
static BOOLEAN RgIsValueProtectedByEntryLocked(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName)
{
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];

    if (KeyNorm == NULL || ValueName == NULL) {
        return FALSE;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(KeyNorm, ValueName, composite))) {
        return FALSE;
    }
    return (RgFindValueIndex(composite) != -1);
}

/**************************************************/
/*  5  快照域 (内部辅助)                          */
/**************************************************/

/*++ 释放单个快照的动态值数组 --*/
static VOID RgFreeSnapshotValues(_In_ PRG_KEY_SNAPSHOT Snapshot)
{
    ULONG i;

    if (Snapshot == NULL) {
        return;
    }
    if (Snapshot->Values != NULL) {
        for (i = 0; i < Snapshot->ValueCount; i++) {
            if (Snapshot->Values[i].Data != NULL) {
                free(Snapshot->Values[i].Data);
            }
        }
        free(Snapshot->Values);
        Snapshot->Values = NULL;
    }
    Snapshot->ValueCount = 0;
}

/*++ 释放键条目全部快照 --*/
static VOID RgFreeKeySnapshots(_In_ PRG_KEY_ENTRY Entry)
{
    ULONG i;

    if (Entry == NULL || Entry->Snapshots == NULL) {
        return;
    }
    for (i = 0; i < Entry->SnapshotCount; i++) {
        RgFreeSnapshotValues(&Entry->Snapshots[i]);
    }
    free(Entry->Snapshots);
    Entry->Snapshots = NULL;
    Entry->SnapshotCount = 0;
    Entry->NextSnapshotVersion = 0;
    Entry->Public.HasSnapshot = FALSE;
}

/*++ 快照深拷贝 (出参须由调用方 free: Values 及 Data) --*/
static NTSTATUS RgSnapshotDeepCopy(_Out_ PRG_KEY_SNAPSHOT Dst, _In_ const RG_KEY_SNAPSHOT* Src)
{
    ULONG i;

    if (Dst == NULL || Src == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Dst = *Src;
    Dst->Values = NULL;

    if (Src->ValueCount > 0) {
        Dst->Values = (PRG_SNAPSHOT_ENTRY)malloc(sizeof(RG_SNAPSHOT_ENTRY) * Src->ValueCount);
        if (Dst->Values == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ZeroMemory(Dst->Values, sizeof(RG_SNAPSHOT_ENTRY) * Src->ValueCount);
        for (i = 0; i < Src->ValueCount; i++) {
            Dst->Values[i] = Src->Values[i];
            if (Src->Values[i].DataSize > 0) {
                Dst->Values[i].Data = malloc(Src->Values[i].DataSize);
                if (Dst->Values[i].Data == NULL) {
                    RgFreeSnapshotValues(Dst);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                RtlCopyMemory(Dst->Values[i].Data, Src->Values[i].Data, Src->Values[i].DataSize);
            } else {
                Dst->Values[i].Data = NULL;
            }
        }
    }
    return STATUS_SUCCESS;
}

/*++ 快照入列 (调用方已持排他锁; 满则滑动丢弃最旧, CleanupOldSnapshots) --*/
static NTSTATUS RgPushSnapshot(_In_ PCWSTR KeyNorm, _In_ PRG_KEY_SNAPSHOT Snapshot)
{
    LONG idx;
    PRG_KEY_ENTRY entry;
    ULONG maxCount;

    if (!RgP || KeyNorm == NULL || Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    idx = RgFindKeyIndex(KeyNorm);
    if (idx < 0) {
        return STATUS_INVALID_PARAMETER;    /* 快照仅对受保护键 (对齐 SS) */
    }
    entry = &RgP->Keys[idx];
    maxCount = (RgP->Config.MaxSnapshotsPerKey > 0)
        ? RgP->Config.MaxSnapshotsPerKey
        : RG_MAX_SNAPSHOTS_PER_KEY;
    if (maxCount > RG_MAX_SNAPSHOTS_PER_KEY) {
        maxCount = RG_MAX_SNAPSHOTS_PER_KEY;
    }

    if (entry->Snapshots == NULL) {
        entry->Snapshots = (PRG_KEY_SNAPSHOT)malloc(sizeof(RG_KEY_SNAPSHOT) * RG_MAX_SNAPSHOTS_PER_KEY);
        if (entry->Snapshots == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ZeroMemory(entry->Snapshots, sizeof(RG_KEY_SNAPSHOT) * RG_MAX_SNAPSHOTS_PER_KEY);
    }

    /* 满: 丢弃最旧 (滑动) */
    if (entry->SnapshotCount >= maxCount) {
        RgFreeSnapshotValues(&entry->Snapshots[0]);
        RtlMoveMemory(&entry->Snapshots[0], &entry->Snapshots[1],
            sizeof(RG_KEY_SNAPSHOT) * (entry->SnapshotCount - 1));
        entry->SnapshotCount--;
    }

    RtlCopyMemory(&entry->Snapshots[entry->SnapshotCount], Snapshot, sizeof(RG_KEY_SNAPSHOT));
    entry->SnapshotCount++;
    entry->NextSnapshotVersion++;
    entry->Public.HasSnapshot = TRUE;
    entry->Public.LastSnapshotTime = Snapshot->Timestamp;

    return STATUS_SUCCESS;
}

/**************************************************/
/*  6  事件 / 统计 / 历史域                       */
/**************************************************/

/*++
Routine Description:
    事件分发: 入历史环形缓冲 (锁内) + 快照回调槽 (锁内) → 锁外逐个调用。
    FireBlockedOperationEvent 语义 (回调在锁外执行)。

--*/
static VOID RgDispatchEvent(_In_ const RG_PROTECTION_EVENT* Event)
{
    RG_EVENT_SLOT slots[RG_MAX_CALLBACKS];
    ULONG slotCount = 0;
    ULONG i;
    RG_PROTECTION_EVENT local;

    if (!RgP || Event == NULL) {
        return;
    }

    local = *Event;

    RgLockExclusive();

    local.EventId = (ULONGLONG)InterlockedIncrement64((volatile LONG64*)&RgP->EventIdCounter);

    /* 环形历史 (eventHistory 上限 1000) */
    RgP->History[RgP->HistoryHead] = local;
    RgP->HistoryHead = (RgP->HistoryHead + 1) % RG_MAX_BLOCKED_OPERATIONS_LOG;
    if (RgP->HistoryCount < RG_MAX_BLOCKED_OPERATIONS_LOG) {
        RgP->HistoryCount++;
    }

    RgStatsSet(LastEventTime, local.Timestamp.QuadPart);

    /* 快照回调槽 */
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->EventSlots[i].Callback != NULL) {
            slots[slotCount++] = RgP->EventSlots[i];
        }
    }

    RgUnlockExclusive();

    for (i = 0; i < slotCount; i++) {
        slots[i].Callback(&local, slots[i].Context);
    }
}

/*++ 完整性回调分发 (锁内快照, 锁外调用) --*/
static VOID RgDispatchIntegrityCallback(_In_ PCWSTR KeyNorm, _In_ RG_INTEGRITY_STATUS Status)
{
    RG_INTEGRITY_SLOT slots[RG_MAX_CALLBACKS];
    ULONG slotCount = 0;
    ULONG i;
    RG_PROTECTED_KEY keyCopy;
    BOOLEAN haveKey = FALSE;

    if (!RgP || KeyNorm == NULL) {
        return;
    }

    RgLockShared();

    /* 拷贝键公开信息 (锁内) */
    {
        LONG idx = RgFindKeyIndex(KeyNorm);
        if (idx >= 0) {
            keyCopy = RgP->Keys[idx].Public;
            keyCopy.Integrity = Status;
            haveKey = TRUE;
        }
    }

    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->IntegritySlots[i].Callback != NULL) {
            slots[slotCount++] = RgP->IntegritySlots[i];
        }
    }

    RgUnlockShared();

    if (!haveKey) {
        return;
    }
    for (i = 0; i < slotCount; i++) {
        slots[i].Callback(&keyCopy, slots[i].Context);
    }
}

/*++ 值变更回调分发 (数据快照在锁内完成, 回调锁外执行) --*/
static VOID RgDispatchValueChange(_In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName,
    _In_reads_bytes_opt_(OldSize) const UCHAR* OldData, _In_ ULONG OldSize,
    _In_reads_bytes_opt_(NewSize) const UCHAR* NewData, _In_ ULONG NewSize)
{
    RG_VALUE_CHANGE_SLOT slots[RG_MAX_CALLBACKS];
    ULONG slotCount = 0;
    ULONG i;
    UCHAR* oldCopy = NULL;
    UCHAR* newCopy = NULL;

    if (!RgP || KeyNorm == NULL || ValueName == NULL) {
        return;
    }

    /* 数据深拷贝 (锁外), 回调需要的快照 */
    if (OldSize > 0 && OldData != NULL) {
        oldCopy = (UCHAR*)malloc(OldSize);
        if (oldCopy == NULL) {
            return;
        }
        RtlCopyMemory(oldCopy, OldData, OldSize);
    }
    if (NewSize > 0 && NewData != NULL) {
        newCopy = (UCHAR*)malloc(NewSize);
        if (newCopy == NULL) {
            free(oldCopy);
            return;
        }
        RtlCopyMemory(newCopy, NewData, NewSize);
    }

    RgLockShared();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->ChangeSlots[i].Callback != NULL) {
            slots[slotCount++] = RgP->ChangeSlots[i];
        }
    }
    RgUnlockShared();

    for (i = 0; i < slotCount; i++) {
        slots[i].Callback(KeyNorm, ValueName, oldCopy, OldSize, newCopy, NewSize, slots[i].Context);
    }

    free(oldCopy);
    free(newCopy);
}

/*++
Routine Description:
    事件记账统一入口 (SS 内联于各类 Fire 路径):
    构造 RG_PROTECTION_EVENT → 分发 (历史+回调)。

--*/
static VOID RgNoteEvent(_In_ ULONG Type, _In_ PCWSTR KeyNorm, _In_ PCWSTR ValueName,
    _In_ ULONG Operation, _In_ RG_OPERATION_DECISION Decision, _In_ ULONG Response,
    _In_ BOOLEAN WasBlocked, _In_ BOOLEAN WasRolledBack, _In_ PCSTR Description)
{
    RG_PROTECTION_EVENT evt;

    if (!RgP) {
        return;
    }
    ZeroMemory(&evt, sizeof(evt));

    evt.EventId = 0;                                    /* Dispatch 内分配 */
    evt.Type = Type;
    evt.Timestamp = RgNow();
    if (KeyNorm != NULL) {
        StringCchCopyW(evt.KeyPath, RG_MAX_KEY_PATH_LENGTH, KeyNorm);
    }
    if (ValueName != NULL) {
        StringCchCopyW(evt.ValueName, RG_MAX_VALUE_NAME_LENGTH, ValueName);
    }
    evt.Operation = Operation;
    evt.Decision = Decision;
    evt.ResponseTaken = Response;
    evt.WasBlocked = WasBlocked;
    evt.WasRolledBack = WasRolledBack;
    if (Description != NULL) {
        StringCchCopyA(evt.Description, sizeof(evt.Description), Description);
    }

    RgDispatchEvent(&evt);
}

/**************************************************/
/*  7  键保护域                                    */
/**************************************************/

/*++ 进程枚举: PID → 进程名 (NtQuerySystemInformation, 动态缓冲) --*/
static PWSTR RgGetProcessNameByPid(_In_ ULONG ProcessId, _Out_writes_(NameCch) PWSTR Name, _In_ ULONG NameCch)
{
    NTSTATUS status;
    ULONG bufferSize = 64 * 1024;
    PVOID buffer = NULL;
    PSYSTEM_PROCESS_INFORMATION spi;
    PUCHAR end;

    if (Name == NULL || NameCch == 0) {
        return NULL;
    }
    Name[0] = L'\0';

    for (;;) {
        buffer = malloc(bufferSize);
        if (buffer == NULL) {
            return NULL;
        }
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            bufferSize = bufferSize * 2;
            if (bufferSize > 16 * 1024 * 1024) {
                return NULL;
            }
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return NULL;
    }

    end = (PUCHAR)buffer + bufferSize;
    spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

    for (;;) {
        if ((PUCHAR)spi + sizeof(SYSTEM_PROCESS_INFORMATION) > end) {
            break;
        }
        if ((ULONG)(ULONG_PTR)spi->UniqueProcessId == ProcessId &&
            spi->ImageName.Buffer != NULL && spi->ImageName.Length > 0) {
            ULONG copyLen = spi->ImageName.Length / sizeof(WCHAR);
            if (copyLen >= NameCch) {
                copyLen = NameCch - 1;
            }
            RtlCopyMemory(Name, spi->ImageName.Buffer, copyLen * sizeof(WCHAR));
            Name[copyLen] = L'\0';
            free(buffer);
            return Name;
        }
        if (spi->NextEntryOffset == 0) {
            break;
        }
        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    free(buffer);
    return NULL;
}

/*++ 进程路径: OpenProcess + QueryFullProcessImageNameW --*/
static BOOLEAN RgGetProcessPathByPid(_In_ ULONG ProcessId, _Out_writes_(PathCch) PWSTR Path, _In_ ULONG PathCch)
{
    HANDLE hProcess;
    DWORD size;

    if (Path == NULL || PathCch == 0) {
        return FALSE;
    }
    Path[0] = L'\0';

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    size = PathCch;
    if (!QueryFullProcessImageNameW(hProcess, 0, Path, &size)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    Path[PathCch - 1] = L'\0';

    CloseHandle(hProcess);
    return TRUE;
}

/*++ 白名单名称匹配 (调用方持锁) --*/
static BOOLEAN RgIsWhitelistedLocked(_In_ PCWSTR ProcessName)
{
    ULONG i;

    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return FALSE;
    }
    for (i = 0; i < RgP->WhitelistCount; i++) {
        if (_wcsicmp(RgP->Whitelist[i], ProcessName) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
Routine Description:
    PID 白名单判定 (IsProcessWhitelisted L1889-1920):
    [锁内]名称 IEquals 匹配 → [锁外]取进程路径 → IocVerifySignature 数字签名校验,
    验签失败一律拒绝白名单 (防改名绕过)。
    白名单为空时短路 (降低成本)。

--*/
static BOOLEAN RgIsProcessWhitelisted(_In_ ULONG ProcessId, _Out_writes_(MAX_PATH) PWSTR ProcessNameOut)
{
    WCHAR name[MAX_PATH];
    WCHAR path[MAX_PATH];
    BOOLEAN matched = FALSE;
    IOC_SCAN_RESULT sig;
    LONG i;

    if (!RgP) {
        return FALSE;
    }
    if (ProcessNameOut != NULL) {
        ProcessNameOut[0] = L'\0';
    }

    /* 白名单空 → 短路 */
    RgLockShared();
    if (RgP->WhitelistCount == 0) {
        RgUnlockShared();
        return FALSE;
    }

    /* 名称匹配 (锁内) */
    if (RgGetProcessNameByPid(ProcessId, name, MAX_PATH) == NULL) {
        RgUnlockShared();
        return FALSE;
    }
    if (RgIsWhitelistedLocked(name)) {
        matched = TRUE;
    }
    RgUnlockShared();

    if (!matched) {
        return FALSE;
    }
    if (ProcessNameOut != NULL) {
        StringCchCopyW(ProcessNameOut, MAX_PATH, name);
    }

    /* 验签 (锁外): 白名单仅对有效/目录有效签名放行 */
    if (!RgGetProcessPathByPid(ProcessId, path, MAX_PATH)) {
        RgDbgPrint(RG_DBG_FMT, L"cannot resolve path for whitelisted process '%ls' (PID %lu), denying whitelist",
            name, ProcessId);
        return FALSE;
    }

    ZeroMemory(&sig, sizeof(sig));
    if (!NT_SUCCESS(IocVerifySignature(path, &sig))) {
        RgDbgPrint(RG_DBG_FMT, L"signature verification failed for whitelisted process '%ls' (PID %lu), denying whitelist",
            name, ProcessId);
        return FALSE;
    }

    if (sig.CertStatus != DefCertStatus_Valid && sig.CertStatus != DefCertStatus_ValidCatalog) {
        RgDbgPrint(RG_DBG_FMT,
            L"whitelisted process '%ls' (PID %lu) has no valid signature (status %u), denying whitelist",
            name, ProcessId, (ULONG)sig.CertStatus);
        return FALSE;
    }

    /* 白名单微审计 */
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        /* 无操作: 匹配即视为已白名单, 不重复记录 */
        if (!RgP) break;
        (VOID)RgP;
        break;
    }

    return TRUE;
}

/**************************************************/
/*  8  值保护域                                    */
/**************************************************/

/*++
Routine Description:
    单值完整性校验 (ValidateValue L992-1054):
    读当前值 → 基线哈希比对 → 状态回写 + 变更事件/回调 + 自动回滚。
    调用点须不持表锁 (锁外 I/O; 状态回写内部短程锁)。

--*/
static BOOLEAN RgValidateValue(_In_ PCWSTR KeyNorm, _In_ PRG_VALUE_ENTRY Entry)
{
    PVOID currentData = NULL;
    ULONG currentSize = 0;
    RG_REGISTRY_VALUE_TYPE currentType = RgValueNone;
    UCHAR currentHash[RG_SHA256_SIZE];
    NTSTATUS status;
    BOOLEAN equal;

    if (KeyNorm == NULL || Entry == NULL) {
        return FALSE;
    }

    /* 当前值 (锁外 I/O) */
    status = RgReadValueData(KeyNorm, Entry->Public.ValueName, &currentData, &currentSize, &currentType);
    if (!NT_SUCCESS(status)) {
        /* 值缺失: 基线哈希缺失等同数据消失 */
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
            RgLockExclusive();
            if (RgP) {
                Entry->Public.Integrity = RgIntegrityMissing;
                Entry->Public.LastVerified = RgNow();
            }
            RgUnlockExclusive();
            RgStatsInc(IntegrityViolations);
            RgNoteEvent(RgEventIntegrityViolation, KeyNorm, Entry->Public.ValueName,
                RgOpQueryValue, RgDecisionBlock, RgResponseAlert, TRUE, FALSE, "protected value is missing");
        }
        return FALSE;
    }

    /* 哈希比对 */
    ZeroMemory(currentHash, sizeof(currentHash));
    if (!RgComputeSha256((const UCHAR*)currentData, currentSize, currentHash)) {
        free(currentData);
        return FALSE;
    }
    equal = (RtlEqualMemory(Entry->Public.ExpectedHash, currentHash, RG_SHA256_SIZE) != FALSE);

    if (equal) {
        /* 有效: 回写状态与新哈希 (UpdateValueBaseline 之外的校验路径) */
        RgLockExclusive();
        if (RgP) {
            Entry->Public.Integrity = RgIntegrityValid;
            Entry->Public.LastVerified = RgNow();
            RtlCopyMemory(Entry->Public.CurrentHash, currentHash, RG_SHA256_SIZE);
            Entry->Public.DataSize = currentSize;
        }
        RgUnlockExclusive();
        free(currentData);
        return TRUE;
    }

    /* 变更: 状态 + 计数 + 事件 + 回调 + 自动回滚 */
    {
        UCHAR* oldExpected = NULL;
        ULONG oldSize = Entry->ExpectedDataSize;

        RgLockExclusive();
        if (RgP) {
            Entry->Public.Integrity = RgIntegrityModified;
            Entry->Public.LastVerified = RgNow();
            RtlCopyMemory(Entry->Public.CurrentHash, currentHash, RG_SHA256_SIZE);
            Entry->Public.DataSize = currentSize;
            Entry->Public.ModificationCount++;
        }
        RgUnlockExclusive();

        RgStatsInc(IntegrityViolations);

        /* 值变更回调: 期望(旧) vs 当前(新) */
        if (Entry->ExpectedData != NULL && oldSize > 0) {
            oldExpected = (UCHAR*)malloc(oldSize);
            if (oldExpected != NULL) {
                RtlCopyMemory(oldExpected, Entry->ExpectedData, oldSize);
            }
        }
        if (oldExpected != NULL) {
            RgDispatchValueChange(KeyNorm, Entry->Public.ValueName,
                oldExpected, oldSize, (const UCHAR*)currentData, currentSize);
            free(oldExpected);
        } else {
            RgDispatchValueChange(KeyNorm, Entry->Public.ValueName,
                NULL, 0, (const UCHAR*)currentData, currentSize);
        }

        RgNoteEvent(RgEventValueModified, KeyNorm, Entry->Public.ValueName,
            RgOpSetValue, RgDecisionAllowLogged, RgResponseAlert, FALSE, FALSE,
            "protected value was modified");

        /* 自动回滚 (对齐 SS: enableAutoRollback && 模式>=Rollback) */
        {
            BOOLEAN doRollback = FALSE;
            RgLockShared();
            if (RgP && RgP->Config.EnableAutoRollback && RgP->Config.Mode >= RgModeRollback) {
                doRollback = TRUE;
            }
            RgUnlockShared();
            if (doRollback) {
                RpRollbackValue(KeyNorm, Entry->Public.ValueName);
            }
        }

        free(currentData);
        return FALSE;
    }
}

/**************************************************/
/*  9  操作过滤域                                  */
/**************************************************/

/*++
Routine Description:
    监控线程主循环 (monitoringLoop):
    轮询等待 StopEvent → 每轮完整性检查 (配置使能时) + 旧快照清理。

--*/
static DWORD WINAPI RgMonitorThreadMain(_In_ PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);

    for (;;) {
        ULONG waitMs = RG_POLLING_INTERVAL_MS;

        if (RgP != NULL) {
            waitMs = RgP->Config.PollingIntervalMs;
            if (waitMs == 0) {
                waitMs = RG_POLLING_INTERVAL_MS;
            }
            if (waitMs > 60000) {
                waitMs = 60000;
            }
        }

        if (WaitForSingleObject(RgP->StopEvent, waitMs) != WAIT_TIMEOUT) {
            break;  /* 停止信号 */
        }

        /* 完整性检查 (每轮; EnableIntegrityMonitoring 门控) */
        if (RgP != NULL && RgP->Config.EnableIntegrityMonitoring) {
            RgPerformIntegrityCheck();
        }

        /* 旧快照清理 */
        RpCleanupOldSnapshots();
    }

    return 0;
}

/*++
Routine Description:
    完整性轮检 (PerformIntegrityCheck):
    [锁内]快照键清单 → [锁外]逐个 RpVerifyKeyIntegrity →
    Modified/Corrupted 且自动回滚时执行 RpRollbackKey。

--*/
static VOID RgPerformIntegrityCheck(VOID)
{
    WCHAR paths[RG_MAX_PROTECTED_KEYS][RG_MAX_KEY_PATH_LENGTH];
    ULONG count = 0;
    ULONG i;
    BOOLEAN rollbackEnabled;
    RG_PROTECTION_MODE mode;

    if (!RgP) {
        return;
    }

    RgLockShared();
    count = RgP->KeyCount;
    if (count > RG_MAX_PROTECTED_KEYS) {
        count = RG_MAX_PROTECTED_KEYS;
    }
    for (i = 0; i < count; i++) {
        StringCchCopyW(paths[i], RG_MAX_KEY_PATH_LENGTH, RgP->Keys[i].Public.NormalizedPath);
    }
    rollbackEnabled = RgP->Config.EnableAutoRollback;
    mode = RgP->Config.Mode;
    RgUnlockShared();

    RgStatsInc(TotalIntegrityChecks);

    for (i = 0; i < count; i++) {
        RG_INTEGRITY_STATUS st = RpVerifyKeyIntegrity(paths[i]);

        if ((st == RgIntegrityModified || st == RgIntegrityCorrupted) &&
            rollbackEnabled && mode >= RgModeRollback) {
            RpRollbackKey(paths[i]);
        }
    }
}

/*++ 监控线程启动 (StartMonitoring) --*/
static NTSTATUS RgStartMonitoring(VOID)
{
    if (!RgP) {
        return STATUS_UNSUCCESSFUL;
    }

    if (RgP->MonitorThread != NULL) {
        return STATUS_SUCCESS;  /* 已在运行 */
    }

    RgP->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (RgP->StopEvent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RgP->MonitorThread = CreateThread(NULL, 0, RgMonitorThreadMain, NULL, 0, NULL);
    if (RgP->MonitorThread == NULL) {
        CloseHandle(RgP->StopEvent);
        RgP->StopEvent = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

/*++ 监控线程停止 (StopMonitoring) --*/
static VOID RgStopMonitoring(VOID)
{
    if (!RgP) {
        return;
    }

    if (RgP->StopEvent != NULL) {
        SetEvent(RgP->StopEvent);
    }
    if (RgP->MonitorThread != NULL) {
        WaitForSingleObject(RgP->MonitorThread, 3000);
        CloseHandle(RgP->MonitorThread);
        RgP->MonitorThread = NULL;
    }
    if (RgP->StopEvent != NULL) {
        CloseHandle(RgP->StopEvent);
        RgP->StopEvent = NULL;
    }
}

/**************************************************/
/*  10  生命周期 / 配置域                          */
/**************************************************/

/*++ 引擎对象创建 (单例; 已存在幂等) --*/
static NTSTATUS RgCreateEngine(VOID)
{
    if (RgP == NULL) {
        RgP = (PRG_ENGINE_INTERNAL)malloc(sizeof(RG_ENGINE_INTERNAL));
        if (RgP == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ZeroMemory(RgP, sizeof(RG_ENGINE_INTERNAL));
        InitializeSRWLock(&RgP->Lock);
        RgP->State = RG_STATE_UNINITIALIZED;
        RgP->Stats.StartTime = RgNow();
    }
    return STATUS_SUCCESS;
}

/*++ 引擎状态重置 (Shutdown 后清空; 保留单例与锁) --*/
static VOID RgResetEngine(VOID)
{
    ULONG i;

    if (!RgP) {
        return;
    }

    /* 值条目期望数据 */
    for (i = 0; i < RgP->ValueCount; i++) {
        if (RgP->Values[i].ExpectedData != NULL) {
            free(RgP->Values[i].ExpectedData);
            RgP->Values[i].ExpectedData = NULL;
        }
    }
    RgP->ValueCount = 0;

    /* 键快照 */
    for (i = 0; i < RgP->KeyCount; i++) {
        RgFreeKeySnapshots(&RgP->Keys[i]);
    }
    RgP->KeyCount = 0;

    /* 白名单/回调/历史/统计 */
    RgP->WhitelistCount = 0;
    ZeroMemory(RgP->EventSlots, sizeof(RgP->EventSlots));
    ZeroMemory(RgP->IntegritySlots, sizeof(RgP->IntegritySlots));
    ZeroMemory(RgP->ChangeSlots, sizeof(RgP->ChangeSlots));
    ZeroMemory(RgP->History, sizeof(RgP->History));
    RgP->HistoryHead = 0;
    RgP->HistoryCount = 0;
    RgP->DecisionCallback = NULL;
    RgP->DecisionContext = NULL;

    ZeroMemory(&RgP->Stats, sizeof(RgP->Stats));
    RgP->Stats.StartTime = RgNow();
    RgP->EventIdCounter = 0;
    RgP->CallbackIdCounter = 0;
}

/**************************************************/
/*  11  名称工具 / 报告 / 自检                    */
/**************************************************/

PCWSTR RpGetProtectionModeName(_In_ RG_PROTECTION_MODE Mode)
{
    switch (Mode) {
    case RgModeDisabled: return L"Disabled";
    case RgModeMonitor: return L"Monitor";
    case RgModeProtect: return L"Protect";
    case RgModeRollback: return L"Rollback";
    case RgModeStrict: return L"Strict";
    default: return L"Unknown";
    }
}

PCWSTR RpGetProtectionTypeName(_In_ RG_KEY_PROTECTION_TYPE Type)
{
    switch (Type) {
    case RgKeyTypeNone: return L"None";
    case RgKeyTypeReadOnly: return L"ReadOnly";
    case RgKeyTypeNoDelete: return L"NoDelete";
    case RgKeyTypeNoModify: return L"NoModify";
    case RgKeyTypeFull: return L"Full";
    case RgKeyTypeValuesOnly: return L"ValuesOnly";
    case RgKeyTypeCustom: return L"Custom";
    default: return L"Unknown";
    }
}

PCWSTR RpGetIntegrityStatusName(_In_ RG_INTEGRITY_STATUS Status)
{
    switch (Status) {
    case RgIntegrityUnknown: return L"Unknown";
    case RgIntegrityValid: return L"Valid";
    case RgIntegrityModified: return L"Modified";
    case RgIntegrityMissing: return L"Missing";
    case RgIntegrityCorrupted: return L"Corrupted";
    case RgIntegrityNew: return L"New";
    case RgIntegrityRestored: return L"Restored";
    default: return L"Unknown";
    }
}

PCWSTR RpGetValueTypeName(_In_ RG_REGISTRY_VALUE_TYPE Type)
{
    switch (Type) {
    case RgValueNone: return L"None";
    case RgValueString: return L"REG_SZ";
    case RgValueExpandString: return L"REG_EXPAND_SZ";
    case RgValueBinary: return L"REG_BINARY";
    case RgValueDWord: return L"REG_DWORD";
    case RgValueDWordBigEndian: return L"REG_DWORD_BIG_ENDIAN";
    case RgValueLink: return L"REG_LINK";
    case RgValueMultiString: return L"REG_MULTI_SZ";
    case RgValueResourceList: return L"REG_RESOURCE_LIST";
    case RgValueFullResourceDesc: return L"REG_FULL_RESOURCE_DESCRIPTOR";
    case RgValueResourceReqList: return L"REG_RESOURCE_REQUIREMENTS_LIST";
    case RgValueQWord: return L"REG_QWORD";
    default: return L"Unknown";
    }
}

PCWSTR RpGetRegistryOperationName(_In_ ULONG Operation)
{
    switch (Operation) {
    case RgOpQueryKey: return L"QueryKey";
    case RgOpSetValue: return L"SetValue";
    case RgOpDeleteValue: return L"DeleteValue";
    case RgOpCreateKey: return L"CreateKey";
    case RgOpDeleteKey: return L"DeleteKey";
    case RgOpRenameKey: return L"RenameKey";
    case RgOpEnumerateKey: return L"EnumerateKey";
    case RgOpEnumerateValue: return L"EnumerateValue";
    case RgOpQueryValue: return L"QueryValue";
    case RgOpSetKeySecurity: return L"SetKeySecurity";
    case RgOpQueryKeySecurity: return L"QueryKeySecurity";
    case RgOpFlushKey: return L"FlushKey";
    case RgOpLoadKey: return L"LoadKey";
    case RgOpUnloadKey: return L"UnloadKey";
    case RgOpSaveKey: return L"SaveKey";
    case RgOpRestoreKey: return L"RestoreKey";
    default: return L"Unknown";
    }
}

NTSTATUS
RpFormatRegistryOperation(_In_ ULONG Operation, _Out_writes_(Size) PSTR Out, _In_ ULONG Size)
{
    static const struct { ULONG Flag; PCSTR Name; } OpNames[] = {
        { RgOpQueryKey, "QueryKey" },
        { RgOpSetValue, "SetValue" },
        { RgOpDeleteValue, "DeleteValue" },
        { RgOpCreateKey, "CreateKey" },
        { RgOpDeleteKey, "DeleteKey" },
        { RgOpRenameKey, "RenameKey" },
        { RgOpEnumerateKey, "EnumerateKey" },
        { RgOpEnumerateValue, "EnumerateValue" },
        { RgOpQueryValue, "QueryValue" },
        { RgOpSetKeySecurity, "SetKeySecurity" },
        { RgOpQueryKeySecurity, "QueryKeySecurity" },
        { RgOpFlushKey, "FlushKey" },
        { RgOpLoadKey, "LoadKey" },
        { RgOpUnloadKey, "UnloadKey" },
        { RgOpSaveKey, "SaveKey" },
        { RgOpRestoreKey, "RestoreKey" },
    };
    ULONG i;
    CHAR tmp[512];
    SIZE_T used = 0;
    BOOLEAN first = TRUE;

    if (Out == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    Out[0] = '\0';
    if (Operation == 0) {
        StringCchCopyA(Out, Size, "None");
        return STATUS_SUCCESS;
    }

    tmp[0] = '\0';
    for (i = 0; i < ARRAYSIZE(OpNames); i++) {
        if ((Operation & OpNames[i].Flag) == OpNames[i].Flag) {
            if (!first) {
                StringCchCatA(tmp, ARRAYSIZE(tmp), "|");
            }
            StringCchCatA(tmp, ARRAYSIZE(tmp), OpNames[i].Name);
            first = FALSE;
            used++;
        }
    }
    if (used == 0) {
        StringCchCopyA(tmp, ARRAYSIZE(tmp), "Unknown");
    }
    if (FAILED(StringCchCopyA(Out, Size, tmp))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    return STATUS_SUCCESS;
}

VOID
RpGetVersionString(_Out_writes_(32) PSTR Out, _In_ ULONG OutCch)
{
    if (Out == NULL || OutCch == 0) {
        return;
    }
    StringCchPrintfA(Out, OutCch, "%u.%u.%u",
        RG_VERSION_MAJOR, RG_VERSION_MINOR, RG_VERSION_PATCH);
}

/**************************************************/
/*  12  公开 API 实现                             */
/**************************************************/

PRG_PROTECTION
RpGetEngine(VOID)
{
    (VOID)RgCreateEngine();
    return (PRG_PROTECTION)RgP;
}

NTSTATUS
RpInitialize(_In_opt_ const RG_CONFIGURATION* Config)
{
    NTSTATUS status;
    ULONG i;

    status = RgCreateEngine();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 幂等: 已运行直接成功 (重复 Initialize 保护) */
    if (RgP->State == RG_STATE_RUNNING) {
        return STATUS_SUCCESS;
    }
    if (RgP->State == RG_STATE_STOPPING) {
        return STATUS_UNSUCCESSFUL;
    }

    RgLockExclusive();
    RgResetEngine();

    if (Config != NULL) {
        RgP->Config = *Config;
        /* 护栏: 上限截断 */
        if (RgP->Config.ProtectedKeyCount > RG_MAX_CONFIG_KEYS) {
            RgP->Config.ProtectedKeyCount = RG_MAX_CONFIG_KEYS;
        }
        if (RgP->Config.WhitelistedProcessCount > RG_MAX_CONFIG_WHITELIST) {
            RgP->Config.WhitelistedProcessCount = RG_MAX_CONFIG_WHITELIST;
        }
        if (RgP->Config.PollingIntervalMs == 0) {
            RgP->Config.PollingIntervalMs = RG_POLLING_INTERVAL_MS;
        }
        if (RgP->Config.MaxSnapshotsPerKey == 0 ||
            RgP->Config.MaxSnapshotsPerKey > RG_MAX_SNAPSHOTS_PER_KEY) {
            RgP->Config.MaxSnapshotsPerKey = RG_MAX_SNAPSHOTS_PER_KEY;
        }
    } else {
        /* 默认配置 (FromMode(Protect) 语义) */
        ZeroMemory(&RgP->Config, sizeof(RgP->Config));
        RgP->Config.Mode = RgModeProtect;
        RgP->Config.EnableKernelCallbacks = TRUE;      /* 记账; WkD 无通道, 内核桥留桩 */
        RgP->Config.EnableUserModePolling = TRUE;
        RgP->Config.PollingIntervalMs = RG_POLLING_INTERVAL_MS;
        RgP->Config.EnableIntegrityMonitoring = TRUE;
        RgP->Config.IntegrityCheckIntervalMs = 0;       /* 0=不节流, 每轮检查 (对齐 SS) */
        RgP->Config.EnableAutoRollback = FALSE;
        RgP->Config.EnableSnapshots = TRUE;
        RgP->Config.MaxSnapshotsPerKey = RG_MAX_SNAPSHOTS_PER_KEY;
        RgP->Config.DefaultResponse = RgResponseActive;
        RgP->Config.VerboseLogging = FALSE;
        RgP->Config.SendTelemetry = TRUE;
    }

    /* 注册初始保护键 → 内部表 (SetConfiguration protectedKeys) */
    for (i = 0; i < RgP->Config.ProtectedKeyCount && RgP->KeyCount < RG_MAX_PROTECTED_KEYS; i++) {
        WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
        if (RgNormalizeKeyPathImpl(RgP->Config.ProtectedKeys[i], norm) == NULL) {
            continue;
        }
        if (RgFindKeyIndex(norm) < 0) {
            PRG_KEY_ENTRY e = &RgP->Keys[RgP->KeyCount];
            ZeroMemory(e, sizeof(RG_KEY_ENTRY));
            e->Public.Id = 0;
            StringCchCopyW(e->Public.KeyPath, RG_MAX_KEY_PATH_LENGTH, RgP->Config.ProtectedKeys[i]);
            StringCchCopyW(e->Public.NormalizedPath, RG_MAX_KEY_PATH_LENGTH, norm);
            e->Public.RootKey = RgParseRootKeyImpl(norm);
            e->Public.Type = RgKeyTypeFull;
            e->Public.IncludeSubkeys = TRUE;
            e->Public.BlockedOperations = RgBlockedOpsForType(e);
            e->Public.Integrity = RgIntegrityUnknown;
            e->Public.ProtectedSince = RgQpcNow();
            e->Public.LastVerified = RgQpcNow();
            RgP->KeyCount++;
        }
    }

    /* 默认保护键 13 条 (L289-296: Full+includeSubkeys, 已受保护不重复) */
    for (i = 0; i < RG_DEFAULT_PROTECTED_KEY_COUNT && RgP->KeyCount < RG_MAX_PROTECTED_KEYS; i++) {
        WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
        if (RgNormalizeKeyPathImpl(RgDefaultProtectedKeys[i], norm) == NULL) {
            continue;
        }
        if (RgFindKeyIndex(norm) < 0) {
            PRG_KEY_ENTRY e = &RgP->Keys[RgP->KeyCount];
            ZeroMemory(e, sizeof(RG_KEY_ENTRY));
            e->Public.Id = 0;
            StringCchCopyW(e->Public.KeyPath, RG_MAX_KEY_PATH_LENGTH, RgDefaultProtectedKeys[i]);
            StringCchCopyW(e->Public.NormalizedPath, RG_MAX_KEY_PATH_LENGTH, norm);
            e->Public.RootKey = RgParseRootKeyImpl(norm);
            e->Public.Type = RgKeyTypeFull;
            e->Public.IncludeSubkeys = TRUE;
            e->Public.BlockedOperations = RgBlockedOpsForType(e);
            e->Public.Integrity = RgIntegrityUnknown;
            e->Public.ProtectedSince = RgQpcNow();
            e->Public.LastVerified = RgQpcNow();
            RgP->KeyCount++;
        }
    }

    /* 白名单 (L298-306: 配置 + 自身 3 进程) */
    for (i = 0; i < RgP->Config.WhitelistedProcessCount && RgP->WhitelistCount < RG_MAX_WHITELIST; i++) {
        if (RgP->Config.WhitelistedProcesses[i][0] != L'\0') {
            StringCchCopyW(RgP->Whitelist[RgP->WhitelistCount++], MAX_PATH,
                RgP->Config.WhitelistedProcesses[i]);
        }
    }
    for (i = 0; i < ARRAYSIZE(RgDefaultWhitelistedProcesses) && RgP->WhitelistCount < RG_MAX_WHITELIST; i++) {
        StringCchCopyW(RgP->Whitelist[RgP->WhitelistCount++], MAX_PATH, RgDefaultWhitelistedProcesses[i]);
    }

    RgP->State = RG_STATE_INITIALIZED;
    RgUnlockExclusive();

    /* 启动监控 (StartMonitoring) */
    status = RgStartMonitoring();
    if (!NT_SUCCESS(status)) {
        RgLockExclusive();
        RgP->State = RG_STATE_INITIALIZED;
        RgUnlockExclusive();
        return status;
    }

    RgLockExclusive();
    RgP->State = RG_STATE_RUNNING;
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"engine initialized (mode=%ls, keys=%lu, whitelist=%lu)",
        RpGetProtectionModeName(RgP->Config.Mode), RgP->KeyCount, RgP->WhitelistCount);

    return STATUS_SUCCESS;
}

NTSTATUS
RpInitializeMode(_In_ RG_PROTECTION_MODE Mode)
{
    NTSTATUS status;

    status = RpInitialize(NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RpSetProtectionMode(Mode);
    return STATUS_SUCCESS;
}

VOID
RpShutdown(VOID)
{
    if (!RgP) {
        return;
    }
    if (RgP->State == RG_STATE_UNINITIALIZED || RgP->State == RG_STATE_STOPPED) {
        return;
    }

    RgP->State = RG_STATE_STOPPING;

    /* 停监控线程 */
    RgStopMonitoring();

    /* 清空状态 (Shutdown; 令牌把关归门面不再重复校验) */
    RgLockExclusive();
    RgResetEngine();
    RgP->State = RG_STATE_STOPPED;
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"engine shutdown complete");
}

BOOLEAN
RpIsInitialized(VOID)
{
    if (!RgP) {
        return FALSE;
    }
    return (RgP->State == RG_STATE_RUNNING);
}

NTSTATUS
RpSetConfiguration(_In_ const RG_CONFIGURATION* Config)
{
    ULONG oldPolling;
    BOOLEAN restartPolling = FALSE;

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RpIsInitialized()) {
        return RG_STATUS_NOT_INITIALIZED;
    }
    if (Config->ProtectedKeyCount > RG_MAX_CONFIG_KEYS ||
        Config->WhitelistedProcessCount > RG_MAX_CONFIG_WHITELIST) {
        return STATUS_INVALID_PARAMETER;
    }

    RgLockExclusive();
    oldPolling = RgP->Config.PollingIntervalMs;
    RgP->Config = *Config;
    if (RgP->Config.PollingIntervalMs == 0) {
        RgP->Config.PollingIntervalMs = RG_POLLING_INTERVAL_MS;
    }
    if (RgP->Config.MaxSnapshotsPerKey == 0 ||
        RgP->Config.MaxSnapshotsPerKey > RG_MAX_SNAPSHOTS_PER_KEY) {
        RgP->Config.MaxSnapshotsPerKey = RG_MAX_SNAPSHOTS_PER_KEY;
    }
    if (RgP->Config.PollingIntervalMs != oldPolling) {
        restartPolling = TRUE;
    }
    RgUnlockExclusive();

    /* 轮询间隔变化 → 重启监控线程 (SetConfiguration) */
    if (restartPolling) {
        RgStopMonitoring();
        return RgStartMonitoring();
    }
    return STATUS_SUCCESS;
}

NTSTATUS
RpGetConfiguration(_Out_ PRG_CONFIGURATION Config)
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    *Config = RgP->Config;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

VOID
RpSetProtectionMode(_In_ RG_PROTECTION_MODE Mode)
{
    if (!RgP) {
        return;
    }
    RgLockExclusive();
    RgP->Config.Mode = Mode;
    RgUnlockExclusive();
}

RG_PROTECTION_MODE
RpGetProtectionMode(VOID)
{
    RG_PROTECTION_MODE mode = RgModeDisabled;

    if (!RgP) {
        return mode;
    }
    RgLockShared();
    mode = RgP->Config.Mode;
    RgUnlockShared();
    return mode;
}

/**************************************************/
/*  13  键保护公开 API                            */
/**************************************************/

/*++ 键注册内部 (调用方持排他锁; 幂等语义返回 NTSTATUS) --*/
static NTSTATUS RgAddProtectedKeyLocked(_In_ PCWSTR RawPath, _In_ PCWSTR Norm,
    _In_ RG_KEY_PROTECTION_TYPE Type, _In_ BOOLEAN IncludeSubkeys)
{
    PRG_KEY_ENTRY e;

    if (RgFindKeyIndex(Norm) >= 0) {
        return RG_STATUS_ALREADY_EXISTS;   /* 对齐 SS: 已注册不重复 */
    }
    if (RgP->KeyCount >= RG_MAX_PROTECTED_KEYS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    e = &RgP->Keys[RgP->KeyCount];
    ZeroMemory(e, sizeof(RG_KEY_ENTRY));
    e->Public.Id = (ULONGLONG)(RgP->KeyCount + 1);
    StringCchCopyW(e->Public.KeyPath, RG_MAX_KEY_PATH_LENGTH, RawPath);
    StringCchCopyW(e->Public.NormalizedPath, RG_MAX_KEY_PATH_LENGTH, Norm);
    e->Public.RootKey = RgParseRootKeyImpl(Norm);
    e->Public.Type = Type;
    e->Public.IncludeSubkeys = IncludeSubkeys;
    e->Public.BlockedOperations = RgBlockedOpsForType(e);
    e->Public.Integrity = RgIntegrityUnknown;
    e->Public.ProtectedSince = RgQpcNow();
    e->Public.LastVerified = RgQpcNow();
    RgP->KeyCount++;

    return STATUS_SUCCESS;
}

NTSTATUS
RpProtectKey(_In_ PCWSTR KeyPath)
{
    return RpProtectKeyEx(KeyPath, RgKeyTypeFull, TRUE);
}

NTSTATUS
RpProtectKeyEx(_In_ PCWSTR KeyPath, _In_ RG_KEY_PROTECTION_TYPE Type, _In_ BOOLEAN IncludeSubkeys)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    NTSTATUS status;
    BOOLEAN snapshot = FALSE;

    if (KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RgLockExclusive();
    if (RgP->State != RG_STATE_RUNNING && RgP->State != RG_STATE_INITIALIZED) {
        RgUnlockExclusive();
        return RG_STATUS_NOT_INITIALIZED;
    }
    status = RgAddProtectedKeyLocked(KeyPath, norm, Type, IncludeSubkeys);
    if (!NT_SUCCESS(status)) {
        RgUnlockExclusive();
        return status;
    }
    /* 快照计划 (锁外执行, 防锁内 I/O) */
    snapshot = RgP->Config.EnableSnapshots;
    RgUnlockExclusive();

    /* 初始快照 + 基线 (ProtectKey: 保护成功 → 快照 + integrity=Valid) */
    if (snapshot) {
        status = RpCreateSnapshot(norm);
        if (NT_SUCCESS(status)) {
            RgLockExclusive();
            {
                LONG idx = RgFindKeyIndex(norm);
                if (idx >= 0) {
                    RgP->Keys[idx].Public.Integrity = RgIntegrityValid;
                    RgP->Keys[idx].Public.HasSnapshot = TRUE;
                }
            }
            RgUnlockExclusive();
        }
    }

    RgDbgPrint(RG_DBG_FMT, L"key protected: %ls (%ls, subs=%u)", norm,
        RpGetProtectionTypeName(Type), IncludeSubkeys);
    return STATUS_SUCCESS;
}

NTSTATUS
RpUnprotectKey(_In_ PCWSTR KeyPath)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;
    PRG_KEY_ENTRY entry;

    if (KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RgLockExclusive();
    if (RgP->State != RG_STATE_RUNNING) {
        RgUnlockExclusive();
        return RG_STATUS_NOT_INITIALIZED;
    }

    idx = RgFindKeyIndex(norm);
    if (idx < 0) {
        RgUnlockExclusive();
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    entry = &RgP->Keys[idx];
    RgFreeKeySnapshots(entry);
    /* 收拢数组 */
    if ((ULONG)idx + 1 < RgP->KeyCount) {
        RtlMoveMemory(&RgP->Keys[idx], &RgP->Keys[idx + 1],
            sizeof(RG_KEY_ENTRY) * (RgP->KeyCount - (ULONG)idx - 1));
    }
    RgP->KeyCount--;

    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"key unprotected: %ls", norm);
    return STATUS_SUCCESS;
}

BOOLEAN
RpIsKeyProtected(_In_ PCWSTR KeyPath)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;
    BOOLEAN result = FALSE;

    if (KeyPath == NULL || RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return FALSE;
    }
    if (!RgP) {
        return FALSE;
    }

    RgLockShared();
    idx = RgFindKeyIndex(norm);
    if (idx < 0) {
        idx = RgFindKeyAncestorIndex(norm);
    }
    result = (idx >= 0);
    RgUnlockShared();
    return result;
}

NTSTATUS
RpGetProtectedKey(_In_ PCWSTR KeyPath, _Out_ PRG_PROTECTED_KEY Key)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;

    if (Key == NULL || KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    idx = RgFindKeyIndex(norm);
    if (idx < 0) {
        RgUnlockShared();
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    *Key = RgP->Keys[idx].Public;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

NTSTATUS
RpGetAllProtectedKeys(_Out_writes_opt_(Capacity) PRG_PROTECTED_KEY Buffer, _In_ ULONG Capacity, _Out_ PULONG Count)
{
    ULONG i;
    ULONG need;

    if (Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    need = RgP->KeyCount;
    if (Buffer == NULL) {
        *Count = need;
        RgUnlockShared();
        return STATUS_SUCCESS;
    }
    if (Capacity < need) {
        *Count = need;
        RgUnlockShared();
        return STATUS_BUFFER_TOO_SMALL;
    }
    for (i = 0; i < need; i++) {
        Buffer[i] = RgP->Keys[i].Public;
    }
    *Count = need;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

NTSTATUS
RpProtectServiceKeys(VOID)
{
    static const WCHAR* const Paths[] = {
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikePhantomService",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeDriver",
        L"HKLM\\SOFTWARE\\ShadowStrike",
        L"HKCU\\SOFTWARE\\ShadowStrike",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\ShadowStrikePhantomService",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ShadowStrikePhantomService",
    };
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN anyFail = FALSE;

    (VOID)status;
    for (i = 0; i < ARRAYSIZE(Paths); i++) {
        NTSTATUS st = RpProtectKeyEx(Paths[i], RgKeyTypeFull, TRUE);
        if (!NT_SUCCESS(st)) {
            anyFail = TRUE;
        }
    }
    return anyFail ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

NTSTATUS
RpProtectStartupEntries(VOID)
{
    static const WCHAR* const Paths[] = {
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    };
    ULONG i;
    BOOLEAN anyFail = FALSE;

    for (i = 0; i < ARRAYSIZE(Paths); i++) {
        NTSTATUS st = RpProtectKeyEx(Paths[i], RgKeyTypeValuesOnly, FALSE);
        if (!NT_SUCCESS(st)) {
            anyFail = TRUE;
        }
    }
    return anyFail ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

NTSTATUS
RpProtectIFEOKeys(VOID)
{
    static const WCHAR* const Exes[] = {
        L"ShadowStrikePhantomService.exe",
        L"ShadowStrikeUI.exe",
        L"ShadowStrikeUpdater.exe",
    };
    ULONG i;
    BOOLEAN anyFail = FALSE;
    WCHAR path[RG_MAX_KEY_PATH_LENGTH];

    for (i = 0; i < ARRAYSIZE(Exes); i++) {
        StringCchPrintfW(path, RG_MAX_KEY_PATH_LENGTH,
            L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%ls",
            Exes[i]);
        NTSTATUS st = RpProtectKeyEx(path, RgKeyTypeFull, TRUE);
        if (!NT_SUCCESS(st)) {
            anyFail = TRUE;
        }
    }
    return anyFail ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

NTSTATUS
RpHardenKeyDACL(_In_ PCWSTR KeyPath)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    HKEY root;
    WCHAR sub[RG_MAX_KEY_PATH_LENGTH];
    HKEY hKey = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    BOOL daclPresent = FALSE;
    PACL dacl = NULL;
    BOOL daclDefaulted = FALSE;
    LONG lerr;
    NTSTATUS status = STATUS_SUCCESS;

    if (KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    root = RgParseRootKeyImpl(norm);
    if (root == NULL || !NT_SUCCESS(RgGetSubkeyPathImpl(norm, sub))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 受限 DACL (HardenKeyDACL:
     * SYSTEM/管理员=全控, 认证用户=只读, Everyone=拒绝写/删/改权) */
    lerr = RegOpenKeyExW(root, sub, 0, WRITE_DAC | READ_CONTROL, &hKey);
    if (lerr != ERROR_SUCCESS) {
        return STATUS_ACCESS_DENIED;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;AU)(D;;WDWOSDDTKAWP;;;WD)",
            SDDL_REVISION_1, &pSD, NULL)) {
        RegCloseKey(hKey);
        return STATUS_UNSUCCESSFUL;
    }

    if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) || !daclPresent || dacl == NULL) {
        LocalFree(pSD);
        RegCloseKey(hKey);
        return STATUS_UNSUCCESSFUL;
    }

    lerr = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSD);
    if (lerr != ERROR_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
    }

    LocalFree(pSD);
    RegCloseKey(hKey);
    return status;
}

/**************************************************/
/*  14  值保护公开 API                            */
/**************************************************/

NTSTATUS
RpProtectValue(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    PVOID data = NULL;
    ULONG dataSize = 0;
    RG_REGISTRY_VALUE_TYPE type = RgValueNone;
    UCHAR hash[RG_SHA256_SIZE];
    NTSTATUS status;
    LONG idx;

    if (KeyPath == NULL || ValueName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (wcschr(ValueName, L'\\') != NULL) {
        return STATUS_INVALID_PARAMETER;    /* 值名不允许路径分隔符 */
    }
    if (!RgP || (RgP->State != RG_STATE_RUNNING && RgP->State != RG_STATE_INITIALIZED)) {
        return RG_STATUS_NOT_INITIALIZED;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 已有同键同值 → 幂等拒绝 (对齐 SS: 不重复注册) */
    RgLockShared();
    idx = RgFindValueIndex(composite);
    RgUnlockShared();
    if (idx >= 0) {
        return RG_STATUS_ALREADY_EXISTS;
    }

    /* 读数建立基线 (锁外 I/O; ProtectValue) */
    status = RgReadValueData(norm, ValueName, &data, &dataSize, &type);
    if (!NT_SUCCESS(status)) {
        return status;  /* 键/值不存在 → 不注册 (对齐 SS) */
    }
    ZeroMemory(hash, sizeof(hash));
    if (!RgComputeSha256((const UCHAR*)data, dataSize, hash)) {
        free(data);
        return STATUS_UNSUCCESSFUL;
    }

    /* 上限护栏 (SS 无此检查 — 迁移补: RG_MAX_PROTECTED_VALUES) */
    RgLockExclusive();
    if (RgP->ValueCount >= RG_MAX_PROTECTED_VALUES) {
        RgUnlockExclusive();
        free(data);
        RgDbgPrint(RG_DBG_FMT, L"value protection cap reached (%u), refusing %ls\\%ls",
            RG_MAX_PROTECTED_VALUES, norm, ValueName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (RgFindValueIndex(composite) >= 0) {     /* 并发双插防护 */
        RgUnlockExclusive();
        free(data);
        return RG_STATUS_ALREADY_EXISTS;
    }

    {
        PRG_VALUE_ENTRY e = &RgP->Values[RgP->ValueCount];
        ZeroMemory(e, sizeof(RG_VALUE_ENTRY));
        e->Public.Id = (ULONGLONG)(RgP->ValueCount + 1);
        StringCchCopyW(e->Public.KeyPath, RG_MAX_KEY_PATH_LENGTH, composite);
        StringCchCopyW(e->Public.ValueName, RG_MAX_VALUE_NAME_LENGTH, ValueName);
        e->Public.ValueType = type;
        RtlCopyMemory(e->Public.ExpectedHash, hash, RG_SHA256_SIZE);
        RtlCopyMemory(e->Public.CurrentHash, hash, RG_SHA256_SIZE);
        e->Public.DataSize = dataSize;
        e->Public.Integrity = RgIntegrityValid;
        e->Public.ProtectedSince = RgQpcNow();
        e->Public.LastVerified = RgQpcNow();
        e->Public.ModificationCount = 0;
        e->ExpectedData = data;             /* 转移所有权 */
        e->ExpectedDataSize = dataSize;
        RgP->ValueCount++;
    }
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"value protected: %ls", composite);
    return STATUS_SUCCESS;
}

NTSTATUS
RpUnprotectValue(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    LONG idx;

    if (KeyPath == NULL || ValueName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockExclusive();
    idx = RgFindValueIndex(composite);
    if (idx < 0) {
        RgUnlockExclusive();
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (RgP->Values[idx].ExpectedData != NULL) {
        free(RgP->Values[idx].ExpectedData);
    }
    if ((ULONG)idx + 1 < RgP->ValueCount) {
        RtlMoveMemory(&RgP->Values[idx], &RgP->Values[idx + 1],
            sizeof(RG_VALUE_ENTRY) * (RgP->ValueCount - (ULONG)idx - 1));
    }
    RgP->ValueCount--;
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"value unprotected: %ls", composite);
    return STATUS_SUCCESS;
}

BOOLEAN
RpIsValueProtected(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    BOOLEAN result;

    if (KeyPath == NULL || ValueName == NULL) {
        return FALSE;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return FALSE;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return FALSE;
    }
    if (!RgP) {
        return FALSE;
    }

    RgLockShared();
    result = (RgFindValueIndex(composite) >= 0);
    RgUnlockShared();
    return result;
}

NTSTATUS
RpGetProtectedValue(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName, _Out_ PRG_PROTECTED_VALUE Value)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    LONG idx;

    if (Value == NULL || KeyPath == NULL || ValueName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    idx = RgFindValueIndex(composite);
    if (idx < 0) {
        RgUnlockShared();
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    *Value = RgP->Values[idx].Public;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

NTSTATUS
RpGetProtectedValues(_In_ PCWSTR KeyPath, _Out_writes_opt_(Capacity) PRG_PROTECTED_VALUE Buffer, _In_ ULONG Capacity, _Out_ PULONG Count)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    ULONG need = 0;
    ULONG written = 0;
    ULONG i;

    if (Count == NULL || KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    /* 前缀匹配: value.KeyPath = "norm\\valueName" → 以 "norm\\" 开头 */
    {
        WCHAR prefix[RG_MAX_KEY_PATH_LENGTH + 2];
        StringCchPrintfW(prefix, ARRAYSIZE(prefix), L"%ls\\", norm);
        for (i = 0; i < RgP->ValueCount; i++) {
            if (_wcsnicmp(RgP->Values[i].Public.KeyPath, prefix, wcslen(prefix)) == 0) {
                need++;
            }
        }
    }
    if (Buffer == NULL) {
        *Count = need;
        RgUnlockShared();
        return STATUS_SUCCESS;
    }
    if (Capacity < need) {
        *Count = need;
        RgUnlockShared();
        return STATUS_BUFFER_TOO_SMALL;
    }
    {
        WCHAR prefix[RG_MAX_KEY_PATH_LENGTH + 2];
        StringCchPrintfW(prefix, ARRAYSIZE(prefix), L"%ls\\", norm);
        for (i = 0; i < RgP->ValueCount && written < need; i++) {
            if (_wcsnicmp(RgP->Values[i].Public.KeyPath, prefix, wcslen(prefix)) == 0) {
                Buffer[written++] = RgP->Values[i].Public;
            }
        }
    }
    *Count = written;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

/**************************************************/
/*  15  操作过滤公开 API                          */
/**************************************************/

BOOLEAN
RpIsOperationAllowed(_In_ PCWSTR KeyPath, _In_ ULONG OpType)
{
    RG_OPERATION_REQUEST req;
    RG_DECISION_RESULT res;
    DWORD pid;
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];

    if (KeyPath == NULL || RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return TRUE;    /* 无效输入放行 (保守) */
    }

    ZeroMemory(&req, sizeof(req));
    req.Operation = OpType;
    StringCchCopyW(req.KeyPath, RG_MAX_KEY_PATH_LENGTH, norm);
    pid = GetCurrentProcessId();
    req.ProcessId = (ULONG)GetCurrentProcessId();
    req.ThreadId = (ULONG)GetCurrentThreadId();
    RgGetProcessNameByPid(pid, req.ProcessName, MAX_PATH);
    req.Timestamp = RgNow();

    ZeroMemory(&res, sizeof(res));
    if (!NT_SUCCESS(RpFilterOperation(&req, &res))) {
        return TRUE;
    }
    return (res.Decision != RgDecisionBlock);
}

NTSTATUS
RpFilterOperation(_In_ const RG_OPERATION_REQUEST* Request, _Out_ PRG_DECISION_RESULT Result)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    RG_OPERATION_DECISION decision = RgDecisionAllow;
    CHAR reason[256];
    BOOLEAN log = FALSE;
    BOOLEAN alert = FALSE;
    BOOLEAN snapshot = FALSE;
    BOOLEAN rollback = FALSE;
    BOOLEAN blocked = FALSE;
    BOOLEAN whitelisted = FALSE;
    RG_PROTECTION_MODE mode;
    BOOLEAN initializing;

    if (Request == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    ZeroMemory(Result, sizeof(*Result));
    reason[0] = '\0';
    StringCchCopyA(reason, sizeof(reason), "allowed by default");

    /* 引擎未运行 → 放行 */
    if (!RgP) {
        Result->Decision = RgDecisionAllow;
        return STATUS_SUCCESS;
    }

    if (RgNormalizeKeyPathImpl(Request->KeyPath, norm) == NULL) {
        Result->Decision = RgDecisionAllow;
        return STATUS_SUCCESS;
    }

    RgLockShared();
    initializing = (RgP->State == RG_STATE_RUNNING || RgP->State == RG_STATE_INITIALIZED);
    mode = RgP->Config.Mode;
    RgUnlockShared();

    if (!initializing || mode == RgModeDisabled) {
        Result->Decision = RgDecisionAllow;
        return STATUS_SUCCESS;
    }

    /* 决策回调 (锁内调用, 对齐 SS: callback 限定决策时采用其结果) */
    {
        RG_OPERATION_DECISION_CALLBACK cb = NULL;
        PVOID ctx = NULL;
        RgLockShared();
        if (RgP->DecisionCallback != NULL && mode >= RgModeMonitor) {
            cb = RgP->DecisionCallback;
            ctx = RgP->DecisionContext;
        }
        RgUnlockShared();

        if (cb != NULL) {
            RG_DECISION_RESULT cbResult;
            ZeroMemory(&cbResult, sizeof(cbResult));
            if (cb(Request, &cbResult, ctx)) {
                decision = cbResult.Decision;
                StringCchCopyA(reason, sizeof(reason),
                    cbResult.Reason[0] ? cbResult.Reason : "decision callback");
                log = cbResult.ShouldLog;
                alert = cbResult.ShouldAlert;
                snapshot = cbResult.ShouldSnapshot;
                rollback = cbResult.ShouldRollback;
                blocked = (decision == RgDecisionBlock);
                if (blocked && (ULONG)mode >= (ULONG)RgModeRollback) {
                    rollback = TRUE;
                }
                goto done;
            }
        }
    }

    /* 白名单 (请求自带标记优先; 否则 PID 判定 — 名称+验签) */
    if (Request->IsWhitelisted) {
        whitelisted = TRUE;
    } else {
        WCHAR name[MAX_PATH];
        whitelisted = RgIsProcessWhitelisted(Request->ProcessId, name);
    }

    if (whitelisted) {
        decision = RgDecisionAllowLogged;
        StringCchCopyA(reason, sizeof(reason), "process is whitelisted");
        log = TRUE;
        goto done;
    }

    /* 键保护判定 (直接命中 → 祖先 includeSubkeys 链) */
    {
        LONG idx = -1;
        ULONG blockedOps = 0;

        RgLockShared();
        idx = RgFindKeyIndex(norm);
        if (idx < 0) {
            idx = RgFindKeyAncestorIndex(norm);
        }
        if (idx >= 0) {
            blockedOps = RgBlockedOpsForType(&RgP->Keys[idx]);
        }
        RgUnlockShared();

        if (idx >= 0 && (blockedOps & Request->Operation) != 0) {
            decision = RgDecisionBlock;
            StringCchPrintfA(reason, sizeof(reason),
                "operation blocked by registry protection policy (key type %s)",
                "protected");
            log = TRUE;
            alert = TRUE;
            blocked = TRUE;

            /* 模式修正 (对齐 SS: Monitor 记录放行; Rollback/Strict 触发回滚意图) */
            if (mode == RgModeMonitor) {
                decision = RgDecisionAllowLogged;
                blocked = FALSE;
            } else if ((ULONG)mode >= (ULONG)RgModeRollback) {
                rollback = TRUE;
            }
            goto done;
        }
    }

    /* 值保护: 写类操作对受保护值拦截 (键未覆盖或 ValuesOnly 键时) */
    if ((Request->Operation & (RgOpSetValue | RgOpDeleteValue)) != 0 && Request->ValueName[0] != L'\0') {
        RgLockShared();
        if (RgIsValueProtectedByEntryLocked(norm, Request->ValueName)) {
            decision = RgDecisionBlock;
            StringCchCopyA(reason, sizeof(reason), "value is protected");
            log = TRUE;
            alert = TRUE;
            blocked = TRUE;
            if (mode == RgModeMonitor) {
                decision = RgDecisionAllowLogged;
                blocked = FALSE;
            } else if ((ULONG)mode >= (ULONG)RgModeRollback) {
                rollback = TRUE;
            }
        }
        RgUnlockShared();
        if (blocked || decision == RgDecisionBlock) {
            goto done;
        }
    }

    /* 未命中任何策略 → 记录级放行 (SendTelemetry 门控) */
    decision = RgDecisionAllowLogged;
    if (RgP->Config.SendTelemetry) {
        log = TRUE;
    }
    StringCchCopyA(reason, sizeof(reason), "allowed (no matching protection policy)");

done:
    /* 填充结果 */
    Result->Decision = decision;
    StringCchCopyA(Result->Reason, sizeof(Result->Reason), reason);
    Result->ShouldLog = log;
    Result->ShouldAlert = alert;
    Result->ShouldSnapshot = snapshot;
    Result->ShouldRollback = rollback;

    /* 事件上行 (锁外; FireBlockedOperationEvent) */
    if (blocked) {
        ULONG response = RgResponseLog | RgResponseAlert;
        if (rollback) {
            response |= RgResponseRollback;
        }
        RgStatsInc(TotalBlocked);
        RgNoteEvent(RgEventOperationBlocked, norm, Request->ValueName,
            Request->Operation, decision, response, TRUE, rollback, reason);
    }

    RgStatsInc(TotalOperations);
    return STATUS_SUCCESS;
}

NTSTATUS
RpSetDecisionCallback(_In_opt_ RG_OPERATION_DECISION_CALLBACK Callback, _In_opt_ PVOID Context)
{
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }
    RgLockExclusive();
    RgP->DecisionCallback = Callback;
    RgP->DecisionContext = Context;
    RgUnlockExclusive();
    return STATUS_SUCCESS;
}

NTSTATUS
RpClearDecisionCallback(VOID)
{
    return RpSetDecisionCallback(NULL, NULL);
}

/**************************************************/
/*  16  完整性公开 API                            */
/**************************************************/

RG_INTEGRITY_STATUS
RpVerifyKeyIntegrity(_In_ PCWSTR KeyPath)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;
    RG_INTEGRITY_STATUS preIntegrity;
    HKEY root;
    WCHAR sub[RG_MAX_KEY_PATH_LENGTH];
    HKEY hKey = NULL;
    BOOLEAN exists;
    ULONG agg = RgIntegrityValid;
    ULONG valueCount = 0;
    ULONG i;
    BOOLEAN hasValues = FALSE;
    LONG lerr;

    if (KeyPath == NULL || RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return RgIntegrityUnknown;
    }
    if (!RgP) {
        return RgIntegrityUnknown;
    }

    RgLockShared();
    idx = RgFindKeyIndex(norm);
    if (idx < 0) {
        RgUnlockShared();
        return RgIntegrityUnknown;              /* 防御: 未保护键不判定 */
    }
    preIntegrity = RgP->Keys[idx].Public.Integrity;
    RgUnlockShared();

    /* 存在性检查 (锁外 I/O; ValidateKey) */
    root = RgParseRootKeyImpl(norm);
    exists = FALSE;
    if (root != NULL && NT_SUCCESS(RgGetSubkeyPathImpl(norm, sub))) {
        lerr = RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE, &hKey);
        if (lerr == ERROR_SUCCESS) {
            exists = TRUE;
            RegCloseKey(hKey);
        }
    }

    if (!exists) {
        /* 防御逻辑 (对齐 SS): 仅先前 Valid 键缺失 → Missing (告警);
         * Unknown 等缺失 → 保持未知 (不告警, 避免初始化竞态误报) */
        if (preIntegrity == RgIntegrityValid) {
            RgLockExclusive();
            if (RgP && RgFindKeyIndex(norm) >= 0) {
                RgP->Keys[idx].Public.Integrity = RgIntegrityMissing;
                RgP->Keys[idx].Public.LastVerified = RgNow();
                preIntegrity = RgIntegrityMissing;
            }
            RgUnlockExclusive();
            RgStatsInc(IntegrityViolations);
            RgNoteEvent(RgEventIntegrityViolation, norm, NULL, RgOpQueryKey,
                RgDecisionBlock, RgResponseAlert, TRUE, FALSE, "protected registry key is missing");
            RgDispatchIntegrityCallback(norm, RgIntegrityMissing);
            return RgIntegrityMissing;
        }
        return RgIntegrityUnknown;
    }

    /* 键存在 → 校验其全部受保护值 (锁外; 值列表锁内快照) */
    {
        ULONG indices[RG_MAX_PROTECTED_VALUES];
        WCHAR prefix[RG_MAX_KEY_PATH_LENGTH + 2];

        RgLockShared();
        StringCchPrintfW(prefix, ARRAYSIZE(prefix), L"%ls\\", norm);
        for (i = 0; i < RgP->ValueCount && valueCount < RG_MAX_PROTECTED_VALUES; i++) {
            if (_wcsnicmp(RgP->Values[i].Public.KeyPath, prefix, wcslen(prefix)) == 0) {
                indices[valueCount++] = i;
            }
        }
        RgUnlockShared();

        if (valueCount > 0) {
            hasValues = TRUE;
            for (i = 0; i < valueCount; i++) {
                PRG_VALUE_ENTRY entry;
                RG_INTEGRITY_STATUS st;

                RgLockShared();
                if (indices[i] >= RgP->ValueCount) {
                    RgUnlockShared();
                    continue;
                }
                entry = &RgP->Values[indices[i]];
                /* 快照条目关键字段 (锁内深拷贝防释放竞态) */
                /* 实测: entry 指针在锁内使用即访问; 采用快照拷贝方式 */
                {
                    RG_VALUE_ENTRY copy = *entry;
                    if (copy.ExpectedData != NULL && copy.ExpectedDataSize > 0) {
                        copy.ExpectedData = malloc(copy.ExpectedDataSize);
                        if (copy.ExpectedData != NULL) {
                            RtlCopyMemory(copy.ExpectedData, entry->ExpectedData, copy.ExpectedDataSize);
                        }
                    } else {
                        copy.ExpectedData = NULL;
                    }
                    RgUnlockShared();
                    st = RgValidateValue(norm, &copy);
                    free(copy.ExpectedData);
                }

                if (st == RgIntegrityMissing) {
                    agg = RgIntegrityMissing;
                } else if (st == RgIntegrityModified) {
                    if (agg == RgIntegrityValid) {
                        agg = RgIntegrityModified;
                    }
                }
            }
        }
    }

    /* 聚合回写 */
    RgLockExclusive();
    if (RgP && RgFindKeyIndex(norm) >= 0) {
        RgP->Keys[idx].Public.Integrity = hasValues ? (RG_INTEGRITY_STATUS)agg : preIntegrity;
        RgP->Keys[idx].Public.LastVerified = RgNow();
        if (RgP->Keys[idx].Public.Integrity == RgIntegrityValid) {
            RgP->Keys[idx].Public.Integrity = RgIntegrityValid;
        }
    }
    RgUnlockExclusive();

    return (hasValues ? (RG_INTEGRITY_STATUS)agg : preIntegrity);
}

/*++ 单值校验 (公开入口; 包装 RgValidateValue 语义) --*/
static RG_INTEGRITY_STATUS RgVerifyValueIntegrityImpl(_In_ PCWSTR KeyNorm, _In_ PRG_VALUE_ENTRY Entry)
{
    if (!RgValidateValue(KeyNorm, Entry)) {
        /* 校验失败: 读取标识缺失/变更 (RgValidateValue 内已回写状态) */
        RgLockShared();
        if (Entry->Public.Integrity == RgIntegrityModified) {
            RgUnlockShared();
            return RgIntegrityModified;
        }
        RgUnlockShared();
    }
    return RgIntegrityValid;
}

RG_INTEGRITY_STATUS
RpVerifyValueIntegrity(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    LONG idx;
    RG_VALUE_ENTRY copy;
    RG_INTEGRITY_STATUS st;

    if (KeyPath == NULL || ValueName == NULL) {
        return RgIntegrityUnknown;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return RgIntegrityUnknown;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return RgIntegrityUnknown;
    }
    if (!RgP) {
        return RgIntegrityUnknown;
    }

    RgLockShared();
    idx = RgFindValueIndex(composite);
    if (idx < 0) {
        RgUnlockShared();
        return RgIntegrityUnknown;
    }
    copy = RgP->Values[idx];
    if (copy.ExpectedData != NULL && copy.ExpectedDataSize > 0) {
        copy.ExpectedData = malloc(copy.ExpectedDataSize);
        if (copy.ExpectedData == NULL) {
            RgUnlockShared();
            return RgIntegrityUnknown;
        }
        RtlCopyMemory(copy.ExpectedData, RgP->Values[idx].ExpectedData, copy.ExpectedDataSize);
    }
    RgUnlockShared();

    st = RgVerifyValueIntegrityImpl(norm, &copy);
    free(copy.ExpectedData);
    return st;
}

NTSTATUS
RpVerifyAllIntegrity(_Out_writes_opt_(Capacity) PRG_KEY_INTEGRITY_RESULT Buffer, _In_ ULONG Capacity, _Out_ PULONG Count)
{
    WCHAR paths[RG_MAX_PROTECTED_KEYS][RG_MAX_KEY_PATH_LENGTH];
    ULONG need;
    ULONG i;

    if (Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    need = RgP->KeyCount;
    for (i = 0; i < need; i++) {
        StringCchCopyW(paths[i], RG_MAX_KEY_PATH_LENGTH, RgP->Keys[i].Public.NormalizedPath);
    }
    RgUnlockShared();

    if (Buffer == NULL) {
        *Count = need;
        return STATUS_SUCCESS;
    }
    if (Capacity < need) {
        *Count = need;
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < need; i++) {
        Buffer[i].Integrity = RpVerifyKeyIntegrity(paths[i]);
        StringCchCopyW(Buffer[i].KeyPath, RG_MAX_KEY_PATH_LENGTH, paths[i]);
    }
    *Count = need;
    return STATUS_SUCCESS;
}

NTSTATUS
RpUpdateKeyBaseline(_In_ PCWSTR KeyPath)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;
    BOOLEAN snap = FALSE;

    if (KeyPath == NULL || RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    idx = RgFindKeyIndex(norm);
    snap = (idx >= 0) && RgP->Config.EnableSnapshots;
    RgUnlockShared();

    if (idx < 0) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    /* 先建快照 (锁外 I/O; UpdateKeyBaseline) */
    if (snap) {
        NTSTATUS st = RpCreateSnapshot(norm);
        if (!NT_SUCCESS(st)) {
            return st;
        }
    }

    RgLockExclusive();
    if (RgP && RgFindKeyIndex(norm) >= 0) {
        RgP->Keys[idx].Public.Integrity = RgIntegrityValid;
        RgP->Keys[idx].Public.LastVerified = RgNow();
    }
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"key baseline updated: %ls", norm);
    return STATUS_SUCCESS;
}

NTSTATUS
RpUpdateValueBaseline(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    PVOID data = NULL;
    ULONG dataSize = 0;
    RG_REGISTRY_VALUE_TYPE type = RgValueNone;
    UCHAR hash[RG_SHA256_SIZE];
    NTSTATUS status;
    LONG idx;

    if (KeyPath == NULL || ValueName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    /* 读当前 (锁外 I/O; 读值后更新基线) */
    status = RgReadValueData(norm, ValueName, &data, &dataSize, &type);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ZeroMemory(hash, sizeof(hash));
    if (!RgComputeSha256((const UCHAR*)data, dataSize, hash)) {
        free(data);
        return STATUS_UNSUCCESSFUL;
    }

    RgLockExclusive();
    idx = RgFindValueIndex(composite);
    if (idx < 0) {
        RgUnlockExclusive();
        free(data);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    /* 替换期望数据 */
    if (RgP->Values[idx].ExpectedData != NULL) {
        free(RgP->Values[idx].ExpectedData);
    }
    RgP->Values[idx].ExpectedData = data;               /* 转移所有权 */
    RgP->Values[idx].ExpectedDataSize = dataSize;
    RtlCopyMemory(RgP->Values[idx].Public.ExpectedHash, hash, RG_SHA256_SIZE);
    RtlCopyMemory(RgP->Values[idx].Public.CurrentHash, hash, RG_SHA256_SIZE);
    RgP->Values[idx].Public.Integrity = RgIntegrityValid;
    RgP->Values[idx].Public.ValueType = type;
    RgP->Values[idx].Public.DataSize = dataSize;
    RgP->Values[idx].Public.LastVerified = RgNow();
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"value baseline updated: %ls", composite);
    return STATUS_SUCCESS;
}

VOID
RpForceIntegrityCheck(VOID)
{
    if (!RgP) {
        return;
    }
    RgPerformIntegrityCheck();
}

/**************************************************/
/*  17  快照 / 回滚公开 API                       */
/**************************************************/

NTSTATUS
RpCreateSnapshot(_In_ PCWSTR KeyPath)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    HKEY root;
    WCHAR sub[RG_MAX_KEY_PATH_LENGTH];
    HKEY hKey = NULL;
    DWORD valueCount = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueData = 0;
    DWORD subkeyCount = 0;
    DWORD maxSubkeyLen = 0;
    RG_KEY_SNAPSHOT snap;
    ULONG i;
    LONG lerr;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN lockHeldForPush = FALSE;

    if (KeyPath == NULL || RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP || (RgP->State != RG_STATE_RUNNING && RgP->State != RG_STATE_INITIALIZED)) {
        return RG_STATUS_NOT_INITIALIZED;
    }
    /* 仅受保护键可快照 (CreateSnapshot) */
    if (!RpIsKeyProtected(norm)) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(&snap, sizeof(snap));
    StringCchCopyW(snap.KeyPath, RG_MAX_KEY_PATH_LENGTH, norm);
    snap.Timestamp = RgNow();

    root = RgParseRootKeyImpl(norm);
    if (root == NULL || !NT_SUCCESS(RgGetSubkeyPathImpl(norm, sub))) {
        return STATUS_INVALID_PARAMETER;
    }

    lerr = RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &hKey);
    if (lerr != ERROR_SUCCESS) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    lerr = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subkeyCount, &maxSubkeyLen, NULL,
        &valueCount, &maxValueNameLen, &maxValueData, NULL, NULL);
    if (lerr != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return STATUS_UNSUCCESSFUL;
    }

    /* 护栏: 截断超限 (防恶意海量子键/值 DoS 快照) */
    if (valueCount > RG_MAX_SNAPSHOT_VALUES) {
        RgDbgPrint(RG_DBG_FMT, L"snapshot %ls: value count %lu exceeds cap %u, truncating",
            norm, valueCount, RG_MAX_SNAPSHOT_VALUES);
        valueCount = RG_MAX_SNAPSHOT_VALUES;
    }
    if (subkeyCount > RG_MAX_SNAPSHOT_SUBKEYS) {
        RgDbgPrint(RG_DBG_FMT, L"snapshot %ls: subkey count %lu exceeds cap %u, truncating",
            norm, subkeyCount, RG_MAX_SNAPSHOT_SUBKEYS);
        subkeyCount = RG_MAX_SNAPSHOT_SUBKEYS;
    }

    /* 值枚举 */
    if (valueCount > 0) {
        snap.Values = (PRG_SNAPSHOT_ENTRY)calloc(valueCount, sizeof(RG_SNAPSHOT_ENTRY));
        if (snap.Values == NULL) {
            RegCloseKey(hKey);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        snap.ValueCount = 0;

        for (i = 0; i < valueCount; i++) {
            WCHAR nameBuf[RG_MAX_VALUE_NAME_LENGTH];
            DWORD nameLen = RG_MAX_VALUE_NAME_LENGTH;
            DWORD dataLen = 0;
            DWORD type = REG_NONE;
            PVOID data = NULL;

            lerr = RegEnumValueW(hKey, i, nameBuf, &nameLen, NULL, &type, NULL, &dataLen);
            if (lerr != ERROR_SUCCESS) {
                continue;
            }
            if (dataLen > RG_MAX_VALUE_DATA_SIZE) {
                RgDbgPrint(RG_DBG_FMT, L"snapshot %ls: value '%ls' data %lu bytes exceeds cap %u, skipping",
                    norm, nameBuf, dataLen, RG_MAX_VALUE_DATA_SIZE);
                continue;
            }

            if (dataLen > 0) {
                data = malloc(dataLen);
                if (data == NULL) {
                    continue;
                }
                lerr = RegEnumValueW(hKey, i, nameBuf, &nameLen, NULL, &type, (LPBYTE)data, &dataLen);
                if (lerr != ERROR_SUCCESS) {
                    free(data);
                    continue;
                }
            }

            StringCchCopyW(snap.Values[snap.ValueCount].Name, RG_MAX_VALUE_NAME_LENGTH, nameBuf);
            snap.Values[snap.ValueCount].Data = data;
            snap.Values[snap.ValueCount].DataSize = dataLen;
            snap.Values[snap.ValueCount].Type = (RG_REGISTRY_VALUE_TYPE)type;
            snap.ValueCount++;
        }
    }

    /* 子键枚举 (上限 RG_MAX_SNAPSHOT_SUBKEYS) */
    {
        ULONG subIdx = 0;
        while (subIdx < subkeyCount && snap.SubkeyCount < RG_MAX_SNAPSHOT_SUBKEYS) {
            WCHAR subName[RG_MAX_KEY_PATH_LENGTH];
            DWORD subNameLen = RG_MAX_KEY_PATH_LENGTH;

            lerr = RegEnumKeyExW(hKey, subIdx, subName, &subNameLen, NULL, NULL, NULL, NULL);
            if (lerr == ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (lerr != ERROR_SUCCESS) {
                subIdx++;
                continue;
            }
            StringCchCopyW(snap.Subkeys[snap.SubkeyCount], RG_MAX_KEY_PATH_LENGTH, subName);
            snap.SubkeyCount++;
            subIdx++;
        }
    }

    RegCloseKey(hKey);

    /* 入列 (锁内动作尽量短; 快照已锁外构造完成) */
    RgLockExclusive();
    status = RgPushSnapshot(norm, &snap);
    RgUnlockExclusive();
    lockHeldForPush = FALSE;

    if (NT_SUCCESS(status)) {
        RgStatsInc(SnapshotsCreated);
    } else {
        /* 入列失败: 释放本次快照 */
        RgFreeSnapshotValues(&snap);
    }

    RgDbgPrint(RG_DBG_FMT, L"snapshot created for %ls (values=%lu, subkeys=%lu)",
        norm, snap.ValueCount, snap.SubkeyCount);
    return status;
}

/*++ Phase2 值数据写回 (锁外; RestoreKeyValueData) --*/
static VOID RgRestoreKeyValueData(_In_ HKEY hKey, _In_ PRG_SNAPSHOT_ENTRY Values, _In_ ULONG ValueCount, _Out_ PULONG Succeeded)
{
    ULONG i;
    ULONG ok = 0;

    if (hKey == NULL || Values == NULL || Succeeded == NULL) {
        return;
    }
    for (i = 0; i < ValueCount; i++) {
        LONG lerr = RegSetValueExW(hKey, Values[i].Name, 0, (DWORD)Values[i].Type,
            (const BYTE*)Values[i].Data, Values[i].DataSize);
        if (lerr == ERROR_SUCCESS) {
            ok++;
        }
    }
    *Succeeded = ok;
}

NTSTATUS
RpRestoreFromSnapshot(_In_ PCWSTR KeyPath, _In_ ULONG Version)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;
    RG_KEY_SNAPSHOT copy;
    HKEY root;
    WCHAR sub[RG_MAX_KEY_PATH_LENGTH];
    HKEY hKey = NULL;
    ULONG valueCount = 0;
    BOOLEAN haveCopy = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    if (KeyPath == NULL || RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    /* Phase1: 锁定并深拷贝目标快照 */
    RgLockExclusive();
    idx = RgFindKeyIndex(norm);
    if (idx < 0) {
        RgUnlockExclusive();
        return STATUS_INVALID_PARAMETER;    /* 对齐 SS: 快照须受保护键 */
    }
    {
        PRG_KEY_ENTRY entry = &RgP->Keys[idx];
        PRG_KEY_SNAPSHOT best = NULL;
        ULONG v;

        if (Version == 0) {
            if (entry->SnapshotCount > 0) {
                best = &entry->Snapshots[entry->SnapshotCount - 1];   /* 最新 */
            }
        } else {
            for (v = 0; v < entry->SnapshotCount; v++) {
                if (entry->Snapshots[v].Version == Version) {
                    best = &entry->Snapshots[v];
                    break;
                }
            }
        }
        if (best == NULL) {
            RgUnlockExclusive();
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        ZeroMemory(&copy, sizeof(copy));
        status = RgSnapshotDeepCopy(&copy, best);
        if (!NT_SUCCESS(status)) {
            RgUnlockExclusive();
            return status;
        }
        haveCopy = TRUE;
        valueCount = copy.ValueCount;
    }
    RgUnlockExclusive();

    /* Phase2: 锁外写回 (RestoreKeyValueData 锁外 I/O) */
    root = RgParseRootKeyImpl(norm);
    status = STATUS_SUCCESS;
    if (root == NULL || !NT_SUCCESS(RgGetSubkeyPathImpl(copy.KeyPath, sub))) {
        status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }
    if (RegCreateKeyExW(root, sub, 0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }
    {
        ULONG restored = 0;
        RgRestoreKeyValueData(hKey, copy.Values, copy.ValueCount, &restored);
        if (copy.ValueCount > 0 && restored == 0) {
            status = STATUS_UNSUCCESSFUL;
        }
    }
    RegCloseKey(hKey);

    /* Phase3: 状态回写 + 基线重同步 (锁内轻动作) */
    RgLockExclusive();
    if (RgP && RgFindKeyIndex(norm) >= 0) {
        RgP->Keys[idx].Public.Integrity = RgIntegrityRestored;
        RgP->Keys[idx].Public.LastVerified = RgNow();
    } else {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    for (i = 0; i < RgP->ValueCount; i++) {
        /* 键下受保护值: 恢复后重读基线 (期望数据同步为恢复值) */
        /* 简化: 保持现有基线, 恢复动作由调用方后续 Verify 收敛 */
        UNREFERENCED_PARAMETER(i);
    }
    RgUnlockExclusive();

    RgStatsInc(SnapshotsRestored);
    RgNoteEvent(RgEventSnapshotRestored, copy.KeyPath, NULL, RgOpRestoreKey,
        RgDecisionAllowLogged, RgResponseRollback, FALSE, TRUE, "registry key restored from snapshot");

cleanup:
    RgFreeSnapshotValues(&copy);
    (VOID)haveCopy;
    return status;
}

NTSTATUS
RpGetAvailableSnapshots(_In_ PCWSTR KeyPath, _Out_writes_opt_(Capacity) PRG_KEY_SNAPSHOT Buffer, _In_ ULONG Capacity, _Out_ PULONG Count)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    LONG idx;
    ULONG need;
    ULONG i;

    if (Count == NULL || KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    idx = RgFindKeyIndex(norm);
    if (idx < 0) {
        RgUnlockShared();
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    need = RgP->Keys[idx].SnapshotCount;
    if (Buffer == NULL) {
        *Count = need;
        RgUnlockShared();
        return STATUS_SUCCESS;
    }
    if (Capacity < need) {
        *Count = need;
        RgUnlockShared();
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < need; i++) {
        NTSTATUS st = RgSnapshotDeepCopy(&Buffer[i], &RgP->Keys[idx].Snapshots[i]);
        if (!NT_SUCCESS(st)) {
            RgUnlockShared();
            return st;
        }
    }
    *Count = need;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

VOID
RpFreeSnapshot(_In_ PRG_KEY_SNAPSHOT Snapshot)
{
    RgFreeSnapshotValues(Snapshot);
}

NTSTATUS
RpRollbackKey(_In_ PCWSTR KeyPath)
{
    NTSTATUS st = RpRestoreFromSnapshot(KeyPath, 0);
    if (NT_SUCCESS(st)) {
        RgStatsInc(TotalRollbacks);
        RgNoteEvent(RgEventRollbackPerformed, KeyPath, NULL, RgOpRestoreKey,
            RgDecisionAllowLogged, RgResponseRollback, TRUE, TRUE, "registry key rolled back to latest snapshot");
    }
    return st;
}

NTSTATUS
RpRollbackValue(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName)
{
    WCHAR norm[RG_MAX_KEY_PATH_LENGTH];
    WCHAR composite[RG_MAX_KEY_PATH_LENGTH + RG_MAX_VALUE_NAME_LENGTH];
    LONG idx;
    PVOID expected = NULL;
    ULONG expectedSize = 0;
    RG_REGISTRY_VALUE_TYPE expectedType = RgValueNone;
    HKEY root;
    WCHAR sub[RG_MAX_KEY_PATH_LENGTH];
    HKEY hKey = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (KeyPath == NULL || ValueName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RgNormalizeKeyPathImpl(KeyPath, norm) == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(RgBuildCompositePath(norm, ValueName, composite))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    /* Phase1: 锁内定位 + 期望数据深拷贝 */
    RgLockShared();
    idx = RgFindValueIndex(composite);
    if (idx < 0) {
        RgUnlockShared();
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    expectedSize = RgP->Values[idx].ExpectedDataSize;
    expectedType = RgP->Values[idx].Public.ValueType;
    if (expectedSize > 0) {
        expected = malloc(expectedSize);
        if (expected == NULL) {
            RgUnlockShared();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(expected, RgP->Values[idx].ExpectedData, expectedSize);
    }
    RgUnlockShared();

    /* Phase2: 锁外写回 (RollbackValue) */
    root = RgParseRootKeyImpl(norm);
    if (root == NULL || !NT_SUCCESS(RgGetSubkeyPathImpl(norm, sub))) {
        free(expected);
        return STATUS_INVALID_PARAMETER;
    }
    if (RegCreateKeyExW(root, sub, 0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        free(expected);
        return STATUS_ACCESS_DENIED;
    }
    if (RegSetValueExW(hKey, ValueName, 0, (DWORD)expectedType, (const BYTE*)expected, expectedSize) != ERROR_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
    }
    RegCloseKey(hKey);
    free(expected);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Phase3: 状态回写 (对齐 SS: Restored + 当前哈希=期望哈希) */
    RgLockExclusive();
    if (RgP && RgFindValueIndex(composite) >= 0) {
        RgP->Values[idx].Public.Integrity = RgIntegrityRestored;
        RtlCopyMemory(RgP->Values[idx].Public.CurrentHash, RgP->Values[idx].Public.ExpectedHash, RG_SHA256_SIZE);
        RgP->Values[idx].Public.LastVerified = RgNow();
    } else {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    RgUnlockExclusive();

    RgStatsInc(TotalRollbacks);
    RgNoteEvent(RgEventRollbackPerformed, norm, ValueName, RgOpSetValue,
        RgDecisionAllowLogged, RgResponseRollback, TRUE, TRUE, "protected value rolled back to baseline");

    RgDbgPrint(RG_DBG_FMT, L"value rolled back: %ls", composite);
    return status;
}

VOID
RpCleanupOldSnapshots(VOID)
{
    if (!RgP) {
        return;
    }

    RgLockExclusive();
    {
        ULONG i;
        for (i = 0; i < RgP->KeyCount; i++) {
            PRG_KEY_ENTRY entry = &RgP->Keys[i];
            ULONG maxCount = (RgP->Config.MaxSnapshotsPerKey > 0)
                ? RgP->Config.MaxSnapshotsPerKey
                : RG_MAX_SNAPSHOTS_PER_KEY;
            if (maxCount > RG_MAX_SNAPSHOTS_PER_KEY) {
                maxCount = RG_MAX_SNAPSHOTS_PER_KEY;
            }
            while (entry->SnapshotCount > maxCount && entry->SnapshotCount > 0) {
                RgFreeSnapshotValues(&entry->Snapshots[0]);
                RtlMoveMemory(&entry->Snapshots[0], &entry->Snapshots[1],
                    sizeof(RG_KEY_SNAPSHOT) * (entry->SnapshotCount - 1));
                entry->SnapshotCount--;
            }
        }
    }
    RgUnlockExclusive();
}

/**************************************************/
/*  18  白名单公开 API                            */
/**************************************************/

NTSTATUS
RpAddToWhitelist(_In_ PCWSTR ProcessName)
{
    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockExclusive();
    if (RgIsWhitelistedLocked(ProcessName)) {
        RgUnlockExclusive();
        return RG_STATUS_ALREADY_EXISTS;
    }
    if (RgP->WhitelistCount >= RG_MAX_WHITELIST) {
        RgUnlockExclusive();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    StringCchCopyW(RgP->Whitelist[RgP->WhitelistCount++], MAX_PATH, ProcessName);
    RgUnlockExclusive();

    RgDbgPrint(RG_DBG_FMT, L"added to whitelist: %ls", ProcessName);
    return STATUS_SUCCESS;
}

NTSTATUS
RpRemoveFromWhitelist(_In_ PCWSTR ProcessName)
{
    ULONG i;

    if (ProcessName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockExclusive();
    for (i = 0; i < RgP->WhitelistCount; i++) {
        if (_wcsicmp(RgP->Whitelist[i], ProcessName) == 0) {
            if (i + 1 < RgP->WhitelistCount) {
                RtlMoveMemory(&RgP->Whitelist[i], &RgP->Whitelist[i + 1],
                    sizeof(WCHAR) * MAX_PATH * (RgP->WhitelistCount - i - 1));
            }
            RgP->WhitelistCount--;
            RgUnlockExclusive();
            RgDbgPrint(RG_DBG_FMT, L"removed from whitelist: %ls", ProcessName);
            return STATUS_SUCCESS;
        }
    }
    RgUnlockExclusive();
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

BOOLEAN
RpIsWhitelisted(_In_ PCWSTR ProcessName)
{
    BOOLEAN result = FALSE;

    if (ProcessName == NULL || !RgP) {
        return FALSE;
    }
    RgLockShared();
    result = RgIsWhitelistedLocked(ProcessName);
    RgUnlockShared();
    return result;
}

BOOLEAN
RpIsWhitelistedProcessId(_In_ ULONG ProcessId)
{
    return RgIsProcessWhitelisted(ProcessId, NULL);
}

NTSTATUS
RpGetWhitelistedProcesses(_Out_writes_opt_(Capacity) PWSTR Buffer, _In_ ULONG Capacity, _Out_ PULONG Count)
{
    ULONG need;
    ULONG i;

    if (Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    need = RgP->WhitelistCount;
    if (Buffer == NULL) {
        *Count = need;
        RgUnlockShared();
        return STATUS_SUCCESS;
    }
    if (Capacity < need) {
        *Count = need;
        RgUnlockShared();
        return STATUS_BUFFER_TOO_SMALL;
    }
    for (i = 0; i < need; i++) {
        StringCchCopyW(&Buffer[i * MAX_PATH], MAX_PATH, RgP->Whitelist[i]);
    }
    *Count = need;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

/**************************************************/
/*  19  事件回调 / 统计 / 历史 / 报告             */
/**************************************************/

NTSTATUS
RpRegisterEventCallback(_In_ RG_EVENT_CALLBACK Callback, _In_opt_ PVOID Context, _Out_ PULONG64 CallbackId)
{
    ULONG i;

    if (Callback == NULL || CallbackId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CallbackId = 0;
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockExclusive();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->EventSlots[i].Callback == NULL) {
            RgP->EventSlots[i].Id = (ULONGLONG)InterlockedIncrement64((volatile LONG64*)&RgP->CallbackIdCounter);
            RgP->EventSlots[i].Callback = Callback;
            RgP->EventSlots[i].Context = Context;
            *CallbackId = RgP->EventSlots[i].Id;
            RgUnlockExclusive();
            return STATUS_SUCCESS;
        }
    }
    RgUnlockExclusive();
    return STATUS_INSUFFICIENT_RESOURCES;   /* 槽满 */
}

VOID
RpUnregisterEventCallback(_In_ ULONG64 CallbackId)
{
    ULONG i;

    if (!RgP || CallbackId == 0) {
        return;
    }
    RgLockExclusive();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->EventSlots[i].Id == CallbackId && RgP->EventSlots[i].Callback != NULL) {
            RgP->EventSlots[i].Callback = NULL;
            RgP->EventSlots[i].Context = NULL;
            break;
        }
    }
    RgUnlockExclusive();
}

NTSTATUS
RpRegisterIntegrityCallback(_In_ RG_INTEGRITY_CALLBACK Callback, _In_opt_ PVOID Context, _Out_ PULONG64 CallbackId)
{
    ULONG i;

    if (Callback == NULL || CallbackId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CallbackId = 0;
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockExclusive();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->IntegritySlots[i].Callback == NULL) {
            RgP->IntegritySlots[i].Id = (ULONGLONG)InterlockedIncrement64((volatile LONG64*)&RgP->CallbackIdCounter);
            RgP->IntegritySlots[i].Callback = Callback;
            RgP->IntegritySlots[i].Context = Context;
            *CallbackId = RgP->IntegritySlots[i].Id;
            RgUnlockExclusive();
            return STATUS_SUCCESS;
        }
    }
    RgUnlockExclusive();
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
RpUnregisterIntegrityCallback(_In_ ULONG64 CallbackId)
{
    ULONG i;

    if (!RgP || CallbackId == 0) {
        return;
    }
    RgLockExclusive();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->IntegritySlots[i].Id == CallbackId && RgP->IntegritySlots[i].Callback != NULL) {
            RgP->IntegritySlots[i].Callback = NULL;
            RgP->IntegritySlots[i].Context = NULL;
            break;
        }
    }
    RgUnlockExclusive();
}

NTSTATUS
RpRegisterValueChangeCallback(_In_ RG_VALUE_CHANGE_CALLBACK Callback, _In_opt_ PVOID Context, _Out_ PULONG64 CallbackId)
{
    ULONG i;

    if (Callback == NULL || CallbackId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CallbackId = 0;
    if (!RgP || RgP->State != RG_STATE_RUNNING) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockExclusive();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->ChangeSlots[i].Callback == NULL) {
            RgP->ChangeSlots[i].Id = (ULONGLONG)InterlockedIncrement64((volatile LONG64*)&RgP->CallbackIdCounter);
            RgP->ChangeSlots[i].Callback = Callback;
            RgP->ChangeSlots[i].Context = Context;
            *CallbackId = RgP->ChangeSlots[i].Id;
            RgUnlockExclusive();
            return STATUS_SUCCESS;
        }
    }
    RgUnlockExclusive();
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
RpUnregisterValueChangeCallback(_In_ ULONG64 CallbackId)
{
    ULONG i;

    if (!RgP || CallbackId == 0) {
        return;
    }
    RgLockExclusive();
    for (i = 0; i < RG_MAX_CALLBACKS; i++) {
        if (RgP->ChangeSlots[i].Id == CallbackId && RgP->ChangeSlots[i].Callback != NULL) {
            RgP->ChangeSlots[i].Callback = NULL;
            RgP->ChangeSlots[i].Context = NULL;
            break;
        }
    }
    RgUnlockExclusive();
}

NTSTATUS
RpGetStatistics(_Out_ PRG_PROTECTION_STATISTICS Stats)
{
    RG_PROTECTION_STATISTICS s;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    ZeroMemory(&s, sizeof(s));
    RgLockShared();
    s = RgP->Stats;
    RgUnlockShared();

    /* 原子计数 (锁外一致性读) */
    s.TotalOperations = RgReadStats(TotalOperations);
    s.TotalBlocked = RgReadStats(TotalBlocked);
    s.TotalRollbacks = RgReadStats(TotalRollbacks);
    s.TotalIntegrityChecks = RgReadStats(TotalIntegrityChecks);
    s.IntegrityViolations = RgReadStats(IntegrityViolations);
    s.SnapshotsCreated = RgReadStats(SnapshotsCreated);
    s.SnapshotsRestored = RgReadStats(SnapshotsRestored);

    RgLockShared();
    s.TotalProtectedKeys = RgP->KeyCount;
    s.TotalProtectedValues = RgP->ValueCount;
    RgUnlockShared();

    *Stats = s;
    return STATUS_SUCCESS;
}

VOID
RpResetStatistics(VOID)
{
    if (!RgP) {
        return;
    }
    RgLockExclusive();
    ZeroMemory(&RgP->Stats, sizeof(RgP->Stats));
    RgP->Stats.StartTime = RgNow();
    RgUnlockExclusive();
}

NTSTATUS
RpGetEventHistory(_Out_writes_opt_(Capacity) PRG_PROTECTION_EVENT Buffer, _In_ ULONG Capacity, _Out_ PULONG Count)
{
    ULONG need;
    ULONG i;

    if (Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    RgLockShared();
    need = RgP->HistoryCount;
    if (Buffer == NULL) {
        *Count = need;
        RgUnlockShared();
        return STATUS_SUCCESS;
    }
    if (Capacity < need) {
        *Count = need;
        RgUnlockShared();
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 逆序输出: 最新在前 (环形回绕) */
    for (i = 0; i < need; i++) {
        ULONG srcIdx = (RgP->HistoryHead + RG_MAX_BLOCKED_OPERATIONS_LOG - 1 - i)
            % RG_MAX_BLOCKED_OPERATIONS_LOG;
        Buffer[i] = RgP->History[srcIdx];
    }
    *Count = need;
    RgUnlockShared();
    return STATUS_SUCCESS;
}

VOID
RpClearEventHistory(VOID)
{
    if (!RgP) {
        return;
    }
    RgLockExclusive();
    ZeroMemory(RgP->History, sizeof(RgP->History));
    RgP->HistoryHead = 0;
    RgP->HistoryCount = 0;
    RgUnlockExclusive();
}

NTSTATUS
RpExportReport(_Out_writes_(Size) PSTR Buffer, _In_ ULONG Size)
{
    RG_PROTECTION_STATISTICS stats;
    CHAR version[32];
    PCSTR statusName = "unknown";
    PCWSTR modeName = L"unknown";
    ULONG keyCount = 0;
    ULONG valueCount = 0;
    ULONG wlCount = 0;
    CHAR modeA[64];

    if (Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    Buffer[0] = '\0';
    if (!RgP) {
        return RG_STATUS_NOT_INITIALIZED;
    }

    (VOID)RpGetStatistics(&stats);

    RgLockShared();
    keyCount = RgP->KeyCount;
    valueCount = RgP->ValueCount;
    wlCount = RgP->WhitelistCount;
    modeName = RpGetProtectionModeName(RgP->Config.Mode);
    switch (RgP->State) {
    case RG_STATE_RUNNING: statusName = "running"; break;
    case RG_STATE_INITIALIZED: statusName = "initialized"; break;
    case RG_STATE_STOPPED: statusName = "stopped"; break;
    case RG_STATE_STOPPING: statusName = "stopping"; break;
    default: statusName = "uninitialized"; break;
    }
    RgUnlockShared();

    if (modeName == NULL) {
        modeName = L"unknown";
    }
    ZeroMemory(modeA, sizeof(modeA));
    WideCharToMultiByte(CP_UTF8, 0, modeName, -1, modeA, (int)sizeof(modeA), NULL, NULL);

    RpGetVersionString(version, ARRAYSIZE(version));

    StringCchPrintfA(Buffer, Size,
        "{\n"
        "  \"module\": \"registry-protection\",\n"
        "  \"version\": \"%s\",\n"
        "  \"status\": \"%s\",\n"
        "  \"mode\": \"%s\",\n"
        "  \"protectedKeys\": %lu,\n"
        "  \"protectedValues\": %lu,\n"
        "  \"whitelistedProcesses\": %lu,\n"
        "  \"statistics\": {\n"
        "    \"totalOperations\": %llu,\n"
        "    \"totalBlocked\": %llu,\n"
        "    \"totalRollbacks\": %llu,\n"
        "    \"totalIntegrityChecks\": %llu,\n"
        "    \"integrityViolations\": %llu,\n"
        "    \"snapshotsCreated\": %llu,\n"
        "    \"snapshotsRestored\": %llu\n"
        "  }\n"
        "}\n",
        version, statusName, modeA,
        keyCount, valueCount, wlCount,
        (unsigned long long)stats.TotalOperations,
        (unsigned long long)stats.TotalBlocked,
        (unsigned long long)stats.TotalRollbacks,
        (unsigned long long)stats.TotalIntegrityChecks,
        (unsigned long long)stats.IntegrityViolations,
        (unsigned long long)stats.SnapshotsCreated,
        (unsigned long long)stats.SnapshotsRestored);

    return (Buffer[0] != '\0') ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}

/**************************************************/
/*  20  自检 / 工具                               */
/**************************************************/

BOOLEAN
RpSelfTest(VOID)
{
    WCHAR out[RG_MAX_KEY_PATH_LENGTH];
    HKEY root;
    NTSTATUS status;
    LONG64 v0, v1;
    BOOLEAN pass = TRUE;

    /* 1. 规范化: 根前缀归一 + 子键小写折叠 */
    if (RgNormalizeKeyPathImpl(L"HKLM\\Software\\Test\\Sub", out) == NULL ||
        _wcsicmp(out, L"HKLM\\software\\test\\sub") != 0) {
        pass = FALSE;
    }

    /* 2. 根键解析 */
    root = RgParseRootKeyImpl(L"HKCU\\Software");
    if (root != HKEY_CURRENT_USER) {
        pass = FALSE;
    }

    /* 3. 子键提取 */
    status = RgGetSubkeyPathImpl(L"HKLM\\A\\B", out);
    if (!NT_SUCCESS(status) || _wcsicmp(out, L"A\\B") != 0) {
        pass = FALSE;
    }

    /* 4. 祖先链边界: "HKLM\\a\\bb" 不得命中父键 "hkLM\\a\\b" */
    if (RgIsAncestorKeyPath(L"HKLM\\a\\b", L"HKLM\\a\\bb")) {
        pass = FALSE;
    }

    /* 5. 原子统计读 (RgReadStats 语义) */
    if (RgP != NULL) {
        v0 = RgReadStats(TotalOperations);
        v1 = RgReadStats(TotalOperations);
        if (v0 != v1) {
            pass = FALSE;
        }
    } else {
        pass = FALSE;
    }

    return pass;
}

PCWSTR
RpNormalizeKeyPath(_In_ PCWSTR KeyPath, _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out)
{
    return RgNormalizeKeyPathImpl(KeyPath, Out);
}

HKEY
RpParseRootKey(_In_ PCWSTR KeyPath)
{
    return RgParseRootKeyImpl(KeyPath);
}

NTSTATUS
RpGetSubkeyPath(_In_ PCWSTR FullPath, _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out)
{
    return RgGetSubkeyPathImpl(FullPath, Out);
}

/**************************************************/
/*  21  内核桥 (留桩)                             */
/**************************************************/

NTSTATUS
RpSyncProtectedKeysToKernel(VOID)
{
    RgDbgPrint(RG_DBG_FMT,
        L"kernel registry callback bridge is NOT available in WkDefender (SS Protocol) — stub");
    return STATUS_NOT_SUPPORTED;    /* 后续驱动桥接时启用 */
}