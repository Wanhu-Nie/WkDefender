/**************************************************/
/*  WkDefender 文件系统分析能力模块（FileScan）       */
/**************************************************/

#include "FileSystem.h"   /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */
#include "../Notification/NotificationManager.h"   /* WKD_FLT_OP_* 操作类型（WkdFsTrackFileOperation 使用） */
#include "../Common/Exempts/Exempts.h"             /* 自保护豁免（ExemptsIsProcessTrusted） */

/*++
 * 实现说明：
 *   本模块迁移自 FileSystem\Filter.c 的活跃分析能力（拆分架构落地）：
 *     - canary/蜜罐/自保护/排除/rename 提取/删除确认/write 熵/勒索窗口计数/
 *       综合路径分析（B2）；
 *     - 死代码区（B1 写阻断分析、B3 扩展名分类、B4 敏感写模式、B6 访问模式、
 *       B7 stream context、B8.1 扫描缓存、B8.2 勒索关联、B8.3 EFI、B8.4 TxF、
 *       B8.6 蜜罐通配、B9 覆盖分析、B10 作用域访问分类、限速日志、勒索评分分区 C）
 *       已随 Filter.c 一并删除；勒索评分由 ProcessFileContext 模块（WkdPfcp*）承接。
 *     - 2026-10 迁移：敏感系统文件判定（WkdFsIsSensitiveSystemFile + 判定表）
 *       迁往 FileSystem\FileSystem.c；FspIsHardlinkSensitivePath /
 *       FspIsVolumeShadowCopyPath 迁往 FileSystem\PreSetInformation.c。
 *   本模块仅承载纯分析，不发送任何事件（事件上送归薄层 Callbacks\FileSystemNotification.c）。
 *--*/

/* 26100 SDK 已移除 STATUS_NOT_READY（旧值 0x00000110L）；本地补回兼容宏，
 * 值对齐旧 SDK 语义（设备/功能未就绪）。 */
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY ((NTSTATUS)0x00000110L)
#endif

/* ============================================================================
 * 写缓冲区熵（PostWrite.c g_EntropyTable + PwpCalculateEntropy）
 *   g_FsEntropyTable[i] = round(100*(8-log2(i)))，i=0 → 0。
 *   整数查表法返回 H*100（0~800，8.0bit/byte → 800），无浮点依赖。
 *   填充文件事件 FileEntropy（Q16 定点）供 agent IoaRansomware_UpdateScore
 *   高熵分支消费（阈值 WKD_RANSOM_ENTROPY_Q16 = 7.5<<16 = 491520）。
 * ========================================================================== */
static const UINT16 g_FsEntropyTable[257] = {
    0, 800, 700, 642, 600, 568, 542, 519, 500, 483, 468, 454, 442, 430, 419, 409,
    400, 391, 383, 375, 368, 361, 354, 348, 342, 336, 330, 325, 319, 314, 309, 305,
    300, 296, 291, 287, 283, 279, 275, 271, 268, 264, 261, 257, 254, 251, 248, 245,
    242, 239, 236, 233, 230, 227, 225, 222, 219, 217, 214, 212, 209, 207, 205, 202,
    200, 198, 196, 193, 191, 189, 187, 185, 183, 181, 179, 177, 175, 173, 171, 170,
    168, 166, 164, 162, 161, 159, 157, 156, 154, 152, 151, 149, 148, 146, 145, 143,
    142, 140, 139, 137, 136, 134, 133, 131, 130, 129, 127, 126, 125, 123, 122, 121,
    119, 118, 117, 115, 114, 113, 112, 111, 109, 108, 107, 106, 105, 103, 102, 101,
    100, 99, 98, 97, 96, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84,
    83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 71, 70, 69,
    68, 67, 66, 65, 64, 63, 62, 62, 61, 60, 59, 58, 57, 57, 56, 55,
    54, 53, 52, 52, 51, 50, 49, 48, 48, 47, 46, 45, 45, 44, 43, 42,
    42, 41, 40, 39, 39, 38, 37, 36, 36, 35, 34, 33, 33, 32, 31, 31,
    30, 29, 29, 28, 27, 27, 26, 25, 25, 24, 23, 23, 22, 21, 21, 20,
    19, 19, 18, 17, 17, 16, 15, 15, 14, 14, 13, 12, 12, 11, 11, 10,
    9, 9, 8, 8, 7, 6, 6, 5, 5, 4, 3, 3, 2, 2, 1, 1,
    0
};

#define WKD_FS_ENTROPY_SAMPLE        256     /* 采样字节数（PostWrite） */
#define WKD_FS_ENTROPY_MIN_WRITE     256     /* 小于此长度不采样（性能） */

/* ============================================================================
 * 蜜罐 canary（PreWrite.c PW_CANARY_CONFIG + PwpIsCanaryFile，
 *   PostWrite.c g_HoneypotFileNames）
 *   Canary：精确路径列表（64 上限，WkdFsAddCanaryPath 配置），命中无条件阻断。
 *   Honeypot：内置蜜罐文件名表（包含匹配），命中上送 Flags.Canary 供 agent
 *   勒索评分（IoaRansomware_UpdateScore Canary 分支 +50，WKD_RANSOM_CANARY_SCORE）。
 * ========================================================================== */
#define WKD_FS_MAX_CANARY_PATHS   64

typedef struct _WKD_FS_CANARY_CONFIG {
    UNICODE_STRING Paths[WKD_FS_MAX_CANARY_PATHS];
    volatile LONG  Count;
    EX_PUSH_LOCK   Lock;
    BOOLEAN        Initialized;
} WKD_FS_CANARY_CONFIG, *PWKD_FS_CANARY_CONFIG;

static WKD_FS_CANARY_CONFIG g_FsCanaryConfig;

/* 内置蜜罐文件名表（PostWrite.c g_HoneypotFileNames 12 条，包含匹配） */
static const PCWSTR g_FsHoneypotFileNames[] = {
    L"important_documents.txt", L"passwords.txt", L"bank_accounts.xlsx",
    L"private_keys.txt", L"credit_cards.xlsx", L"financial_report.docx",
    L"secret.txt", L"confidential.doc", L"personal.xlsx",
    L"accounts.txt", L"recovery_key.txt", L"crypto_wallet.dat",
    NULL
};

/* ============================================================================
 * 勒索窗口计数（PostWrite.c PW_PROCESS_ACTIVITY 固定数组模式 +
 *   FileSystemNotification.c FSC_RANSARMWARE_*_THRESHOLD 阈值）
 *   每进程 1 秒窗口内 Write/Rename/Delete 计数，超阈值置 RAPID_RATE 标志，
 *   随下一次文件事件上送（提升优先级），供 agent 及时处置。
 *   采用固定数组（256 槽，无动态分配/lookaside），进程退出经
 *   PsSetCreateProcessNotifyRoutineEx 回调清理槽，防 PID 复用。
 * ========================================================================== */
#define WKD_FS_FILE_ACTIVITY_SLOTS  256
#define WKD_FS_WINDOW_100NS         (1000LL * 10000LL)   /* 1 秒窗口 */
#define WKD_FS_RENAME_THRESHOLD     50
#define WKD_FS_DELETE_THRESHOLD     100
#define WKD_FS_WRITE_THRESHOLD      100

typedef struct _WKD_FS_FILE_ACTIVITY {
    HANDLE        ProcessId;
    LARGE_INTEGER WindowStart;
    volatile LONG RenameCount;
    volatile LONG DeleteCount;
    volatile LONG WriteCount;
    volatile LONG TruncateCount;          /* 截断/分配/有效长度（T1485，PreSetInfo 迁移） */
    volatile LONG ExtensionChangeCount;   /* 勒索扩展名变更（T1486，PreSetInfo 迁移） */
    volatile LONG HardLinkCount;          /* 硬链接创建（T1003.003，PreSetInfo 迁移） */
    volatile LONG AttributeCount;         /* 属性/时间戳/短名变更（T1070.006，PreSetInfo 迁移） */
    /* 总量（PSI_PROCESS_CONTEXT Total*，供 ProcessFileContext 评分迁移参考） */
    volatile LONG64 TotalRenames;
    volatile LONG64 TotalDeletes;
    volatile LONG64 TotalTruncations;
    volatile LONG64 TotalExtensionChanges;
    volatile LONG64 TotalHardLinks;
    volatile LONG64 TotalAttributes;
    volatile LONG IsActive;
} WKD_FS_FILE_ACTIVITY, *PWKD_FS_FILE_ACTIVITY;

static WKD_FS_FILE_ACTIVITY g_FsFileActivity[WKD_FS_FILE_ACTIVITY_SLOTS];
static EX_PUSH_LOCK g_FsFileActivityLock;

/* ============================================================================
 * 综合路径分析（B2，PreCreate.c PcAnalyzeFilePath 全套）
 *   Flags 供 CbpPreAcquireSectionNotifyCallback 评分（薄层）；分值上限 100。
 * ========================================================================== */
#define WKD_FS_PATH_ADS            0x00000001
#define WKD_FS_PATH_DOUBLE_EXT     0x00000002
#define WKD_FS_PATH_TEMP           0x00000004
#define WKD_FS_PATH_RECYCLE        0x00000008
#define WKD_FS_PATH_PUBLIC         0x00000010
#define WKD_FS_PATH_APPDATA        0x00000020
#define WKD_FS_PATH_DOWNLOADS      0x00000040
#define WKD_FS_PATH_REMOVABLE      0x00000080
#define WKD_FS_PATH_NETWORK        0x00000100
#define WKD_FS_PATH_HONEYPOT       0x00000200
#define WKD_FS_PATH_ZONE_ID        0x00000400
#define WKD_FS_PATH_HIDDEN         0x00000800
#define WKD_FS_PATH_SYSTEM_USER    0x00001000
#define WKD_FS_PATH_EXEC_NO_READ   0x00002000
#define WKD_FS_PATH_WRITE_EXEC     0x00004000
#define WKD_FS_PATH_DELETE_ON_CLOSE 0x00008000
#define WKD_FS_PATH_OVERWRITE      0x00010000
#define WKD_FS_PATH_LONG           0x00020000
#define WKD_FS_PATH_RLO            0x00040000
#define WKD_FS_PATH_TRAILING       0x00080000
#define WKD_FS_PATH_RESERVED       0x00100000

typedef struct _WKD_FS_SUSPICIOUS_PATH {
    PCWSTR Pattern;
    ULONG  Flag;
} WKD_FS_SUSPICIOUS_PATH;

/* 可疑路径表（PreCreate.c g_SuspiciousPaths 11 条 + PreAcquireSection.c
 * g_SuspiciousPaths 特有 \staging\、\cache\，共 13 条） */
static const WKD_FS_SUSPICIOUS_PATH g_FsSuspiciousPaths[] = {
    { L"\\temp\\",              WKD_FS_PATH_TEMP },
    { L"\\tmp\\",               WKD_FS_PATH_TEMP },
    { L"\\$recycle.bin\\",      WKD_FS_PATH_RECYCLE },
    { L"\\recycler\\",          WKD_FS_PATH_RECYCLE },
    { L"\\users\\public\\",     WKD_FS_PATH_PUBLIC },
    { L"\\public\\",            WKD_FS_PATH_PUBLIC },
    { L"\\appdata\\local\\",    WKD_FS_PATH_APPDATA },
    { L"\\appdata\\roaming\\",  WKD_FS_PATH_APPDATA },
    { L"\\downloads\\",         WKD_FS_PATH_DOWNLOADS },
    { L"\\perflogs\\",          WKD_FS_PATH_TEMP },
    { L"\\programdata\\",       WKD_FS_PATH_APPDATA },
    { L"\\staging\\",           WKD_FS_PATH_TEMP },  /* SS PreAcquireSection 特有 */
    { L"\\cache\\",             WKD_FS_PATH_TEMP },  /* SS PreAcquireSection 特有 */
};

/* 可执行扩展（PreCreate.c g_ExecutableExtensions 12 条） */
static const PCWSTR g_FsExecutableExtensions[] = {
    L"exe", L"dll", L"scr", L"com", L"pif", L"bat", L"cmd",
    L"ps1", L"vbs", L"js", L"hta", L"msi"
};

/* 保留设备名（PreCreate.c g_ReservedNames 24 个） */
static const PCWSTR g_FsReservedNames[] = {
    L"CON", L"PRN", L"AUX", L"NUL",
    L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
    L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9"
};

/* ============================================================================
 * EDR 自保护（PreCreate ShadowStrikeShouldBlockFileAccess，
 *   FileProtection.c）——驱动/agent 自身文件写/删/改名/执行映射保护。
 *   豁免复用 ExemptsIsProcessTrusted（受保护进程豁免防系统维护误阻断）。
 * ========================================================================== */
typedef struct _WKD_FS_PROTECT_PATH {
    PCWSTR  Path;           /* 后缀精确匹配（大小写不敏感） */
    BOOLEAN BlockWrite;
    BOOLEAN BlockDelete;
    BOOLEAN BlockRename;
    BOOLEAN BlockExecute;   /* 阻止以执行权限映射（PreAcquireSection 迁移，T1562.001） */
} WKD_FS_PROTECT_PATH, *PWKD_FS_PROTECT_PATH;

static const WKD_FS_PROTECT_PATH g_FsProtectPaths[] = {
    { L"\\WkDefender@agent.exe",  TRUE, TRUE, TRUE, TRUE },
    { L"\\WkDefender@agent.dll",  TRUE, TRUE, TRUE, TRUE },
    { L"\\WkDefender@driver.sys", TRUE, TRUE, TRUE, TRUE },
    { L"\\WkDefender@driver.dll", TRUE, TRUE, TRUE, TRUE },
    { L"\\WkdBackup\\",           TRUE, TRUE, FALSE, FALSE },
    { NULL, FALSE, FALSE, FALSE, FALSE }
};

/* ============================================================================
 * 排除检查（Phase 5：路径排除 / 进程排除）
 *   路径排除：agent 下发排除规则表（与 ScanManager 排除规则对齐）时填充。
 *   进程排除：wkd 用 ExemptsIsProcessTrusted 作为进程信任等价（SS IsProcessTrusted），
 *   用户配置排除表由 agent 策略下发（接入前提）。
 * ========================================================================== */
typedef struct _WKD_FS_EXCLUSION {
    UNICODE_STRING Path;    /* 路径前缀（接入时填充） */
} WKD_FS_EXCLUSION, *PWKD_FS_EXCLUSION;

static WKD_FS_EXCLUSION g_FsExclusions[64];   /* 接入时填充（agent 策略下发） */
static volatile LONG    g_FsExclusionCount;

/* ============================================================================
 * 通用大小写不敏感包含匹配（ASCII 折叠，DISPATCH_LEVEL 安全）
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFsContainsStrInsensitive(
    _In_ PCUNICODE_STRING Str,
    _In_ PCWSTR Substr
    )
{
    ULONG slen;
    ULONG plen = 0;
    ULONG i, j;
    BOOLEAN match;

    if (Str == NULL || Str->Buffer == NULL || Substr == NULL) {
        return FALSE;
    }
    slen = Str->Length / sizeof(WCHAR);
    while (Substr[plen] != L'\0') {
        plen++;
    }
    if (plen == 0 || plen > slen) {
        return FALSE;
    }
    for (i = 0; i <= slen - plen; i++) {
        match = TRUE;
        for (j = 0; j < plen; j++) {
            WCHAR a = Str->Buffer[i + j];
            WCHAR b = Substr[j];
            if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
            if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 内置蜜罐文件名包含匹配（ASCII 大小写折叠，DISPATCH_LEVEL 安全）。
 * PostWrite 迁移（2026-09）起导出供 PostWrite 复用（头文件原已声明）。 */
_Use_decl_annotations_
BOOLEAN
WkdFsIsHoneypotFile(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG f, p;
    ULONG fileLen;
    ULONG patLen;
    ULONG i, j;
    BOOLEAN match;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    fileLen = FileName->Length / sizeof(WCHAR);

    for (f = 0; g_FsHoneypotFileNames[f] != NULL; f++) {
        patLen = 0;
        while (g_FsHoneypotFileNames[f][patLen] != L'\0') {
            patLen++;
        }
        if (patLen > fileLen) {
            continue;
        }
        for (i = 0; i <= fileLen - patLen; i++) {
            match = TRUE;
            for (j = 0; j < patLen; j++) {
                WCHAR a = FileName->Buffer[i + j];
                WCHAR b = g_FsHoneypotFileNames[f][j];
                if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                if (a != b) { match = FALSE; break; }
            }
            if (match) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
WkdFsAddCanaryPath(
    PCUNICODE_STRING Path
    )
{
    LONG index;
    PWCHAR buffer;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_FsCanaryConfig.Initialized) {
        return STATUS_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FsCanaryConfig.Lock);

    index = g_FsCanaryConfig.Count;
    if (index >= WKD_FS_MAX_CANARY_PATHS) {
        ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, Path->Length + sizeof(WCHAR), WKD_FSF_POOL_TAG);
    if (buffer == NULL) {
        ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(buffer, Path->Buffer, Path->Length);
    buffer[Path->Length / sizeof(WCHAR)] = L'\0';

    g_FsCanaryConfig.Paths[index].Buffer = buffer;
    g_FsCanaryConfig.Paths[index].Length = Path->Length;
    g_FsCanaryConfig.Paths[index].MaximumLength = Path->Length + sizeof(WCHAR);
    InterlockedIncrement(&g_FsCanaryConfig.Count);

    ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
WkdFsIsCanaryFile(
    PCUNICODE_STRING FileName
    )
{
    LONG i;
    LONG count;
    BOOLEAN result = FALSE;

    if (!g_FsCanaryConfig.Initialized) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FsCanaryConfig.Lock);

    count = g_FsCanaryConfig.Count;
    for (i = 0; i < count; i++) {
        if (RtlEqualUnicodeString(FileName, &g_FsCanaryConfig.Paths[i], TRUE)) {
            result = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_FsCanaryConfig.Lock);
    KeLeaveCriticalRegion();
    return result;
}

/* 整数查表熵：返回 H*100（0~800）。PwpCalculateEntropy。 */
_Use_decl_annotations_
ULONG
WkdFsCalculateEntropyX100(
    PUCHAR Buffer,
    ULONG Length
    )
{
    ULONG byteCounts[256] = { 0 };
    ULONG i;
    ULONG entropy = 0;
    ULONG count;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    for (i = 0; i < Length; i++) {
        byteCounts[Buffer[i]]++;
    }

    for (i = 0; i < 256; i++) {
        count = byteCounts[i];
        if (count > 0) {
            ULONG scaledCount = (count * 256) / Length;
            if (scaledCount > 256) {
                scaledCount = 256;
            }
            entropy += (g_FsEntropyTable[scaledCount] * count) / Length;
        }
    }

    return entropy;
}

/* H*100 → Q16 定点（对齐 agent WKD_RANSOM_ENTROPY_Q16 = 7.5 << 16） */
_Use_decl_annotations_
ULONG
WkdFsEntropyToQ16(
    ULONG EntropyX100
    )
{
    return (EntropyX100 * 65536) / 100;
}

/* 写操作熵采样：仅长度≥256 且 MDL/用户缓冲可读时计算，异常/不可读返回 0 */
_Use_decl_annotations_
ULONG
WkdFsSampleWriteEntropy(
    PFLT_CALLBACK_DATA Data
    )
{
    PVOID writeBuffer = NULL;
    ULONG writeLen = Data->Iopb->Parameters.Write.Length;
    ULONG sampleLen;
    ULONG entropyX100;

    if (writeLen < WKD_FS_ENTROPY_MIN_WRITE) {
        return 0;
    }
    if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
        writeBuffer = MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress,
            NormalPagePriority | MdlMappingNoExecute);
    }
    if (writeBuffer == NULL) {
        writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
    }
    if (writeBuffer == NULL) {
        return 0;
    }
    sampleLen = (writeLen > WKD_FS_ENTROPY_SAMPLE) ? WKD_FS_ENTROPY_SAMPLE : writeLen;
    /* __try { */
        entropyX100 = WkdFsCalculateEntropyX100((PUCHAR)writeBuffer, sampleLen);
    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    } */
    return WkdFsEntropyToQ16(entropyX100);
}

_Use_decl_annotations_
BOOLEAN
WkdFsShouldBlockFileAccess(
    PCUNICODE_STRING FileName,
    ACCESS_MASK DesiredAccess,
    HANDLE ProcessId,
    BOOLEAN IsWriteOp
    )
{
    ULONG i;
    BOOLEAN wantWrite, wantDelete, wantExecute;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    /* 豁免可信进程（自保护豁免） */
    if (ExemptsIsProcessTrusted(ProcessId)) {
        return FALSE;
    }

    wantWrite = (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    wantDelete = (DesiredAccess & DELETE) != 0;
    wantExecute = (DesiredAccess & SECTION_MAP_EXECUTE) != 0;   /* PreAcquireSection 迁移 */

    for (i = 0; g_FsProtectPaths[i].Path != NULL; i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_FsProtectPaths[i].Path);
        if (pattern.Length > FileName->Length) {
            continue;
        }
        {
            UNICODE_STRING suffix;
            suffix.Buffer = FileName->Buffer + (FileName->Length - pattern.Length) / sizeof(WCHAR);
            suffix.Length = pattern.Length;
            suffix.MaximumLength = pattern.Length;
            if (RtlEqualUnicodeString(&suffix, &pattern, TRUE)) {
                if ((wantWrite && g_FsProtectPaths[i].BlockWrite) ||
                    (wantDelete && g_FsProtectPaths[i].BlockDelete) ||
                    (wantExecute && g_FsProtectPaths[i].BlockExecute) ||
                    (IsWriteOp && g_FsProtectPaths[i].BlockRename)) {
                    return TRUE;
                }
                return FALSE;
            }
        }
    }
    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
WkdFsIsPathExcluded(
    PCUNICODE_STRING FileName
    )
{
    LONG i;
    LONG count = g_FsExclusionCount;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < count; i++) {
        if (g_FsExclusions[i].Path.Length > 0 &&
            g_FsExclusions[i].Path.Length <= FileName->Length) {
            UNICODE_STRING prefix;
            prefix.Buffer = FileName->Buffer;
            prefix.Length = g_FsExclusions[i].Path.Length;
            prefix.MaximumLength = g_FsExclusions[i].Path.Length;
            if (RtlEqualUnicodeString(&prefix, &g_FsExclusions[i].Path, TRUE)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
WkdFsIsProcessExcluded(
    HANDLE ProcessId
    )
{
    /* 用户配置进程排除表（agent 策略下发，接入前提）。当前仅信任表等价。 */
    UNREFERENCED_PARAMETER(ProcessId);
    return FALSE;
}

/* ============================================================================
 * Rename/Link 目标路径提取（PreSetInfo.c PsipGetRenameDestination
 *   L2305-2436，重功能实现）
 *   从 SetInformation 用户缓冲中安全提取目标路径，含：
 *     - 缓冲长度/FileInformationClass 偏移校验（Ex 变体 RootDirectory 后多
 *       一个 ULONG Flags，FileName 偏移 +4；修复 SS 用普通结构读取 Ex 布局
 *       导致 FileNameLength/FileName 字段错位的隐患）
 *     - 用户缓冲 __try 访问
 *     - USHORT 截断防护（bufferLength = fileNameLength + 2 不溢出 USHORT，
 *       v2.1.0 修复，防下游 UNICODE_STRING 操作 OOB）
 *     - 分配大小溢出检查 + 分配上限（防 DoS）
 *   调用者负责 ExFreePoolWithTag(NewFileName->Buffer, WKD_FSF_POOL_TAG)。
 * ========================================================================== */
#define WKD_FS_MAX_RENAME_BUFFER_SIZE  65535    /* PSI_MAX_RENAME_BUFFER_SIZE */

_Use_decl_annotations_
NTSTATUS
WkdFsGetRenameDestination(
    PFLT_CALLBACK_DATA Data,
    FILE_INFORMATION_CLASS InfoClass,
    PUNICODE_STRING NewFileName
    )
{
    PFILE_RENAME_INFORMATION renameInfo;
    ULONG infoBufferLength;
    ULONG fileNameLength;
    ULONG bufferLength;
    ULONG maxFileNameLength;
    ULONG fileNameLengthOffset;
    ULONG fileNameDataOffset;
    PWCHAR buffer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(NewFileName, sizeof(UNICODE_STRING));

    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    infoBufferLength = Data->Iopb->Parameters.SetFileInformation.Length;

    if (renameInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (infoBufferLength < sizeof(FILE_RENAME_INFORMATION)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Ex 变体（FileRenameInformationEx/FileLinkInformationEx）布局多一个 ULONG
     * Flags（RootDirectory 之后、FileNameLength 之前），FileNameLength 与
     * FileName 偏移均 +4（提取语义，修复布局错位隐患）。 */
    if (InfoClass == FileRenameInformationEx || InfoClass == FileLinkInformationEx) {
        fileNameLengthOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength) + sizeof(ULONG);
        fileNameDataOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + sizeof(ULONG);
    } else {
        fileNameLengthOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength);
        fileNameDataOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    }

    /* 防 maxFileNameLength 下溢：InfoBuffer 长度不足以容纳 FileName 偏移时
     * 直接拒绝（Ex 变体偏移 +4，恶意超短缓冲会触发）。 */
    if (infoBufferLength < fileNameDataOffset) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maxFileNameLength = infoBufferLength - fileNameDataOffset;

    /* __try { */
        /* 从潜在用户态缓冲读取 FileNameLength */
        fileNameLength = *(PULONG)((PUCHAR)renameInfo + fileNameLengthOffset);

        if (fileNameLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (fileNameLength > maxFileNameLength) {
            return STATUS_BUFFER_OVERFLOW;
        }
        if (fileNameLength > WKD_FS_MAX_RENAME_BUFFER_SIZE) {
            return STATUS_NAME_TOO_LONG;
        }
        /* USHORT 截断防护：fileNameLength == MAXUSHORT 时 bufferLength 会溢出
         * USHORT 的 MaximumLength，收紧边界防下游 OOB（v2.1.0 修复）。 */
        if (fileNameLength > (ULONG)(MAXUSHORT - sizeof(WCHAR))) {
            return STATUS_NAME_TOO_LONG;
        }

        /* 分配大小 +1 WCHAR 存 NUL，溢出检查 */
        bufferLength = fileNameLength + sizeof(WCHAR);
        if (bufferLength < fileNameLength) {
            return STATUS_INTEGER_OVERFLOW;
        }

        buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, bufferLength, WKD_FSF_POOL_TAG);
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(buffer, (PUCHAR)renameInfo + fileNameDataOffset, fileNameLength);
        buffer[fileNameLength / sizeof(WCHAR)] = L'\0';

        NewFileName->Buffer = buffer;
        NewFileName->Length = (USHORT)fileNameLength;
        NewFileName->MaximumLength = (USHORT)bufferLength;

        buffer = NULL;   /* 所有权移交调用者 */
        status = STATUS_SUCCESS;

    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    } */

    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, WKD_FSF_POOL_TAG);
    }

    return status;
}

/* ============================================================================
 * 真实删除判定（FSC-3，PreSetInfo.c L976-1021）
 *   FileDispositionInformation：DeleteFile=FALSE 是"清除删除标记"（undelete），
 *   非真实删除；FileDispositionInformationEx：FILE_DISPOSITION_DELETE 位（bit0）。
 *   把 undelete 当删除计数会污染勒索统计（RecentDeletes）导致误报，SS 视为
 *   CRITICAL 修复（FSC-3）。命中返回 TRUE 才走删除计数/备份/阻断。
 * ========================================================================== */
_Use_decl_annotations_
BOOLEAN
FspIsConfirmedDeletion(
    PFLT_CALLBACK_DATA Data
    )
{
    FILE_INFORMATION_CLASS infoClass;
    ULONG length;
    PVOID buffer;

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    length = Data->Iopb->Parameters.SetFileInformation.Length;
    buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (infoClass == FileDispositionInformation) {
        if (length >= sizeof(FILE_DISPOSITION_INFORMATION) && buffer != NULL) {
            /* __try { */
                return ((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile;
            /* } __except (EXCEPTION_EXECUTE_HANDLER) {
                return FALSE;
            } */
        }
        return FALSE;
    }

    /* FileDispositionInformationEx */
    if (length >= sizeof(FILE_DISPOSITION_INFORMATION_EX) && buffer != NULL) {
        /* __try { */
            return (((PFILE_DISPOSITION_INFORMATION_EX)buffer)->Flags & FILE_DISPOSITION_DELETE) != 0;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        } */
    }
    return FALSE;
}

/* 进程退出清理（PsSetCreateProcessNotifyRoutineEx 回调，任意 IRQL 安全——
 * 仅原子置 IsActive=0，不碰 PushLock）。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdFsProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    ULONG i;
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        return;   /* 仅处理进程退出 */
    }

    for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
        if (g_FsFileActivity[i].IsActive &&
            g_FsFileActivity[i].ProcessId == ProcessId) {
            InterlockedExchange(&g_FsFileActivity[i].IsActive, 0);
        }
    }
}

/* 逐进程窗口计数。返回是否超速率阈值（RAPID_RATE）。PASSIVE_LEVEL（PushLock）。 */
_Use_decl_annotations_
BOOLEAN
WkdFsTrackFileOperation(
    HANDLE ProcessId,
    ULONG OpType               /* WKD_FLT_OP_* */
    )
{
    ULONG i;
    PWKD_FS_FILE_ACTIVITY slot = NULL;
    LARGE_INTEGER now;
    BOOLEAN rateSuspicious = FALSE;

    KeQuerySystemTime(&now);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FsFileActivityLock);

    for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
        if (g_FsFileActivity[i].IsActive && g_FsFileActivity[i].ProcessId == ProcessId) {
            slot = &g_FsFileActivity[i];
            break;
        }
    }
    if (slot == NULL) {
        for (i = 0; i < WKD_FS_FILE_ACTIVITY_SLOTS; i++) {
            if (!g_FsFileActivity[i].IsActive) {
                slot = &g_FsFileActivity[i];
                RtlZeroMemory(slot, sizeof(WKD_FS_FILE_ACTIVITY));
                slot->ProcessId = ProcessId;
                slot->WindowStart = now;
                InterlockedExchange(&slot->IsActive, 1);
                break;
            }
        }
    }
    if (slot == NULL) {
        ExReleasePushLockExclusive(&g_FsFileActivityLock);
        KeLeaveCriticalRegion();
        return FALSE;
    }

    if (now.QuadPart - slot->WindowStart.QuadPart > WKD_FS_WINDOW_100NS) {
        slot->WindowStart = now;
        InterlockedExchange(&slot->RenameCount, 0);
        InterlockedExchange(&slot->DeleteCount, 0);
        InterlockedExchange(&slot->WriteCount, 0);
        InterlockedExchange(&slot->TruncateCount, 0);
        InterlockedExchange(&slot->ExtensionChangeCount, 0);
        InterlockedExchange(&slot->HardLinkCount, 0);
        InterlockedExchange(&slot->AttributeCount, 0);
    }

    switch (OpType) {
    case WKD_FLT_OP_RENAME:
        InterlockedIncrement64(&slot->TotalRenames);
        rateSuspicious = (InterlockedIncrement(&slot->RenameCount) > WKD_FS_RENAME_THRESHOLD);
        break;
    case WKD_FLT_OP_DELETE:
        InterlockedIncrement64(&slot->TotalDeletes);
        rateSuspicious = (InterlockedIncrement(&slot->DeleteCount) > WKD_FS_DELETE_THRESHOLD);
        break;
    case WKD_FLT_OP_TRUNCATE:
        /* 截断仅监控计数（PsipUpdateProcessMetrics：截断/分配/有效长度
         * 累计 RecentTruncations/TotalTruncations），不置 RAPID_RATE 速率阻断。 */
        InterlockedIncrement64(&slot->TotalTruncations);
        InterlockedIncrement(&slot->TruncateCount);
        rateSuspicious = FALSE;
        break;
    case WKD_FLT_OP_HARDLINK:
        /* 硬链接仅监控计数（RecentHardLinks/TotalHardLinks），阻断走
         * 敏感表 BlockHardLink 强信号直断（FsPreSetInformationNotifyCallback），非速率阻断。 */
        InterlockedIncrement64(&slot->TotalHardLinks);
        InterlockedIncrement(&slot->HardLinkCount);
        rateSuspicious = FALSE;
        break;
    case WKD_FLT_OP_ATTRIBUTE:
        /* 属性/短名仅监控计数（RecentAttributeChanges），不参与速率阻断。 */
        InterlockedIncrement64(&slot->TotalAttributes);
        InterlockedIncrement(&slot->AttributeCount);
        rateSuspicious = FALSE;
        break;
    case WKD_FLT_OP_WRITE:
    default:
        rateSuspicious = (InterlockedIncrement(&slot->WriteCount) > WKD_FS_WRITE_THRESHOLD);
        break;
    }

    ExReleasePushLockExclusive(&g_FsFileActivityLock);
    KeLeaveCriticalRegion();

    return rateSuspicious;
}

/* ============================================================================
 * 综合路径分析（B2）子检测器（PreCreate.c Pc* 系列）
 * ========================================================================== */

/* 标志→分值（PcCalculateFlagScore，上限 100） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdFsCalcPathFlagScore(
    _In_ ULONG Flags
    )
{
    ULONG score = 0;
    if (Flags & WKD_FS_PATH_ADS)             score += 15;
    if (Flags & WKD_FS_PATH_DOUBLE_EXT)      score += 25;
    if (Flags & WKD_FS_PATH_TEMP)            score += 10;
    if (Flags & WKD_FS_PATH_RECYCLE)         score += 10;
    if (Flags & WKD_FS_PATH_PUBLIC)          score += 15;
    if (Flags & WKD_FS_PATH_APPDATA)         score += 10;
    if (Flags & WKD_FS_PATH_DOWNLOADS)       score += 5;
    if (Flags & WKD_FS_PATH_REMOVABLE)       score += 10;
    if (Flags & WKD_FS_PATH_NETWORK)         score += 5;
    if (Flags & WKD_FS_PATH_HONEYPOT)        score += 40;
    if (Flags & WKD_FS_PATH_ZONE_ID)         score += 5;
    if (Flags & WKD_FS_PATH_HIDDEN)          score += 10;
    if (Flags & WKD_FS_PATH_SYSTEM_USER)     score += 15;
    if (Flags & WKD_FS_PATH_EXEC_NO_READ)    score += 20;
    if (Flags & WKD_FS_PATH_WRITE_EXEC)      score += 20;
    if (Flags & WKD_FS_PATH_DELETE_ON_CLOSE) score += 10;
    if (Flags & WKD_FS_PATH_OVERWRITE)       score += 5;
    if (Flags & WKD_FS_PATH_LONG)            score += 10;
    if (Flags & WKD_FS_PATH_RLO)             score += 30;
    if (Flags & WKD_FS_PATH_TRAILING)        score += 15;
    if (Flags & WKD_FS_PATH_RESERVED)        score += 20;
    return (score > 100) ? 100 : score;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFsIsExecutableExt(
    _In_ PCWSTR Extension
    )
{
    ULONG i;
    if (Extension == NULL) {
        return FALSE;
    }
    for (i = 0; i < ARRAYSIZE(g_FsExecutableExtensions); i++) {
        if (_wcsicmp(Extension, g_FsExecutableExtensions[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ADS检测（备用数据流，T1564.004 - NTFS File Attributes）：驱动器冒号（位置 2）后再现冒号 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
FspDetectAlternateDataStreams(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT i;
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length < 4 * sizeof(WCHAR)) {
        return FALSE;
    }
    for (i = 2; i < FileName->Length / sizeof(WCHAR); i++) {
        if (FileName->Buffer[i] == L':') {
            return TRUE;
        }
    }
    return FALSE;
}

/* 双扩展名检测（PcDetectDoubleExtension）：长度感知迭代，最终扩展可执行
 * + 隐藏扩展为文档类型（invoice.pdf.exe 经典模式） */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
FspDetectDoubleExt(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING Extension
    )
{
    static const PCWSTR documentExts[] = {
        L"pdf", L"doc", L"docx", L"xls", L"xlsx", L"txt",
        L"jpg", L"png", L"mp3", L"mp4", L"zip", L"rar", L"bmp"
    };
    PWCHAR fileNameStart = NULL;
    PWCHAR current;
    PWCHAR bufferEnd;
    PWCHAR firstDot = NULL;
    PWCHAR lastDot = NULL;
    ULONG dotCount = 0;
    WCHAR hiddenExt[32];
    ULONG hiddenExtLen = 0;
    ULONG i;
    BOOLEAN hiddenExec = FALSE;
    USHORT charCount;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0 || Extension == NULL) {
        return FALSE;
    }
    charCount = FileName->Length / sizeof(WCHAR);
    bufferEnd = FileName->Buffer + charCount;

    fileNameStart = FileName->Buffer;
    for (current = FileName->Buffer; current < bufferEnd; current++) {
        if (*current == L'\\') {
            fileNameStart = current + 1;
        }
    }
    if (fileNameStart >= bufferEnd) {
        return FALSE;
    }

    for (current = fileNameStart; current < bufferEnd; current++) {
        if (*current == L'.') {
            dotCount++;
            if (firstDot == NULL) firstDot = current;
            lastDot = current;
        }
    }
    if (dotCount < 2 || firstDot == NULL || lastDot == NULL || firstDot == lastDot) {
        return FALSE;
    }

    current = firstDot + 1;
    hiddenExtLen = 0;
    while (current < lastDot && hiddenExtLen < 30) {
        if (*current == L'.') break;
        hiddenExt[hiddenExtLen++] = *current;
        current++;
    }
    if (hiddenExtLen == 0) return FALSE;
    hiddenExt[hiddenExtLen] = L'\0';

    if (Extension->Buffer != NULL && Extension->Length > 0) {
        WCHAR appExt[32];
        USHORT appExtLen = Extension->Length / sizeof(WCHAR);
        PCWSTR extStart = Extension->Buffer;
        if (*extStart == L'.') {
            extStart++;
            appExtLen--;
        }
        if (appExtLen > 0 && appExtLen < 30) {
            RtlCopyMemory(appExt, extStart, appExtLen * sizeof(WCHAR));
            appExt[appExtLen] = L'\0';
            if (WkdFsIsExecutableExt(appExt)) {
                for (i = 0; i < ARRAYSIZE(documentExts); i++) {
                    if (_wcsicmp(hiddenExt, documentExts[i]) == 0) {
                        hiddenExec = TRUE;
                        break;
                    }
                }
            }
        }
    }
    return hiddenExec;
}

/* Unicode 混淆检测（PcpDetectUnicodeObfuscation）：RLO/LRO/PDF/LRM/RLM + 零宽 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFsDetectUnicodeObf(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT i;
    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }
    for (i = 0; i < FileName->Length / sizeof(WCHAR); i++) {
        WCHAR ch = FileName->Buffer[i];
        if (ch == 0x202E || ch == 0x202D || ch == 0x202C ||
            ch == 0x200E || ch == 0x200F ||
            ch == 0x200B || ch == 0x200C || ch == 0x200D || ch == 0xFEFF) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 保留设备名检测（PcpDetectReservedName）：长度感知，CON/PRN/COM1-9/LPT1-9 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFsDetectReservedName(
    _In_ PCUNICODE_STRING FileName
    )
{
    PWCHAR fileNameStart = NULL;
    PWCHAR current;
    PWCHAR bufferEnd;
    PWCHAR dotPos = NULL;
    WCHAR nameBuffer[16];
    ULONG nameLen = 0;
    ULONG i;
    USHORT charCount;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    charCount = FileName->Length / sizeof(WCHAR);
    bufferEnd = FileName->Buffer + charCount;

    fileNameStart = FileName->Buffer;
    for (current = FileName->Buffer; current < bufferEnd; current++) {
        if (*current == L'\\') {
            fileNameStart = current + 1;
        }
    }
    if (fileNameStart >= bufferEnd) {
        return FALSE;
    }

    for (current = fileNameStart; current < bufferEnd; current++) {
        if (*current == L'.') {
            dotPos = current;
            break;
        }
    }
    nameLen = (dotPos != NULL) ? (ULONG)(dotPos - fileNameStart) : (ULONG)(bufferEnd - fileNameStart);
    if (nameLen == 0 || nameLen >= 15) {
        return FALSE;
    }

    RtlCopyMemory(nameBuffer, fileNameStart, nameLen * sizeof(WCHAR));
    nameBuffer[nameLen] = L'\0';

    for (i = 0; i < ARRAYSIZE(g_FsReservedNames); i++) {
        if (_wcsicmp(nameBuffer, g_FsReservedNames[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 尾部空格/点检测（PcpDetectTrailingChars）：排除当前目录 "." */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdFsDetectTrailing(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT len;
    WCHAR lastChar;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length < sizeof(WCHAR)) {
        return FALSE;
    }
    len = FileName->Length / sizeof(WCHAR);
    lastChar = FileName->Buffer[len - 1];
    if (lastChar == L' ' || lastChar == L'.') {
        if (len == 1 && lastChar == L'.') {
            return FALSE;   /* 当前目录 "." */
        }
        return TRUE;
    }
    return FALSE;
}

/* 综合路径分析（PcAnalyzeFilePath）：返回威胁分（0-100），Flags 输出 */
_Use_decl_annotations_
ULONG
FspAnalyzeFilePath(
    PCUNICODE_STRING FileName,
    PCUNICODE_STRING Extension,
    PULONG OutFlags
    )
{
    ULONG flags = 0;
    ULONG i;

    if (OutFlags) {
        *OutFlags = 0;
    }
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return 0;
    }

    for (i = 0; i < ARRAYSIZE(g_FsSuspiciousPaths); i++) {
        if (WkdFsContainsStrInsensitive(FileName, g_FsSuspiciousPaths[i].Pattern)) {
            flags |= g_FsSuspiciousPaths[i].Flag;
        }
    }
    if (FileName->Length > 500 * sizeof(WCHAR)) {
        flags |= WKD_FS_PATH_LONG;
    }
    if (FspDetectAlternateDataStreams(FileName)) {
        flags |= WKD_FS_PATH_ADS;
    }
    if (FspDetectDoubleExt(FileName, Extension)) {
        flags |= WKD_FS_PATH_DOUBLE_EXT;
    }
    if (WkdFsDetectUnicodeObf(FileName)) {
        flags |= WKD_FS_PATH_RLO;
    }
    if (WkdFsDetectReservedName(FileName)) {
        flags |= WKD_FS_PATH_RESERVED;
    }
    if (WkdFsDetectTrailing(FileName)) {
        flags |= WKD_FS_PATH_TRAILING;
    }

    if (OutFlags) {
        *OutFlags = flags;
    }
    return WkdFsCalcPathFlagScore(flags);
}

/* ============================================================================
 * 生命周期（CbInitializeFileSystemNotification/FsCleanup 内调）
 * ========================================================================== */
_Use_decl_annotations_
NTSTATUS
WkdFsScanInitialize(
    VOID
    )
{
    NTSTATUS status;
    ULONG i;

    /* 勒索窗口计数槽（零初始化全局，显式二次清零防前次运行残留） */
    RtlZeroMemory(g_FsFileActivity, sizeof(g_FsFileActivity));
    ExInitializePushLock(&g_FsFileActivityLock);

    /* canary 配置区 */
    ExInitializePushLock(&g_FsCanaryConfig.Lock);
    InterlockedExchange(&g_FsCanaryConfig.Count, 0);
    g_FsCanaryConfig.Initialized = TRUE;

    /* 排除表复位（agent 策略下发前为空） */
    InterlockedExchange(&g_FsExclusionCount, 0);
    for (i = 0; i < ARRAYSIZE(g_FsExclusions); i++) {
        RtlZeroMemory(&g_FsExclusions[i], sizeof(WKD_FS_EXCLUSION));
    }

    status = PsSetCreateProcessNotifyRoutineEx(WkdFsProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        g_FsCanaryConfig.Initialized = FALSE;
        return status;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdFsScanCleanup(
    VOID
    )
{
    ULONG i;

    /* 注销进程退出回调（失败仅记录，继续清理） */
    PsSetCreateProcessNotifyRoutineEx(WkdFsProcessNotify, TRUE);

    /* 释放 canary 路径 */
    if (g_FsCanaryConfig.Initialized) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_FsCanaryConfig.Lock);

        for (i = 0; i < (ULONG)g_FsCanaryConfig.Count; i++) {
            if (g_FsCanaryConfig.Paths[i].Buffer != NULL) {
                ExFreePoolWithTag(g_FsCanaryConfig.Paths[i].Buffer, WKD_FSF_POOL_TAG);
                g_FsCanaryConfig.Paths[i].Buffer = NULL;
                g_FsCanaryConfig.Paths[i].Length = 0;
                g_FsCanaryConfig.Paths[i].MaximumLength = 0;
            }
        }
        InterlockedExchange(&g_FsCanaryConfig.Count, 0);
        g_FsCanaryConfig.Initialized = FALSE;

        ExReleasePushLockExclusive(&g_FsCanaryConfig.Lock);
        KeLeaveCriticalRegion();
    }

    /* 勒索窗口槽复位（防再次初始化时残留） */
    RtlZeroMemory(g_FsFileActivity, sizeof(g_FsFileActivity));
}