/**************************************************/
/*  WkDefender 文件备份/回滚引擎（勒索 CoW）         */
/**************************************************/

#include "Filter.h"
#include "FileBackupEngine.h"
#include "../Notification/NotificationManager.h"   /* 回滚结果上送（NtfCreateMessage/NtfSendMessageAsync） */
#include <ntstrsafe.h>

/*++
 * 实现说明：
 *   勒索软件 Copy-on-First-Write 备份/回滚引擎，迁移自 ShadowStrike
 *   FileBackupEngine.c（重功能实现非源码复制）。各公共 API 对齐 SS 行号标注。
 *
 * 存储设计（自持实现，不复用 wkd Common/HashMap）：
 *   - wkd HashMap 键上限 WKD_HASH_MAP_MAX_KEY_SIZE=32B，FBE 键为
 *     (PID, 路径≤300WCHAR)，且两阶段回滚需要无锁恢复链（InterlockedCompareExchange
 *     + EX_RUNDOWN_REF），与 CoHashMap 桶级 PushLock+锁内回调模型语义冲突。
 *   - 自持：哈希表 (PID,Path) 256 桶 + 进程 tracker 64 桶 + 全局 LRU
 *     + 2 个 NPAGED_LOOKASIDE + EX_RUNDOWN_REF。
 *
 * 迁移裁剪（对齐 SS 行号）：
 *   - FbeGetStatistics/FbeHasBackups：死代码，无查询流水线/UI 消费方。
 *   - FbeOp_Truncate/FbeOp_SetAllocation 备份分支：SS PreSetInfo 亦未接线
 *     （仅 Delete/Rename 调 FbePreSetInfoBackup），保留接口语义。
 *   - 网络路径备份（\Device\Mup\、\Device\LanmanRedirector）：拒绝，对齐 SS。
 *--*/

/**************************************************/
/*                      私有类型                   */
/**************************************************/

typedef struct _FBE_HASH_BUCKET {
    LIST_ENTRY      Head;
    EX_PUSH_LOCK    Lock;
    volatile LONG   Count;
} FBE_HASH_BUCKET, *PFBE_HASH_BUCKET;

/* 全局引擎状态 */
typedef struct _FBE_ENGINE_STATE {
    volatile LONG       State;          /* 0=uninit, 1=initializing, 2=ready, 3=shutdown */
    EX_RUNDOWN_REF      RundownRef;

    FBE_HASH_BUCKET     Buckets[FBE_HASH_BUCKET_COUNT];  /* (PID XOR PathHash) % 256 */

    LIST_ENTRY          LruHead;        /* 全局 LRU（最旧在前） */
    EX_PUSH_LOCK        LruLock;
    volatile LONG       TotalEntryCount;

    FBE_HASH_BUCKET     ProcessBuckets[64]; /* hash(ProcessId) -> tracker 链表 */

    NPAGED_LOOKASIDE_LIST EntryLookaside;   /* FBE_BACKUP_ENTRY */
    NPAGED_LOOKASIDE_LIST TrackerLookaside; /* FBE_PROCESS_TRACKER */

    volatile LONG64     NextBackupId;

    FBE_CONFIG          Config;
    FBE_STATISTICS      Stats;
} FBE_ENGINE_STATE, *PFBE_ENGINE_STATE;

/**************************************************/
/*                      全局状态                   */
/**************************************************/

static FBE_ENGINE_STATE g_FbeState;

/* 重入哨兵：恢复 I/O 期间设置 IoSetTopLevelIrp，
 * 防止 PreWrite 备份自身恢复写入。 */
#define FBE_ROLLBACK_SENTINEL   ((PIRP)(ULONG_PTR)0xF8E80118)

/**************************************************/
/*                      扩展名白名单               */
/**************************************************/

/*
 * 值得备份的扩展名（勒索目标 = 用户数据）。
 * SORTED ALPHABETICALLY (case-insensitive) 供二分查找，禁止重排。
 */
static const UNICODE_STRING g_FbeBackupExtensions[] = {
    RTL_CONSTANT_STRING(L".7z"),    RTL_CONSTANT_STRING(L".accdb"),
    RTL_CONSTANT_STRING(L".ai"),    RTL_CONSTANT_STRING(L".avi"),
    RTL_CONSTANT_STRING(L".bak"),   RTL_CONSTANT_STRING(L".bmp"),
    RTL_CONSTANT_STRING(L".c"),     RTL_CONSTANT_STRING(L".cfg"),
    RTL_CONSTANT_STRING(L".conf"),  RTL_CONSTANT_STRING(L".cpp"),
    RTL_CONSTANT_STRING(L".crt"),   RTL_CONSTANT_STRING(L".cs"),
    RTL_CONSTANT_STRING(L".css"),   RTL_CONSTANT_STRING(L".csv"),
    RTL_CONSTANT_STRING(L".db"),    RTL_CONSTANT_STRING(L".dbf"),
    RTL_CONSTANT_STRING(L".doc"),   RTL_CONSTANT_STRING(L".docx"),
    RTL_CONSTANT_STRING(L".dwg"),   RTL_CONSTANT_STRING(L".dxf"),
    RTL_CONSTANT_STRING(L".flac"),  RTL_CONSTANT_STRING(L".gif"),
    RTL_CONSTANT_STRING(L".go"),    RTL_CONSTANT_STRING(L".gz"),
    RTL_CONSTANT_STRING(L".h"),     RTL_CONSTANT_STRING(L".hpp"),
    RTL_CONSTANT_STRING(L".htm"),   RTL_CONSTANT_STRING(L".html"),
    RTL_CONSTANT_STRING(L".ini"),   RTL_CONSTANT_STRING(L".iso"),
    RTL_CONSTANT_STRING(L".java"),  RTL_CONSTANT_STRING(L".jpeg"),
    RTL_CONSTANT_STRING(L".jpg"),   RTL_CONSTANT_STRING(L".js"),
    RTL_CONSTANT_STRING(L".json"),  RTL_CONSTANT_STRING(L".key"),
    RTL_CONSTANT_STRING(L".kt"),    RTL_CONSTANT_STRING(L".log"),
    RTL_CONSTANT_STRING(L".mdb"),   RTL_CONSTANT_STRING(L".mkv"),
    RTL_CONSTANT_STRING(L".mp3"),   RTL_CONSTANT_STRING(L".mp4"),
    RTL_CONSTANT_STRING(L".odp"),   RTL_CONSTANT_STRING(L".ods"),
    RTL_CONSTANT_STRING(L".odt"),   RTL_CONSTANT_STRING(L".p12"),
    RTL_CONSTANT_STRING(L".pdf"),   RTL_CONSTANT_STRING(L".pem"),
    RTL_CONSTANT_STRING(L".pfx"),   RTL_CONSTANT_STRING(L".php"),
    RTL_CONSTANT_STRING(L".png"),   RTL_CONSTANT_STRING(L".ppt"),
    RTL_CONSTANT_STRING(L".pptx"),  RTL_CONSTANT_STRING(L".psd"),
    RTL_CONSTANT_STRING(L".py"),    RTL_CONSTANT_STRING(L".rar"),
    RTL_CONSTANT_STRING(L".rb"),    RTL_CONSTANT_STRING(L".rs"),
    RTL_CONSTANT_STRING(L".rtf"),   RTL_CONSTANT_STRING(L".sldasm"),
    RTL_CONSTANT_STRING(L".sldprt"),RTL_CONSTANT_STRING(L".sql"),
    RTL_CONSTANT_STRING(L".sqlite"),RTL_CONSTANT_STRING(L".step"),
    RTL_CONSTANT_STRING(L".stl"),   RTL_CONSTANT_STRING(L".svg"),
    RTL_CONSTANT_STRING(L".swift"), RTL_CONSTANT_STRING(L".tar"),
    RTL_CONSTANT_STRING(L".tif"),   RTL_CONSTANT_STRING(L".tiff"),
    RTL_CONSTANT_STRING(L".ts"),    RTL_CONSTANT_STRING(L".txt"),
    RTL_CONSTANT_STRING(L".vhd"),   RTL_CONSTANT_STRING(L".vhdx"),
    RTL_CONSTANT_STRING(L".vmdk"),  RTL_CONSTANT_STRING(L".wav"),
    RTL_CONSTANT_STRING(L".xls"),   RTL_CONSTANT_STRING(L".xlsx"),
    RTL_CONSTANT_STRING(L".xml"),   RTL_CONSTANT_STRING(L".yaml"),
    RTL_CONSTANT_STRING(L".yml"),   RTL_CONSTANT_STRING(L".zip"),
};

#define FBE_BACKUP_EXTENSION_COUNT \
    (sizeof(g_FbeBackupExtensions) / sizeof(g_FbeBackupExtensions[0]))

/**************************************************/
/*                      哈希与工具                 */
/**************************************************/

/*++
 *  FbepHashPath
 *    路径 DJB2 哈希（大小写不敏感）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
FbepHashPath(
    _In_ PCUNICODE_STRING Path
    )
{
    ULONG Hash = 5381;
    USHORT Length = Path->Length / sizeof(WCHAR);

    for (USHORT i = 0; i < Length; i++) {
        WCHAR Ch = RtlUpcaseUnicodeChar(Path->Buffer[i]);
        Hash = ((Hash << 5) + Hash) + (ULONG)Ch;
    }

    return Hash;
}

/*++
 *  FbepComputeBucketIndex
 *    计算 (PID, Path) 的哈希桶索引。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
FbepComputeBucketIndex(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath
    )
{
    ULONG PathHash = FbepHashPath(FilePath);
    ULONG PidHash = HandleToULong(ProcessId);
    return (PathHash ^ PidHash) % FBE_HASH_BUCKET_COUNT;
}

/*++
 *  FbepProcessBucketIndex
 *    计算进程桶索引（hash(ProcessId) % 64）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
FbepProcessBucketIndex(
    _In_ HANDLE ProcessId
    )
{
    return (HandleToULong(ProcessId) >> 2) % 64;
}

/*++
 *  FbepShouldBackup
 *    扩展名二分查找：命中白名单返回 TRUE。
 *    无扩展名默认不备份（减少临时文件/流噪声）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
FbepShouldBackup(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT Length = FileName->Length / sizeof(WCHAR);
    USHORT DotPos = 0;
    UNICODE_STRING Extension;

    for (USHORT i = Length; i > 0; i--) {
        if (FileName->Buffer[i - 1] == L'.') {
            DotPos = i - 1;
            break;
        }
        if (FileName->Buffer[i - 1] == L'\\') {
            break;
        }
    }

    if (DotPos == 0) {
        return FALSE;
    }

    Extension.Buffer = &FileName->Buffer[DotPos];
    Extension.Length = (Length - DotPos) * sizeof(WCHAR);
    Extension.MaximumLength = Extension.Length;

    LONG Lo = 0;
    LONG Hi = (LONG)FBE_BACKUP_EXTENSION_COUNT - 1;

    while (Lo <= Hi) {
        LONG Mid = Lo + (Hi - Lo) / 2;
        LONG Cmp = RtlCompareUnicodeString(&Extension, &g_FbeBackupExtensions[Mid], TRUE);
        if (Cmp == 0) {
            return TRUE;
        } else if (Cmp < 0) {
            Hi = Mid - 1;
        } else {
            Lo = Mid + 1;
        }
    }

    return FALSE;
}

/*++
 *  FbepGetFileSize
 *    查询文件大小（EndOfFile）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepGetFileSize(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLARGE_INTEGER FileSize
    )
{
    NTSTATUS Status;
    FILE_STANDARD_INFORMATION FileInfo;

    FileSize->QuadPart = 0;

    Status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &FileInfo,
        sizeof(FileInfo),
        FileStandardInformation,
        NULL
        );

    if (NT_SUCCESS(Status)) {
        FileSize->QuadPart = FileInfo.EndOfFile.QuadPart;
    }

    return Status;
}

/**************************************************/
/*                      生命周期辅助               */
/**************************************************/

/*++
 *  FbepEnterOperation
 *    进入操作：状态就绪检查 + 获取 rundown 保护。
 *--*/
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
FbepEnterOperation(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_FbeState.State, 0, 0) != 2) {
        return FALSE;
    }

    return ExAcquireRundownProtection(&g_FbeState.RundownRef);
}

/*++
 *  FbepLeaveOperation
 *    离开操作：释放 rundown 保护。
 *--*/
_IRQL_requires_max_(APC_LEVEL)
static VOID
FbepLeaveOperation(
    VOID
    )
{
    ExReleaseRundownProtection(&g_FbeState.RundownRef);
}

/**************************************************/
/*                      目录与路径                 */
/**************************************************/

/*++
 *  FbepGenerateBackupPath
 *    构造备份路径：<VolumePrefix>\WkdBackup\<BackupId>.bak
 *    拒绝网络重定向路径（Mup/LanmanRedirector）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepGenerateBackupPath(
    _In_ PCUNICODE_STRING OriginalPath,
    _Out_ PUNICODE_STRING BackupPath,
    _In_ PWCHAR BackupBuffer,
    _In_ USHORT BackupBufferSize
    )
{
    NTSTATUS Status;
    LONG64 BackupId;
    UNICODE_STRING Result;

    /* 提取卷前缀（第 3 个反斜杠），最小长度 10 字符 */
    USHORT OrigLen = OriginalPath->Length / sizeof(WCHAR);
    USHORT SlashCount = 0;
    USHORT VolumeEnd = 0;

    if (OrigLen < 10) {
        return STATUS_INVALID_PARAMETER;
    }

    for (USHORT i = 0; i < OrigLen; i++) {
        if (OriginalPath->Buffer[i] == L'\\') {
            SlashCount++;
            if (SlashCount == 3) {
                VolumeEnd = i;
                break;
            }
        }
    }

    if (VolumeEnd == 0 || VolumeEnd < 8) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 拒绝网络重定向路径 */
    {
        UNICODE_STRING VolumePrefix;
        VolumePrefix.Buffer = OriginalPath->Buffer;
        VolumePrefix.Length = VolumeEnd * sizeof(WCHAR);
        VolumePrefix.MaximumLength = VolumePrefix.Length;

        UNICODE_STRING MupPrefix = RTL_CONSTANT_STRING(L"\\Device\\Mup");
        UNICODE_STRING LanmanPrefix = RTL_CONSTANT_STRING(L"\\Device\\LanmanRedirector");

        if (RtlEqualUnicodeString(&VolumePrefix, &MupPrefix, TRUE) ||
            RtlEqualUnicodeString(&VolumePrefix, &LanmanPrefix, TRUE)) {
            return STATUS_NOT_SUPPORTED;
        }
    }

    BackupId = InterlockedIncrement64(&g_FbeState.NextBackupId);

    Result.Buffer = BackupBuffer;
    Result.Length = 0;
    Result.MaximumLength = BackupBufferSize;

    Status = RtlUnicodeStringPrintf(
        &Result,
        L"%.*s" FBE_BACKUP_DIR_NAME L"\\%I64u.bak",
        VolumeEnd,
        OriginalPath->Buffer,
        (ULONGLONG)BackupId
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    BackupPath->Buffer = BackupBuffer;
    BackupPath->Length = Result.Length;
    BackupPath->MaximumLength = BackupBufferSize;

    return STATUS_SUCCESS;
}

/*++
 *  FbepEnsureBackupDirectory
 *    创建备份目录（仅 LOCAL_SYSTEM 访问，SE_DACL_PROTECTED 防继承，
 *    防勒索先删备份文件）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepEnsureBackupDirectory(
    _In_ PCUNICODE_STRING BackupPath
    )
{
    NTSTATUS Status;
    HANDLE DirHandle;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    UNICODE_STRING DirPath;
    USHORT LastSlash = 0;
    PACL Dacl = NULL;

    if (BackupPath->Length == 0 || BackupPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 提取目录部分：...\WkdBackup\<id>.bak -> ...\WkdBackup */
    for (USHORT i = BackupPath->Length / sizeof(WCHAR); i > 0; i--) {
        if (BackupPath->Buffer[i - 1] == L'\\') {
            LastSlash = i - 1;
            break;
        }
    }

    if (LastSlash == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    DirPath.Buffer = BackupPath->Buffer;
    DirPath.Length = LastSlash * sizeof(WCHAR);
    DirPath.MaximumLength = DirPath.Length;

    /* 构造受限安全描述符：仅 LOCAL_SYSTEM 全权，SE_DACL_PROTECTED 防父继承 */
    SECURITY_DESCRIPTOR Sd;
    BOOLEAN SdValid = FALSE;

    {
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        UCHAR SystemSidBuf[SECURITY_MAX_SID_SIZE];
        PSID SystemSid = (PSID)SystemSidBuf;

        RtlInitializeSid(SystemSid, &NtAuthority, 1);
        *RtlSubAuthoritySid(SystemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

        ULONG SidLength = RtlLengthSid(SystemSid);
        ULONG AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + SidLength;
        ULONG AclSize = sizeof(ACL) + AceSize;

        AclSize = (AclSize + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);

        Dacl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED, AclSize, WKD_FBE_POOL_TAG);
        if (Dacl != NULL) {
            Status = RtlCreateAcl(Dacl, AclSize, ACL_REVISION);
            if (NT_SUCCESS(Status)) {
                Status = RtlAddAccessAllowedAceEx(
                    Dacl,
                    ACL_REVISION,
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                    FILE_ALL_ACCESS,
                    SystemSid
                    );
            }

            if (NT_SUCCESS(Status)) {
                Status = RtlCreateSecurityDescriptor(
                    &Sd, SECURITY_DESCRIPTOR_REVISION);
            }

            if (NT_SUCCESS(Status)) {
                Status = RtlSetDaclSecurityDescriptor(
                    &Sd, TRUE, Dacl, FALSE);
            }

            if (NT_SUCCESS(Status)) {
                Sd.Control |= SE_DACL_PROTECTED;
                SdValid = TRUE;
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[WkDefender/FBE] Failed to build backup dir SD: 0x%08X\n",
                           Status);
            }
        }
    }

    InitializeObjectAttributes(
        &ObjAttrs,
        &DirPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        SdValid ? &Sd : NULL
        );

    /* FILE_OPEN_IF：不存在则创建，存在则打开；SD 仅创建时应用 */
    Status = FltCreateFile(
        WkdFsGetFilterHandle(),
        NULL,
        &DirHandle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0
        );

    if (NT_SUCCESS(Status)) {
        FltClose(DirHandle);
    }

    if (Dacl != NULL) {
        ExFreePoolWithTag(Dacl, WKD_FBE_POOL_TAG);
    }

    return Status;
}

/**************************************************/
/*                      文件 I/O                   */
/**************************************************/

/*++
 *  FbepDeleteBackupFile
 *    删除备份文件（文件不存在视为成功）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepDeleteBackupFile(
    _In_ PCUNICODE_STRING BackupPath
    )
{
    NTSTATUS Status;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    FILE_DISPOSITION_INFORMATION DispositionInfo;

    InitializeObjectAttributes(
        &ObjAttrs,
        (PUNICODE_STRING)BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        WkdFsGetFilterHandle(),
        NULL,
        &FileHandle,
        NULL,
        DELETE | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
            Status == STATUS_OBJECT_PATH_NOT_FOUND) {
            return STATUS_SUCCESS;
        }
        return Status;
    }

    DispositionInfo.DeleteFile = TRUE;
    Status = ZwSetInformationFile(
        FileHandle,
        &IoStatus,
        &DispositionInfo,
        sizeof(DispositionInfo),
        FileDispositionInformation
        );

    FltClose(FileHandle);
    return Status;
}

/*++
 *  FbepCopyFileToBackup
 *    将源文件内容分块复制到备份路径（64KB 缓冲，FILE_WRITE_THROUGH）。
 *    目录不存在时自动创建；FILE_CREATE 冲突回退 SUPERSEDE。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepCopyFileToBackup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING SourcePath,
    _In_ PCUNICODE_STRING BackupPath,
    _Out_ PLARGE_INTEGER BytesCopied
    )
{
    NTSTATUS Status;
    HANDLE BackupHandle = NULL;
    PFILE_OBJECT BackupFileObject = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    PVOID CopyBuffer = NULL;
    LARGE_INTEGER Offset;
    LARGE_INTEGER FileSize;
    ULONG BytesRead;

    UNREFERENCED_PARAMETER(SourcePath);

    BytesCopied->QuadPart = 0;

    Status = FbepGetFileSize(FltObjects, &FileSize);
    if (!NT_SUCCESS(Status) || FileSize.QuadPart == 0) {
        return STATUS_SUCCESS;
    }

    CopyBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, FBE_IO_BUFFER_SIZE, WKD_FBE_IO_POOL_TAG);
    if (CopyBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 创建备份文件 */
    InitializeObjectAttributes(
        &ObjAttrs,
        (PUNICODE_STRING)BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        WkdFsGetFilterHandle(),
        FltObjects->Instance,
        &BackupHandle,
        &BackupFileObject,
        GENERIC_WRITE | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        0,                              /* 写入期间不共享 */
        FILE_CREATE,                    /* 已存在则失败 */
        FILE_NON_DIRECTORY_FILE |
            FILE_WRITE_THROUGH |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_OBJECT_PATH_NOT_FOUND) {
            Status = FbepEnsureBackupDirectory(BackupPath);
            if (NT_SUCCESS(Status)) {
                Status = FltCreateFileEx(
                    WkdFsGetFilterHandle(),
                    FltObjects->Instance,
                    &BackupHandle,
                    &BackupFileObject,
                    GENERIC_WRITE | SYNCHRONIZE,
                    &ObjAttrs,
                    &IoStatus,
                    NULL,
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                    0,
                    FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE |
                        FILE_WRITE_THROUGH |
                        FILE_SYNCHRONOUS_IO_NONALERT,
                    NULL,
                    0,
                    IO_IGNORE_SHARE_ACCESS_CHECK
                    );
            }
        }

        if (Status == STATUS_OBJECT_NAME_COLLISION) {
            Status = FltCreateFileEx(
                WkdFsGetFilterHandle(),
                FltObjects->Instance,
                &BackupHandle,
                &BackupFileObject,
                GENERIC_WRITE | SYNCHRONIZE,
                &ObjAttrs,
                &IoStatus,
                NULL,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                0,
                FILE_SUPERSEDE,
                FILE_NON_DIRECTORY_FILE |
                    FILE_WRITE_THROUGH |
                    FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0,
                IO_IGNORE_SHARE_ACCESS_CHECK
                );
        }

        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(CopyBuffer, WKD_FBE_IO_POOL_TAG);
            return Status;
        }
    }

    /* 分块复制；FILE_WRITE_THROUGH 下无扇区对齐顾虑 */
    Offset.QuadPart = 0;

    while (Offset.QuadPart < FileSize.QuadPart) {
        ULONG ReadSize = FBE_IO_BUFFER_SIZE;
        LONGLONG Remaining = FileSize.QuadPart - Offset.QuadPart;
        if (Remaining < (LONGLONG)ReadSize) {
            ReadSize = (ULONG)Remaining;
        }

        BytesRead = 0;
        Status = FltReadFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &Offset,
            ReadSize,
            CopyBuffer,
            FLTFL_IO_OPERATION_NON_CACHED |
                FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &BytesRead,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
                break;
            }
            goto Cleanup;
        }

        if (BytesRead == 0) {
            break;
        }

        /* 防御：钳制 BytesRead 到 ReadSize，防下层 filter 虚报 */
        if (BytesRead > ReadSize) {
            BytesRead = ReadSize;
        }

        Status = FltWriteFile(
            FltObjects->Instance,
            BackupFileObject,
            &Offset,
            BytesRead,
            CopyBuffer,
            FLTFL_IO_OPERATION_NON_CACHED |
                FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            NULL,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            goto Cleanup;
        }

        Offset.QuadPart += BytesRead;
    }

    BytesCopied->QuadPart = min(Offset.QuadPart, FileSize.QuadPart);
    Status = STATUS_SUCCESS;

Cleanup:
    if (BackupFileObject != NULL) {
        ObDereferenceObject(BackupFileObject);
    }

    if (BackupHandle != NULL) {
        FltClose(BackupHandle);
    }

    if (CopyBuffer != NULL) {
        ExFreePoolWithTag(CopyBuffer, WKD_FBE_IO_POOL_TAG);
    }

    if (!NT_SUCCESS(Status) && BytesCopied->QuadPart == 0) {
        FbepDeleteBackupFile(BackupPath);
    }

    return Status;
}

/*++
 *  FbepRestoreFileFromBackup
 *    从备份恢复原始文件（FILE_OVERWRITE_IF 保留 ACL）。
 *    设置 FBE_ROLLBACK_SENTINEL 防止恢复写入被再次备份。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepRestoreFileFromBackup(
    _In_ PFBE_BACKUP_ENTRY Entry
    )
{
    NTSTATUS Status;
    HANDLE SourceHandle = NULL;
    PFILE_OBJECT SourceFileObject = NULL;
    HANDLE TargetHandle = NULL;
    PFILE_OBJECT TargetFileObject = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    PVOID CopyBuffer = NULL;
    LARGE_INTEGER Offset;
    ULONG BytesRead;

    PIRP SavedTopLevelIrp = IoGetTopLevelIrp();
    IoSetTopLevelIrp(FBE_ROLLBACK_SENTINEL);

    CopyBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, FBE_IO_BUFFER_SIZE, WKD_FBE_IO_POOL_TAG);
    if (CopyBuffer == NULL) {
        IoSetTopLevelIrp(SavedTopLevelIrp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 打开备份文件读 */
    InitializeObjectAttributes(
        &ObjAttrs,
        &Entry->BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        WkdFsGetFilterHandle(),
        NULL,
        &SourceHandle,
        &SourceFileObject,
        GENERIC_READ | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(CopyBuffer, WKD_FBE_IO_POOL_TAG);
        IoSetTopLevelIrp(SavedTopLevelIrp);
        return Status;
    }

    /* 打开/覆盖原始文件（保留 ACL，删除时重建） */
    InitializeObjectAttributes(
        &ObjAttrs,
        &Entry->OriginalPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        WkdFsGetFilterHandle(),
        NULL,
        &TargetHandle,
        &TargetFileObject,
        GENERIC_WRITE | SYNCHRONIZE | DELETE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    /* 复制回原位置，限制到 OriginalFileSize 排除非缓冲填充 */
    Offset.QuadPart = 0;

    while (Offset.QuadPart < Entry->OriginalFileSize.QuadPart) {
        ULONG ReadSize = FBE_IO_BUFFER_SIZE;
        LONGLONG Remaining = Entry->OriginalFileSize.QuadPart - Offset.QuadPart;
        if (Remaining < (LONGLONG)ReadSize) {
            ReadSize = (ULONG)Remaining;
        }

        Status = FltReadFile(
            NULL,
            SourceFileObject,
            &Offset,
            ReadSize,
            CopyBuffer,
            0,
            &BytesRead,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status) || BytesRead == 0) {
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
            }
            break;
        }

        ULONG WriteSize = BytesRead;
        if (Offset.QuadPart + WriteSize > Entry->OriginalFileSize.QuadPart) {
            WriteSize = (ULONG)(Entry->OriginalFileSize.QuadPart - Offset.QuadPart);
        }

        Status = FltWriteFile(
            NULL,
            TargetFileObject,
            &Offset,
            WriteSize,
            CopyBuffer,
            0,
            NULL,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset.QuadPart += WriteSize;
    }

    /* 设置精确 EOF（去除对齐填充） */
    if (NT_SUCCESS(Status) && TargetFileObject != NULL) {
        FILE_END_OF_FILE_INFORMATION EofInfo;
        EofInfo.EndOfFile = Entry->OriginalFileSize;
        FltSetInformationFile(
            NULL,
            TargetFileObject,
            &EofInfo,
            sizeof(EofInfo),
            FileEndOfFileInformation
            );
    }

Cleanup:
    if (TargetFileObject != NULL) {
        ObDereferenceObject(TargetFileObject);
    }
    if (TargetHandle != NULL) {
        FltClose(TargetHandle);
    }
    if (SourceFileObject != NULL) {
        ObDereferenceObject(SourceFileObject);
    }
    if (SourceHandle != NULL) {
        FltClose(SourceHandle);
    }
    if (CopyBuffer != NULL) {
        ExFreePoolWithTag(CopyBuffer, WKD_FBE_IO_POOL_TAG);
    }

    IoSetTopLevelIrp(SavedTopLevelIrp);

    return Status;
}

/**************************************************/
/*                      条目管理                   */
/**************************************************/

/*++
 *  FbepFindEntry
 *    在哈希桶中查找 (PID, Path) 备份条目。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_BACKUP_ENTRY
FbepFindEntry(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG BucketIndex
    )
{
    LIST_ENTRY *ListEntry;

    for (ListEntry = g_FbeState.Buckets[BucketIndex].Head.Flink;
         ListEntry != &g_FbeState.Buckets[BucketIndex].Head;
         ListEntry = ListEntry->Flink) {

        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, HashLink);

        if (Entry->ProcessId == ProcessId &&
            Entry->OriginalPath.Length == FilePath->Length &&
            RtlEqualUnicodeString(&Entry->OriginalPath, FilePath, TRUE)) {

            LONG EntryState = ReadAcquire(&Entry->State);
            if (EntryState == FbeEntryState_Valid ||
                EntryState == FbeEntryState_Pending) {
                return Entry;
            }
        }
    }

    return NULL;
}

/*++
 *  FbepAllocateEntry
 *    lookaside 分配备份条目（零初始化 + 三链表初始化）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_BACKUP_ENTRY
FbepAllocateEntry(
    VOID
    )
{
    PFBE_BACKUP_ENTRY Entry;

    Entry = (PFBE_BACKUP_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_FbeState.EntryLookaside);

    if (Entry != NULL) {
        RtlZeroMemory(Entry, sizeof(FBE_BACKUP_ENTRY));
        InitializeListHead(&Entry->ProcessLink);
        InitializeListHead(&Entry->HashLink);
        InitializeListHead(&Entry->LruLink);
    }

    return Entry;
}

/*++
 *  FbepFreeEntry
 *    lookaside 释放备份条目。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepFreeEntry(
    _In_ PFBE_BACKUP_ENTRY Entry
    )
{
    ExFreeToNPagedLookasideList(&g_FbeState.EntryLookaside, Entry);
}

/**************************************************/
/*                      进程追踪器                 */
/**************************************************/

/*++
 *  FbepFindOrCreateTracker
 *    按 PID 查找进程追踪器，不存在则创建（含 TOCTOU 二次检查）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_PROCESS_TRACKER
FbepFindOrCreateTracker(
    _In_ HANDLE ProcessId
    )
{
    PFBE_PROCESS_TRACKER Tracker;
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    LIST_ENTRY *ListEntry;

    /* 共享锁下查找 */
    FltAcquirePushLockShared(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    for (ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
         ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head;
         ListEntry = ListEntry->Flink) {

        Tracker = CONTAINING_RECORD(ListEntry, FBE_PROCESS_TRACKER, Link);
        if (Tracker->ProcessId == ProcessId) {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            return Tracker;
        }
    }

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    /* 未找到，分配新 tracker */
    Tracker = (PFBE_PROCESS_TRACKER)ExAllocateFromNPagedLookasideList(
        &g_FbeState.TrackerLookaside);

    if (Tracker == NULL) {
        return NULL;
    }

    RtlZeroMemory(Tracker, sizeof(FBE_PROCESS_TRACKER));
    Tracker->ProcessId = ProcessId;
    InitializeListHead(&Tracker->BackupEntries);
    FltInitializePushLock(&Tracker->Lock);
    InitializeListHead(&Tracker->Link);

    /* 互斥锁下插入 + 二次判重 */
    FltAcquirePushLockExclusive(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    for (ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
         ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head;
         ListEntry = ListEntry->Flink) {

        PFBE_PROCESS_TRACKER Existing = CONTAINING_RECORD(
            ListEntry, FBE_PROCESS_TRACKER, Link);

        if (Existing->ProcessId == ProcessId) {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            FltDeletePushLock(&Tracker->Lock);
            ExFreeToNPagedLookasideList(&g_FbeState.TrackerLookaside, Tracker);
            return Existing;
        }
    }

    InsertTailList(&g_FbeState.ProcessBuckets[ProcBucket].Head, &Tracker->Link);
    InterlockedIncrement(&g_FbeState.ProcessBuckets[ProcBucket].Count);

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    return Tracker;
}

/*++
 *  FbepFindTracker
 *    按 PID 查找进程追踪器。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_PROCESS_TRACKER
FbepFindTracker(
    _In_ HANDLE ProcessId
    )
{
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    for (ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
         ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head;
         ListEntry = ListEntry->Flink) {

        PFBE_PROCESS_TRACKER Tracker = CONTAINING_RECORD(
            ListEntry, FBE_PROCESS_TRACKER, Link);

        if (Tracker->ProcessId == ProcessId) {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            return Tracker;
        }
    }

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
    return NULL;
}

/*++
 *  FbepFreeTracker
 *    释放进程追踪器。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepFreeTracker(
    _In_ PFBE_PROCESS_TRACKER Tracker
    )
{
    FltDeletePushLock(&Tracker->Lock);
    ExFreeToNPagedLookasideList(&g_FbeState.TrackerLookaside, Tracker);
}

/**************************************************/
/*                      LRU 淘汰                   */
/**************************************************/

/*++
 *  FbepEvictLruEntries
 *    两阶段 LRU 驱逐：锁内 CAS 夺取最旧 Valid 条目，锁外卸载/删文件/释放。
 *    跳过 Pending 条目（I/O 进行中归属发起者）。
 *    每轮最多驱逐 128 条。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepEvictLruEntries(
    _In_ LONGLONG BytesNeeded
    )
{
    PFBE_BACKUP_ENTRY Entry;
    LIST_ENTRY *ListEntry;
    ULONG Evicted = 0;
    ULONG MaxEvict = 128;

    while (Evicted < MaxEvict) {
        LONGLONG Usage = InterlockedCompareExchange64(
            &g_FbeState.Stats.CurrentBackupDiskUsage, 0, 0);
        LONG TotalCount = InterlockedCompareExchange(
            &g_FbeState.TotalEntryCount, 0, 0);

        if (BytesNeeded > 0 &&
            Usage + BytesNeeded <= g_FbeState.Config.MaxTotalBackupSize &&
            TotalCount < FBE_MAX_TOTAL_ENTRIES) {
            break;
        }
        if (BytesNeeded == 0 && TotalCount < FBE_MAX_TOTAL_ENTRIES) {
            break;
        }

        /* Phase 1：LRU 锁下定位最旧条目并 CAS Valid→Evicted 夺取所有权 */
        Entry = NULL;

        FltAcquirePushLockExclusive(&g_FbeState.LruLock);

        ListEntry = g_FbeState.LruHead.Flink;
        while (ListEntry != &g_FbeState.LruHead) {
            PFBE_BACKUP_ENTRY Candidate = CONTAINING_RECORD(
                ListEntry, FBE_BACKUP_ENTRY, LruLink);

            LONG Prev = InterlockedCompareExchange(
                &Candidate->State, FbeEntryState_Evicted, FbeEntryState_Valid);

            if (Prev == FbeEntryState_Valid) {
                RemoveEntryList(&Candidate->LruLink);
                Entry = Candidate;
                break;
            }

            ListEntry = ListEntry->Flink;
        }

        FltReleasePushLock(&g_FbeState.LruLock);

        if (Entry == NULL) {
            break;
        }

        /* Phase 2：从哈希桶与进程追踪器卸载 */
        ULONG BucketIndex = FbepComputeBucketIndex(Entry->ProcessId, &Entry->OriginalPath);
        FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);
        RemoveEntryList(&Entry->HashLink);
        InterlockedDecrement(&g_FbeState.Buckets[BucketIndex].Count);
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

        PFBE_PROCESS_TRACKER Tracker = FbepFindTracker(Entry->ProcessId);
        if (Tracker != NULL) {
            FltAcquirePushLockExclusive(&Tracker->Lock);
            RemoveEntryList(&Entry->ProcessLink);
            InterlockedDecrement(&Tracker->EntryCount);
            FltReleasePushLock(&Tracker->Lock);
        }

        InterlockedDecrement(&g_FbeState.TotalEntryCount);

        if (Entry->BackupFileSize.QuadPart > 0) {
            InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage,
                             -Entry->BackupFileSize.QuadPart);
        }
        FbepDeleteBackupFile(&Entry->BackupPath);

        InterlockedIncrement64(&g_FbeState.Stats.EntriesEvicted);

        FbepFreeEntry(Entry);
        Evicted++;
    }

    if (Evicted > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[WkDefender/FBE] Evicted %lu LRU backup entries\n",
                   Evicted);
    }
}

/**************************************************/
/*                      生命周期                   */
/**************************************************/

/*++
 *  FbeInitialize
 *    初始化备份引擎：哈希桶/进程桶/LRU/lookaside/默认配置。
 *    对齐 SS FbeInitialize。
 *--*/
_Use_decl_annotations_
NTSTATUS
FbeInitialize(
    VOID
    )
{
    LONG PreviousState;

    PreviousState = InterlockedCompareExchange(&g_FbeState.State, 1, 0);
    if (PreviousState != 0) {
        return (PreviousState == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_FbeState.RundownRef);

    for (ULONG i = 0; i < FBE_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_FbeState.Buckets[i].Head);
        FltInitializePushLock(&g_FbeState.Buckets[i].Lock);
        g_FbeState.Buckets[i].Count = 0;
    }

    for (ULONG i = 0; i < 64; i++) {
        InitializeListHead(&g_FbeState.ProcessBuckets[i].Head);
        FltInitializePushLock(&g_FbeState.ProcessBuckets[i].Lock);
        g_FbeState.ProcessBuckets[i].Count = 0;
    }

    InitializeListHead(&g_FbeState.LruHead);
    FltInitializePushLock(&g_FbeState.LruLock);
    g_FbeState.TotalEntryCount = 0;

    ExInitializeNPagedLookasideList(
        &g_FbeState.EntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(FBE_BACKUP_ENTRY),
        WKD_FBE_ENTRY_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_FbeState.TrackerLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(FBE_PROCESS_TRACKER),
        WKD_FBE_POOL_TAG,
        0
        );

    /* 默认配置：沿用 SS 容量上限 */
    g_FbeState.Config.MaxTotalBackupSize = FBE_MAX_BACKUP_SIZE_DEFAULT;
    g_FbeState.Config.MaxSingleFileSize = FBE_MAX_SINGLE_FILE_SIZE;
    g_FbeState.Config.MaxEntriesPerProcess = FBE_MAX_ENTRIES_PER_PROCESS;
    g_FbeState.Config.EnableWriteBackup = TRUE;
    g_FbeState.Config.EnableRenameBackup = TRUE;
    g_FbeState.Config.EnableDeleteBackup = TRUE;
    g_FbeState.Config.EnableTruncateBackup = TRUE;

    g_FbeState.NextBackupId = 0;

    RtlZeroMemory(&g_FbeState.Stats, sizeof(FBE_STATISTICS));

    InterlockedExchange(&g_FbeState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/FBE] File Backup Engine initialized "
               "(MaxBackup=%lld MB, MaxSingleFile=%lld MB)\n",
               g_FbeState.Config.MaxTotalBackupSize / (1024 * 1024),
               g_FbeState.Config.MaxSingleFileSize / (1024 * 1024));

    return STATUS_SUCCESS;
}

/*++
 *  FbeShutdown
 *    关闭引擎：排空操作、释放全部条目与追踪器、删除 lookaside。
 *    对齐 SS FbeShutdown。
 *--*/
_Use_decl_annotations_
VOID
FbeShutdown(
    VOID
    )
{
    LIST_ENTRY *ListEntry;
    PFBE_PROCESS_TRACKER Tracker;

    if (InterlockedCompareExchange(&g_FbeState.State, 3, 2) != 2) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/FBE] Shutting down File Backup Engine...\n");

    ExWaitForRundownProtectionRelease(&g_FbeState.RundownRef);

    /* 释放全部进程追踪器及其条目（遍历 ProcessBuckets） */
    for (ULONG BucketIdx = 0; BucketIdx < 64; BucketIdx++) {
        FltAcquirePushLockExclusive(&g_FbeState.ProcessBuckets[BucketIdx].Lock);

        while (!IsListEmpty(&g_FbeState.ProcessBuckets[BucketIdx].Head)) {
            ListEntry = RemoveHeadList(&g_FbeState.ProcessBuckets[BucketIdx].Head);
            Tracker = CONTAINING_RECORD(ListEntry, FBE_PROCESS_TRACKER, Link);

            while (!IsListEmpty(&Tracker->BackupEntries)) {
                LIST_ENTRY *EntryLink = RemoveHeadList(&Tracker->BackupEntries);
                PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
                    EntryLink, FBE_BACKUP_ENTRY, ProcessLink);

                FltAcquirePushLockExclusive(&g_FbeState.LruLock);
                RemoveEntryList(&Entry->LruLink);
                FltReleasePushLock(&g_FbeState.LruLock);

                ULONG HashBucket = FbepComputeBucketIndex(
                    Entry->ProcessId, &Entry->OriginalPath);
                FltAcquirePushLockExclusive(&g_FbeState.Buckets[HashBucket].Lock);
                RemoveEntryList(&Entry->HashLink);
                InterlockedDecrement(&g_FbeState.Buckets[HashBucket].Count);
                FltReleasePushLock(&g_FbeState.Buckets[HashBucket].Lock);

                if (Entry->State == FbeEntryState_Valid) {
                    FbepDeleteBackupFile(&Entry->BackupPath);
                }

                FbepFreeEntry(Entry);
                InterlockedDecrement(&g_FbeState.TotalEntryCount);
            }

            FbepFreeTracker(Tracker);
        }

        g_FbeState.ProcessBuckets[BucketIdx].Count = 0;
        FltReleasePushLock(&g_FbeState.ProcessBuckets[BucketIdx].Lock);
    }

    ExDeleteNPagedLookasideList(&g_FbeState.EntryLookaside);
    ExDeleteNPagedLookasideList(&g_FbeState.TrackerLookaside);

    for (ULONG i = 0; i < FBE_HASH_BUCKET_COUNT; i++) {
        FltDeletePushLock(&g_FbeState.Buckets[i].Lock);
    }
    for (ULONG i = 0; i < 64; i++) {
        FltDeletePushLock(&g_FbeState.ProcessBuckets[i].Lock);
    }
    FltDeletePushLock(&g_FbeState.LruLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/FBE] Shutdown complete. "
               "Created=%lld, Restored=%lld, Evicted=%lld\n",
               g_FbeState.Stats.BackupsCreated,
               g_FbeState.Stats.RollbackFilesRestored,
               g_FbeState.Stats.EntriesEvicted);
}

/**************************************************/
/*                      备份操作                   */
/**************************************************/

/*++
 *  FbePreWriteBackup
 *    IRP_MJ_WRITE 前 CoW 备份（copy-on-first-write）。
 *    对齐 SS FbePreWriteBackup。
 *--*/
_Use_decl_annotations_
NTSTATUS
FbePreWriteBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    )
{
    NTSTATUS Status;
    PFBE_BACKUP_ENTRY Entry;
    PFBE_PROCESS_TRACKER Tracker;
    ULONG BucketIndex;
    HANDLE ProcessId;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER BytesCopied;

    UNREFERENCED_PARAMETER(Data);

    /* 重入守卫：自身恢复路径写入跳过 */
    if (IoGetTopLevelIrp() == FBE_ROLLBACK_SENTINEL) {
        return STATUS_FBE_SKIP;
    }

    InterlockedIncrement64(&g_FbeState.Stats.TotalBackupRequests);

    if (!g_FbeState.Config.EnableWriteBackup) {
        return STATUS_FBE_SKIP;
    }

    if (!FbepEnterOperation()) {
        return STATUS_FBE_SKIP;
    }

    if (!FbepShouldBackup(FileName)) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedExtension);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    ProcessId = PsGetCurrentProcessId();
    BucketIndex = FbepComputeBucketIndex(ProcessId, FileName);

    /* CoW：检查是否已有备份 */
    FltAcquirePushLockShared(&g_FbeState.Buckets[BucketIndex].Lock);
    Entry = FbepFindEntry(ProcessId, FileName, BucketIndex);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    if (Entry != NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    /* 条目数容量检查 + 驱逐 */
    if (InterlockedCompareExchange(&g_FbeState.TotalEntryCount, 0, 0) >= FBE_MAX_TOTAL_ENTRIES) {
        FbepEvictLruEntries(0);
        if (InterlockedCompareExchange(&g_FbeState.TotalEntryCount, 0, 0) >= FBE_MAX_TOTAL_ENTRIES) {
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    Status = FbepGetFileSize(FltObjects, &FileSize);
    if (!NT_SUCCESS(Status) || FileSize.QuadPart == 0) {
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    if (FileSize.QuadPart > g_FbeState.Config.MaxSingleFileSize) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedSize);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    /* 总磁盘用量检查 + 驱逐 */
    if (InterlockedCompareExchange64(&g_FbeState.Stats.CurrentBackupDiskUsage, 0, 0) +
        FileSize.QuadPart > g_FbeState.Config.MaxTotalBackupSize) {
        FbepEvictLruEntries(FileSize.QuadPart);
        if (InterlockedCompareExchange64(&g_FbeState.Stats.CurrentBackupDiskUsage, 0, 0) +
            FileSize.QuadPart > g_FbeState.Config.MaxTotalBackupSize) {
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return STATUS_DISK_FULL;
        }
    }

    Entry = FbepAllocateEntry();
    if (Entry == NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entry->ProcessId = ProcessId;
    Entry->OperationType = FbeOp_Write;
    KeQuerySystemTime(&Entry->Timestamp);
    Entry->OriginalFileSize = FileSize;
    InterlockedExchange(&Entry->State, FbeEntryState_Pending);

    if (FileName->Length >= sizeof(Entry->OriginalPathBuffer)) {
        FbepFreeEntry(Entry);
        FbepLeaveOperation();
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(Entry->OriginalPathBuffer, FileName->Buffer, FileName->Length);
    Entry->OriginalPath.Buffer = Entry->OriginalPathBuffer;
    Entry->OriginalPath.Length = FileName->Length;
    Entry->OriginalPath.MaximumLength = sizeof(Entry->OriginalPathBuffer);

    Status = FbepGenerateBackupPath(
        FileName,
        &Entry->BackupPath,
        Entry->BackupPathBuffer,
        sizeof(Entry->BackupPathBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return Status;
    }

    BytesCopied.QuadPart = 0;
    Status = FbepCopyFileToBackup(FltObjects, FileName, &Entry->BackupPath, &BytesCopied);

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[WkDefender/FBE] Backup copy failed for %wZ: 0x%08X\n",
                   FileName, Status);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return Status;
    }

    Entry->BackupFileSize = BytesCopied;
    InterlockedExchange(&Entry->State, FbeEntryState_Valid);

    Tracker = FbepFindOrCreateTracker(ProcessId);
    if (Tracker == NULL) {
        FbepDeleteBackupFile(&Entry->BackupPath);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if ((ULONG)InterlockedCompareExchange(&Tracker->EntryCount, 0, 0) >=
        g_FbeState.Config.MaxEntriesPerProcess) {
        FbepDeleteBackupFile(&Entry->BackupPath);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    /* 插入哈希桶（互斥锁 + TOCTOU 二次判重） */
    FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);

    PFBE_BACKUP_ENTRY Existing = FbepFindEntry(ProcessId, FileName, BucketIndex);
    if (Existing != NULL) {
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);
        FbepDeleteBackupFile(&Entry->BackupPath);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    InsertTailList(&g_FbeState.Buckets[BucketIndex].Head, &Entry->HashLink);
    InterlockedIncrement(&g_FbeState.Buckets[BucketIndex].Count);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    /* 插入进程追踪器 */
    FltAcquirePushLockExclusive(&Tracker->Lock);
    InsertTailList(&Tracker->BackupEntries, &Entry->ProcessLink);
    InterlockedIncrement(&Tracker->EntryCount);
    InterlockedAdd64(&Tracker->TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedIncrement64(&Tracker->FilesBackedUp);
    FltReleasePushLock(&Tracker->Lock);

    /* 插入 LRU（尾部 = 最新） */
    FltAcquirePushLockExclusive(&g_FbeState.LruLock);
    InsertTailList(&g_FbeState.LruHead, &Entry->LruLink);
    FltReleasePushLock(&g_FbeState.LruLock);

    InterlockedIncrement(&g_FbeState.TotalEntryCount);

    InterlockedIncrement64(&g_FbeState.Stats.BackupsCreated);
    InterlockedAdd64(&g_FbeState.Stats.TotalBytesBackedUp, BytesCopied.QuadPart);
    LONGLONG CurrentUsage = InterlockedAdd64(
        &g_FbeState.Stats.CurrentBackupDiskUsage, BytesCopied.QuadPart);

    LONGLONG PeakUsage;
    do {
        PeakUsage = InterlockedCompareExchange64(
            &g_FbeState.Stats.PeakBackupDiskUsage, 0, 0);
        if (CurrentUsage <= PeakUsage) break;
    } while (InterlockedCompareExchange64(
        &g_FbeState.Stats.PeakBackupDiskUsage,
        CurrentUsage,
        PeakUsage) != PeakUsage);

    FbepLeaveOperation();
    return STATUS_SUCCESS;
}

/*++
 *  FbePreSetInfoBackup
 *    IRP_MJ_SET_INFORMATION 前 CoW 备份（Rename/Delete/Truncate/SetAllocation）。
 *    Truncate/SetAllocation 为死代码分支（SS PreSetInfo 亦未接线）。
 *    对齐 SS FbePreSetInfoBackup。
 *--*/
_Use_decl_annotations_
NTSTATUS
FbePreSetInfoBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName,
    _In_ FBE_OPERATION_TYPE OpType
    )
{
    NTSTATUS Status;
    PFBE_BACKUP_ENTRY Entry;
    PFBE_PROCESS_TRACKER Tracker;
    ULONG BucketIndex;
    HANDLE ProcessId;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER BytesCopied;

    UNREFERENCED_PARAMETER(Data);

    if (IoGetTopLevelIrp() == FBE_ROLLBACK_SENTINEL) {
        return STATUS_FBE_SKIP;
    }

    InterlockedIncrement64(&g_FbeState.Stats.TotalBackupRequests);

    /* 按操作类型检查配置开关 */
    switch (OpType) {
    case FbeOp_Rename:
        if (!g_FbeState.Config.EnableRenameBackup) return STATUS_FBE_SKIP;
        break;
    case FbeOp_Delete:
        if (!g_FbeState.Config.EnableDeleteBackup) return STATUS_FBE_SKIP;
        break;
    case FbeOp_Truncate:
    case FbeOp_SetAllocation:
        /* 死代码：SS PreSetInfo 仅 Delete/Rename 调本函数，截断只监控不备份 */
        if (!g_FbeState.Config.EnableTruncateBackup) return STATUS_FBE_SKIP;
        break;
    default:
        return STATUS_FBE_SKIP;
    }

    if (!FbepEnterOperation()) {
        return STATUS_FBE_SKIP;
    }

    if (!FbepShouldBackup(FileName)) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedExtension);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    ProcessId = PsGetCurrentProcessId();
    BucketIndex = FbepComputeBucketIndex(ProcessId, FileName);

    FltAcquirePushLockShared(&g_FbeState.Buckets[BucketIndex].Lock);
    Entry = FbepFindEntry(ProcessId, FileName, BucketIndex);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    if (Entry != NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    /* Delete 操作文件可能随后不存在，必须现在备份；零长度文件仍建条目 */
    Status = FbepGetFileSize(FltObjects, &FileSize);
    if (!NT_SUCCESS(Status) || FileSize.QuadPart == 0) {
        if (OpType != FbeOp_Delete) {
            FbepLeaveOperation();
            return STATUS_FBE_SKIP;
        }
        FileSize.QuadPart = 0;
    }

    if (FileSize.QuadPart > g_FbeState.Config.MaxSingleFileSize) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedSize);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    /* 容量检查 + 驱逐 */
    if (FileSize.QuadPart > 0 &&
        InterlockedCompareExchange64(&g_FbeState.Stats.CurrentBackupDiskUsage, 0, 0) +
            FileSize.QuadPart > g_FbeState.Config.MaxTotalBackupSize) {
        FbepEvictLruEntries(FileSize.QuadPart);
    }

    if (InterlockedCompareExchange(&g_FbeState.TotalEntryCount, 0, 0) >= FBE_MAX_TOTAL_ENTRIES) {
        FbepEvictLruEntries(0);
        if (InterlockedCompareExchange(&g_FbeState.TotalEntryCount, 0, 0) >= FBE_MAX_TOTAL_ENTRIES) {
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    Entry = FbepAllocateEntry();
    if (Entry == NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entry->ProcessId = ProcessId;
    Entry->OperationType = OpType;
    KeQuerySystemTime(&Entry->Timestamp);
    Entry->OriginalFileSize = FileSize;
    InterlockedExchange(&Entry->State, FbeEntryState_Pending);

    if (FileName->Length >= sizeof(Entry->OriginalPathBuffer)) {
        FbepFreeEntry(Entry);
        FbepLeaveOperation();
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(Entry->OriginalPathBuffer, FileName->Buffer, FileName->Length);
    Entry->OriginalPath.Buffer = Entry->OriginalPathBuffer;
    Entry->OriginalPath.Length = FileName->Length;
    Entry->OriginalPath.MaximumLength = sizeof(Entry->OriginalPathBuffer);

    Status = FbepGenerateBackupPath(
        FileName,
        &Entry->BackupPath,
        Entry->BackupPathBuffer,
        sizeof(Entry->BackupPathBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return Status;
    }

    BytesCopied.QuadPart = 0;
    if (FileSize.QuadPart > 0) {
        Status = FbepCopyFileToBackup(FltObjects, FileName, &Entry->BackupPath, &BytesCopied);
        if (!NT_SUCCESS(Status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[WkDefender/FBE] SetInfo backup copy failed for %wZ: 0x%08X\n",
                       FileName, Status);
            FbepFreeEntry(Entry);
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return Status;
        }
    }

    Entry->BackupFileSize = BytesCopied;
    InterlockedExchange(&Entry->State, FbeEntryState_Valid);

    Tracker = FbepFindOrCreateTracker(ProcessId);
    if (Tracker == NULL) {
        if (BytesCopied.QuadPart > 0) {
            FbepDeleteBackupFile(&Entry->BackupPath);
        }
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if ((ULONG)InterlockedCompareExchange(&Tracker->EntryCount, 0, 0) >=
        g_FbeState.Config.MaxEntriesPerProcess) {
        if (BytesCopied.QuadPart > 0) {
            FbepDeleteBackupFile(&Entry->BackupPath);
        }
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);

    PFBE_BACKUP_ENTRY Existing = FbepFindEntry(ProcessId, FileName, BucketIndex);
    if (Existing != NULL) {
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);
        if (BytesCopied.QuadPart > 0) {
            FbepDeleteBackupFile(&Entry->BackupPath);
        }
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    InsertTailList(&g_FbeState.Buckets[BucketIndex].Head, &Entry->HashLink);
    InterlockedIncrement(&g_FbeState.Buckets[BucketIndex].Count);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    FltAcquirePushLockExclusive(&Tracker->Lock);
    InsertTailList(&Tracker->BackupEntries, &Entry->ProcessLink);
    InterlockedIncrement(&Tracker->EntryCount);
    InterlockedAdd64(&Tracker->TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedIncrement64(&Tracker->FilesBackedUp);
    FltReleasePushLock(&Tracker->Lock);

    FltAcquirePushLockExclusive(&g_FbeState.LruLock);
    InsertTailList(&g_FbeState.LruHead, &Entry->LruLink);
    FltReleasePushLock(&g_FbeState.LruLock);

    InterlockedIncrement(&g_FbeState.TotalEntryCount);
    InterlockedIncrement64(&g_FbeState.Stats.BackupsCreated);
    InterlockedAdd64(&g_FbeState.Stats.TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage, BytesCopied.QuadPart);

    FbepLeaveOperation();
    return STATUS_SUCCESS;
}

/**************************************************/
/*                      回滚操作                   */
/**************************************************/

/*++
 *  FbepSendRollbackResult
 *    回滚完成后上送结果事件到 agent（对齐 SS FbeRollbackProcess 中
 *    BeEngineSubmitEvent(FileRollbackStarted) 的事件上报语义，wkd 结果导向）。
 *    agent 侧暂不解析（死代码：待 UI 消费接线），消息经 ALPC 0x300B 转发。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepSendRollbackResult(
    _In_ HANDLE ProcessId,
    _In_ FBE_ROLLBACK_RESULT Result,
    _In_ ULONG FilesRestored
    )
{
    NTSTATUS status;
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_FILE_ROLLBACK body;

    msg = NtfCreateMessage(WkdMessage_FileRollbackResult, WkdMessage_SourceFile,
                           WkdMessage_PriorityNormal, sizeof(WKD_MESSAGE_BODY_FILE_ROLLBACK));
    if (msg == NULL) {
        return;
    }

    body = (PWKD_MESSAGE_BODY_FILE_ROLLBACK)msg->Body;
    body->ProcessId = ProcessId;
    body->Result = (ULONG)Result;
    body->FilesRestored = FilesRestored;

    status = NtfSendMessageAsync(msg);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(msg);
    }
}

/*++
 *  FbeRollbackProcess
 *    按进程回滚全部备份（两阶段：锁内 CAS 收集 → 无锁恢复）。
 *    逆序恢复（最新优先）以正确处理重命名链。
 *    对齐 SS FbeRollbackProcess。
 *--*/
_Use_decl_annotations_
FBE_ROLLBACK_RESULT
FbeRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    )
{
    PFBE_PROCESS_TRACKER Tracker;
    LIST_ENTRY *ListEntry;
    ULONG Restored = 0;
    ULONG Failed = 0;
    NTSTATUS Status;

    if (FilesRestored != NULL) {
        *FilesRestored = 0;
    }

    InterlockedIncrement64(&g_FbeState.Stats.RollbackRequests);

    if (!FbepEnterOperation()) {
        return FbeRollback_ShuttingDown;
    }

    Tracker = FbepFindTracker(ProcessId);
    if (Tracker == NULL) {
        FbepLeaveOperation();
        return FbeRollback_NoBackupsFound;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[WkDefender/FBE] RANSOMWARE ROLLBACK: Restoring %ld files "
               "for PID=%lu (%lld bytes backed up)\n",
               Tracker->EntryCount,
               HandleToULong(ProcessId),
               Tracker->TotalBytesBackedUp);

    /* 回滚开始事件（SS BeEngineSubmitEvent(FileRollbackStarted)）：wkd 结果导向，
     * 开始事件由末尾 FbepSendRollbackResult 结果通知覆盖（agent 为回滚发起方，已知开始）。 */

    /* 两阶段回滚：锁内收集条目，锁外处理，防 FbeCommitProcess 并发 UAF */

    #define FBE_ROLLBACK_STACK_BATCH    64
    PFBE_BACKUP_ENTRY StackBatch[FBE_ROLLBACK_STACK_BATCH];
    PFBE_BACKUP_ENTRY *RollbackBatch = StackBatch;
    ULONG BatchCapacity = FBE_ROLLBACK_STACK_BATCH;
    ULONG ClaimedCount = 0;
    BOOLEAN UsedPoolAlloc = FALSE;

    if ((ULONG)Tracker->EntryCount > FBE_ROLLBACK_STACK_BATCH) {
        ULONG AllocCount = min((ULONG)Tracker->EntryCount, FBE_MAX_ENTRIES_PER_PROCESS);
        ULONG AllocSize = AllocCount * sizeof(PFBE_BACKUP_ENTRY);

        if (AllocSize <= 64 * 1024) {
            RollbackBatch = (PFBE_BACKUP_ENTRY *)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, AllocSize, WKD_FBE_ROLLBACK_POOL_TAG);
            if (RollbackBatch != NULL) {
                BatchCapacity = AllocCount;
                UsedPoolAlloc = TRUE;
            } else {
                RollbackBatch = StackBatch;
            }
        }
    }

    /* Phase 1：共享锁下反向遍历，CAS Valid→Pending 收集 */
    FltAcquirePushLockShared(&Tracker->Lock);

    for (ListEntry = Tracker->BackupEntries.Blink;
         ListEntry != &Tracker->BackupEntries && ClaimedCount < BatchCapacity;
         ListEntry = ListEntry->Blink) {

        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, ProcessLink);

        if (InterlockedCompareExchange(&Entry->State,
                                       FbeEntryState_Pending,
                                       FbeEntryState_Valid) == FbeEntryState_Valid) {
            RollbackBatch[ClaimedCount++] = Entry;
        }
    }

    FltReleasePushLock(&Tracker->Lock);

    /* Phase 2：无锁恢复 */
    for (ULONG i = 0; i < ClaimedCount; i++) {
        PFBE_BACKUP_ENTRY Entry = RollbackBatch[i];

        Status = FbepRestoreFileFromBackup(Entry);
        if (NT_SUCCESS(Status)) {
            InterlockedExchange(&Entry->State, FbeEntryState_RolledBack);
            Restored++;
            InterlockedIncrement64(&g_FbeState.Stats.RollbackFilesRestored);
            InterlockedAdd64(&g_FbeState.Stats.TotalBytesRolledBack,
                             Entry->BackupFileSize.QuadPart);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[WkDefender/FBE] Restored: %wZ (%lld bytes)\n",
                       &Entry->OriginalPath,
                       Entry->BackupFileSize.QuadPart);
        } else {
            InterlockedExchange(&Entry->State, FbeEntryState_Valid);
            Failed++;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[WkDefender/FBE] RESTORE FAILED: %wZ (0x%08X)\n",
                       &Entry->OriginalPath, Status);
        }
    }

    if (UsedPoolAlloc) {
        ExFreePoolWithTag(RollbackBatch, WKD_FBE_ROLLBACK_POOL_TAG);
    }

    if (FilesRestored != NULL) {
        *FilesRestored = Restored;
    }

    /* 回滚结果上送 agent（对齐 SS 回滚事件上报语义；结果反馈给 UI 消费） */
    {
        FBE_ROLLBACK_RESULT fbResult =
            (Restored > 0 && Failed == 0) ? FbeRollback_Success :
            (Restored > 0)                ? FbeRollback_PartialSuccess :
                                            FbeRollback_IOError;
        FbepSendRollbackResult(ProcessId, fbResult, Restored);
    }

    if (Restored > 0 && Failed == 0) {
        InterlockedIncrement64(&g_FbeState.Stats.RollbacksSucceeded);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WkDefender/FBE] ROLLBACK COMPLETE: %lu files restored for PID=%lu\n",
                   Restored, HandleToULong(ProcessId));
        FbepLeaveOperation();
        return FbeRollback_Success;
    } else if (Restored > 0 && Failed > 0) {
        InterlockedIncrement64(&g_FbeState.Stats.RollbacksFailed);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WkDefender/FBE] ROLLBACK PARTIAL: %lu restored, %lu failed for PID=%lu\n",
                   Restored, Failed, HandleToULong(ProcessId));
        FbepLeaveOperation();
        return FbeRollback_PartialSuccess;
    } else {
        InterlockedIncrement64(&g_FbeState.Stats.RollbacksFailed);
        FbepLeaveOperation();
        return FbeRollback_IOError;
    }
}

/*++
 *  FbeCommitProcess
 *    进程退出时丢弃备份（两阶段：锁内 CAS 收集 → 无锁释放）。
 *    Pending 条目不夺取（I/O 进行中归属发起者）。
 *    对齐 SS FbeCommitProcess。
 *--*/
_Use_decl_annotations_
VOID
FbeCommitProcess(
    _In_ HANDLE ProcessId
    )
{
    PFBE_PROCESS_TRACKER Tracker;
    LIST_ENTRY *ListEntry;
    LIST_ENTRY *NextEntry;
    ULONG BucketIndex;

    if (!FbepEnterOperation()) {
        return;
    }

    Tracker = FbepFindTracker(ProcessId);
    if (Tracker == NULL) {
        FbepLeaveOperation();
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[WkDefender/FBE] Committing (discarding) %ld backups for PID=%lu\n",
               InterlockedCompareExchange(&Tracker->EntryCount, 0, 0),
               HandleToULong(ProcessId));

    /* Phase 1：tracker 锁下 CAS Valid→RolledBack 收集；已 Evicted 条目不触碰 */
    LIST_ENTRY ClaimedHead;
    InitializeListHead(&ClaimedHead);

    FltAcquirePushLockExclusive(&Tracker->Lock);

    ListEntry = Tracker->BackupEntries.Flink;
    while (ListEntry != &Tracker->BackupEntries) {
        NextEntry = ListEntry->Flink;
        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, ProcessLink);

        LONG Prev = InterlockedCompareExchange(
            &Entry->State, FbeEntryState_RolledBack, FbeEntryState_Valid);

        if (Prev == FbeEntryState_Valid) {
            RemoveEntryList(&Entry->ProcessLink);
            InterlockedDecrement(&Tracker->EntryCount);
            InsertTailList(&ClaimedHead, &Entry->ProcessLink);
        }

        ListEntry = NextEntry;
    }

    FltReleasePushLock(&Tracker->Lock);

    /* Phase 2：无锁释放已夺取条目 */
    while (!IsListEmpty(&ClaimedHead)) {
        ListEntry = RemoveHeadList(&ClaimedHead);
        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, ProcessLink);

        BucketIndex = FbepComputeBucketIndex(Entry->ProcessId, &Entry->OriginalPath);
        FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);
        RemoveEntryList(&Entry->HashLink);
        InterlockedDecrement(&g_FbeState.Buckets[BucketIndex].Count);
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

        FltAcquirePushLockExclusive(&g_FbeState.LruLock);
        RemoveEntryList(&Entry->LruLink);
        FltReleasePushLock(&g_FbeState.LruLock);

        InterlockedDecrement(&g_FbeState.TotalEntryCount);

        if (Entry->BackupFileSize.QuadPart > 0) {
            InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage,
                             -Entry->BackupFileSize.QuadPart);
        }
        FbepDeleteBackupFile(&Entry->BackupPath);

        FbepFreeEntry(Entry);
    }

    /* tracker 无剩余条目（含驱逐所有权）则移除 */
    if (InterlockedCompareExchange(&Tracker->EntryCount, 0, 0) == 0) {
        ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
        FltAcquirePushLockExclusive(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

        FltAcquirePushLockShared(&Tracker->Lock);
        BOOLEAN Empty = IsListEmpty(&Tracker->BackupEntries);
        FltReleasePushLock(&Tracker->Lock);

        if (Empty) {
            RemoveEntryList(&Tracker->Link);
            InterlockedDecrement(&g_FbeState.ProcessBuckets[ProcBucket].Count);
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            FbepFreeTracker(Tracker);
        } else {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
        }
    }

    FbepLeaveOperation();
}

/**************************************************/
/*                      查询操作（死代码）         */
/**************************************************/

/*++
 *  FbeGetStatistics
 *    获取统计快照。死代码：wkd 无查询流水线/UI 消费方，接口保留对齐 SS。
 *--*/
_Use_decl_annotations_
VOID
FbeGetStatistics(
    _Out_ PFBE_STATISTICS Statistics
    )
{
    RtlZeroMemory(Statistics, sizeof(FBE_STATISTICS));

    if (!FbepEnterOperation()) {
        return;
    }

    Statistics->TotalBackupRequests        = InterlockedCompareExchange64(&g_FbeState.Stats.TotalBackupRequests, 0, 0);
    Statistics->BackupsCreated             = InterlockedCompareExchange64(&g_FbeState.Stats.BackupsCreated, 0, 0);
    Statistics->BackupsSkippedDuplicate    = InterlockedCompareExchange64(&g_FbeState.Stats.BackupsSkippedDuplicate, 0, 0);
    Statistics->BackupsSkippedSize         = InterlockedCompareExchange64(&g_FbeState.Stats.BackupsSkippedSize, 0, 0);
    Statistics->BackupsSkippedExtension    = InterlockedCompareExchange64(&g_FbeState.Stats.BackupsSkippedExtension, 0, 0);
    Statistics->BackupsFailed              = InterlockedCompareExchange64(&g_FbeState.Stats.BackupsFailed, 0, 0);
    Statistics->TotalBytesBackedUp         = InterlockedCompareExchange64(&g_FbeState.Stats.TotalBytesBackedUp, 0, 0);
    Statistics->TotalBytesRolledBack       = InterlockedCompareExchange64(&g_FbeState.Stats.TotalBytesRolledBack, 0, 0);
    Statistics->RollbackRequests           = InterlockedCompareExchange64(&g_FbeState.Stats.RollbackRequests, 0, 0);
    Statistics->RollbacksSucceeded         = InterlockedCompareExchange64(&g_FbeState.Stats.RollbacksSucceeded, 0, 0);
    Statistics->RollbacksFailed            = InterlockedCompareExchange64(&g_FbeState.Stats.RollbacksFailed, 0, 0);
    Statistics->RollbackFilesRestored      = InterlockedCompareExchange64(&g_FbeState.Stats.RollbackFilesRestored, 0, 0);
    Statistics->EntriesEvicted             = InterlockedCompareExchange64(&g_FbeState.Stats.EntriesEvicted, 0, 0);
    Statistics->CurrentBackupDiskUsage     = InterlockedCompareExchange64(&g_FbeState.Stats.CurrentBackupDiskUsage, 0, 0);
    Statistics->PeakBackupDiskUsage        = InterlockedCompareExchange64(&g_FbeState.Stats.PeakBackupDiskUsage, 0, 0);

    FbepLeaveOperation();
}

/*++
 *  FbeHasBackups
 *    检查进程是否有待处理备份。死代码：同 FbeGetStatistics。
 *--*/
_Use_decl_annotations_
BOOLEAN
FbeHasBackups(
    _In_ HANDLE ProcessId
    )
{
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    BOOLEAN Found = FALSE;

    if (!FbepEnterOperation()) {
        return FALSE;
    }

    FltAcquirePushLockShared(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    LIST_ENTRY *ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
    while (ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head) {
        PFBE_PROCESS_TRACKER Tracker = CONTAINING_RECORD(
            ListEntry, FBE_PROCESS_TRACKER, Link);
        if (Tracker->ProcessId == ProcessId &&
            InterlockedCompareExchange(&Tracker->EntryCount, 0, 0) > 0) {
            Found = TRUE;
            break;
        }
        ListEntry = ListEntry->Flink;
    }

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
    FbepLeaveOperation();
    return Found;
}

