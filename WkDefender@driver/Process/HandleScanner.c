/**************************************************/
/*  WkDefender — 句柄扫描引擎实现                    */
/*  参考 PhantomSensor HandleTracker.c               */
/*                                                   */
/*  安全注意事项：                                    */
/*    - 全程不访问未引用的 Object 指针                 */
/*    - 句柄类型查询通过 ZwDuplicateObject +           */
/*      ZwQueryObject 安全完成                        */
/*    - 目标 PID 通过 ZwQueryInformationProcess/Thread */
/*    - 所有分配使用 POOL_FLAG_NON_PAGED               */
/*    - 所有用户指针在返回前已释放                      */
/**************************************************/

#include "HandleScanner.h"

// ============================================================================
// 前向声明（Zw* APIs Nt* 版 — 内核态可用）
// ============================================================================

NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateObject(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

// ============================================================================
// 私有常量
// ============================================================================

//
// 可疑访问组合
//
#define HS_PROCESS_INJECTION_ACCESS  (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)
#define HS_PROCESS_DUMP_ACCESS       (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
#define HS_TOKEN_STEAL_ACCESS        (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)
#define HS_THREAD_HIJACK_ACCESS      (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)

//
// ZwQuerySystemInformation info class
//
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

//
// ZwQueryObject info class
//
#ifndef ObjectTypeInformation
#define ObjectTypeInformation 2
#endif

//
// 缓冲区限制
//
#define HS_INITIAL_BUFFER_SIZE      0x100000    // 1MB
#define HS_MAX_BUFFER_SIZE          0x4000000   // 64MB

// ============================================================================
// 系统结构定义（WDK 未导出）
// ============================================================================

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID    Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG    GrantedAccess;
    USHORT   CreatorBackTraceIndex;
    USHORT   ObjectTypeIndex;
    ULONG    HandleAttributes;
    ULONG    Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID    TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// ============================================================================
// 内部辅助函数
// ============================================================================

/*++
    从完整路径提取文件名（最后一段）
--*/
static
VOID
HspExtractFileName(
    _In_  PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING  FileName
    )
{
    USHORT i;
    USHORT lastSlash = 0;

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        FileName->Buffer = NULL;
        FileName->Length = 0;
        FileName->MaximumLength = 0;
        return;
    }

    for (i = 0; i < FullPath->Length / sizeof(WCHAR); i++) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            lastSlash = i + 1;
        }
    }

    if (lastSlash >= FullPath->Length / sizeof(WCHAR)) {
        FileName->Buffer = FullPath->Buffer;
        FileName->Length = FullPath->Length;
        FileName->MaximumLength = FullPath->Length;
        return;
    }

    FileName->Buffer = &FullPath->Buffer[lastSlash];
    FileName->Length = FullPath->Length - (lastSlash * sizeof(WCHAR));
    FileName->MaximumLength = FileName->Length;
}

/*++
    检查进程名是否为敏感进程（对齐 PS HtpIsSensitiveProcessByName）

    敏感进程列表（对齐 PS HtpInitializeSensitiveProcessList）：
        lsass.exe, csrss.exe, smss.exe, wininit.exe,
        winlogon.exe, services.exe, svchost.exe, spoolsv.exe,
        lsm.exe, conhost.exe, dwm.exe
--*/
static
BOOLEAN
HspIsSensitiveProcessName(
    _In_ PCUNICODE_STRING ImageName
    )
{
    static const PCWSTR sensitiveNames[] = {
        L"lsass.exe",
        L"csrss.exe",
        L"smss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"services.exe",
        L"spoolsv.exe",
        L"lsm.exe",
        L"conhost.exe",
        L"dwm.exe",
        /* ---- 补全（对齐 SS HtpInitializeSensitiveProcessList 16 条，2026-08）---- */
        L"svchost.exe",             /* 高误报：svchost 是系统高频进程，跨进程持有其句柄需结合上下文，标注可配置 */
        L"taskmgr.exe",
        L"SecurityHealthService.exe",
        L"MsMpEng.exe",
        L"MsSense.exe",
        L"WkDefender@agent.exe",    /* wkd 自身 agent（对齐 SS PhantomSensor.exe，按实际发布镜像名调整） */
    };

    UNICODE_STRING fileName;
    ULONG i;

    HspExtractFileName(ImageName, &fileName);
    if (fileName.Buffer == NULL || fileName.Length == 0) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(sensitiveNames); i++) {
        UNICODE_STRING compareUS;
        RtlInitUnicodeString(&compareUS, sensitiveNames[i]);

        if (RtlEqualUnicodeString(&fileName, &compareUS, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

/*++
    根据句柄类型和访问掩码判断是否为高权限访问
--*/
static
BOOLEAN
HspIsHighPrivilegeAccess(
    _In_ HS_HANDLE_TYPE Type,
    _In_ ACCESS_MASK    Access
    )
{
    switch (Type) {
    case HsTypeProcess:
        if ((Access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) return TRUE;
        if (Access & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION)) return TRUE;
        break;

    case HsTypeThread:
        if ((Access & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS) return TRUE;
        if (Access & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT)) return TRUE;
        break;

    case HsTypeToken:
        if (Access & (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY)) return TRUE;
        break;

    case HsTypeSection:
        if (Access & (SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)) return TRUE;
        break;

    default:
        break;
    }

    return FALSE;
}

/*++
    判断是否为具备注入能力的访问组合
--*/
static
BOOLEAN
HspIsInjectionCapableAccess(
    _In_ ACCESS_MASK Access
    )
{
    if ((Access & HS_PROCESS_INJECTION_ACCESS) == HS_PROCESS_INJECTION_ACCESS) {
        return TRUE;
    }
    if ((Access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) {
        return TRUE;
    }
    return FALSE;
}

/*++
    计算怀疑评分（对齐 PS HtpCalculateSuspicionScore）
--*/
static
ULONG
HspCalculateScore(
    _In_ HS_SUSPICION Flags
    )
{
    ULONG score = 0;

    if (Flags & HsSuspicion_CrossProcess)     score += 15;
    if (Flags & HsSuspicion_HighPrivilege)    score += 20;
    if (Flags & HsSuspicion_DuplicatedIn)     score += 15;   /* 对齐 SS HtpCalculateSuspicionScore（SS 枚举未置位，死逻辑标注） */
    if (Flags & HsSuspicion_SensitiveTarget)  score += 35;
    if (Flags & HsSuspicion_ManyHandles)      score += 10;
    if (Flags & HsSuspicion_InjectionCapable) score += 25;
    if (Flags & HsSuspicion_TokenSteal)       score += 30;
    if (Flags & HsSuspicion_CredentialAccess) score += 40;
    if (Flags & HsSuspicion_SystemProcess)    score += 5;

    if (score > 100) score = 100;
    return score;
}

/*++
    通过 ZwQueryObject 查询句柄类型名并映射到 HS_HANDLE_TYPE
--*/
static
HS_HANDLE_TYPE
HspGetHandleType(
    _In_ HANDLE DuplicatedHandle
    )
{
    NTSTATUS status;
    PVOID typeInfo = NULL;
    ULONG typeInfoSize = sizeof(OBJECT_TYPE_INFORMATION) + 256;
    ULONG returnLength;
    HS_HANDLE_TYPE type = HsTypeUnknown;

    /* 类型名→HS_HANDLE_TYPE 映射表（对齐 PS HtpGetHandleTypeFromName） */
    static const struct {
        PCWSTR        Name;
        USHORT        Length;    /* 字节数 */
        HS_HANDLE_TYPE Type;
    } typeMap[] = {
        { L"Process",   14, HsTypeProcess },
        { L"Thread",    12, HsTypeThread },
        { L"File",       8, HsTypeFile },
        { L"Key",        6, HsTypeKey },
        { L"Section",   14, HsTypeSection },
        { L"Token",     10, HsTypeToken },
        { L"Event",     10, HsTypeEvent },
        { L"Semaphore", 18, HsTypeSemaphore },
        { L"Mutant",    12, HsTypeMutex },
        { L"Timer",     10, HsTypeTimer },
        { L"ALPC Port", 18, HsTypePort },
        { L"Device",    12, HsTypeDevice },
        { L"Driver",    12, HsTypeDriver },
    };

    typeInfo = ExAllocatePool2(POOL_FLAG_NON_PAGED, typeInfoSize, HS_POOL_TAG_BUFFER);
    if (typeInfo == NULL) {
        return HsTypeUnknown;
    }

    status = ZwQueryObject(
        DuplicatedHandle,
        ObjectTypeInformation,
        typeInfo,
        typeInfoSize,
        &returnLength
        );

    if (NT_SUCCESS(status)) {
        POBJECT_TYPE_INFORMATION objInfo = (POBJECT_TYPE_INFORMATION)typeInfo;

        if (objInfo->TypeName.Buffer != NULL) {
            ULONG i;

            for (i = 0; i < RTL_NUMBER_OF(typeMap); i++) {
                UNICODE_STRING compareUS;
                compareUS.Buffer = (PWCH)typeMap[i].Name;
                compareUS.Length = typeMap[i].Length;
                compareUS.MaximumLength = typeMap[i].Length + sizeof(WCHAR);

                if (RtlEqualUnicodeString(&objInfo->TypeName, &compareUS, TRUE)) {
                    type = typeMap[i].Type;
                    break;
                }
            }
        }
    }

    ExFreePoolWithTag(typeInfo, HS_POOL_TAG_BUFFER);
    return type;
}

/*++
    分析单条句柄的怀疑标记（对齐 PS HtpAnalyzeHandleSuspicion）
--*/
static
HS_SUSPICION
HspAnalyzeHandleSuspicion(
    _In_ HANDLE           OwnerProcessId,
    _In_ PHS_HANDLE_ENTRY Entry,
    _In_ BOOLEAN          EnableSensitiveDetection
    )
{
    HS_SUSPICION flags = HsSuspicion_None;

    /* 跨进程句柄 */
    if (Entry->TargetProcessId != NULL &&
        Entry->TargetProcessId != OwnerProcessId) {
        flags |= HsSuspicion_CrossProcess;

        /* 敏感目标（需做进程名查询——较贵，仅 PASSIVE_LEVEL 且启用时） */
        if (EnableSensitiveDetection) {
            BOOLEAN isSensitive = FALSE;
            if (NT_SUCCESS(HsIsSensitiveProcess(Entry->TargetProcessId, &isSensitive)) &&
                isSensitive) {
                flags |= HsSuspicion_SensitiveTarget;

                /* 凭证访问：Process + VM_READ|QUERY_INFORMATION → LSASS dump */
                if (Entry->Type == HsTypeProcess &&
                    (Entry->GrantedAccess & HS_PROCESS_DUMP_ACCESS) == HS_PROCESS_DUMP_ACCESS) {
                    flags |= HsSuspicion_CredentialAccess;
                }
            }
        }
    }

    /* 高权限 */
    if (HspIsHighPrivilegeAccess(Entry->Type, Entry->GrantedAccess)) {
        flags |= HsSuspicion_HighPrivilege;
    }

    /* 注入能力 */
    if (Entry->Type == HsTypeProcess &&
        HspIsInjectionCapableAccess(Entry->GrantedAccess)) {
        flags |= HsSuspicion_InjectionCapable;
    }

    /* 令牌窃取 */
    if (Entry->Type == HsTypeToken &&
        (Entry->GrantedAccess & HS_TOKEN_STEAL_ACCESS) == HS_TOKEN_STEAL_ACCESS) {
        flags |= HsSuspicion_TokenSteal;
    }

    /* System 进程 */
    if (OwnerProcessId == (HANDLE)(ULONG_PTR)4) {
        flags |= HsSuspicion_SystemProcess;
    }

    /* 复制流入句柄（对齐 SS HtpAnalyzeHandleSuspicion；SS 枚举路径未置 IsDuplicated，死逻辑标注） */
    if (Entry->IsDuplicated) {
        flags |= HsSuspicion_DuplicatedIn;
    }

    return flags;
}

//
// 获取默认配置
//
static
VOID
HspGetDefaultConfig(
    _Out_ PHS_CONFIG Config
    )
{
    Config->MaxHandlesPerProcess = HS_DEFAULT_MAX_HANDLES;
    Config->MaxCrossProcessResults = HS_DEFAULT_MAX_CROSS_PROCESS;
    Config->EnableCrossProcessDetection = TRUE;
    Config->EnableTokenStealDetection = TRUE;
    Config->EnableSensitiveProcessDetection = TRUE;
    /* ---- 补充字段默认值（对齐 SS HT_CONFIG，2026-08）---- */
    Config->EnableDuplicationTracking = TRUE;
    Config->SuspicionThreshold = 50;
    Config->MaxDuplications = HS_MAX_DUPLICATIONS;
    Config->CleanupIntervalMs = HS_DEFAULT_CLEANUP_INTERVAL_MS;
    Config->CacheTimeoutMs = HS_DEFAULT_CACHE_TIMEOUT_MS;
}

// ============================================================================
// 公共 API 实现
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HsScanProcessHandles(
    PHS_CONFIG            Config,
    HANDLE                ProcessId,
    PHS_PROCESS_HANDLE_RESULT Result
    )
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = HS_INITIAL_BUFFER_SIZE;
    ULONG returnLength = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG_PTR i;
    PEPROCESS targetProcess = NULL;
    HANDLE targetProcessHandle = NULL;
    HS_CONFIG localConfig;
    ULONG entryIndex = 0;

    PAGED_CODE();

    /* 参数验证 */
    if (Result == NULL || Result->Handles == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config == NULL) {
        HspGetDefaultConfig(&localConfig);
        Config = &localConfig;
    }

    /* 确保目标进程存在并获取句柄 */
    status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    status = ObOpenObjectByPointer(
        targetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &targetProcessHandle
        );

    ObDereferenceObject(targetProcess);
    targetProcess = NULL;

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 分配缓冲区 — 循环直到大小足够 */
    do {
        if (buffer != NULL) {
            ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
            buffer = NULL;
        }

        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, HS_POOL_TAG_BUFFER);
        if (buffer == NULL) {
            ZwClose(targetProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer,
            bufferSize,
            &returnLength
            );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 0x10000;
            if (bufferSize > HS_MAX_BUFFER_SIZE) {
                ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
                ZwClose(targetProcessHandle);
                return STATUS_BUFFER_OVERFLOW;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
        ZwClose(targetProcessHandle);
        return status;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;

    /* 清空聚合结果 */
    Result->CrossProcessCount = 0;
    Result->InjectionCapableCount = 0;
    Result->TokenStealCount = 0;
    Result->CredentialAccessCount = 0;
    Result->HighPrivilegeCount = 0;
    Result->AggregatedFlags = HsSuspicion_None;
    Result->SuspicionScore = 0;
    Result->HandleCount = 0;

    /* 遍历句柄表 */
    for (i = 0; i < handleInfo->NumberOfHandles && entryIndex < Result->MaxHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysEntry = &handleInfo->Handles[i];

        /* 只处理目标进程的句柄 */
        if ((HANDLE)(ULONG_PTR)sysEntry->UniqueProcessId != ProcessId) {
            continue;
        }

        PHS_HANDLE_ENTRY entry = &Result->Handles[entryIndex];

        /* 填充基础信息（不访问 Object 指针——安全问题） */
        entry->HandleValue = (HANDLE)sysEntry->HandleValue;
        entry->GrantedAccess = sysEntry->GrantedAccess;
        entry->OwnerProcessId = ProcessId;
        entry->TargetProcessId = NULL;
        entry->Type = HsTypeUnknown;
        entry->SuspicionFlags = HsSuspicion_None;
        entry->SuspicionScore = 0;
        /* ---- 补充字段初始化（对齐 SS HT_HANDLE_ENTRY，2026-08）---- */
        entry->IsDuplicated = FALSE;
        entry->DuplicatedFromProcess = NULL;
        entry->ObjectNameLength = 0;
        RtlZeroMemory(entry->ObjectName, sizeof(entry->ObjectName));

        //
        // 安全复制句柄后查询类型和目标 PID
        //
        {
            HANDLE duplicatedHandle = NULL;

            status = ZwDuplicateObject(
                targetProcessHandle,
                (HANDLE)sysEntry->HandleValue,
                ZwCurrentProcess(),
                &duplicatedHandle,
                0,               /* 不需要额外权限 */
                0,
                DUPLICATE_SAME_ACCESS
                );

            if (NT_SUCCESS(status) && duplicatedHandle != NULL) {
                /* 查询句柄类型 */
                entry->Type = HspGetHandleType(duplicatedHandle);

                /* 对 Process/Thread 句柄查询目标 PID */
                if (entry->Type == HsTypeProcess) {
                    PROCESS_BASIC_INFORMATION basicInfo;
                    ULONG retLen;

                    status = ZwQueryInformationProcess(
                        duplicatedHandle,
                        ProcessBasicInformation,
                        &basicInfo,
                        sizeof(basicInfo),
                        &retLen
                        );

                    if (NT_SUCCESS(status)) {
                        entry->TargetProcessId = (HANDLE)basicInfo.UniqueProcessId;
                    }
                } else if (entry->Type == HsTypeThread) {
                    THREAD_BASIC_INFORMATION threadInfo;
                    ULONG retLen;

                    status = ZwQueryInformationThread(
                        duplicatedHandle,
                        ThreadBasicInformation,
                        &threadInfo,
                        sizeof(threadInfo),
                        &retLen
                        );

                    if (NT_SUCCESS(status)) {
                        entry->TargetProcessId = threadInfo.ClientId.UniqueProcess;
                    }
                }

                ZwClose(duplicatedHandle);
            }
        }

        /* 分析怀疑 */
        entry->SuspicionFlags = HspAnalyzeHandleSuspicion(
            ProcessId,
            entry,
            Config->EnableSensitiveProcessDetection
            );
        entry->SuspicionScore = HspCalculateScore(entry->SuspicionFlags);

        /* 更新计数器 */
        if (entry->SuspicionFlags & HsSuspicion_CrossProcess) {
            Result->CrossProcessCount++;
        }
        if (entry->SuspicionFlags & HsSuspicion_InjectionCapable) {
            Result->InjectionCapableCount++;
        }
        if (entry->SuspicionFlags & HsSuspicion_TokenSteal) {
            Result->TokenStealCount++;
        }
        if (entry->SuspicionFlags & HsSuspicion_CredentialAccess) {
            Result->CredentialAccessCount++;
        }
        if (entry->SuspicionFlags & HsSuspicion_HighPrivilege) {
            Result->HighPrivilegeCount++;
        }

        Result->AggregatedFlags |= entry->SuspicionFlags;
        entryIndex++;
    }

    Result->HandleCount = entryIndex;

    /* 句柄过多标志 */
    if (entryIndex > Config->MaxHandlesPerProcess / 2) {
        Result->AggregatedFlags |= HsSuspicion_ManyHandles;
    }

    /* 计算聚合评分 */
    Result->SuspicionScore = HspCalculateScore(Result->AggregatedFlags);

    ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
    ZwClose(targetProcessHandle);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HsFindCrossProcessHandles(
    PHS_CONFIG              Config,
    HANDLE                  TargetProcessId,
    PHS_CROSS_PROCESS_RESULT Results,
    ULONG                   MaxResults,
    PULONG                  ResultCount
    )
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = HS_INITIAL_BUFFER_SIZE;
    ULONG returnLength = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG_PTR i;
    ULONG foundCount = 0;
    HS_CONFIG localConfig;
    HANDLE targetProcessHandle = NULL;
    PEPROCESS targetProcess = NULL;
    BOOLEAN enableSensitive;

    PAGED_CODE();

    if (Results == NULL || ResultCount == NULL || MaxResults == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ResultCount = 0;

    if (Config == NULL) {
        HspGetDefaultConfig(&localConfig);
        Config = &localConfig;
    }

    enableSensitive = Config->EnableSensitiveProcessDetection;

    /* 获取目标进程句柄用于后续句柄复制 */
    status = PsLookupProcessByProcessId(TargetProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    status = ObOpenObjectByPointer(
        targetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &targetProcessHandle
        );

    ObDereferenceObject(targetProcess);
    targetProcess = NULL;

    if (!NT_SUCCESS(status)) {
        /* 即使无法打开目标进程句柄，仍然可以扫描系统句柄表
         * 只是无法做 ZwDuplicateObject 验证。这种情况下只做
         * ObjectTypeIndex 过滤，不查具体类型。
         */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] HsFindCrossProcessHandles: cannot open target PID %p, "
            "proceeding without duplicate verification (type accuracy reduced)\n",
            TargetProcessId);
    }

    /* 枚举全系统句柄 */
    do {
        if (buffer != NULL) {
            ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
            buffer = NULL;
        }

        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, HS_POOL_TAG_BUFFER);
        if (buffer == NULL) {
            if (targetProcessHandle) ZwClose(targetProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer,
            bufferSize,
            &returnLength
            );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 0x10000;
            if (bufferSize > HS_MAX_BUFFER_SIZE) {
                ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
                if (targetProcessHandle) ZwClose(targetProcessHandle);
                return STATUS_BUFFER_OVERFLOW;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
        if (targetProcessHandle) ZwClose(targetProcessHandle);
        return status;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;

    /*
     * 遍历全系统句柄，查找指向目标进程的句柄
     * 注意：不能直接通过 Object 指针判断（不安全），必须通过
     * ZwDuplicateObject + ZwQueryInformationProcess 确认。
     */
    for (i = 0; i < handleInfo->NumberOfHandles && foundCount < MaxResults; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysEntry = &handleInfo->Handles[i];
        HANDLE ownerPid = (HANDLE)(ULONG_PTR)sysEntry->UniqueProcessId;

        /* 跳过自己 */
        if (ownerPid == TargetProcessId) {
            continue;
        }

        {
            HANDLE duplicatedHandle = NULL;
            HS_HANDLE_TYPE hType;

            /* 打开持有者进程句柄，从中复制目标句柄来查询目标 PID。
             * （修正 2026-08：删除旧版"用 target 进程句柄复制 owner 句柄"的错误语义
             *   ——句柄属于 owner，必须用 owner 的进程句柄复制；对齐 SS
             *   HtFindCrossProcessHandles。此步可能失败（权限不足），跳过即可。） */
            {
                HANDLE ownerProcessHandle = NULL;
                PEPROCESS ownerProcess = NULL;

                status = PsLookupProcessByProcessId(ownerPid, &ownerProcess);
                if (!NT_SUCCESS(status)) continue;

                status = ObOpenObjectByPointer(
                    ownerProcess,
                    OBJ_KERNEL_HANDLE,
                    NULL,
                    PROCESS_DUP_HANDLE,
                    *PsProcessType,
                    KernelMode,
                    &ownerProcessHandle
                    );

                ObDereferenceObject(ownerProcess);

                if (!NT_SUCCESS(status) || ownerProcessHandle == NULL) {
                    continue;
                }

                /* 从 owner 进程中复制句柄 */
                status = ZwDuplicateObject(
                    ownerProcessHandle,
                    (HANDLE)sysEntry->HandleValue,
                    ZwCurrentProcess(),
                    &duplicatedHandle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS
                    );

                ZwClose(ownerProcessHandle);

                if (!NT_SUCCESS(status) || duplicatedHandle == NULL) {
                    continue;
                }

                /* 查询句柄类型（对齐 SS：类型过滤在复制成功后执行） */
                hType = HspGetHandleType(duplicatedHandle);
                if (hType != HsTypeProcess && hType != HsTypeThread) {
                    ZwClose(duplicatedHandle);
                    continue;
                }

                /* 查询目标 PID */
                HANDLE targetPid = NULL;
                if (hType == HsTypeProcess) {
                    PROCESS_BASIC_INFORMATION basicInfo;
                    ULONG retLen;

                    status = ZwQueryInformationProcess(
                        duplicatedHandle,
                        ProcessBasicInformation,
                        &basicInfo,
                        sizeof(basicInfo),
                        &retLen
                        );

                    if (NT_SUCCESS(status)) {
                        targetPid = (HANDLE)basicInfo.UniqueProcessId;
                    }
                } else { /* HsTypeThread */
                    THREAD_BASIC_INFORMATION threadInfo;
                    ULONG retLen;

                    status = ZwQueryInformationThread(
                        duplicatedHandle,
                        ThreadBasicInformation,
                        &threadInfo,
                        sizeof(threadInfo),
                        &retLen
                    );

                    if (NT_SUCCESS(status)) {
                        targetPid = threadInfo.ClientId.UniqueProcess;
                    }
                }

                ZwClose(duplicatedHandle);

                /* 确认指向目标进程 */
                if (targetPid != TargetProcessId) {
                    continue;
                }

                /* 命中！填充结果 */
                PHS_CROSS_PROCESS_RESULT result = &Results[foundCount];

                result->SourceProcessId = ownerPid;
                result->HandleValue = (HANDLE)sysEntry->HandleValue;
                result->Type = hType;
                result->GrantedAccess = sysEntry->GrantedAccess;
                result->SuspicionFlags = HsSuspicion_CrossProcess;

                /* 注入/令牌/凭证检测 */
                if (hType == HsTypeProcess) {
                    if (HspIsInjectionCapableAccess(sysEntry->GrantedAccess)) {
                        result->SuspicionFlags |= HsSuspicion_InjectionCapable;
                    }
                    if ((sysEntry->GrantedAccess & HS_PROCESS_DUMP_ACCESS) == HS_PROCESS_DUMP_ACCESS &&
                        enableSensitive) {
                        result->SuspicionFlags |= HsSuspicion_CredentialAccess;
                    }
                }

                if (enableSensitive) {
                    result->SuspicionFlags |= HsSuspicion_SensitiveTarget;
                }

                result->SuspicionScore = HspCalculateScore(result->SuspicionFlags);
                foundCount++;
            }
        }
    }

    *ResultCount = foundCount;

    ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
    if (targetProcessHandle) ZwClose(targetProcessHandle);

    if (foundCount == MaxResults) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HsIsSensitiveProcess(
    HANDLE   ProcessId,
    PBOOLEAN IsSensitive
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    PAGED_CODE();

    if (IsSensitive == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSensitive = FALSE;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {
        *IsSensitive = HspIsSensitiveProcessName(imageName);
        ExFreePool(imageName);
    }

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/**************************************************/
/*  死代码分区：复制追踪 / 缓存层 / 统计 / 查询 /   */
/*  创建时快照分析                                  */
/*                                                   */
/*  对齐 SS Callbacks/Process/HandleTracker.{c,h}    */
/*  迁移 2026-08。功能面覆盖但未接入流水线，各函数    */
/*  注释给出接入点与不接入原因。                     */
/**************************************************/

/* WKD_PROCESS + WKD_BEHAVIOR_HANDLE_*（创建时快照映射用） */
#include "ProcessMonitor.h"

//
// 缓存条目：活代码扫描输出结构 + 链表链接（缓存层专用）
// 对齐 SS HT_HANDLE_ENTRY（内含 ListEntry）；wkd 活代码 HS_HANDLE_ENTRY
// 为扫描输出结构，链表化由本包裹结构完成（重功能实现非复制）。
//
typedef struct _HS_CACHED_HANDLE {
    LIST_ENTRY      ListEntry;
    HS_HANDLE_ENTRY Entry;
} HS_CACHED_HANDLE, *PHS_CACHED_HANDLE;

/* 死代码分区前向声明：HspDereferenceProcessHandles 定义在 HspFreeAllHandleEntries 之前，
 * 需前向声明避免 C4013 隐含函数声明（对齐 SS HandleTracker.c 的前向声明块风格）。 */
static
VOID
HspFreeAllHandleEntries(
    _In_ PHS_TRACKER Tracker,
    _Inout_ PHS_PROCESS_HANDLES Handles
    );

/*++
    PID 哈希 — MurmurHash3 finalizer（对齐 SS HtpHashProcessId L1638）
    死代码库函数：缓存层未接入（HspInsert/RemoveProcessHandles 无调用者），
    非 static 规避 C4505。
--*/
_Use_decl_annotations_
ULONG
HspHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR value = (ULONG_PTR)ProcessId;

    value ^= (value >> 16);
    value *= 0x85ebca6b;
    value ^= (value >> 13);
    value *= 0xc2b2ae35;
    value ^= (value >> 16);

    return (ULONG)(value & HS_HASH_BUCKET_MASK);
}

/*++
    从 lookaside 分配缓存句柄条目（对齐 SS HtpAllocateHandleEntry L1682）
    死代码库函数：缓存枚举链未接入（见 HspEnumerateProcessHandles），非 static 规避 C4505。
--*/
_Use_decl_annotations_
PHS_CACHED_HANDLE
HspAllocateHandleEntry(
    _In_ PHS_TRACKER Tracker
    )
{
    PHS_CACHED_HANDLE entry;

    entry = (PHS_CACHED_HANDLE)ExAllocateFromNPagedLookasideList(
        &Tracker->HandleEntryLookaside);
    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(HS_CACHED_HANDLE));
        InitializeListHead(&entry->ListEntry);
    }

    return entry;
}

static
VOID
HspFreeHandleEntry(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_CACHED_HANDLE Entry
    )
{
    ExFreeToNPagedLookasideList(&Tracker->HandleEntryLookaside, Entry);
}

/*++
    分配进程句柄快照（含 PEPROCESS 引用，对齐 SS HtpAllocateProcessHandles L1710）
    死代码库函数：缓存枚举链未接入（对应 SS HtSnapshotHandles 分配步骤），非 static 规避 C4505。
--*/
_Use_decl_annotations_
PHS_PROCESS_HANDLES
HspAllocateProcessHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
{
    PHS_PROCESS_HANDLES handles;
    NTSTATUS status;

    handles = (PHS_PROCESS_HANDLES)ExAllocateFromNPagedLookasideList(
        &Tracker->ProcessHandlesLookaside);
    if (handles != NULL) {
        RtlZeroMemory(handles, sizeof(HS_PROCESS_HANDLES));
        handles->Signature = HS_SIGNATURE;
        handles->RefCount = 1;
        handles->ProcessId = ProcessId;
        InitializeListHead(&handles->HandleList);
        ExInitializePushLock(&handles->Lock);
        InitializeListHead(&handles->HashEntry);
        InitializeListHead(&handles->GlobalEntry);

        /* 进程对象引用（生命周期管理，对齐 SS） */
        status = PsLookupProcessByProcessId(ProcessId, &handles->ProcessObject);
        if (NT_SUCCESS(status)) {
            /* ProcessObject 已持有引用 */
        }

        KeQuerySystemTime(&handles->SnapshotTime);
    }

    return handles;
}

/*++
    引用计数递减，归零时释放全部句柄条目 + 进程对象引用（对齐 SS HtpDereferenceProcessHandles L1757）
    死代码库函数：缓存层未接入，非 static 规避 C4505。
--*/
_Use_decl_annotations_
VOID
HspDereferenceProcessHandles(
    _In_ PHS_TRACKER Tracker,
    _Inout_ PHS_PROCESS_HANDLES Handles
    )
{
    LONG newRefCount;

    newRefCount = InterlockedDecrement(&Handles->RefCount);

    if (newRefCount == 0) {
        /* 释放全部句柄条目 */
        HspFreeAllHandleEntries(Tracker, Handles);

        /* 释放进程对象引用 */
        if (Handles->ProcessObject != NULL) {
            ObDereferenceObject(Handles->ProcessObject);
            Handles->ProcessObject = NULL;
        }

        Handles->Signature = 0;
        ExFreeToNPagedLookasideList(&Tracker->ProcessHandlesLookaside, Handles);
    }
}

/*++
    释放快照的全部句柄条目（对齐 SS HtpFreeAllHandleEntries L1794）
--*/
static
VOID
HspFreeAllHandleEntries(
    _In_ PHS_TRACKER Tracker,
    _Inout_ PHS_PROCESS_HANDLES Handles
    )
{
    PLIST_ENTRY entry;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Handles->Lock);

    while (!IsListEmpty(&Handles->HandleList)) {
        entry = RemoveHeadList(&Handles->HandleList);

        ExReleasePushLockExclusive(&Handles->Lock);
        KeLeaveCriticalRegion();

        HspFreeHandleEntry(Tracker, CONTAINING_RECORD(entry, HS_CACHED_HANDLE, ListEntry));

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Handles->Lock);
    }

    ExReleasePushLockExclusive(&Handles->Lock);
    KeLeaveCriticalRegion();
}

/*++
    枚举并缓存指定进程的全部句柄（对齐 SS HtpEnumerateProcessHandles L2001-2274）
    死代码：缓存层未接入，无调用者（创建时快照走活代码 HsScanProcessHandles，
    见 HspAnalyzeNewProcessHandles）。非 static 规避 C4505。
--*/
_Use_decl_annotations_
NTSTATUS
HspEnumerateProcessHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Inout_ PHS_PROCESS_HANDLES Handles
    )
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = HS_INITIAL_BUFFER_SIZE;
    ULONG returnLength = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG_PTR i;
    PEPROCESS targetProcess = NULL;
    HANDLE targetProcessHandle = NULL;

    PAGED_CODE();

    /* 验证目标进程存在并打开句柄（对齐 SS L2023-2046） */
    status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    status = ObOpenObjectByPointer(
        targetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &targetProcessHandle
        );

    ObDereferenceObject(targetProcess);
    targetProcess = NULL;

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 枚举缓冲区循环增长（对齐 SS L2051-2090） */
    do {
        if (buffer != NULL) {
            ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
            buffer = NULL;
        }

        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, HS_POOL_TAG_BUFFER);
        if (buffer == NULL) {
            ZwClose(targetProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer,
            bufferSize,
            &returnLength
            );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 0x10000;
            if (bufferSize > HS_MAX_BUFFER_SIZE) {
                ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
                ZwClose(targetProcessHandle);
                return STATUS_BUFFER_OVERFLOW;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
        ZwClose(targetProcessHandle);
        return status;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;

    for (i = 0; i < handleInfo->NumberOfHandles &&
         (ULONG)Handles->HandleCount < Tracker->Config.MaxHandlesPerProcess; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysEntry = &handleInfo->Handles[i];
        PHS_CACHED_HANDLE cached;
        PHS_HANDLE_ENTRY entry;
        HANDLE duplicatedHandle = NULL;

        /* 过滤目标进程句柄 */
        if ((HANDLE)(ULONG_PTR)sysEntry->UniqueProcessId != ProcessId) {
            continue;
        }

        cached = HspAllocateHandleEntry(Tracker);
        if (cached == NULL) {
            continue;
        }
        entry = &cached->Entry;

        /* 填充基础信息（不访问 Object 指针——安全问题，对齐 SS L2120-2126） */
        entry->HandleValue = (HANDLE)sysEntry->HandleValue;
        entry->GrantedAccess = sysEntry->GrantedAccess;
        entry->OwnerProcessId = ProcessId;
        entry->Type = HsTypeUnknown;
        entry->IsDuplicated = FALSE;
        entry->DuplicatedFromProcess = NULL;
        entry->ObjectNameLength = 0;
        RtlZeroMemory(entry->ObjectName, sizeof(entry->ObjectName));

        /* 安全复制句柄后查询类型/目标 PID（对齐 SS L2128-2190） */
        status = ZwDuplicateObject(
            targetProcessHandle,
            (HANDLE)sysEntry->HandleValue,
            ZwCurrentProcess(),
            &duplicatedHandle,
            0,
            0,
            DUPLICATE_SAME_ACCESS
            );

        if (NT_SUCCESS(status) && duplicatedHandle != NULL) {
            entry->Type = HspGetHandleType(duplicatedHandle);

            if (entry->Type == HsTypeProcess) {
                PROCESS_BASIC_INFORMATION basicInfo;
                ULONG retLen;

                status = ZwQueryInformationProcess(
                    duplicatedHandle,
                    ProcessBasicInformation,
                    &basicInfo,
                    sizeof(basicInfo),
                    &retLen
                    );

                if (NT_SUCCESS(status)) {
                    entry->TargetProcessId = (HANDLE)basicInfo.UniqueProcessId;
                }
            } else if (entry->Type == HsTypeThread) {
                THREAD_BASIC_INFORMATION threadInfo;
                ULONG retLen;

                status = ZwQueryInformationThread(
                    duplicatedHandle,
                    ThreadBasicInformation,
                    &threadInfo,
                    sizeof(threadInfo),
                    &retLen
                    );

                if (NT_SUCCESS(status)) {
                    entry->TargetProcessId = threadInfo.ClientId.UniqueProcess;
                }
            }

            ZwClose(duplicatedHandle);
            duplicatedHandle = NULL;
        }

        /* 跨进程计数 */
        if (entry->TargetProcessId != NULL &&
            entry->TargetProcessId != ProcessId) {
            Handles->CrossProcessHandleCount++;
        }

        /* 怀疑分析 + 评分（对齐 SS L2203-2204） */
        entry->SuspicionFlags = HspAnalyzeHandleSuspicion(
            ProcessId, entry, Tracker->Config.EnableSensitiveProcessDetection);
        entry->SuspicionScore = HspCalculateScore(entry->SuspicionFlags);

        /* 类型统计（对齐 SS L2209-2238） */
        switch (entry->Type) {
        case HsTypeProcess:  Handles->ProcessHandleCount++; break;
        case HsTypeThread:   Handles->ThreadHandleCount++; break;
        case HsTypeFile:     Handles->FileHandleCount++; break;
        case HsTypeToken:
            Handles->TokenHandleCount++;
            InterlockedIncrement64(&Tracker->Stats.TokenHandlesTracked);
            break;
        case HsTypeSection:  Handles->SectionHandleCount++; break;
        default:             Handles->OtherHandleCount++; break;
        }

        if (entry->SuspicionFlags & HsSuspicion_HighPrivilege) {
            Handles->HighPrivilegeHandleCount++;
            InterlockedIncrement64(&Tracker->Stats.HighPrivilegeHandles);
        }
        if (entry->SuspicionFlags & HsSuspicion_InjectionCapable) {
            InterlockedIncrement64(&Tracker->Stats.InjectionHandlesDetected);
        }

        /* 插入链表 */
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Handles->Lock);
        InsertTailList(&Handles->HandleList, &cached->ListEntry);
        InterlockedIncrement(&Handles->HandleCount);
        ExReleasePushLockExclusive(&Handles->Lock);
        KeLeaveCriticalRegion();
    }

    /* 聚合怀疑（对齐 SS L2252-2268） */
    Handles->AggregatedSuspicion = HsSuspicion_None;

    if (Handles->CrossProcessHandleCount > 0) {
        Handles->AggregatedSuspicion |= HsSuspicion_CrossProcess;
    }
    if (Handles->HighPrivilegeHandleCount > 0) {
        Handles->AggregatedSuspicion |= HsSuspicion_HighPrivilege;
    }
    if ((ULONG)Handles->HandleCount > Tracker->Config.MaxHandlesPerProcess / 2) {
        Handles->AggregatedSuspicion |= HsSuspicion_ManyHandles;
    }

    Handles->SuspicionScore = HspCalculateScore(Handles->AggregatedSuspicion);

    /* 统计（对齐 SS L1132-1141） */
    InterlockedIncrement64(&Tracker->Stats.TotalEnumerations);
    InterlockedAdd64(&Tracker->Stats.HandlesTracked, Handles->HandleCount);
    if (Handles->CrossProcessHandleCount > 0) {
        InterlockedAdd64(&Tracker->Stats.CrossProcessHandles, Handles->CrossProcessHandleCount);
    }
    if (Handles->AggregatedSuspicion != HsSuspicion_None) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousHandles);
    }

    ExFreePoolWithTag(buffer, HS_POOL_TAG_BUFFER);
    ZwClose(targetProcessHandle);

    return STATUS_SUCCESS;
}

/*++
    插入快照到 hash 表 + 全局列表（含同 PID 旧快照淘汰，对齐 SS HtpInsertProcessHandles L1852-1949）
    死代码库函数：缓存层未接入（对应 SS HtSnapshotHandles/HtReleaseHandles 内部），非 static 规避 C4505。
--*/
_Use_decl_annotations_
NTSTATUS
HspInsertProcessHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_PROCESS_HANDLES Handles
    )
{
    ULONG hash;
    PLIST_ENTRY scanEntry;
    PHS_PROCESS_HANDLES existing;
    LIST_ENTRY evictedList;

    hash = HspHashProcessId(Handles->ProcessId);
    Handles->HashBucket = hash;
    InitializeListHead(&evictedList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->HashBuckets[hash].Lock);

    if (!Handles->InHashTable) {
        /* 淘汰同 PID 旧快照（防 NPAGED 池泄漏 + 桶遍历退化 O(n)，对齐 SS L1879-1901） */
        for (scanEntry = Tracker->HashBuckets[hash].ProcessList.Flink;
             scanEntry != &Tracker->HashBuckets[hash].ProcessList;
             /* advanced inside */) {
            existing = CONTAINING_RECORD(scanEntry, HS_PROCESS_HANDLES, HashEntry);
            scanEntry = scanEntry->Flink;

            if (existing->ProcessId == Handles->ProcessId &&
                existing != Handles &&
                existing->InHashTable) {
                RemoveEntryList(&existing->HashEntry);
                InitializeListHead(&existing->HashEntry);
                InterlockedDecrement(&Tracker->HashBuckets[hash].Count);
                existing->InHashTable = FALSE;
                /* 复用 HashEntry 作为临时淘汰链表链接 */
                InsertTailList(&evictedList, &existing->HashEntry);
            }
        }

        InsertTailList(&Tracker->HashBuckets[hash].ProcessList, &Handles->HashEntry);
        InterlockedIncrement(&Tracker->HashBuckets[hash].Count);
        Handles->InHashTable = TRUE;
        InterlockedIncrement(&Handles->RefCount);   /* hash 表引用 */

        ExReleasePushLockExclusive(&Tracker->HashBuckets[hash].Lock);
        KeLeaveCriticalRegion();

        /* 全局进程列表 */
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Tracker->ProcessListLock);
        InsertTailList(&Tracker->ProcessList, &Handles->GlobalEntry);
        InterlockedIncrement(&Tracker->ProcessCount);
        ExReleasePushLockExclusive(&Tracker->ProcessListLock);
        KeLeaveCriticalRegion();

        /* 锁外释放被淘汰快照（对齐 SS L1926-1942） */
        while (!IsListEmpty(&evictedList)) {
            PLIST_ENTRY evicted = RemoveHeadList(&evictedList);
            existing = CONTAINING_RECORD(evicted, HS_PROCESS_HANDLES, HashEntry);
            InitializeListHead(&existing->HashEntry);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Tracker->ProcessListLock);
            if (!IsListEmpty(&existing->GlobalEntry)) {
                RemoveEntryList(&existing->GlobalEntry);
                InitializeListHead(&existing->GlobalEntry);
                InterlockedDecrement(&Tracker->ProcessCount);
            }
            ExReleasePushLockExclusive(&Tracker->ProcessListLock);
            KeLeaveCriticalRegion();

            HspDereferenceProcessHandles(Tracker, existing);
        }
    } else {
        ExReleasePushLockExclusive(&Tracker->HashBuckets[hash].Lock);
        KeLeaveCriticalRegion();
    }

    return STATUS_SUCCESS;
}

/*++
    从 hash 表 + 全局列表移除快照（对齐 SS HtpRemoveProcessHandles L1951-1999）
    死代码库函数：缓存层未接入（对应 SS HtReleaseHandles 内部），非 static 规避 C4505。
--*/
_Use_decl_annotations_
VOID
HspRemoveProcessHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_PROCESS_HANDLES Handles
    )
{
    ULONG hash;
    BOOLEAN wasInHashTable = FALSE;

    if (!Handles->InHashTable) {
        return;
    }

    hash = Handles->HashBucket;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->HashBuckets[hash].Lock);

    if (Handles->InHashTable) {
        RemoveEntryList(&Handles->HashEntry);
        InitializeListHead(&Handles->HashEntry);
        InterlockedDecrement(&Tracker->HashBuckets[hash].Count);
        Handles->InHashTable = FALSE;
        wasInHashTable = TRUE;
    }

    ExReleasePushLockExclusive(&Tracker->HashBuckets[hash].Lock);
    KeLeaveCriticalRegion();

    /* 全局列表 */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ProcessListLock);
    if (!IsListEmpty(&Handles->GlobalEntry)) {
        RemoveEntryList(&Handles->GlobalEntry);
        InitializeListHead(&Handles->GlobalEntry);
        InterlockedDecrement(&Tracker->ProcessCount);
    }
    ExReleasePushLockExclusive(&Tracker->ProcessListLock);
    KeLeaveCriticalRegion();

    if (wasInHashTable) {
        HspDereferenceProcessHandles(Tracker, Handles);
    }
}

/*++
    清理超期复制记录（对齐 SS HtpCleanupStaleDuplications L2771-2816）
    死代码：复制追踪未接入（事件源=Ob 回调 DUPLICATE，Ob 回调未激活）。
--*/
static
VOID
HspCleanupStaleDuplications(
    _In_ PHS_TRACKER Tracker
    )
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeoutInterval;
    PLIST_ENTRY entry, next;
    PHS_DUPLICATION_RECORD record;
    LIST_ENTRY staleList;

    KeQuerySystemTime(&currentTime);
    timeoutInterval.QuadPart = (LONGLONG)Tracker->Config.CacheTimeoutMs * 10000;

    InitializeListHead(&staleList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->DuplicationLock);

    for (entry = Tracker->DuplicationList.Flink;
         entry != &Tracker->DuplicationList;
         entry = next) {
        next = entry->Flink;
        record = CONTAINING_RECORD(entry, HS_DUPLICATION_RECORD, ListEntry);

        if (currentTime.QuadPart > record->Timestamp.QuadPart &&
            (currentTime.QuadPart - record->Timestamp.QuadPart) > timeoutInterval.QuadPart) {
            RemoveEntryList(&record->ListEntry);
            InterlockedDecrement(&Tracker->DuplicationCount);
            InsertTailList(&staleList, &record->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Tracker->DuplicationLock);
    KeLeaveCriticalRegion();

    /* 锁外释放（对齐 SS L2811-2815） */
    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        record = CONTAINING_RECORD(entry, HS_DUPLICATION_RECORD, ListEntry);
        ExFreeToNPagedLookasideList(&Tracker->DuplicationLookaside, record);
    }
}

/*++
    周期清理 worker 线程（对齐 SS HtpWorkerThreadRoutine L2730-2769）
    适配：SS 用 TimerManager(TmCreatePeriodic) 设 WorkAvailableEvent；wkd 无
    TimerManager，改为 KeWaitForMultipleObjects 带 CleanupIntervalMs 超时，
    超时即触发周期清理（重功能实现非复制，语义等价：每周期清一次 TTL 过期记录）。
--*/
static
VOID
HspWorkerThreadRoutine(
    _In_ PVOID StartContext
    )
{
    PHS_TRACKER tracker = (PHS_TRACKER)StartContext;
    PVOID waitObjects[2];
    LARGE_INTEGER timeout;
    NTSTATUS status;

    waitObjects[0] = &tracker->ShutdownEvent;
    waitObjects[1] = &tracker->WorkAvailableEvent;

    timeout.QuadPart = -10 * 10000LL * tracker->Config.CleanupIntervalMs;  /* 100ns 单位 */

    while (!tracker->ShutdownRequested) {
        status = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            &timeout,
            NULL
            );

        if (status == STATUS_WAIT_0 || tracker->ShutdownRequested) {
            break;   /* ShutdownEvent 或关闭请求 */
        }

        /* STATUS_WAIT_1（WorkAvailableEvent 立即清理）或 STATUS_TIMEOUT（周期清理） */
        if (tracker->Initialized && !tracker->ShutdownRequested) {
            HspCleanupStaleDuplications(tracker);
        }

        /* 重置周期超时 */
        timeout.QuadPart = -10 * 10000LL * tracker->Config.CleanupIntervalMs;
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*++
    初始化句柄追踪器（缓存层）（对齐 SS HtInitialize L641-917）
    死代码：缓存层未接入，服务于创建时全量快照，wkd 由 Agent 按需扫描替代。
    适配：SS 用 TimerManager(TmCreatePeriodic)；wkd 无 TimerManager，周期清理由
    worker 线程带超时 KeWaitForMultipleObjects 完成（见 HspWorkerThreadRoutine）。
--*/
_Use_decl_annotations_
NTSTATUS
HsInitialize(
    _Out_ PHS_TRACKER* OutTracker,
    _In_opt_ PHS_CONFIG Config
    )
{
    NTSTATUS status;
    PHS_TRACKER tracker = NULL;
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    ULONG i;
    SIZE_T hashTableSize;

    PAGED_CODE();

    if (OutTracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutTracker = NULL;

    tracker = (PHS_TRACKER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(HS_TRACKER), HS_POOL_TAG);
    if (tracker == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(tracker, sizeof(HS_TRACKER));
    tracker->Signature = HS_SIGNATURE;

    /* rundown 保护 */
    ExInitializeRundownProtection(&tracker->RundownRef);

    /* 全局进程列表 */
    InitializeListHead(&tracker->ProcessList);
    ExInitializePushLock(&tracker->ProcessListLock);

    /* hash 桶 */
    tracker->HashBucketCount = HS_HASH_BUCKET_COUNT;
    hashTableSize = (SIZE_T)HS_HASH_BUCKET_COUNT * sizeof(HS_HASH_BUCKET);
    tracker->HashBuckets = (PHS_HASH_BUCKET)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, hashTableSize, HS_POOL_TAG);
    if (tracker->HashBuckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(tracker->HashBuckets, hashTableSize);
    for (i = 0; i < HS_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&tracker->HashBuckets[i].ProcessList);
        ExInitializePushLock(&tracker->HashBuckets[i].Lock);
    }

    /* 复制追踪列表 */
    InitializeListHead(&tracker->DuplicationList);
    ExInitializePushLock(&tracker->DuplicationLock);

    /* lookaside 列表 */
    ExInitializeNPagedLookasideList(
        &tracker->HandleEntryLookaside, NULL, NULL, POOL_NX_ALLOCATION,
        sizeof(HS_CACHED_HANDLE), HS_POOL_TAG_ENTRY, 0);
    ExInitializeNPagedLookasideList(
        &tracker->ProcessHandlesLookaside, NULL, NULL, POOL_NX_ALLOCATION,
        sizeof(HS_PROCESS_HANDLES), HS_POOL_TAG_PROCESS, 0);
    ExInitializeNPagedLookasideList(
        &tracker->DuplicationLookaside, NULL, NULL, POOL_NX_ALLOCATION,
        sizeof(HS_DUPLICATION_RECORD), HS_POOL_TAG_ENTRY, 0);
    tracker->LookasideInitialized = TRUE;

    /* 配置（默认或用户） */
    if (Config != NULL) {
        tracker->Config = *Config;
    } else {
        HspGetDefaultConfig(&tracker->Config);
    }

    /* 校验限制（对齐 SS L774-785） */
    if (tracker->Config.MaxHandlesPerProcess == 0) {
        tracker->Config.MaxHandlesPerProcess = HS_MAX_HANDLES_PER_PROCESS;
    }
    if (tracker->Config.MaxDuplications == 0) {
        tracker->Config.MaxDuplications = HS_MAX_DUPLICATIONS;
    }
    if (tracker->Config.CleanupIntervalMs < 1000) {
        tracker->Config.CleanupIntervalMs = HS_DEFAULT_CLEANUP_INTERVAL_MS;
    }
    if (tracker->Config.CacheTimeoutMs < 1000) {
        tracker->Config.CacheTimeoutMs = HS_DEFAULT_CACHE_TIMEOUT_MS;
    }

    KeQuerySystemTime(&tracker->Stats.StartTime);

    /* worker 线程同步 */
    KeInitializeEvent(&tracker->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&tracker->WorkAvailableEvent, SynchronizationEvent, FALSE);

    /* worker 线程（周期清理 + 关闭同步） */
    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(
        &threadHandle, THREAD_ALL_ACCESS, &objectAttributes, NULL, NULL,
        HspWorkerThreadRoutine, tracker);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = ObReferenceObjectByHandle(
        threadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
        (PVOID*)&tracker->WorkerThreadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&tracker->ShutdownRequested, 1);
        KeSetEvent(&tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        goto Cleanup;
    }

    InterlockedExchange(&tracker->Initialized, 1);
    *OutTracker = tracker;

    return STATUS_SUCCESS;

Cleanup:
    if (tracker->WorkerThreadObject != NULL) {
        InterlockedExchange(&tracker->ShutdownRequested, 1);
        KeSetEvent(&tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(tracker->WorkerThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(tracker->WorkerThreadObject);
    }
    if (tracker->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&tracker->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&tracker->ProcessHandlesLookaside);
        ExDeleteNPagedLookasideList(&tracker->DuplicationLookaside);
    }
    if (tracker->HashBuckets != NULL) {
        ExFreePoolWithTag(tracker->HashBuckets, HS_POOL_TAG);
    }
    ExFreePoolWithTag(tracker, HS_POOL_TAG);
    return status;
}

/*++
    安全关闭句柄追踪器（对齐 SS HtShutdown L919-1082）
    死代码：随 HsInitialize。
--*/
_Use_decl_annotations_
VOID
HsShutdown(
    _Inout_ PHS_TRACKER* TrackerPtr
    )
{
    PHS_TRACKER tracker;
    PLIST_ENTRY entry;
    PHS_PROCESS_HANDLES handles;
    PHS_DUPLICATION_RECORD dupRecord;
    ULONG i;

    PAGED_CODE();

    if (TrackerPtr == NULL || *TrackerPtr == NULL) {
        return;
    }

    tracker = *TrackerPtr;
    *TrackerPtr = NULL;

    if (tracker->Signature != HS_SIGNATURE) {
        return;
    }

    InterlockedExchange(&tracker->Initialized, 0);
    InterlockedExchange(&tracker->ShutdownRequested, 1);

    /* 等待所有进行中操作完成 */
    ExWaitForRundownProtectionRelease(&tracker->RundownRef);

    /* 停止 worker 线程 */
    KeSetEvent(&tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&tracker->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);

    if (tracker->WorkerThreadObject != NULL) {
        KeWaitForSingleObject(tracker->WorkerThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(tracker->WorkerThreadObject);
        tracker->WorkerThreadObject = NULL;
    }

    /* 释放 hash 表全部快照（对齐 SS L987-1036） */
    for (i = 0; i < tracker->HashBucketCount; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&tracker->HashBuckets[i].Lock);

        while (!IsListEmpty(&tracker->HashBuckets[i].ProcessList)) {
            entry = RemoveHeadList(&tracker->HashBuckets[i].ProcessList);
            handles = CONTAINING_RECORD(entry, HS_PROCESS_HANDLES, HashEntry);
            handles->InHashTable = FALSE;
            InterlockedDecrement(&tracker->HashBuckets[i].Count);

            ExReleasePushLockExclusive(&tracker->HashBuckets[i].Lock);
            KeLeaveCriticalRegion();

            /* 卸载全局列表 */
            if (!IsListEmpty(&handles->GlobalEntry)) {
                KeEnterCriticalRegion();
                ExAcquirePushLockExclusive(&tracker->ProcessListLock);
                RemoveEntryList(&handles->GlobalEntry);
                InitializeListHead(&handles->GlobalEntry);
                InterlockedDecrement(&tracker->ProcessCount);
                ExReleasePushLockExclusive(&tracker->ProcessListLock);
                KeLeaveCriticalRegion();
            }

            HspFreeAllHandleEntries(tracker, handles);
            if (handles->ProcessObject != NULL) {
                ObDereferenceObject(handles->ProcessObject);
            }
            ExFreeToNPagedLookasideList(&tracker->ProcessHandlesLookaside, handles);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&tracker->HashBuckets[i].Lock);
        }

        ExReleasePushLockExclusive(&tracker->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    /* 释放全部复制记录（对齐 SS L1041-1059） */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&tracker->DuplicationLock);

    while (!IsListEmpty(&tracker->DuplicationList)) {
        entry = RemoveHeadList(&tracker->DuplicationList);
        dupRecord = CONTAINING_RECORD(entry, HS_DUPLICATION_RECORD, ListEntry);
        InterlockedDecrement(&tracker->DuplicationCount);

        ExReleasePushLockExclusive(&tracker->DuplicationLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&tracker->DuplicationLookaside, dupRecord);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&tracker->DuplicationLock);
    }

    ExReleasePushLockExclusive(&tracker->DuplicationLock);
    KeLeaveCriticalRegion();

    if (tracker->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&tracker->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&tracker->ProcessHandlesLookaside);
        ExDeleteNPagedLookasideList(&tracker->DuplicationLookaside);
    }

    if (tracker->HashBuckets != NULL) {
        ExFreePoolWithTag(tracker->HashBuckets, HS_POOL_TAG);
    }

    tracker->Signature = 0;
    ExFreePoolWithTag(tracker, HS_POOL_TAG);
}

/*++
    记录一条句柄复制事件（对齐 SS HtRecordDuplication L1256-1365）
    死代码：事件源=Ob 回调 OB_OPERATION_HANDLE_DUPLICATE（ObjectNotify.c
    CbInitializeObjectNotify 被 WkdEntry 注释，未激活）。跨进程复制关联应
    归 Agent 因果图（IOA_TIER3 跨进程边，对齐 SS PrAddRelationship）。
--*/
_Use_decl_annotations_
NTSTATUS
HsRecordDuplication(
    _In_ PHS_TRACKER Tracker,
    _In_ HANDLE SourceProcess,
    _In_ HANDLE TargetProcess,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetHandle,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ HS_HANDLE_TYPE HandleType
    )
{
    PHS_DUPLICATION_RECORD record = NULL;
    HS_SUSPICION suspicion = HsSuspicion_None;

    if (Tracker == NULL || Tracker->Signature != HS_SIGNATURE || Tracker->Initialized == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Config.EnableDuplicationTracking) {
        return STATUS_SUCCESS;
    }

    if (!ExAcquireRundownProtection(&Tracker->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* CAS 槽位预留：防止并发超限耗尽非分页池（对齐 SS L1286-1304） */
    {
        LONG snapshot;
        for (;;) {
            snapshot = ReadAcquire(&Tracker->DuplicationCount);
            if (snapshot < 0 || (ULONG)snapshot >= Tracker->Config.MaxDuplications) {
                ExReleaseRundownProtection(&Tracker->RundownRef);
                return STATUS_QUOTA_EXCEEDED;
            }
            if (InterlockedCompareExchange(&Tracker->DuplicationCount,
                                           snapshot + 1, snapshot) == snapshot) {
                break;
            }
        }
    }

    record = (PHS_DUPLICATION_RECORD)ExAllocateFromNPagedLookasideList(
        &Tracker->DuplicationLookaside);
    if (record == NULL) {
        InterlockedDecrement(&Tracker->DuplicationCount);
        ExReleaseRundownProtection(&Tracker->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(record, sizeof(HS_DUPLICATION_RECORD));
    InitializeListHead(&record->ListEntry);
    record->SourceProcessId = SourceProcess;
    record->TargetProcessId = TargetProcess;
    record->SourceHandle = SourceHandle;
    record->TargetHandle = TargetHandle;
    record->GrantedAccess = GrantedAccess;
    record->HandleType = HandleType;
    KeQuerySystemTime(&record->Timestamp);

    /* 怀疑分析（对齐 SS L1330-1342） */
    if (SourceProcess != TargetProcess) {
        suspicion |= HsSuspicion_CrossProcess;
        suspicion |= HsSuspicion_DuplicatedIn;
    }
    if (HandleType == HsTypeProcess && HspIsInjectionCapableAccess(GrantedAccess)) {
        suspicion |= HsSuspicion_InjectionCapable;
    }
    if (HandleType == HsTypeToken && (GrantedAccess & HS_TOKEN_STEAL_ACCESS)) {
        suspicion |= HsSuspicion_TokenSteal;
    }
    record->SuspicionFlags = suspicion;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->DuplicationLock);
    InsertTailList(&Tracker->DuplicationList, &record->ListEntry);
    ExReleasePushLockExclusive(&Tracker->DuplicationLock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&Tracker->Stats.DuplicationsRecorded);
    if (suspicion != HsSuspicion_None) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousHandles);
    }

    ExReleaseRundownProtection(&Tracker->RundownRef);
    return STATUS_SUCCESS;
}

/*++
    获取追踪器统计（对齐 SS HtGetStatistics L1573-1599）
    死代码：无消费方（对齐 SS，SS 的 HtGetStatistics 亦无调用方）。
--*/
_Use_decl_annotations_
NTSTATUS
HsGetStatistics(
    _In_ PHS_TRACKER Tracker,
    _Out_ PHS_STATISTICS Stats
    )
{
    if (Tracker == NULL || Tracker->Signature != HS_SIGNATURE || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Stats->HandlesTracked = Tracker->Stats.HandlesTracked;
    Stats->SuspiciousHandles = Tracker->Stats.SuspiciousHandles;
    Stats->CrossProcessHandles = Tracker->Stats.CrossProcessHandles;
    Stats->TotalEnumerations = Tracker->Stats.TotalEnumerations;
    Stats->DuplicationsRecorded = Tracker->Stats.DuplicationsRecorded;
    Stats->SensitiveAccessDetected = Tracker->Stats.SensitiveAccessDetected;
    Stats->HighPrivilegeHandles = Tracker->Stats.HighPrivilegeHandles;
    Stats->TokenHandlesTracked = Tracker->Stats.TokenHandlesTracked;
    Stats->InjectionHandlesDetected = Tracker->Stats.InjectionHandlesDetected;
    Stats->StartTime = Tracker->Stats.StartTime;

    return STATUS_SUCCESS;
}

/*++
    读取快照摘要（对齐 SS HtGetHandlesInfo L1154-1192）
    死代码：依赖缓存层（HS_PROCESS_HANDLES），未接入。
--*/
_Use_decl_annotations_
NTSTATUS
HsGetHandlesInfo(
    _In_ PHS_PROCESS_HANDLES Handles,
    _Out_ PHS_PROCESS_HANDLES_INFO Info
    )
{
    if (Handles == NULL || Handles->Signature != HS_SIGNATURE || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(HS_PROCESS_HANDLES_INFO));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Handles->Lock);

    Info->ProcessId = Handles->ProcessId;
    Info->HandleCount = Handles->HandleCount;
    Info->AggregatedSuspicion = Handles->AggregatedSuspicion;
    Info->SuspicionScore = Handles->SuspicionScore;
    Info->ProcessHandleCount = Handles->ProcessHandleCount;
    Info->ThreadHandleCount = Handles->ThreadHandleCount;
    Info->FileHandleCount = Handles->FileHandleCount;
    Info->TokenHandleCount = Handles->TokenHandleCount;
    Info->SectionHandleCount = Handles->SectionHandleCount;
    Info->OtherHandleCount = Handles->OtherHandleCount;
    Info->CrossProcessHandleCount = Handles->CrossProcessHandleCount;
    Info->HighPrivilegeHandleCount = Handles->HighPrivilegeHandleCount;
    Info->SnapshotTime = Handles->SnapshotTime;

    ExReleasePushLockShared(&Handles->Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/*++
    按索引读取单条句柄（对齐 SS HtGetHandleByIndex L1194-1252）
    死代码：依赖缓存层，未接入。
--*/
_Use_decl_annotations_
NTSTATUS
HsGetHandleByIndex(
    _In_ PHS_PROCESS_HANDLES Handles,
    _In_ ULONG Index,
    _Out_ PHS_HANDLE_INFO Info
    )
{
    PLIST_ENTRY entry;
    PHS_CACHED_HANDLE cached;
    PHS_HANDLE_ENTRY handleEntry;
    ULONG currentIndex = 0;

    if (Handles == NULL || Handles->Signature != HS_SIGNATURE || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(HS_HANDLE_INFO));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Handles->Lock);

    for (entry = Handles->HandleList.Flink;
         entry != &Handles->HandleList;
         entry = entry->Flink) {

        if (currentIndex == Index) {
            cached = CONTAINING_RECORD(entry, HS_CACHED_HANDLE, ListEntry);
            handleEntry = &cached->Entry;

            Info->HandleValue = handleEntry->HandleValue;
            Info->Type = handleEntry->Type;
            Info->GrantedAccess = handleEntry->GrantedAccess;
            Info->TargetProcessId = handleEntry->TargetProcessId;
            Info->IsDuplicated = handleEntry->IsDuplicated;
            Info->DuplicatedFromProcess = handleEntry->DuplicatedFromProcess;
            Info->SuspicionFlags = handleEntry->SuspicionFlags;
            Info->SuspicionScore = handleEntry->SuspicionScore;
            Info->ObjectNameLength = handleEntry->ObjectNameLength;

            if (handleEntry->ObjectNameLength > 0) {
                RtlCopyMemory(
                    Info->ObjectName,
                    handleEntry->ObjectName,
                    min(handleEntry->ObjectNameLength, sizeof(Info->ObjectName) - sizeof(WCHAR))
                    );
            }

            ExReleasePushLockShared(&Handles->Lock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }

        currentIndex++;
    }

    ExReleasePushLockShared(&Handles->Lock);
    KeLeaveCriticalRegion();

    return STATUS_NO_MORE_ENTRIES;
}

/*++
    句柄怀疑标志 → 进程行为标志映射
    （对齐 SS PnpAnalyzeProcess 的 PN_BEHAVIOR_HANDLE_INJECTION/
     CRED_ACCESS/TOKEN_STEAL 映射，ProcessNotify.c:3414-3422）
--*/
static
ULONG
HspMapSuspicionToBehaviorFlags(
    _In_ HS_SUSPICION Suspicion
    )
{
    ULONG flags = 0;

    if (Suspicion & HsSuspicion_InjectionCapable) {
        flags |= WKD_BEHAVIOR_HANDLE_INJECTION;
    }
    if (Suspicion & HsSuspicion_CredentialAccess) {
        flags |= WKD_BEHAVIOR_HANDLE_CRED_ACCESS;
    }
    if (Suspicion & HsSuspicion_TokenSteal) {
        flags |= WKD_BEHAVIOR_HANDLE_TOKEN_STEAL;
    }

    return flags;
}

/*++
    新进程句柄快照分析（对齐 SS PnpAnalyzeProcess HandleTracker 段，
    ProcessNotify.c:3398-3465：HtSnapshotHandles+HtAnalyzeHandles →
    PN_BEHAVIOR_HANDLE_* 映射 → SuspicionScore 累加）。
    适配：wkd 无缓存层，用活代码 HsScanProcessHandles 实时枚举替代缓存快照；
    类型细分统计（ProcessHandleCount 等）在实时枚举下为 0，完整类型统计
    需接入缓存枚举（HspEnumerateProcessHandles）。
    死代码：进程创建热路径全系统枚举成本高，wkd 以 Ob 回调实时检测
    （IocDetectHandle，操作时）为主路径；接入需门控开关默认关。
--*/
_Use_decl_annotations_
NTSTATUS
HspAnalyzeNewProcessHandles(
    _In_ struct _WKD_PROCESS* Process,
    _Inout_ PULONG BehaviorFlags,
    _Out_ PHS_PROCESS_HANDLES_INFO Info
    )
{
    NTSTATUS status;
    HS_CONFIG config;
    HS_PROCESS_HANDLE_RESULT result;
    PHS_HANDLE_ENTRY entries;
    ULONG maxEntries;
    HANDLE processId;

    if (Process == NULL || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    processId = Process->Core.ProcessId;
    RtlZeroMemory(Info, sizeof(HS_PROCESS_HANDLES_INFO));

    /* 实时枚举（对齐 SS HtSnapshotHandles 功能面） */
    HspGetDefaultConfig(&config);
    maxEntries = config.MaxHandlesPerProcess;
    entries = (PHS_HANDLE_ENTRY)ExAllocatePool2(
        POOL_FLAG_PAGED, maxEntries * sizeof(HS_HANDLE_ENTRY), HS_POOL_TAG_BUFFER);
    if (entries == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&result, sizeof(result));
    result.Handles = entries;
    result.MaxHandles = maxEntries;

    status = HsScanProcessHandles(&config, processId, &result);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entries, HS_POOL_TAG_BUFFER);
        return status;
    }

    /* 聚合摘要（对齐 SS HtAnalyzeHandles 输出） */
    Info->ProcessId = processId;
    Info->HandleCount = (LONG)result.HandleCount;
    Info->AggregatedSuspicion = result.AggregatedFlags;
    Info->SuspicionScore = result.SuspicionScore;
    Info->CrossProcessHandleCount = result.CrossProcessCount;
    Info->HighPrivilegeHandleCount = result.HighPrivilegeCount;
    KeQuerySystemTime(&Info->SnapshotTime);

    /* 行为标志映射（对齐 SS PN_BEHAVIOR_HANDLE_* 映射） */
    if (BehaviorFlags != NULL) {
        *BehaviorFlags |= HspMapSuspicionToBehaviorFlags(result.AggregatedFlags);
    }

    /* 告警决策 + 建议累计分（对齐 SS BeEngineSubmitEvent + SuspicionScore 累加，
     * ProcessNotify.c:3427-3449；死代码：接入方决定上报/写回进程评分） */
    (VOID)HspSubmitHandleAlerts(result.AggregatedFlags, NULL);

    ExFreePoolWithTag(entries, HS_POOL_TAG_BUFFER);
    return STATUS_SUCCESS;
}

/*++
    快照并缓存指定进程的全部句柄（对齐 SS HtSnapshotHandles L1084-1152）。
    组合 API：分配 → 枚举 → 缓存（hash 表 + 全局列表），统计已在
    HspEnumerateProcessHandles 内更新。返回快照 RefCount=2（hash 1 + 调用者 1），
    调用者用完须 HspReleaseHandles 释放。
    死代码：缓存层未接入（wkd 创建时快照走 HspAnalyzeNewProcessHandles 实时枚举）。
--*/
_Use_decl_annotations_
NTSTATUS
HspSnapshotHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PHS_PROCESS_HANDLES* OutHandles
    )
{
    NTSTATUS status;
    PHS_PROCESS_HANDLES handles = NULL;

    PAGED_CODE();

    if (Tracker == NULL || Tracker->Signature != HS_SIGNATURE || OutHandles == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutHandles = NULL;

    if (!ExAcquireRundownProtection(&Tracker->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    handles = HspAllocateProcessHandles(Tracker, ProcessId);
    if (handles == NULL) {
        ExReleaseRundownProtection(&Tracker->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = HspEnumerateProcessHandles(Tracker, ProcessId, handles);
    if (!NT_SUCCESS(status)) {
        HspDereferenceProcessHandles(Tracker, handles);
        ExReleaseRundownProtection(&Tracker->RundownRef);
        return status;
    }

    (VOID)HspInsertProcessHandles(Tracker, handles);

    *OutHandles = handles;

    ExReleaseRundownProtection(&Tracker->RundownRef);
    return STATUS_SUCCESS;
}

/*++
    对快照做聚合分析（对齐 SS HtAnalyzeHandles L1367-1438）。
    遍历聚合 SuspicionFlags + ManyHandles 阈值，独占锁更新缓存聚合字段
    （发布一致对，防 HspGetHandlesInfo 并发 torn read）。
    死代码：缓存层未接入。
--*/
_Use_decl_annotations_
NTSTATUS
HspAnalyzeHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_PROCESS_HANDLES Handles,
    _Out_ HS_SUSPICION* Flags,
    _Out_opt_ PULONG Score
    )
{
    PLIST_ENTRY entry;
    PHS_CACHED_HANDLE cached;
    HS_SUSPICION aggregated = HsSuspicion_None;

    if (Tracker == NULL || Tracker->Signature != HS_SIGNATURE ||
        Handles == NULL || Handles->Signature != HS_SIGNATURE || Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = HsSuspicion_None;
    if (Score != NULL) {
        *Score = 0;
    }

    if (!ExAcquireRundownProtection(&Tracker->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* 独占锁：聚合 + 更新缓存聚合字段（对齐 SS L1397-1429） */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Handles->Lock);

    for (entry = Handles->HandleList.Flink;
         entry != &Handles->HandleList;
         entry = entry->Flink) {
        cached = CONTAINING_RECORD(entry, HS_CACHED_HANDLE, ListEntry);
        aggregated |= cached->Entry.SuspicionFlags;
    }

    if ((ULONG)Handles->HandleCount > Tracker->Config.MaxHandlesPerProcess / 2) {
        aggregated |= HsSuspicion_ManyHandles;
    }

    Handles->AggregatedSuspicion = aggregated;
    Handles->SuspicionScore = HspCalculateScore(aggregated);

    ExReleasePushLockExclusive(&Handles->Lock);
    KeLeaveCriticalRegion();

    *Flags = aggregated;
    if (Score != NULL) {
        *Score = HspCalculateScore(aggregated);
    }

    ExReleaseRundownProtection(&Tracker->RundownRef);
    return STATUS_SUCCESS;
}

/*++
    释放快照（对齐 SS HtReleaseHandles L1551-1571）：移除缓存 + 引用递减。
    死代码：缓存层未接入。
--*/
_Use_decl_annotations_
VOID
HspReleaseHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_PROCESS_HANDLES Handles
    )
{
    if (Tracker == NULL || Tracker->Signature != HS_SIGNATURE ||
        Handles == NULL || Handles->Signature != HS_SIGNATURE) {
        return;
    }

    HspRemoveProcessHandles(Tracker, Handles);
    HspDereferenceProcessHandles(Tracker, Handles);
}

/*++
    句柄聚合怀疑 → 告警位图 + 建议累计分
    （对齐 SS PnpAnalyzeProcess 的 BeEngineSubmitEvent 三类告警 + SuspicionScore
     累加，ProcessNotify.c:3427-3449。权重对齐 SS：CredentialDumping=40/
     RemoteThreadCreate=25/LSASSAccess=30，cap 100）。
    死代码：接入点在进程创建路径（AeOrchestratorDispatch ProcessCreated 分支，
    门控默认关）；wkd 以 Ob 回调实时检测（IocDetectHandle）为主路径。
    返回告警位图（HS_ALERT_*），AccumulatedScore 输出建议写入进程评分的累计分。
--*/
_Use_decl_annotations_
ULONG
HspSubmitHandleAlerts(
    _In_ HS_SUSPICION AggregatedSuspicion,
    _Out_opt_ PULONG AccumulatedScore
    )
{
    ULONG alerts = 0;
    ULONG score = 0;

    if (AggregatedSuspicion & HsSuspicion_CredentialAccess) {
        alerts |= HS_ALERT_CREDENTIAL_DUMP;
        score += 40;   /* 对齐 SS BehaviorEvent_CredentialDumping 权重 */
    }
    if (AggregatedSuspicion & HsSuspicion_InjectionCapable) {
        alerts |= HS_ALERT_INJECTION;
        score += 25;   /* 对齐 SS BehaviorEvent_RemoteThreadCreate 权重 */
    }
    if (AggregatedSuspicion & HsSuspicion_TokenSteal) {
        alerts |= HS_ALERT_TOKEN_STEAL;
        score += 30;   /* 对齐 SS BehaviorEvent_LSASSAccess 权重 */
    }

    if (score > 100) {
        score = 100;
    }

    if (AccumulatedScore != NULL) {
        *AccumulatedScore = score;
    }

    return alerts;
}
