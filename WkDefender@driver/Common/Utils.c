#include "Utils.h"

//
// 全局变量：缓存 Windows 版本信息
//
static ULONG WkdWindowsBuildNumber = 0;
static PVOID WkdNtoskrnlBase = NULL;

//
// LOLBin文件名列表
//
// 2026-08 补全：对齐 SS BepIsLolBin（BehaviorEngine.c L4856）补 esentutl/
// expand/extrac32/findstr/ie4uinit/makecab/mmc/pubprn/replace/rpcping/
// schtasks/scriptrunner 12 项。不迁 SS 的 cmd.exe/powershell.exe/pwsh.exe
// （普通命令/脚本宿主走独立行为标志，避免误报加分）。
// 2026-08 补全 SS CommandLineParser g_LOLBinDefinitions 独有条目
// (control/eudcedit/eventvwr/fodhelper/computerdefaults/slui/sdclt/at/sc/
//  reg/netsh/curl/wget/print/bash/wsl, 不迁 cmd/powershell 归脚本宿主)。
// 2026-08 ProcessAnalyzer 迁移：补 SS PapInitializeLOLBins L3071-3123 独有
// (atbroker/gpscript/microsoft.workflow.compiler/regedit/register-cimprovider/
//  runscripthelper/ttdinject/tttracer/vbc 9 项)。
//
const WCHAR* g_WkdLolbinList[] = {
    L"at.exe",
    L"atbroker.exe",
    L"bash.exe",
    L"bitsadmin.exe",
    L"certutil.exe",
    L"cmstp.exe",
    L"computerdefaults.exe",
    L"control.exe",
    L"cscript.exe",
    L"curl.exe",
    L"dnscmd.exe",
    L"esentutl.exe",
    L"eudcedit.exe",
    L"eventvwr.exe",
    L"expand.exe",
    L"extrac32.exe",
    L"findstr.exe",
    L"fodhelper.exe",
    L"forfiles.exe",
    L"ftp.exe",
    L"gpscript.exe",
    L"hh.exe",
    L"ie4uinit.exe",
    L"ieexec.exe",
    L"infdefaultinstall.exe",
    L"installutil.exe",
    L"makecab.exe",
    L"mavinject.exe",
    L"microsoft.workflow.compiler.exe",
    L"mmc.exe",
    L"msbuild.exe",
    L"msconfig.exe",
    L"msdeploy.exe",
    L"msdt.exe",
    L"mshta.exe",
    L"msiexec.exe",
    L"netsh.exe",
    L"odbcconf.exe",
    L"pcalua.exe",
    L"pcwrun.exe",
    L"presentationhost.exe",
    L"print.exe",
    L"pubprn.vbs",
    L"rcsi.exe",
    L"reg.exe",
    L"regasm.exe",
    L"regedit.exe",
    L"register-cimprovider.exe",
    L"regsvcs.exe",
    L"regsvr32.exe",
    L"replace.exe",
    L"rpcping.exe",
    L"rundll32.exe",
    L"runscripthelper.exe",
    L"sc.exe",
    L"schtasks.exe",
    L"scriptrunner.exe",
    L"sdclt.exe",
    L"sfc.exe",
    L"slui.exe",
    L"syncappvpublishingserver.exe",
    L"te.exe",
    L"tracker.exe",
    L"ttdinject.exe",
    L"tttracer.exe",
    L"vbc.exe",
    L"verclsid.exe",
    L"wget.exe",
    L"wmic.exe",
    L"wscript.exe",
    L"wsl.exe",
    L"xwizard.exe"
};

//
// 全局变量：缓存 DriverObject 用于模块遍历
//
static PDRIVER_OBJECT WkdDriverObject = NULL;

//
// 设置全局 DriverObject（在驱动入口调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UtSetDriverObject(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    WkdDriverObject = DriverObject;
}

//
// KLDR_DATA_TABLE_ENTRY 结构定义（简化版）
// 用于遍历已加载的内核模块
//
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

const ULONG g_WkdLolbinCount = RTL_NUMBER_OF(g_WkdLolbinList);

//
// PowerShell检测模式
//
const WCHAR* g_WkdPowershellPatterns[] = {
    L"-enc",
    L"-EncodedCommand",
    L"-e ",
    L"-ec ",
    L"-nop",
    L"-noni",
    L"-w hidden",
    L"-windowstyle hidden",
    L"-ep bypass",
    L"-executionpolicy bypass",
    L"bypass"
};

const ULONG g_WkdPowershellPatternCount = RTL_NUMBER_OF(g_WkdPowershellPatterns);

//
// 下载器检测模式
//
const WCHAR* g_WkdDownloaderPatterns[] = {
    L"DownloadString",
    L"DownloadFile",
    L"DownloadData",
    L"WebClient",
    L"Invoke-WebRequest",
    L"Invoke-RestMethod",
    L"wget",
    L"curl",
    L"bitsadmin",
    L"Start-BitsTransfer"
};

const ULONG g_WkdDownloaderPatternCount = RTL_NUMBER_OF(g_WkdDownloaderPatterns);

//
// 反射加载检测模式
//
const WCHAR* g_WkdReflectivePatterns[] = {
    L"[Reflection.Assembly]",
    L"Reflection.Assembly",
    L"::Load(",
    L"FromBase64String"
};

const ULONG g_WkdReflectivePatternCount = RTL_NUMBER_OF(g_WkdReflectivePatterns);

//
// 敏感特权列表
//
const WCHAR* g_WkdSensitivePrivileges[] = {
    L"SeDebugPrivilege",
    L"SeImpersonatePrivilege",
    L"SeTcbPrivilege",
    L"SeAssignPrimaryTokenPrivilege"
};

const ULONG g_WkdSensitivePrivilegeCount = RTL_NUMBER_OF(g_WkdSensitivePrivileges);

//
// 字符串包含检测
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdStringContains(
    _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Pattern
    )
{
    if (!Source || !Pattern || Source->Length == 0 || Pattern->Length == 0) {
        return FALSE;
    }

    PWCHAR src = Source->Buffer;
    PWCHAR pat = Pattern->Buffer;
    ULONG srcLen = Source->Length / sizeof(WCHAR);
    ULONG patLen = Pattern->Length / sizeof(WCHAR);

    if (patLen > srcLen) {
        return FALSE;
    }

    for (ULONG i = 0; i <= srcLen - patLen; i++) {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < patLen; j++) {
            if (src[i + j] != pat[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// 字符串前缀检测
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdStringStartsWith(
    _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Prefix
    )
{
    if (!Source || !Prefix || Source->Length == 0 || Prefix->Length == 0) {
        return FALSE;
    }

    ULONG prefixLen = Prefix->Length / sizeof(WCHAR);
    ULONG sourceLen = Source->Length / sizeof(WCHAR);

    if (prefixLen > sourceLen) {
        return FALSE;
    }

    for (ULONG i = 0; i < prefixLen; i++) {
        if (Source->Buffer[i] != Prefix->Buffer[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

//
// 字符串后缀检测
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdStringEndsWith(
    _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Suffix
    )
{
    if (!Source || !Suffix || Source->Length == 0 || Suffix->Length == 0) {
        return FALSE;
    }

    ULONG suffixLen = Suffix->Length / sizeof(WCHAR);
    ULONG sourceLen = Source->Length / sizeof(WCHAR);

    if (suffixLen > sourceLen) {
        return FALSE;
    }

    PWCHAR sourceEnd = Source->Buffer + sourceLen - suffixLen;

    for (ULONG i = 0; i < suffixLen; i++) {
        if (sourceEnd[i] != Suffix->Buffer[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

//
// 转换为小写
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdStringToLower(
    _Inout_ PUNICODE_STRING Str
    )
{
    if (!Str || !Str->Buffer) {
        return;
    }

    ULONG len = Str->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < len; i++) {
        if (Str->Buffer[i] >= L'A' && Str->Buffer[i] <= L'Z') {
            Str->Buffer[i] = Str->Buffer[i] + (L'a' - L'A');
        }
    }
}

/**************************************************/
/*        UNICODE_STRING 工具（通用 hash set 适配）*/
/**************************************************/

//
// FNV-1a 32-bit hash（小写化），适配 PFN_HASHSET_HASH_FUNC
// Element 为 PUNICODE_STRING 值（非指针的指针）
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
UtHashUnicodeString(
    _In_ PVOID Element
    )
{
    PUNICODE_STRING str = (PUNICODE_STRING)Element;
    ULONG hash = 2166136261UL;
    USHORT i;
    WCHAR c;

    if (!str || !str->Buffer) return 0;

    for (i = 0; i < str->Length / sizeof(WCHAR); i++) {
        c = str->Buffer[i];
        if (c >= L'A' && c <= L'Z') {
            c += (WCHAR)(L'a' - L'A');
        }
        hash ^= (ULONG)c;
        hash *= 16777619UL;
    }
    return hash;
}

//
// 释放 PUNICODE_STRING 及其缓冲区，适配 PFN_HASHSET_ENUM
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
CoFreeUnicodeStringElement(
    _In_ ULONG64 Element,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);
    PUNICODE_STRING str = (PUNICODE_STRING)Element;

    if (str) {
        if (str->Buffer) {
            ExFreePoolWithTag(str->Buffer, 'uspb');
        }
        ExFreePoolWithTag(str, 'usp');
    }
    return TRUE; /* 继续遍历 */
}

//
// 卷设备到 DOS 路径映射缓存
//
// 优化：卷设备数量极为有限（通常 ≤ 26 个），通过 ZwOpenSymbolicLinkObject +
//       ZwQuerySymbolicLinkObject 遍历 A-Z 符号链接查询设备映射，首次命中后
//       缓存结果，后续同名路径归一化直接命中缓存，无需重复查询。
//
#define VOLUME_DOS_CACHE_MAX_ENTRIES 26

typedef struct _VOLUME_DOS_CACHE_ENTRY {
    UNICODE_STRING NtDeviceName;   // \Device\HarddiskVolume1
    UNICODE_STRING DosDeviceName;  // \??\C:
} VOLUME_DOS_CACHE_ENTRY;

static VOLUME_DOS_CACHE_ENTRY g_VolumeDosCache[VOLUME_DOS_CACHE_MAX_ENTRIES];
static FAST_MUTEX g_VolumeDosCacheLock;
static BOOLEAN g_VolumeDosCacheInitialized = FALSE;

//
// 初始化卷设备缓存锁（懒初始化）
//
static 
FORCEINLINE 
VOID
UtVolumeDosCacheInit(
    VOID
    )
{
    if (!g_VolumeDosCacheInitialized) {
        ExInitializeFastMutex(&g_VolumeDosCacheLock);
        g_VolumeDosCacheInitialized = TRUE;
    }
}

//
// 在缓存中查找 NT 设备名对应的 DOS 路径
//
static 
BOOLEAN
UtpVolumeDeviceDosNameCacheLookup(
    _In_ PUNICODE_STRING NtDeviceName,
    _Outptr_ PUNICODE_STRING *DosDeviceName
    )
{
    if (!NtDeviceName || !DosDeviceName) {
        return FALSE;
    }

    UtVolumeDosCacheInit();
    ExAcquireFastMutex(&g_VolumeDosCacheLock);

    for (int i = 0; i < VOLUME_DOS_CACHE_MAX_ENTRIES; i++) {
        if (g_VolumeDosCache[i].NtDeviceName.Buffer != NULL &&
            RtlCompareUnicodeString(NtDeviceName,
                &g_VolumeDosCache[i].NtDeviceName, TRUE) == 0) {

            *DosDeviceName = &g_VolumeDosCache[i].DosDeviceName;
            ExReleaseFastMutex(&g_VolumeDosCacheLock);
            return TRUE;
        }
    }

    *DosDeviceName = NULL;
    ExReleaseFastMutex(&g_VolumeDosCacheLock);
    return FALSE;
}

//
// 向缓存中添加 NT 设备名到 DOS 路径的映射
// 内部会复制两个字符串，调用者可自由释放传入的缓冲区
//
static NTSTATUS
UtpVolumeDeviceDosNameCacheAdd(
    _In_ PUNICODE_STRING NtDeviceName,
    _In_ PUNICODE_STRING DosDeviceName
    )
{
    ULONG i;
    PWCHAR buffer;
    NTSTATUS status = STATUS_NO_MEDIA;

    UtVolumeDosCacheInit();
    ExAcquireFastMutex(&g_VolumeDosCacheLock);

    for (i = 0; i < VOLUME_DOS_CACHE_MAX_ENTRIES; i++) {
        if (g_VolumeDosCache[i].NtDeviceName.Buffer == NULL) {
            //
            // 复制 NT 设备名
            //
            buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, NtDeviceName->Length, 'vdcn');
            if (!buffer) {
                break;
            }
            RtlCopyMemory(buffer, NtDeviceName->Buffer, NtDeviceName->Length);

            g_VolumeDosCache[i].NtDeviceName.Buffer = buffer;
            g_VolumeDosCache[i].NtDeviceName.Length = NtDeviceName->Length;
            g_VolumeDosCache[i].NtDeviceName.MaximumLength = NtDeviceName->Length;

            //
            // 复制 DOS 设备名
            //
            buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, DosDeviceName->Length, 'vdcd');
            if (!buffer) {
                ExFreePoolWithTag(g_VolumeDosCache[i].NtDeviceName.Buffer, 'vdcn');
                g_VolumeDosCache[i].NtDeviceName.Buffer = NULL;
                break;
            }
            RtlCopyMemory(buffer, DosDeviceName->Buffer, DosDeviceName->Length);

            g_VolumeDosCache[i].DosDeviceName.Buffer = buffer;
            g_VolumeDosCache[i].DosDeviceName.Length = DosDeviceName->Length;
            g_VolumeDosCache[i].DosDeviceName.MaximumLength = DosDeviceName->Length;

            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseFastMutex(&g_VolumeDosCacheLock);
    return status;
}
   
//
// 解析并缓存 \SystemRoot 符号链接的目标路径
// 典型目标: \Device\HarddiskVolume2\Windows
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
UtpResolveSystemRoot(
    _Outptr_ PUNICODE_STRING *SystemRoot
    )
{
    NTSTATUS status;
    HANDLE linkHandle = NULL;
    UNICODE_STRING linkName;
    OBJECT_ATTRIBUTES objAttr;
    ULONG returnLength = 0;
    
    //
    // \SystemRoot 符号链接缓存
    //
    static UNICODE_STRING WkdpSystemRoot = { 0 };

    if (!SystemRoot) {
        return STATUS_INVALID_PARAMETER;
    }

    if (WkdpSystemRoot.Buffer) {
        *SystemRoot = &WkdpSystemRoot;
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&linkName, L"\\SystemRoot");
    InitializeObjectAttributes(&objAttr, &linkName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &objAttr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WkdpSystemRoot.MaximumLength = 64 * sizeof(WCHAR);
    WkdpSystemRoot.Length = 0;
    WkdpSystemRoot.Buffer = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, WkdpSystemRoot.MaximumLength, 'usrT');
    if (!WkdpSystemRoot.Buffer) {
        ZwClose(linkHandle);
        return STATUS_NO_MEMORY;
    }

    status = ZwQuerySymbolicLinkObject(linkHandle, &WkdpSystemRoot, &returnLength);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        // 缓冲区不够大，按需重新分配
        ExFreePoolWithTag(WkdpSystemRoot.Buffer, 'usrT');

        WkdpSystemRoot.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, returnLength, 'usrT');
        if (!WkdpSystemRoot.Buffer) {
            ZwClose(linkHandle);
            return STATUS_NO_MEMORY;
        }
        WkdpSystemRoot.MaximumLength = (USHORT)returnLength;

        status = ZwQuerySymbolicLinkObject(linkHandle, &WkdpSystemRoot, &returnLength);
    }

    if (NT_SUCCESS(status)) {
        WkdpSystemRoot.Length = (USHORT)(returnLength - sizeof(WCHAR));  // 减去终止符
    }

    *SystemRoot = &WkdpSystemRoot;
    ZwClose(linkHandle);

    return status;
}

//
// 将 NT 路径转换为标准 DOS 路径
//
// 优化说明：
//   1. 优先检测 \Device\HarddiskVolumeX\... 格式，通过 ZwOpenSymbolicLinkObject +
//      ZwQuerySymbolicLinkObject 遍历 A-Z 盘符符号链接匹配 NT 设备名。
//      不发 IRP，无 minifilter 递归风险，且 IoVolumeDeviceToDosName 已 deprecated。
//   2. 引入卷设备→DOS 路径缓存（g_VolumeDosCache），首次查询后直接复用，
//      后续同设备路径归一化零额外查询开销。
//   3. RawPath和NormalizedPath均有调用者释放。
//
_Use_decl_annotations_
NTSTATUS
CoNormalizeDosPath(
    _In_     PCUNICODE_STRING  RawPath,
    _Outptr_ PUNICODE_STRING* NormalizedPath
    )
{
    NTSTATUS status;
    UNICODE_STRING result = { 0 };
    PUNICODE_STRING trans = NULL;   /* 转小写 */
    USHORT remainingLen;

    if (!RawPath || !RawPath->Buffer || RawPath->Length == 0 ||
        !NormalizedPath) {
        return STATUS_INVALID_PARAMETER;
    }
    *NormalizedPath = NULL;

    //
    // 格式一: \Device\HarddiskVolume...\... → 转换为 DOS 路径
    //
    // 从路径中提取卷设备名（\Device\HarddiskVolumeX），查缓存；
    // 缓存未命中时通过 ZwOpenSymbolicLinkObject + ZwQuerySymbolicLinkObject
    // 遍历 A-Z 符号链接匹配设备名，解析后加入缓存。
    //
    if (RawPath->Length >= (8 * sizeof(WCHAR)) &&
        RawPath->Buffer[0] == L'\\' &&
        RawPath->Buffer[1] == L'D' &&
        RawPath->Buffer[2] == L'e' &&
        RawPath->Buffer[3] == L'v' &&
        RawPath->Buffer[4] == L'i' &&
        RawPath->Buffer[5] == L'c' &&
        RawPath->Buffer[6] == L'e' &&
        RawPath->Buffer[7] == L'\\') {

        ULONG pathLen;          // WCHAR 索引
        ULONG ptr = 8;          // 卷设备名结束位置，跳过 /Device/
        UNICODE_STRING deviceNtName;
        PUNICODE_STRING cachedDosName;

        //
        // 找到 \Device\ 之后卷设备名的末尾（下一个 \ 的位置）
        //
        pathLen = RawPath->Length / sizeof(WCHAR);
        while (ptr < pathLen) {
            if (RawPath->Buffer[ptr] == L'\\') {
                break;
            }
            ptr++;
        }
        // 此时 ptr 指向卷名后的分隔符（或 pathLen）

        //
        // 构造 NT 设备名字符串（指向 RawPath 内部缓冲区，不复制）
        //
        deviceNtName.Buffer = RawPath->Buffer;
        deviceNtName.Length = (USHORT)(ptr * sizeof(WCHAR));
        deviceNtName.MaximumLength = deviceNtName.Length;

Retry:
        //
        // 查缓存
        //
        if (UtpVolumeDeviceDosNameCacheLookup(&deviceNtName, &cachedDosName)) {
            //
            // 缓存命中：DOS 前缀 + 剩余路径
            //
            remainingLen = RawPath->Length - deviceNtName.Length;
            USHORT totalLen = cachedDosName->Length + remainingLen;

            result.Buffer = (PWCHAR)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, totalLen, 'upbp');
            if (!result.Buffer) {
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }

            RtlCopyMemory(result.Buffer,
                cachedDosName->Buffer, cachedDosName->Length);
            RtlCopyMemory((PUCHAR)result.Buffer + cachedDosName->Length,
                RawPath->Buffer + ptr, remainingLen);
            result.Length = totalLen;
            result.MaximumLength = totalLen;

            goto Convert;
        }

        //
        // 缓存未命中：遍历 A-Z 盘符，通过符号链接匹配 NT 设备名
        // 使用 ZwOpenSymbolicLinkObject + ZwQuerySymbolicLinkObject 而非
        // IoGetDeviceObjectPointer + IoVolumeDeviceToDosName（deprecated since Vista），
        // 避免发 IRP 到存储设备栈，无递归风险。
        //
            
        //
        // 复制 NT 设备名（用于缓存键）
        //
        UNICODE_STRING deviceNtCopyName;
        deviceNtCopyName.Length = deviceNtName.Length;
        deviceNtCopyName.MaximumLength = deviceNtName.Length;
        deviceNtCopyName.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, deviceNtCopyName.Length, 'vdcn');
        if (!deviceNtCopyName.Buffer) {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }
        RtlCopyMemory(deviceNtCopyName.Buffer, deviceNtName.Buffer, deviceNtName.Length);

        //
        // 遍历 A-Z 盘符，在 \DosDevices\ 目录中查询符号链接目标
        //
        WCHAR linkName[] = L"\\DosDevices\\ :";  // 13 WCHAR + null
        UNICODE_STRING us;

        for (WCHAR drive = L'A'; drive <= L'Z'; drive++) {
            HANDLE linkHandle;
            OBJECT_ATTRIBUTES oa;

            linkName[12] = drive;
            RtlInitUnicodeString(&us, linkName);
            InitializeObjectAttributes(
                &oa, &us, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

            status = ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &oa);
            if (!NT_SUCCESS(status)) {
                continue;  // 此盘符不存在，跳过
            }

            //
            // 查询符号链接目标（如 \Device\HarddiskVolume3）
            //
            WCHAR targetBuffer[MAX_PATH] = { 0 };
            us.Buffer        = targetBuffer;
            us.Length        = 0;
            us.MaximumLength = sizeof(targetBuffer);

            status = ZwQuerySymbolicLinkObject(linkHandle, &us, NULL);
            ZwClose(linkHandle);

            if (!NT_SUCCESS(status)) {
                continue;
            }

            //
            // 比较目标设备名与路径中的 NT 设备名
            //
            if (RtlCompareUnicodeString(&us, &deviceNtName, TRUE) == 0) {
                //
                // 匹配命中！DOS 盘符为 drive:（不加反斜杠，
                // 避免与后续路径拼接时出现双反斜杠）
                //
                WCHAR dosBuffer[3] = { drive, L':', L'\0' };
                RtlInitUnicodeString(&us, dosBuffer);

                //
                // 加入缓存，后续查询直接命中
                //
                status = UtpVolumeDeviceDosNameCacheAdd(&deviceNtCopyName, &us);
                ExFreePoolWithTag(deviceNtCopyName.Buffer, 'vdcn');
                if (NT_SUCCESS(status)) goto Retry;
                else goto Cleanup;
            }
        }

        ExFreePoolWithTag(deviceNtCopyName.Buffer, 'vdcn');
    }
    
    //
    // 格式二: \??\C:\...  → 直接去掉 \??\ 前缀
    //
    if (RawPath->Length >= (4 * sizeof(WCHAR)) &&
        RawPath->Buffer[0] == L'\\' &&
        RawPath->Buffer[1] == L'?' &&
        RawPath->Buffer[2] == L'?' &&
        RawPath->Buffer[3] == L'\\') {

        USHORT prefixLen = 4;

        result.Length = RawPath->Length - (USHORT)(prefixLen * sizeof(WCHAR));
        result.MaximumLength = result.Length;
        result.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, result.Length, 'upbp');
        if (!result.Buffer) {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }
        RtlCopyMemory(result.Buffer, RawPath->Buffer + prefixLen, result.Length);

        goto Convert;
    }

    //
    // 格式三: \SystemRoot\System32\... → 解析符号链接后递归归一化
    //
    // \SystemRoot 是 NT 命名空间中的一个符号链接，指向 Windows 系统根目录
    // （如 \Device\HarddiskVolume2\Windows），需要先解析再走格式一的流程。
    //
    if (RawPath->Length >= (12 * sizeof(WCHAR)) &&
        RawPath->Buffer[0] == L'\\' &&
        RawPath->Buffer[1] == L'S' &&
        RawPath->Buffer[2] == L'y' &&
        RawPath->Buffer[3] == L's' &&
        RawPath->Buffer[4] == L't' &&
        RawPath->Buffer[5] == L'e' &&
        RawPath->Buffer[6] == L'm' &&
        RawPath->Buffer[7] == L'R' &&
        RawPath->Buffer[8] == L'o' &&
        RawPath->Buffer[9] == L'o' &&
        RawPath->Buffer[10] == L't' &&
        RawPath->Buffer[11] == L'\\') {

        PUNICODE_STRING systemRoot;

        // 解析 \SystemRoot 符号链接（有缓存，仅首次真实查询）
        status = UtpResolveSystemRoot(&systemRoot);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        // 剩余路径部分（跳过 \SystemRoot\，12 个 WCHAR）
        remainingLen = RawPath->Length - (12 * sizeof(WCHAR));

        // 分配新路径：目标路径 + 剩余部分
        result.Length = systemRoot->Length + remainingLen;
        result.MaximumLength = result.Length;
        result.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, result.Length, 'upbp');
        if (!result.Buffer) {
            goto Cleanup;
        }

        RtlCopyMemory(result.Buffer,
            systemRoot->Buffer, systemRoot->Length);
        RtlCopyMemory((PUCHAR)result.Buffer + systemRoot->Length,
            RawPath->Buffer + 12, remainingLen);

        // 递归调用自身处理 \Device\HarddiskVolumeX\Windows\... 格式
        status = CoNormalizeDosPath(&result, NormalizedPath);

        /* 此时路径已经转小写，释放返回 */
        ExFreePoolWithTag(result.Buffer, 'upbp');
        return status;
    }
    
    //
    // [兜底] 无法识别的路径格式或者已经是Dos风格的路径，直接复制原文
    //
    result.Length = RawPath->Length;
    result.MaximumLength = RawPath->Length;
    result.Buffer = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, result.Length, 'upbp');
    if (!result.Buffer) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }
    RtlCopyMemory(result.Buffer, RawPath->Buffer, RawPath->Length);
 
Convert:
    trans = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'usTs');
    if (!trans) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    trans->Length = result.Length;
    trans->MaximumLength = result.Length + sizeof(WCHAR);
    trans->Buffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, trans->MaximumLength, 'usTs');
    if (!trans) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    /* 将标准化后的路径转小写 */
    status = RtlDowncaseUnicodeString(trans, &result, FALSE);
    if (NT_SUCCESS(status)) {
        // 释放result.buffer内存
        ExFreePoolWithTag(result.Buffer, 'upbp');

        *NormalizedPath = trans;
        return STATUS_SUCCESS;
    }

Cleanup:
    if (result.Buffer) ExFreePoolWithTag(result.Buffer, 'upbp');
    if (trans && trans->Buffer) ExFreePoolWithTag(trans->Buffer, 'usTs');
    if (trans) ExFreePoolWithTag(trans, 'usTs');
    return status;
}

//
// 校验文件签名
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdValidateSignature(
    _In_ PUNICODE_STRING FilePath
    )
{
    UNREFERENCED_PARAMETER(FilePath);
    return TRUE;
}

//
// 计算熵值（Shannon 整数熵 ×1000，对齐 SS MmMonitorCalculateEntropy）
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdCalculateEntropy(
    _In_ PVOID Buffer,
    _In_ ULONG Size
    )
/*++
Routine Description:
    计算缓冲区的 Shannon 熵值，纯整数运算（无浮点依赖），结果 ×1000（0-8000）。
    用于高熵内容预判（shellcode/加密载荷/加壳数据）。
Arguments:
    Buffer - 待分析缓冲。
    Size   - 缓冲大小（字节）。
Return Value:
    熵值 ×1000，范围 [0, 8000]。
--*/
{
    PUCHAR data = (PUCHAR)Buffer;
    ULONG byteCount[256] = { 0 };
    ULONG entropy = 0;
    ULONG log2N = 0;
    ULONG tempN;
    ULONG i;

    if (Buffer == NULL || Size == 0) {
        return 0;
    }

    // 统计字节频率
    for (i = 0; i < Size; i++) {
        byteCount[data[i]]++;
    }

    // floor(log2(Size))
    tempN = Size;
    while (tempN > 1) {
        log2N++;
        tempN >>= 1;
    }

    // Shannon: H = -sum(p*log2(p))，整数近似
    // 每项贡献 = Count * (log2(N) - log2(Count)) * 1000 / N
    for (i = 0; i < 256; i++) {
        ULONG count = byteCount[i];
        ULONG log2C = 0;
        ULONG tempC;

        if (count == 0) {
            continue;
        }

        // floor(log2(Count))
        tempC = count;
        while (tempC > 1) {
            log2C++;
            tempC >>= 1;
        }

        if (log2N > log2C) {
            entropy += (ULONG)((ULONGLONG)count * (log2N - log2C) * 1000ULL / Size);
        }
    }

    // cap 8000（8 bit 最大熵 ×1000）
    if (entropy > 8000) {
        entropy = 8000;
    }

    return entropy;
}

//
// 跨进程内存读取（对齐 SS MmpReadProcessMemory）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    附加到目标进程读取指定地址的内存（SEH 保护）。
    对齐 SS MmpReadProcessMemory（MemoryMonitor.c），由 AmsiBypassDetector
    的 AbdpReadProcessMemory（原 static、PAGE_SIZE 上限）迁出扩展为通用工具。
Arguments:
    ProcessId - 目标进程 PID。
    Address   - 源地址（目标进程虚拟地址空间）。
    Buffer    - 输出缓冲。
    Size      - 读取大小。
Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    PAGED_CODE();

    if (Buffer == NULL || Address == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    /* __try { */
        ProbeForRead(Address, Size, 1);
        RtlCopyMemory(Buffer, Address, Size);
        status = STATUS_SUCCESS;
    /* } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode(); } */

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

//
// Base64解码
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdBase64Decode(
    _In_ PUNICODE_STRING Encoded,
    _Out_ PVOID* Decoded,
    _Out_ PULONG DecodedSize
    )
{
    UNREFERENCED_PARAMETER(Encoded);
    UNREFERENCED_PARAMETER(Decoded);
    UNREFERENCED_PARAMETER(DecodedSize);
    return STATUS_NOT_IMPLEMENTED;
}

//
// 内存分配
//
_IRQL_requires_(PASSIVE_LEVEL)
PVOID
WkdAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
    )
{
    return ExAllocatePool2(PoolType, Size, Tag);
}

//
// 内存释放
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdFreePoolWithTag(
    _In_ PVOID Buffer,
    _In_ ULONG Tag
    )
{
    UNREFERENCED_PARAMETER(Tag);
    ExFreePoolWithTag(Buffer, Tag);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoCopyUnicodeString(
    _Out_ PUNICODE_STRING* Dst,
    _In_ PCUNICODE_STRING Src
    )
{
    NTSTATUS status;
    PUNICODE_STRING string;

    if (!Dst || !CoCheckUnicodeStringValidity(Src)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Dst = NULL;

    string = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'usp');
    if (!string) return STATUS_NO_MEMORY;

    string->Length = Src->Length;
    string->MaximumLength = Src->Length + sizeof(WCHAR);
    string->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, string->MaximumLength, 'uspb');
    if (!string->Buffer) {
        ExFreePoolWithTag(string, 'usp');
        return STATUS_NO_MEMORY;
    }

    RtlCopyMemory(string->Buffer, Src->Buffer, Src->Length);
    string->Buffer[string->Length / sizeof(WCHAR)] = '\0';

    *Dst = string;
    return STATUS_SUCCESS;
}

//
// 获取 Windows 构建号
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
UtGetWindowsBuildNumber(
    VOID
    )
{
    RTL_OSVERSIONINFOW osVersion;
    NTSTATUS status;

    // 如果已初始化，直接返回缓存值
    if (WkdWindowsBuildNumber) {
        return WkdWindowsBuildNumber;
    }

    // 获取操作系统版本信息
    RtlZeroMemory(&osVersion, sizeof(RTL_OSVERSIONINFOW));
    osVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    
    status = RtlGetVersion(&osVersion);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get Windows version: 0x%08X\n", status);
        return 0;
    }

    // 缓存构建号
    WkdWindowsBuildNumber = osVersion.dwBuildNumber;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Windows Build Number: %lu\n", WkdWindowsBuildNumber);

    return WkdWindowsBuildNumber;
}

//
// 判断是否为 Windows 11 或更高版本
// Windows 11 起始构建号为 22000
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdIsWindows11OrLater(
    VOID
    )
{
    ULONG buildNumber = UtGetWindowsBuildNumber();
    return (buildNumber >= 22000);
}

//
// 获取当前线程的系统调用号
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
UtGetCurrentThreadSyscallNumber(
    VOID
    )
{
    ULONG syscallNumber = 0;

    /* 目标结构体：_WMI_LOGGER_CONTEXT::GetCpuClock */

    switch (UtGetWindowsBuildNumber()) {
    case 19045:
        syscallNumber = *(PULONG)((ULONG64)KeGetCurrentThread() + 0x80);
        break;
    default:
        break;
    }

    return syscallNumber;
}

//
// 获取当前线程的Trap Frame
//
_IRQL_requires_(PASSIVE_LEVEL)
PKTRAP_FRAME
UtGetCurrentThreadTrapFrame(
    VOID
)
{
    PKTRAP_FRAME trapFrame = NULL;
   
    switch (UtGetWindowsBuildNumber()) {
    case 19045:
        trapFrame = *(PKTRAP_FRAME *)((ULONG64)KeGetCurrentThread() + 0x90);
        break;
    default:
        break;
    }

    return trapFrame;
}

//
// 获取内核模块基地址
// 通过 DriverObject->DriverSection 遍历已加载模块链表
// 优势：无需依赖未导出的 PsLoadedModuleList 全局变量
//
_IRQL_requires_(PASSIVE_LEVEL)
PVOID
UtGetKernelModuleBase(
    _In_ PCWSTR ModuleName
    )
{
    PKLDR_DATA_TABLE_ENTRY currentEntry;
    PLIST_ENTRY listHead;
    UNICODE_STRING usMoudleName;
    PVOID moduleBase = NULL;

    if (!ModuleName) {
        return NULL;
    }

    // 初始化目标模块名称
    RtlInitUnicodeString(&usMoudleName, ModuleName);

    // 检查是否已初始化 DriverObject
    if (!WkdDriverObject || !WkdDriverObject->DriverSection) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] WkdDriverObject not initialized\n");
        return NULL;
    }

    /* __try { */
        // 从当前驱动的 DriverSection 开始遍历
        currentEntry = (PKLDR_DATA_TABLE_ENTRY)WkdDriverObject->DriverSection;
        listHead = &currentEntry->InLoadOrderLinks;

        // 遍历模块链表
        do {
            // 使用 SEH 保护访问每个模块条目
            /* __try { */
                // 比较模块名称（不区分大小写）
                if (currentEntry->BaseDllName.Length > 0 &&
                    currentEntry->BaseDllName.Buffer &&
                    RtlEqualUnicodeString(&currentEntry->BaseDllName, &usMoudleName, TRUE)) {
                        
                    moduleBase = currentEntry->DllBase;
                        
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[WkDefender] Found module %wZ at base 0x%p\n",
                        &currentEntry->BaseDllName, moduleBase);
                        
                    break;
                }
                
                // 移动到下一个模块
                currentEntry = CONTAINING_RECORD(
                    currentEntry->InLoadOrderLinks.Flink,
                    KLDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks
                );
                
            /* }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[WkDefender] Exception accessing module entry\n");
                // 继续遍历下一个模块
                // 注意：如果 currentEntry 本身访问异常导致无法获取 Flink，这里可能会有问题
                // 但在大多数情况下，CONTAINING_RECORD 只是指针运算，是安全的
                currentEntry = CONTAINING_RECORD(
                    currentEntry->InLoadOrderLinks.Flink,
                    KLDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks
                );
            } */
            
        } while (&currentEntry->InLoadOrderLinks != listHead);
        
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception traversing module list: 0x%08X\n",
            GetExceptionCode());
    } */

    if (!moduleBase) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Module %ws not found\n", ModuleName);
    }

    return moduleBase;
}


//
// 获取 ntoskrnl.exe 基地址（带缓存）
//
_IRQL_requires_(PASSIVE_LEVEL)
PVOID
UtGetNtoskrnlBase(
    VOID
)
{
    PVOID base = NULL;

    if (WkdNtoskrnlBase != NULL) {
        return WkdNtoskrnlBase;
    }

    // 尝试常见的内核模块名称（按优先级排序）
    PCWSTR kernelNames[] = {
        L"ntoskrnl.exe",   // 标准单处理器内核
        L"ntkrnlmp.exe",   // 多处理器内核
        L"ntkrnlpa.exe",   // PAE 模式内核
        L"ntkrpamp.exe"    // PAE + 多处理器
    };
    
    for (ULONG i = 0; i < RTL_NUMBER_OF(kernelNames); i++) {
        base = UtGetKernelModuleBase(kernelNames[i]);
        if (base != NULL) {
            break;
        }
    }
    
    if (base != NULL) {
        // 原子操作确保线程安全（虽然 PASSIVE_LEVEL 下通常单线程调用）
        InterlockedCompareExchangePointer(
            (PVOID volatile *)&WkdNtoskrnlBase,
            base,
            NULL
        );
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Cached kernel base: 0x%p\n", WkdNtoskrnlBase);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to find kernel module base\n");
    }

    return WkdNtoskrnlBase;
}

_Use_decl_annotations_
NTSTATUS
CoGetBasenameFromPath(
    _In_ PCUNICODE_STRING Path,
    _Out_ PUNICODE_STRING Basename
    )
/*++
Routine Description:
    从镜像路径提取 basename（最后一个分隔符之后的部分，零拷贝）。

Arguments:
    Path      - 镜像路径。
    Basename  - 输出 basename（零拷贝视图，指向原缓冲）。

Return Value:
    TRUE 提取成功（Length > 0）。
--*/
{
    USHORT lastSlash = 0;
    USHORT basenameLength;

    if (!Path || !Path->Buffer || Path->Length == 0 ||
        !Basename) {
        return STATUS_INVALID_PARAMETER;
    }
    /* 输入目录而非文件 */
    if (Path->Buffer[Path->Length - 1 == L'\\']) {
        return STATUS_NOT_FOUND;
    }
    RtlZeroMemory(Basename, sizeof(UNICODE_STRING));

    for (ULONG i = 0; i < Path->Length / sizeof(WCHAR); i++) {
        if (Path->Buffer[i] == L'\\') {
            lastSlash = i + 1;
        }
    }

    basenameLength = Path->Length - (lastSlash * sizeof(WCHAR));
    if (basenameLength > 0) {
        Basename->Buffer = &Path->Buffer[lastSlash];
        Basename->Length = basenameLength;
        Basename->MaximumLength = basenameLength + sizeof(WCHAR);
        return STATUS_SUCCESS;
    }
    
    /* 发生了未知错误??? */
    return STATUS_UNSUCCESSFUL;
}
