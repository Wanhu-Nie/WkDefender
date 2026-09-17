/**************************************************/
/*  WkDefender Agent — 时序逃逸检测引擎             */
/*  AntiEvasio / TimeBasedEvasionDetector.c        */
/*                                                  */
/*  迁移自 ShadowStrike TimeBasedEvasionDetector    */
/*  (.hpp 1778行 + .cpp 2676行)。纯 C 实现。        */
/*                                                  */
/*  架构：                                           */
/*    - RDTSC/RDTSCP 字节模式扫描（主模块代码）      */
/*    - 睡眠逃避分析（PE 导入 + 监控上下文证据）     */
/*    - API 时序交叉校验（PE 导入分类）              */
/*    - NTP/网络时间校验（命令行 + 导入分析）        */
/*    - 硬件定时器操作（ntdll 定时器解析导入）       */
/*    - 多技术关联与威胁评分（T1497.003 映射）       */
/*    - 持续监控线程（CreateThread + 停止事件）      */
/*                                                  */
/*  降级决策（详见头文件）：                         */
/*    - PhantomDisassembler → 字节模式扫描           */
/*    - PEParser           → 内联 PE 导入解析       */
/*    - asm 时序函数       → 全部省略（零调用）     */
/*    - ThreadPool/异步    → 省略（仅同步分析）     */
/*    - std::thread/CV     → CreateThread + 事件     */
/*    - std::function 回调 → 函数指针槽位数组       */
/*    - std::chrono        → GetTickCount64 毫秒    */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "TimeBasedEvasionDetector.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <math.h>
#include <intrin.h>

#include <tlhelp32.h>

#define TED_TAG 'deTx'

/**************************************************/
/*          内部工具宏                             */
/**************************************************/

#define TED_ARRAY_COUNT(a)  (sizeof(a) / sizeof((a)[0]))

/* NOMINMAX 模式下 CRT min/max 不可用，自备（避免与常量前缀混淆，
   使用全大写参数名） */
#define TED_MIN(A, B)  (((A) < (B)) ? (A) : (B))
#define TED_MAX(A, B)  (((A) > (B)) ? (A) : (B))

#define TED_CLAMP_ULONG(v, lo, hi) \
    (((v) < (lo)) ? (lo) : (((v) > (hi)) ? (hi) : (v)))

#define TED_CLAMP_DOUBLE(v, lo, hi) \
    (((v) < (lo)) ? (lo) : (((v) > (hi)) ? (hi) : (v)))

#define TED_CLAMP_FLOAT(v, lo, hi) \
    (((v) < (lo)) ? (lo) : (((v) > (hi)) ? (hi) : (v)))

/* 宽字符串安全拷贝（带 NUL 终止；src 为 NULL 时置空串） */
#define TED_WCOPY(dst, src, cap) \
    do { \
        if ((src) != NULL) { \
            (void)wcsncpy_s((dst), (cap), (src), _TRUNCATE); \
        } else { \
            (dst)[0] = L'\0'; \
        } \
    } while (0)

/* 窄字符串安全拷贝（带 NUL 终止；src 为 NULL 时置空串） */
#define TED_ACOPY(dst, src, cap) \
    do { \
        if ((src) != NULL) { \
            (void)strncpy_s((dst), (cap), (src), _TRUNCATE); \
        } else { \
            (dst)[0] = '\0'; \
        } \
    } while (0)

/* 结果位图操作：DetectedTypes 为 256 位（32 字节）位图 */
#define TED_BITMAP_SET(Bitmap, Type) \
    do { (Bitmap)[(Type) >> 3] |= (UINT8)(1u << ((Type) & 7)); } while (0)

#define TED_BITMAP_TEST(Bitmap, Type) \
    (((Bitmap)[(Type) >> 3] & (UINT8)(1u << ((Type) & 7))) != 0)

/**************************************************/
/*          内部结构：进程模块信息                 */
/**************************************************/

typedef struct _TED_PROCESS_MODULE_INFO {
    WCHAR       Path[TED_MAX_PATH];             /* 模块盘路径 */
    WCHAR       BaseName[TED_MAX_PROCESS_NAME]; /* 模块文件名 */
    ULONG_PTR   BaseAddress;                    /* 加载基址 */
    SIZE_T      Size;                           /* 映像大小 */
} TED_PROCESS_MODULE_INFO;

/**************************************************/
/*          静态数据表（对齐源 cpp 常量表）        */
/**************************************************/

/* 时序 API 导入名 */
static const CHAR* const g_TedTimingApiImports[] = {
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "GetSystemTimeAsFileTime",
    "GetSystemTimePreciseAsFileTime",
    "timeGetTime",
    "NtQuerySystemTime",
    "RtlGetSystemTimePrecise"
};
#define TED_TIMING_API_IMPORT_COUNT TED_ARRAY_COUNT(g_TedTimingApiImports)

/* 睡眠相关 API 导入名 */
static const CHAR* const g_TedSleepApiImports[] = {
    "Sleep",
    "SleepEx",
    "NtDelayExecution",
    "WaitForSingleObject",
    "WaitForSingleObjectEx",
    "WaitForMultipleObjects",
    "WaitForMultipleObjectsEx",
    "MsgWaitForMultipleObjects",
    "MsgWaitForMultipleObjectsEx",
    "SetWaitableTimer",
    "SetWaitableTimerEx"
};
#define TED_SLEEP_API_IMPORT_COUNT TED_ARRAY_COUNT(g_TedSleepApiImports)

/* NTP 服务器域名特征（命令行搜索） */
static const WCHAR* const g_TedNtpPatterns[] = {
    L"time.windows.com",
    L"time.nist.gov",
    L"pool.ntp.org",
    L"time.google.com",
    L"ntp.ubuntu.com",
    L"time.apple.com",
    L"clock.isc.org"
};
#define TED_NTP_PATTERN_COUNT TED_ARRAY_COUNT(g_TedNtpPatterns)

/* DLL 子串 → 外部时间校验分类（小写匹配） */
static const WCHAR* const g_TedHttpTimeDllPatterns[] = {
    L"winhttp",
    L"wininet"
};
#define TED_HTTP_TIME_DLL_COUNT TED_ARRAY_COUNT(g_TedHttpTimeDllPatterns)

/* ws2_32（UDP → NTP 可能） */
static const WCHAR* const g_TedNtpSocketDllPattern = L"ws2_32";

/* 硬件定时器解析 API（ntdll） */
static const CHAR* const g_TedHardwareTimerApis[] = {
    "NtQueryTimerResolution",
    "NtSetTimerResolution"
};
#define TED_HARDWARE_TIMER_API_COUNT TED_ARRAY_COUNT(g_TedHardwareTimerApis)

/**************************************************/
/*          时序指令模式（对齐源 TimingPatterns）  */
/**************************************************/

/* RDTSC (0F 31) */
static const UINT8 g_TedRdtscPattern[]  = { 0x0F, 0x31 };
#define TED_RDTSC_PATTERN_LEN (sizeof(g_TedRdtscPattern))

/* RDTSCP (0F 01 F9) */
static const UINT8 g_TedRdtscpPattern[] = { 0x0F, 0x01, 0xF9 };
#define TED_RDTSCP_PATTERN_LEN (sizeof(g_TedRdtscpPattern))

/* CPUID (0F A2) */
static const UINT8 g_TedCpuidPattern[]  = { 0x0F, 0xA2 };
#define TED_CPUID_PATTERN_LEN (sizeof(g_TedCpuidPattern))

/*++
 
TedCountPatternOccurrences

    统计缓冲区中指定字节模式的出现次数（重叠不计数，
    命中后跳过整个模式长度继续扫描）。

--*/
static SIZE_T
TedCountPatternOccurrences(
    _In_reads_(BufferSize) const UINT8* Buffer,
    _In_ SIZE_T BufferSize,
    _In_reads_(PatternSize) const UINT8* Pattern,
    _In_ SIZE_T PatternSize
    )
{
    SIZE_T count = 0;
    SIZE_T i;

    if (Buffer == NULL || Pattern == NULL || PatternSize == 0) {
        return 0;
    }

    for (i = 0; i + PatternSize <= BufferSize; ++i) {
        SIZE_T j;
        BOOLEAN match = TRUE;

        for (j = 0; j < PatternSize; ++j) {
            if (Buffer[i + j] != Pattern[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            ++count;
            i += PatternSize - 1;   /* 跳过已匹配模式 */
        }
    }
    return count;
}

/*++
 
TedCountRdtscCpuidCombos

    统计 CPUID 后 20 字节距离内出现 RDTSC 的组合数。
    这是反 VM 探测（序列化时序）的典型模式。
    命中后仅跳过已消费的 CPUID 长度，避免跳过相邻
    组合（源 CORRECTNESS FIX 同款逻辑）。

--*/
static SIZE_T
TedCountRdtscCpuidCombos(
    _In_reads_(BufferSize) const UINT8* Buffer,
    _In_ SIZE_T BufferSize
    )
{
    SIZE_T count = 0;
    SIZE_T i;

    if (Buffer == NULL || BufferSize < TED_CPUID_PATTERN_LEN) {
        return 0;
    }

    for (i = 0; i + TED_CPUID_PATTERN_LEN <= BufferSize; ++i) {
        /* 匹配 CPUID */
        if (memcmp(Buffer + i, g_TedCpuidPattern, TED_CPUID_PATTERN_LEN) == 0) {
            SIZE_T j;

            /* 在 CPUID 后 20 字节内寻找 RDTSC */
            for (j = i + TED_CPUID_PATTERN_LEN;
                 j < BufferSize && j < i + TED_RDTSC_CPUID_MAX_DISTANCE;
                 ++j) {
                if (j + TED_RDTSC_PATTERN_LEN <= BufferSize &&
                    memcmp(Buffer + j, g_TedRdtscPattern, TED_RDTSC_PATTERN_LEN) == 0) {
                    ++count;
                    /* 跳过刚消费的 CPUID（外层 ++i 再前进一位） */
                    i += TED_CPUID_PATTERN_LEN - 1;
                    break;
                }
            }
        }
    }
    return count;
}

/**************************************************/
/*          宽串小写包含匹配                       */
/**************************************************/

/*++
 
TedWcsContainsICase

    判断 Haystack 是否包含 Needle（不区分大小写）。
    空 Needle 恒为 TRUE；空 Haystack 恒为 FALSE。

--*/
static BOOLEAN
TedWcsContainsICase(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    PCWSTR h;

    if (Needle == NULL || Needle[0] == L'\0') {
        return TRUE;
    }
    if (Haystack == NULL) {
        return FALSE;
    }

    for (h = Haystack; *h != L'\0'; ++h) {
        PCWSTR hp = h;
        PCWSTR np = Needle;

        while (*np != L'\0' && *hp != L'\0' &&
               towlower((wint_t)*hp) == towlower((wint_t)*np)) {
            ++hp;
            ++np;
        }
        if (*np == L'\0') {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*          内联 PE 解析（迁移自 SED 同款实现）    */
/**************************************************/

typedef struct _TED_PE_FILE {
    const UINT8* Data;                    /* 磁盘映像缓冲区 */
    SIZE_T       Size;
    BOOLEAN      Is64Bit;
    ULONG        SectionCount;
    const IMAGE_SECTION_HEADER* Sections;
    ULONG        ImportDirRva;
    ULONG        ImportDirSize;
} TED_PE_FILE;

/*++
 
TedPeRvaToOffset

    RVA → 文件偏移（节内映射；无节时按平铺近似）。

--*/
static BOOLEAN
TedPeRvaToOffset(
    _In_ const TED_PE_FILE* Pe,
    _In_ ULONG Rva,
    _Out_ PSIZE_T Offset
    )
{
    ULONG i;

    if (Pe == NULL || Offset == NULL || Pe->Data == NULL) {
        return FALSE;
    }

    if (Pe->SectionCount == 0) {
        if (Rva < Pe->Size) {
            *Offset = Rva;
            return TRUE;
        }
        return FALSE;
    }

    for (i = 0; i < Pe->SectionCount; ++i) {
        const IMAGE_SECTION_HEADER* s = &Pe->Sections[i];
        ULONG extent = (s->Misc.VirtualSize > s->SizeOfRawData)
            ? s->Misc.VirtualSize : s->SizeOfRawData;

        if (Rva >= s->VirtualAddress && Rva < s->VirtualAddress + extent) {
            if (s->SizeOfRawData == 0) {
                return FALSE;
            }
            *Offset = s->PointerToRawData + ((SIZE_T)Rva - s->VirtualAddress);
            return (*Offset < Pe->Size);
        }
    }
    return FALSE;
}

/*++
 
TedPeLoad

    读取磁盘 PE 文件到堆缓冲并初始化解析上下文。
    调用者负责 HeapFree(*OutData)。

--*/
static BOOLEAN
TedPeLoad(
    _In_ PCWSTR Path,
    _Out_ PBYTE* OutData,
    _Out_ PSIZE_T OutSize,
    _Out_ PTED_PE_FILE Pe
    )
{
    HANDLE hFile;
    LARGE_INTEGER fileSize;
    PBYTE data;
    DWORD bytesRead;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;

    if (Path == NULL || OutData == NULL || OutSize == NULL || Pe == NULL) {
        return FALSE;
    }

    hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > (LONGLONG)(256 * 1024 * 1024)) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                            (SIZE_T)fileSize.QuadPart);
    if (data == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, data, (DWORD)fileSize.QuadPart, &bytesRead, NULL) ||
        bytesRead != (DWORD)fileSize.QuadPart) {
        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    /* --- 头校验 --- */
    if ((SIZE_T)fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }
    dos = (const IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > (SIZE_T)fileSize.QuadPart) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }
    nt = (const IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }

    RtlZeroMemory(Pe, sizeof(*Pe));
    Pe->Data = data;
    Pe->Size = (SIZE_T)fileSize.QuadPart;
    Pe->SectionCount = nt->FileHeader.NumberOfSections;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32* opt32 =
            (const IMAGE_OPTIONAL_HEADER32*)&nt->OptionalHeader;
        Pe->Is64Bit = FALSE;
        Pe->ImportDirRva = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        Pe->ImportDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* opt64 =
            (const IMAGE_OPTIONAL_HEADER64*)&nt->OptionalHeader;
        Pe->Is64Bit = TRUE;
        Pe->ImportDirRva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        Pe->ImportDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }

    /* 节表边界校验 */
    if (Pe->SectionCount > 0) {
        const UINT8* p = (const UINT8*)IMAGE_FIRST_SECTION(nt);
        if ((SIZE_T)(p - data) +
            (SIZE_T)Pe->SectionCount * sizeof(IMAGE_SECTION_HEADER) > Pe->Size) {
            HeapFree(GetProcessHeap(), 0, data);
            RtlZeroMemory(Pe, sizeof(*Pe));
            return FALSE;
        }
        Pe->Sections = (const IMAGE_SECTION_HEADER*)p;
    }

    *OutData = data;
    *OutSize = Pe->Size;
    return TRUE;
}

/*++
 
TedPeImportsContain

    遍历 PE 导入表，判断函数 `FunctionName` 是否被导入。
    命中时（可选）经 OutWide 输出宽字符函数名。

--*/
static BOOLEAN
TedPeImportsContain(
    _In_ const TED_PE_FILE* Pe,
    _In_ PCSTR FunctionName,
    _Out_opt_ _Out_writes_(OutChars) PWSTR OutWide,
    _In_ SIZE_T OutChars
    )
{
    SIZE_T idescOff;
    const IMAGE_IMPORT_DESCRIPTOR* idesc;
    SIZE_T numDesc;
    SIZE_T i;

    if (Pe == NULL || Pe->Data == NULL || FunctionName == NULL ||
        Pe->ImportDirRva == 0 || Pe->ImportDirSize == 0) {
        return FALSE;
    }

    if (!TedPeRvaToOffset(Pe, Pe->ImportDirRva, &idescOff) ||
        idescOff + Pe->ImportDirSize > Pe->Size) {
        return FALSE;
    }

    idesc = (const IMAGE_IMPORT_DESCRIPTOR*)(Pe->Data + idescOff);
    numDesc = Pe->ImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (numDesc > 512) {
        numDesc = 512;
    }

    for (i = 0; i < numDesc; ++i) {
        ULONG thunkRva;
        SIZE_T thunkOff;
        ULONG_PTR ordinalFlag;
        SIZE_T orgThunkSize;

        /* 全零描述符 = 表尾 */
        if (idesc[i].OriginalFirstThunk == 0 && idesc[i].FirstThunk == 0) {
            break;
        }

        /* 优先 INT（OriginalFirstThunk），无则用 IAT（FirstThunk） */
        thunkRva = (idesc[i].OriginalFirstThunk != 0)
            ? idesc[i].OriginalFirstThunk : idesc[i].FirstThunk;
        if (!TedPeRvaToOffset(Pe, thunkRva, &thunkOff) ||
            thunkOff >= Pe->Size) {
            continue;
        }

        orgThunkSize = Pe->Is64Bit ? 8 : 4;
        ordinalFlag = Pe->Is64Bit ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

        for (;;) {
            ULONGLONG thunkValue = 0;
            SIZE_T byNameOff = 0;
            const IMAGE_IMPORT_BY_NAME* byName;

            if (thunkOff + orgThunkSize > Pe->Size) {
                break;
            }
            RtlCopyMemory(&thunkValue, Pe->Data + thunkOff, orgThunkSize);

            if (thunkValue == 0) {
                break;                          /* 表尾 */
            }
            if (thunkValue & ordinalFlag) {     /* 序号导入，跳过 */
                thunkOff += orgThunkSize;
                continue;
            }

            if (!TedPeRvaToOffset(Pe, (ULONG)thunkValue, &byNameOff) ||
                byNameOff + sizeof(IMAGE_IMPORT_BY_NAME) > Pe->Size) {
                thunkOff += orgThunkSize;
                continue;
            }
            byName = (const IMAGE_IMPORT_BY_NAME*)(Pe->Data + byNameOff);

            if (strcmp(byName->Name, FunctionName) == 0) {
                if (OutWide != NULL && OutChars > 0) {
                    MultiByteToWideChar(CP_ACP, 0, byName->Name, -1,
                                        OutWide, (int)OutChars);
                }
                return TRUE;
            }

            thunkOff += orgThunkSize;
        }
    }
    return FALSE;
}

/*++
 
TedPeDllImportsContain

    遍历 PE 导入表，判断 DLL 名包含 `DllSubstring`（不区分大小写）
    的模块中是否导入了 `FunctionName`。
    用于按模块归属分类（如 ntdll 定时器解析、winhttp 时间头）。

--*/
static BOOLEAN
TedPeDllImportsContain(
    _In_ const TED_PE_FILE* Pe,
    _In_ PCWSTR DllSubstring,
    _In_ PCSTR FunctionName
    )
{
    SIZE_T idescOff;
    const IMAGE_IMPORT_DESCRIPTOR* idesc;
    SIZE_T numDesc;
    SIZE_T i;

    if (Pe == NULL || Pe->Data == NULL || DllSubstring == NULL ||
        FunctionName == NULL || Pe->ImportDirRva == 0 || Pe->ImportDirSize == 0) {
        return FALSE;
    }

    if (!TedPeRvaToOffset(Pe, Pe->ImportDirRva, &idescOff) ||
        idescOff + Pe->ImportDirSize > Pe->Size) {
        return FALSE;
    }

    idesc = (const IMAGE_IMPORT_DESCRIPTOR*)(Pe->Data + idescOff);
    numDesc = Pe->ImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (numDesc > 512) {
        numDesc = 512;
    }

    for (i = 0; i < numDesc; ++i) {
        ULONG thunkRva;
        SIZE_T thunkOff;
        ULONG_PTR ordinalFlag;
        SIZE_T orgThunkSize;
        WCHAR dllName[TED_MAX_DLL_NAME];
        SIZE_T nameOff;

        /* 全零描述符 = 表尾 */
        if (idesc[i].OriginalFirstThunk == 0 && idesc[i].FirstThunk == 0) {
            break;
        }

        /* DLL 名匹配（Name 字段 RVA 指向宽字符串） */
        if (!TedPeRvaToOffset(Pe, idesc[i].Name, &nameOff) ||
            nameOff + sizeof(WCHAR) > Pe->Size) {
            continue;
        }
        if (wcsncpy_s(dllName, TED_MAX_DLL_NAME,
                      (PCWSTR)(Pe->Data + nameOff), _TRUNCATE) != 0) {
            continue;
        }
        if (!TedWcsContainsICase(dllName, DllSubstring)) {
            continue;
        }

        /* 遍历该 DLL 的导入函数 */
        thunkRva = (idesc[i].OriginalFirstThunk != 0)
            ? idesc[i].OriginalFirstThunk : idesc[i].FirstThunk;
        if (!TedPeRvaToOffset(Pe, thunkRva, &thunkOff) ||
            thunkOff >= Pe->Size) {
            continue;
        }

        orgThunkSize = Pe->Is64Bit ? 8 : 4;
        ordinalFlag = Pe->Is64Bit ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

        for (;;) {
            ULONGLONG thunkValue = 0;
            SIZE_T byNameOff = 0;
            const IMAGE_IMPORT_BY_NAME* byName;

            if (thunkOff + orgThunkSize > Pe->Size) {
                break;
            }
            RtlCopyMemory(&thunkValue, Pe->Data + thunkOff, orgThunkSize);

            if (thunkValue == 0) {
                break;
            }
            if (thunkValue & ordinalFlag) {
                thunkOff += orgThunkSize;
                continue;
            }

            if (!TedPeRvaToOffset(Pe, (ULONG)thunkValue, &byNameOff) ||
                byNameOff + sizeof(IMAGE_IMPORT_BY_NAME) > Pe->Size) {
                thunkOff += orgThunkSize;
                continue;
            }
            byName = (const IMAGE_IMPORT_BY_NAME*)(Pe->Data + byNameOff);

            if (strcmp(byName->Name, FunctionName) == 0) {
                return TRUE;
            }

            thunkOff += orgThunkSize;
        }
    }
    return FALSE;
}

/**************************************************/
/*          进程工具（内联，无外部 ProcessUtils）  */
/**************************************************/

/*++
 
TedOpenProcess

    以查询+读取权限打开进程（对齐源 PROCESS_QUERY_INFORMATION |
    PROCESS_VM_READ）。失败返回 NULL。

--*/
static HANDLE
TedOpenProcess(
    _In_ ULONG ProcessId
    )
{
    return OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                       FALSE, ProcessId);
}

/*++
 
TedIsProcess64Bit

    判断目标进程是否为 64 位（对齐 PES 同款实现）。

--*/
static BOOLEAN
TedIsProcess64Bit(
    _In_ HANDLE hProcess
    )
{
    BOOL isWow64 = FALSE;

    if (IsWow64Process(hProcess, &isWow64)) {
        return !isWow64;
    }
#ifdef _WIN64
    return TRUE;
#else
    return FALSE;
#endif
}

/*++
 
TedIsProcessRunning

    进程是否存活（GetExitCodeProcess 语义：STILL_ACTIVE）。
    打不开进程句柄视为不存在（对齐源 IsProcessRunning 简化）。

--*/
static BOOLEAN
TedIsProcessRunning(
    _In_ ULONG ProcessId
    )
{
    HANDLE hProcess;
    DWORD exitCode = 0;
    BOOLEAN running = FALSE;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    if (GetExitCodeProcess(hProcess, &exitCode)) {
        running = (exitCode == STILL_ACTIVE);
    }
    CloseHandle(hProcess);
    return running;
}

/*++
 
TedGetParentProcessId

    通过 Toolhelp 进程快照获取父进程 PID。失败返回 0。

--*/
static ULONG
TedGetParentProcessId(
    _In_ ULONG ProcessId
    )
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    ULONG parent = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ProcessId) {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return parent;
}

/*++
 
TedGetProcessNameByPid

    通过 Toolhelp 获取进程可执行文件名（szExeFile）。
    失败返回 FALSE。

--*/
static BOOLEAN
TedGetProcessNameByPid(
    _In_ ULONG ProcessId,
    _Out_writes_(NameChars) PWCHAR Name,
    _In_ ULONG NameChars
    )
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    BOOLEAN found = FALSE;

    if (Name == NULL || NameChars == 0) {
        return FALSE;
    }
    Name[0] = L'\0';

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ProcessId) {
                wcsncpy_s(Name, NameChars, pe.szExeFile, _TRUNCATE);
                found = TRUE;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/*++
 
TedGetMainModule

    获取进程主模块信息（路径/基址/大小）。可选返回已打开的句柄
    （调用者负责 CloseHandle）。

--*/
static BOOLEAN
TedGetMainModule(
    _In_ ULONG ProcessId,
    _Out_opt_ PTED_PROCESS_MODULE_INFO Module,
    _Out_opt_ PHANDLE OutHandle
    )
{
    HANDLE hProcess;
    HANDLE snap;
    MODULEENTRY32W me;
    BOOLEAN ok = FALSE;

    hProcess = TedOpenProcess(ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                    ProcessId);
    if (snap == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }

    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        if (Module != NULL) {
            RtlZeroMemory(Module, sizeof(*Module));
            wcsncpy_s(Module->Path, TED_MAX_PATH, me.szExePath, _TRUNCATE);
            wcsncpy_s(Module->BaseName, TED_MAX_PROCESS_NAME,
                      me.szModule, _TRUNCATE);
            Module->BaseAddress = (ULONG_PTR)me.modBaseAddr;
            Module->Size = (SIZE_T)me.modBaseSize;
        }
        ok = TRUE;
    } else {
        /* 32 位进程在 64 位宿主上快照失败时，退化为单进程进程快照补充 */
        /* （本模块主模块信息仅用于路径/基址，失败即返回 FALSE） */
    }

    CloseHandle(snap);

    if (OutHandle != NULL) {
        *OutHandle = hProcess;      /* 即使失败也返回句柄，由调用者关闭 */
    } else {
        CloseHandle(hProcess);
    }
    return ok;
}

/*++

TedGetProcessCommandLine

    通过 PEB 读取进程命令行（NtQueryInformationProcess + ReadProcessMemory）。
    支持 64 位目标（PEB64）与 32 位目标（PEB32/WOW64）。
    失败（权限不足/进程退出）返回 FALSE 并置空串。

    偏移依据（NT Internals 稳定布局）：
      - x64 PEB.ProcessParameters        = +0x20
      - x86 PEB.ProcessParameters        = +0x10
      - x64 RTL_USER_PROCESS_PARAMETERS.CommandLine = +0x70
      - x86 RTL_USER_PROCESS_PARAMETERS.CommandLine = +0x70

--*/
typedef struct _TED_PROCESS_BASIC_INFORMATION {
    PVOID       Reserved1;
    ULONG_PTR   PebBaseAddress;
    PVOID       Reserved2[2];
    ULONG_PTR   UniqueProcessId;
    PVOID       Reserved3;
} TED_PROCESS_BASIC_INFORMATION;

typedef struct _TED_UNICODE_STRING64 {
    USHORT      Length;
    USHORT      MaximumLength;
    ULONG       Padding;
    ULONGLONG   Buffer;
} TED_UNICODE_STRING64;

typedef struct _TED_UNICODE_STRING32 {
    USHORT      Length;
    USHORT      MaximumLength;
    ULONG       Buffer;
} TED_UNICODE_STRING32;

typedef NTSTATUS (NTAPI *PfnTedNtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

static PfnTedNtQueryInformationProcess g_TedNtQueryInfoProcess = NULL;

static BOOLEAN
TedGetProcessCommandLine(
    _In_ ULONG ProcessId,
    _Out_writes_(CommandLineChars) PWCHAR CommandLine,
    _In_ ULONG CommandLineChars
    )
{
    HANDLE hProcess;
    TED_PROCESS_BASIC_INFORMATION pbi;
    ULONG_PTR pebAddr;
    ULONG_PTR paramsAddr = 0;
    BOOLEAN is64Proc;
    BOOLEAN is64Host;
    ULONG cmdLen = 0;
    ULONG_PTR cmdBufAddr = 0;
    ULONG charsToCopy;
    ULONG bytesToRead;

    if (CommandLine == NULL || CommandLineChars == 0) {
        return FALSE;
    }
    CommandLine[0] = L'\0';

    if (g_TedNtQueryInfoProcess == NULL) {
        return FALSE;
    }

    hProcess = TedOpenProcess(ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    RtlZeroMemory(&pbi, sizeof(pbi));
    if (g_TedNtQueryInfoProcess(hProcess, 0 /* ProcessBasicInformation */,
                                &pbi, (ULONG)sizeof(pbi), NULL) < 0) {
        CloseHandle(hProcess);
        return FALSE;
    }
    pebAddr = pbi.PebBaseAddress;
    if (pebAddr == 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    is64Proc = TedIsProcess64Bit(hProcess);
#ifdef _WIN64
    is64Host = TRUE;
#else
    is64Host = FALSE;
#endif

    if (is64Proc && is64Host) {
        ULONG_PTR remoteParams = 0;
        TED_UNICODE_STRING64 cmd;

        /* PEB64 +0x20 → ProcessParameters */
        if (!ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x20),
                               &remoteParams, sizeof(remoteParams), NULL)) {
            CloseHandle(hProcess);
            return FALSE;
        }
        paramsAddr = remoteParams;
        if (paramsAddr == 0) {
            CloseHandle(hProcess);
            return FALSE;
        }

        /* ProcessParameters +0x70 → CommandLine (UNICODE_STRING64) */
        RtlZeroMemory(&cmd, sizeof(cmd));
        if (!ReadProcessMemory(hProcess, (LPCVOID)(paramsAddr + 0x70),
                               &cmd, sizeof(cmd), NULL)) {
            CloseHandle(hProcess);
            return FALSE;
        }
        cmdLen = cmd.Length;
        cmdBufAddr = (ULONG_PTR)cmd.Buffer;
    } else {
        ULONG remoteParams = 0;
        TED_UNICODE_STRING32 cmd;

        /* PEB32 +0x10 → ProcessParameters */
        if (!ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x10),
                               &remoteParams, sizeof(remoteParams), NULL)) {
            CloseHandle(hProcess);
            return FALSE;
        }
        paramsAddr = remoteParams;
        if (paramsAddr == 0) {
            CloseHandle(hProcess);
            return FALSE;
        }

        /* ProcessParameters +0x70 → CommandLine (UNICODE_STRING32) */
        RtlZeroMemory(&cmd, sizeof(cmd));
        if (!ReadProcessMemory(hProcess, (LPCVOID)(paramsAddr + 0x70),
                               &cmd, sizeof(cmd), NULL)) {
            CloseHandle(hProcess);
            return FALSE;
        }
        cmdLen = cmd.Length;
        cmdBufAddr = cmd.Buffer;
    }

    if (cmdBufAddr == 0 || cmdLen < sizeof(WCHAR)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    charsToCopy = cmdLen / sizeof(WCHAR);
    if (charsToCopy >= CommandLineChars) {
        charsToCopy = CommandLineChars - 1;
    }
    bytesToRead = charsToCopy * sizeof(WCHAR);

    if (!ReadProcessMemory(hProcess, (LPCVOID)cmdBufAddr,
                           CommandLine, bytesToRead, NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    CommandLine[charsToCopy] = L'\0';

    CloseHandle(hProcess);
    return TRUE;
}

/*++
 
TedGetNowMs

    当前单调时间戳（GetTickCount64 毫秒）。用于事件时间戳、
    分析起止时间与缓存 TTL 判定。

--*/
static ULONGLONG
TedGetNowMs(
    VOID
    )
{
    return GetTickCount64();
}

/*++
 
TedGetUnixSeconds

    当前 Unix 时间戳（秒），用于统计中的 lastAnalysisTimestamp。

--*/
static ULONGLONG
TedGetUnixSeconds(
    VOID
    )
{
    FILETIME ft;
    ULARGE_INTEGER ui;

    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    /* FILETIME（1601 纪元 100ns）→ Unix 秒（1970 纪元） */
    return (ui.QuadPart / 10000000ULL) - 11644473600ULL;
}

/**************************************************/
/*          内部结构（Part 2）                      */
/*  对齐源 Impl 的成员（进程监控上下文/回调/缓存）   */
/**************************************************/

typedef struct _TED_MONITORING_CONTEXT {
    ULONG       ProcessId;
    UINT8       State;                  /* TED_MON_STATE_* */
    UINT8       Reserved0[3];
    ULONGLONG   StartTimeMs;            /* 开始监控时间（GetTickCount64） */
    ULONGLONG   LastUpdateMs;

    /* 累积统计（监控线程按采样周期累加） */
    ULONGLONG   RdtscCount;
    ULONGLONG   TotalSleepDurationMs;
    ULONG       SleepCallCount;
    ULONG       GetTickCountCalls;
    ULONG       QpcCalls;

    /* 事件环形缓冲（容量 == EventCapacity，动态分配） */
    PTED_EVENT_RECORD Events;
    SIZE_T      EventCapacity;
    SIZE_T      EventCount;
    SIZE_T      EventWriteIndex;

    /* 检测状态 */
    BOOLEAN     RdtscHighFrequencyDetected;
    BOOLEAN     SleepBombingDetected;
    BOOLEAN     SleepAccelerationDetected;
    UINT8       LastNotifiedType;       /* 防抖：上次通知的主逃逸类型 */
    UINT8       Reserved1[3];
    ULONGLONG   LastNotifyMs;           /* 防抖：上次通知时刻 */
} TED_MONITORING_CONTEXT;

typedef struct _TED_CALLBACK_SLOT {
    ULONGLONG            Id;            /* 注册 ID（供注销） */
    BOOLEAN              Active;        /* 0=空闲 1=占用 */
    UINT8                Reserved0[3];
    TED_EVASION_CALLBACK Fn;
} TED_CALLBACK_SLOT;

typedef struct _TED_EVENT_CALLBACK_SLOT {
    ULONGLONG           Id;
    BOOLEAN             Active;
    UINT8               Reserved0[3];
    TED_EVENT_CALLBACK  Fn;
} TED_EVENT_CALLBACK_SLOT;

typedef struct _TED_CACHE_ENTRY {
    ULONG       ProcessId;
    ULONGLONG   InsertedMs;             /* GetTickCount64 插入时刻 */
    BOOLEAN     Valid;
    UINT8       Reserved0[3];
    PTED_RESULT Result;                 /* HeapAlloc 拷贝（避免数组放大） */
} TED_CACHE_ENTRY;

/*++
 
TedContextFindUnlocked

    线性查找进程监控上下文（调用者须已持有 monitor 写/读锁）。
    未找到返回 NULL。

--*/
static PTED_MONITORING_CONTEXT
TedContextFindUnlocked(
    _In_ ULONG ProcessId
    )
{
    ULONG i;

    for (i = 0; i < TED_ARRAY_COUNT(g_TedMonitoredProcesses); ++i) {
        if (g_TedMonitoredProcesses[i].ProcessId == ProcessId) {
            return &g_TedMonitoredProcesses[i];
        }
    }
    return NULL;
}

/*++
 
TedContextInit

    初始化监控上下文槽（前置：调用者确保槽空闲，如 StartMonitoring 的
    分配流程）。Capacity 被钳制到 TED_MAX_EVENTS_PER_PROCESS。

--*/
static BOOLEAN
TedContextInit(
    _Out_ PTED_MONITORING_CONTEXT Ctx,
    _In_ ULONG ProcessId,
    _In_ SIZE_T Capacity
    )
{
    SIZE_T cap;

    RtlZeroMemory(Ctx, sizeof(*Ctx));
    Ctx->ProcessId = ProcessId;

    cap = Capacity;
    if (cap > TED_MAX_EVENTS_PER_PROCESS) {
        cap = TED_MAX_EVENTS_PER_PROCESS;
    }
    Ctx->EventCapacity = cap;

    if (cap > 0) {
        Ctx->Events = (PTED_EVENT_RECORD)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, cap * sizeof(TED_EVENT_RECORD));
        if (Ctx->Events == NULL) {
            Ctx->EventCapacity = 0;
            return FALSE;
        }
    }
    return TRUE;
}

/*++
 
TedContextFree

    释放监控上下文资源并复位（调用者须持 monitor 写锁）。

--*/
static VOID
TedContextFree(
    _Inout_ PTED_MONITORING_CONTEXT Ctx
    )
{
    if (Ctx == NULL) {
        return;
    }
    if (Ctx->Events != NULL) {
        HeapFree(GetProcessHeap(), 0, Ctx->Events);
        Ctx->Events = NULL;
    }
    RtlZeroMemory(Ctx, sizeof(*Ctx));
}

/*++
 
TedContextAddEvent

    向监控上下文追加事件（环形缓冲，对齐源 AddEvent）。
    未填满时顺序追加；填满后覆盖 EventWriteIndex 并循环步进。

--*/
static VOID
TedContextAddEvent(
    _Inout_ PTED_MONITORING_CONTEXT Ctx,
    _In_ const TED_EVENT_RECORD* Event,
    _In_ SIZE_T MaxEvents
    )
{
    SIZE_T effectiveMax;

    if (Ctx == NULL || Event == NULL || Ctx->Events == NULL) {
        return;
    }
    effectiveMax = (Ctx->EventCapacity > 0)
        ? Ctx->EventCapacity : MaxEvents;
    if (effectiveMax == 0 || effectiveMax > TED_MAX_EVENTS_PER_PROCESS) {
        return;
    }

    if (Ctx->EventCount < effectiveMax) {
        Ctx->Events[Ctx->EventCount] = *Event;
        ++Ctx->EventCount;
        if (Ctx->EventCount == effectiveMax) {
            Ctx->EventWriteIndex = 0;
        }
    } else {
        Ctx->Events[Ctx->EventWriteIndex] = *Event;
        Ctx->EventWriteIndex =
            (Ctx->EventWriteIndex + 1) % effectiveMax;
    }
}

/**************************************************/
/*          全局实例状态（对齐源 Impl 静态成员）    */
/**************************************************/

static volatile LONG g_TedInitialized = 0;

static TED_CONFIG g_TedConfig;
static SRWLOCK   g_TedConfigLock = SRWLOCK_INIT;

static SRWLOCK   g_TedMonitorLock  = SRWLOCK_INIT;
static SRWLOCK   g_TedCallbackLock = SRWLOCK_INIT;
static SRWLOCK   g_TedCacheLock    = SRWLOCK_INIT;

static TED_STATS g_TedStats;

static TED_MONITORING_CONTEXT g_TedMonitoredProcesses[TED_MAX_MONITORED_PROCESSES];
static TED_CALLBACK_SLOT      g_TedCallbacks[TED_MAX_CALLBACKS];
static TED_EVENT_CALLBACK_SLOT g_TedEventCallbacks[TED_MAX_EVENT_CALLBACKS];

static volatile LONGLONG g_TedNextCallbackId = TED_CALLBACK_ID_START;

static TED_CACHE_ENTRY g_TedCache[TED_MAX_CACHE_ENTRIES];

/* 监控线程控制 */
static volatile LONG g_TedMonitoringActive = 0;
static HANDLE        g_TedMonitoringThread = NULL;
static HANDLE        g_TedStopEvent = NULL;      /* 手动复位，初始化时创建 */

/**************************************************/
/*          内部辅助：缓存                         */
/**************************************************/

/*++
 
TedCacheEntryFree

    释放缓存条目内结果拷贝（调用者须持 cache 写锁）。

--*/
static VOID
TedCacheEntryFree(
    _Inout_ PTED_CACHE_ENTRY Entry
    )
{
    if (Entry->Result != NULL) {
        HeapFree(GetProcessHeap(), 0, Entry->Result);
        Entry->Result = NULL;
    }
    Entry->Valid = FALSE;
    Entry->ProcessId = 0;
    Entry->InsertedMs = 0;
}

/*++
 
TedCacheFind

    按 PID 查找有效缓存条目。TTL 过期视为未命中（调用者须持
    cache 读/写锁；返回条目指针仅在持锁期间有效）。

--*/
static PTED_CACHE_ENTRY
TedCacheFind(
    _In_ ULONG ProcessId
    )
{
    ULONGLONG now = TedGetNowMs();
    ULONG i;
    PTED_CACHE_ENTRY hit = NULL;
    PTED_CACHE_ENTRY expired = NULL;

    for (i = 0; i < TED_ARRAY_COUNT(g_TedCache); ++i) {
        PTED_CACHE_ENTRY e = &g_TedCache[i];

        if (!e->Valid || e->ProcessId != ProcessId) {
            continue;
        }
        if (now - e->InsertedMs <= (ULONGLONG)g_TedConfig.ResultCacheTTLMs) {
            hit = e;
        } else {
            expired = e;    /* 过期条目：本次返回未命中但顺带记录待删 */
        }
    }

    if (expired != NULL && hit == NULL) {
        TedCacheEntryFree(expired);
    }
    return hit;
}

/*++
 
TedCacheInsert

    插入/更新缓存条目（调用者须持 cache 写锁）。
    满时批量淘汰最旧 TED_CACHE_EVICT_COUNT 条后再插入。

--*/
static BOOLEAN
TedCacheInsert(
    _In_ ULONG ProcessId,
    _In_ const TED_RESULT* Result
    )
{
    ULONG i;
    ULONG freeSlot = TED_ARRAY_COUNT(g_TedCache);
    ULONG lastEvicted = TED_ARRAY_COUNT(g_TedCache);
    ULONG evicted = 0;

    /* 已有条目 → 原位更新 */
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCache); ++i) {
        if (g_TedCache[i].Valid && g_TedCache[i].ProcessId == ProcessId) {
            freeSlot = i;
            break;
        }
        if (freeSlot == TED_ARRAY_COUNT(g_TedCache) && !g_TedCache[i].Valid) {
            freeSlot = i;
        }
    }

    if (freeSlot == TED_ARRAY_COUNT(g_TedCache)) {
        /* 满：批量淘汰最旧条目 */
        while (evicted < TED_CACHE_EVICT_COUNT) {
            ULONG oldest = TED_ARRAY_COUNT(g_TedCache);
            ULONGLONG oldestMs = (ULONGLONG)-1;

            for (i = 0; i < TED_ARRAY_COUNT(g_TedCache); ++i) {
                if (g_TedCache[i].Valid && g_TedCache[i].InsertedMs < oldestMs) {
                    oldestMs = g_TedCache[i].InsertedMs;
                    oldest = i;
                }
            }
            if (oldest == TED_ARRAY_COUNT(g_TedCache)) {
                break;      /* 无有效条目（理论不可达） */
            }
            TedCacheEntryFree(&g_TedCache[oldest]);
            lastEvicted = oldest;
            ++evicted;
        }
        if (evicted == 0) {
            return FALSE;
        }
        freeSlot = lastEvicted;
    }

    if (freeSlot == TED_ARRAY_COUNT(g_TedCache)) {
        return FALSE;
    }

    TedCacheEntryFree(&g_TedCache[freeSlot]);   /* 更新时释放旧拷贝 */
    g_TedCache[freeSlot].Result = (PTED_RESULT)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(TED_RESULT));
    if (g_TedCache[freeSlot].Result == NULL) {
        return FALSE;
    }
    RtlCopyMemory(g_TedCache[freeSlot].Result, Result, sizeof(TED_RESULT));
    g_TedCache[freeSlot].ProcessId = ProcessId;
    g_TedCache[freeSlot].InsertedMs = TedGetNowMs();
    g_TedCache[freeSlot].Valid = TRUE;
    return TRUE;
}

/*++
 
TedCacheClear

    清空全部缓存条目（调用者须持 cache 写锁）。

--*/
static VOID
TedCacheClear(
    VOID
    )
{
    ULONG i;

    for (i = 0; i < TED_ARRAY_COUNT(g_TedCache); ++i) {
        TedCacheEntryFree(&g_TedCache[i]);
    }
}

/**************************************************/
/*          内部辅助：统计                         */
/**************************************************/

/* 原子累加计数 */
#define TED_STATS_ADD(Field, Increment) \
    InterlockedExchangeAdd64(&(g_TedStats).Field, (LONGLONG)(Increment))

/* 原子置位（EMA 等） */
#define TED_STATS_SET(Field, Value) \
    InterlockedExchange64(&(g_TedStats).Field, (LONGLONG)(Value))

/*++
 
TedStatsUpdateAvgDurationUs

    平均分析耗时的指数移动平均（EMA 系数 1/8，对齐源）。
    CAS 保证并发安全。

--*/
static VOID
TedStatsUpdateAvgDurationUs(
    _In_ LONGLONG DurationUs
    )
{
    LONGLONG prev;
    LONGLONG next;

    do {
        prev = g_TedStats.AvgAnalysisDurationUs;
        next = prev - (prev >> 3) + (DurationUs >> 3);
    } while (InterlockedCompareExchange64(&(g_TedStats.AvgAnalysisDurationUs),
                                          next, prev) != prev);
}

/*++
 
TedBumpDetectionStats

    认定一次逃避后累加分类统计（并发回调复用时保持原子性）。

--*/
static VOID
TedBumpDetectionStats(
    _In_ ULONG Type,
    _In_ ULONGLONG DurationUs
    )
{
    TED_STATS_ADD(TotalEvasionsDetected, 1);
    if (Type < TED_TYPE_COUNT) {
        TED_STATS_ADD(DetectionsByType[Type], 1);
    }
    if (DurationUs > 0) {
        TedStatsUpdateAvgDurationUs((LONGLONG)DurationUs);
    }
}

/**************************************************/
/*          配置工厂与生命周期（Part 2）           */
/**************************************************/

/*++
 
TedSanitizeConfig

    将用户配置钳制到合法范围（内部函数，假定 Cfg 非空）。

--*/
static VOID
TedSanitizeConfig(
    _Inout_ PTED_CONFIG Cfg
    )
{
    Cfg->SampleIntervalMs = TED_CLAMP_ULONG(Cfg->SampleIntervalMs,
        TED_MIN_SAMPLE_INTERVAL_MS, TED_MAX_SAMPLE_INTERVAL_MS);
    Cfg->MaxMonitoredProcesses = TED_CLAMP_ULONG(Cfg->MaxMonitoredProcesses,
        1, TED_MAX_MONITORED_PROCESSES);
    Cfg->MaxEventsPerProcess = TED_CLAMP_ULONG(Cfg->MaxEventsPerProcess,
        1, TED_MAX_EVENTS_PER_PROCESS);
    Cfg->ResultCacheTTLMs = TED_CLAMP_ULONG(Cfg->ResultCacheTTLMs,
        1000, (24 * 60 * 60 * 1000));   /* 1 秒 ~ 1 天 */

    if (Cfg->SleepAccelerationThreshold <= 0.0) {
        Cfg->SleepAccelerationThreshold = TED_SLEEP_ACCELERATION_RATIO;
    }
}

/*++
 
TedCreateDefaultConfig

    默认配置（对齐源 CreateDefaultConfig）：全特性开启、标准阈值。

--*/
VOID
TedCreateDefaultConfig(
    _Out_ PTED_CONFIG Out
    )
{
    if (Out == NULL) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    Out->Enabled = TRUE;
    Out->ContinuousMonitoring = TRUE;
    Out->SampleIntervalMs = TED_DEFAULT_SAMPLE_INTERVAL_MS;
    Out->MaxMonitoredProcesses = TED_MAX_MONITORED_PROCESSES;
    Out->MaxEventsPerProcess = TED_MAX_EVENTS_PER_PROCESS;

    Out->RdtscFrequencyThreshold = TED_RDTSC_HIGH_FREQUENCY_THRESHOLD;
    Out->RdtscDeltaThresholdNs = TED_RDTSC_DELTA_VM_THRESHOLD_NS;
    Out->SleepEvasionThresholdMs = TED_SLEEP_EVASION_THRESHOLD_MS;
    Out->SleepAccelerationThreshold = TED_SLEEP_ACCELERATION_RATIO;
    Out->MinSleepFragments = TED_MIN_SLEEP_FRAGMENTS;
    Out->TimeDriftThresholdSeconds = TED_TIME_DRIFT_THRESHOLD_SECONDS;
    Out->TickCountAnomalyPercent = TED_TICKCOUNT_ANOMALY_PERCENT;
    Out->QpcAnomalyPercent = TED_QPC_ANOMALY_PERCENT;

    Out->DetectRDTSC = TRUE;
    Out->DetectSleepEvasion = TRUE;
    Out->DetectAPITiming = TRUE;
    Out->DetectNTPEvasion = TRUE;
    Out->DetectHardwareTimers = TRUE;
    Out->DetectSideChannels = FALSE;    /* 高开销，默认关闭 */
    Out->EnableCorrelation = TRUE;

    Out->MinReportableConfidence = TED_MIN_REPORTABLE_CONFIDENCE;
    Out->IncludeEventDetails = TRUE;
    Out->IncludeEvidence = FALSE;
    Out->EnableMitreMapping = TRUE;

    Out->EnableResultCache = TRUE;
    Out->ResultCacheTTLMs = TED_DEFAULT_CACHE_TTL_MS;
}

/*++
 
TedCreateHighSensitivityConfig

    高灵敏度配置（对齐源）：更激进阈值，开启侧信道检测。

--*/
VOID
TedCreateHighSensitivityConfig(
    _Out_ PTED_CONFIG Out
    )
{
    if (Out == NULL) {
        return;
    }
    TedCreateDefaultConfig(Out);

    Out->RdtscFrequencyThreshold = 1000;
    Out->SleepEvasionThresholdMs = 10000;
    Out->SleepAccelerationThreshold = 0.3;
    Out->MinReportableConfidence = 5.0f;
    Out->DetectSideChannels = TRUE;
    Out->IncludeEvidence = TRUE;
}

/*++
 
TedCreatePerformanceOptimizedConfig

    性能优化配置（对齐源）：大采样间隔、事件数最大化、
    关闭高开销特性。MaxEventsPerProcess 超纯 C 上限时钳制到 512。

--*/
VOID
TedCreatePerformanceOptimizedConfig(
    _Out_ PTED_CONFIG Out
    )
{
    if (Out == NULL) {
        return;
    }
    TedCreateDefaultConfig(Out);

    Out->SampleIntervalMs = 500;
    Out->ContinuousMonitoring = TRUE;
    Out->MaxEventsPerProcess = 10000;   /* 源值；TedSanitizeConfig 钳制 */
    Out->DetectSideChannels = FALSE;
    Out->IncludeEventDetails = FALSE;
    Out->IncludeEvidence = FALSE;

    TedSanitizeConfig(Out);
}

/*++
 
TedInitialize

    初始化检测器（可重复调用，后续调用为无操作，对齐源）。
    完成：函数解析、停止事件、默认配置、数据结构复位。

--*/
BOOLEAN
TedInitialize(
    _In_opt_ const TED_CONFIG* Config
    )
{
    ULONG i;

    if (InterlockedCompareExchange(&g_TedInitialized, 0, 0) != 0) {
        /* 已初始化：忽略新配置（对齐源日志行为） */
        return TRUE;
    }

    /* 延迟解析 NtQueryInformationProcess（命令行读取依赖） */
    if (g_TedNtQueryInfoProcess == NULL) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll != NULL) {
            g_TedNtQueryInfoProcess = (PfnTedNtQueryInformationProcess)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }

    if (g_TedStopEvent == NULL) {
        g_TedStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (g_TedStopEvent == NULL) {
            return FALSE;
        }
    }

    TedCreateDefaultConfig(&g_TedConfig);
    if (Config != NULL) {
        g_TedConfig = *Config;
        TedSanitizeConfig(&g_TedConfig);
    }

    for (i = 0; i < TED_ARRAY_COUNT(g_TedMonitoredProcesses); ++i) {
        RtlZeroMemory(&g_TedMonitoredProcesses[i],
                      sizeof(g_TedMonitoredProcesses[i]));
    }
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCache); ++i) {
        g_TedCache[i].Valid = FALSE;
        g_TedCache[i].ProcessId = 0;
        g_TedCache[i].InsertedMs = 0;
        g_TedCache[i].Result = NULL;
    }
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCallbacks); ++i) {
        g_TedCallbacks[i].Active = FALSE;
        g_TedCallbacks[i].Fn = NULL;
        g_TedCallbacks[i].Id = 0;
    }
    for (i = 0; i < TED_ARRAY_COUNT(g_TedEventCallbacks); ++i) {
        g_TedEventCallbacks[i].Active = FALSE;
        g_TedEventCallbacks[i].Fn = NULL;
        g_TedEventCallbacks[i].Id = 0;
    }

    InterlockedExchange(&g_TedInitialized, 1);
    return TRUE;
}

/*++
 
TedIsInitialized

    检测器是否已初始化。

--*/
BOOLEAN
TedIsInitialized(
    VOID
    )
{
    return InterlockedCompareExchange(&g_TedInitialized, 0, 0) != 0;
}

/*++
 
TedUpdateConfig

    运行时更新配置（对齐源 UpdateConfig，无复制修正）。
    已在运行的监控不受影响（对齐源语义：忽略 UpdateConfig 对
    活动监控的即时影响）。

--*/
VOID
TedUpdateConfig(
    _In_ const TED_CONFIG* Config
    )
{
    if (Config == NULL || !TedIsInitialized()) {
        return;
    }
    AcquireSRWLockExclusive(&g_TedConfigLock);
    g_TedConfig = *Config;
    TedSanitizeConfig(&g_TedConfig);
    ReleaseSRWLockExclusive(&g_TedConfigLock);
}

/*++
 
TedGetConfig

    获取当前配置副本。

--*/
BOOLEAN
TedGetConfig(
    _Out_ PTED_CONFIG Out
    )
{
    if (Out == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    AcquireSRWLockShared(&g_TedConfigLock);
    *Out = g_TedConfig;
    ReleaseSRWLockShared(&g_TedConfigLock);
    return TRUE;
}

/**************************************************/
/*          四个专项分析器（Part 3）                */
/*  对齐源 RegisterRDTSC/AnalyseSleep/RegisterAPITiming/  */
/*  RegisterNTPAnalysis。纯 C 降级：静态字节扫描、   */
/*  delta 无法反汇编推算处置 FALSE/0。              */
/**************************************************/

/* 睡眠 API 宽名表（与 g_TedSleepApiImports 一一对应，
   AnalyzeSleep 用于填充 SleepAPIsUsed 的人读名） */
static const WCHAR* const g_TedSleepApiImportsW[] = {
    L"Sleep",
    L"SleepEx",
    L"NtDelayExecution",
    L"WaitForSingleObject",
    L"WaitForSingleObjectEx",
    L"WaitForMultipleObjects",
    L"WaitForMultipleObjectsEx",
    L"MsgWaitForMultipleObjects",
    L"MsgWaitForMultipleObjectsEx",
    L"SetWaitableTimer",
    L"SetWaitableTimerEx"
};

/*++
 
TedExtractHttpHosts

    从命令行提取 http(s):// 主机名列表（对齐源 regex
    `https?://([^/]+)` 语义：截取到第一个 '/' 或空白）。
    已按 HostsMax 封顶；Count 返回提取数。

--*/
static VOID
TedExtractHttpHosts(
    _In_ PCWSTR CommandLine,
    _Out_ WCHAR Hosts[TED_MAX_HTTP_HOSTS][TED_MAX_HOSTNAME],
    _Out_ PULONG Count
    )
{
    PCWSTR p = CommandLine;
    static const PCWSTR Prefixes[2] = { L"https://", L"http://" };

    if (CommandLine == NULL || Hosts == NULL || Count == NULL) {
        return;
    }
    *Count = 0;

    while (*p != L'\0') {
        PCWSTR best = NULL;
        SIZE_T bestLen = 0;
        ULONG pi;

        /* 选取最近且最长匹配的前缀 */
        for (pi = 0; pi < 2; ++pi) {
            PCWSTR m = wcsstr(p, Prefixes[pi]);
            if (m != NULL) {
                SIZE_T mLen = wcslen(Prefixes[pi]);
                if (best == NULL || m < best ||
                    (m == best && mLen > bestLen)) {
                    best = m;
                    bestLen = mLen;
                }
            }
        }
        if (best == NULL) {
            break;
        }
        p = best + bestLen;

        /* 截取主机名：到 '/'、空白或引号为止 */
        {
            SIZE_T len = wcscspn(p, L"/ \t\r\n\"'");

            if (len > 0 && *Count < TED_MAX_HTTP_HOSTS) {
                if (len >= TED_MAX_HOSTNAME) {
                    len = TED_MAX_HOSTNAME - 1;
                }
                wcsncpy_s(Hosts[*Count], TED_MAX_HOSTNAME, p, len);
                ++(*Count);
            }
            p += len;
        }
    }
}

/*++
 
TedAnalyzeRDTSC

    RDTSC/RDTSCP/CPUID 组合的静态字节模式扫描（对齐源
    RegisterRDTSCAnalysis 的进制反汇编预期——纯 C 无反汇编，
    以模式统计替代）。
    注意：DeltaCheck/FrequencyMeasurement 依赖反汇编时序仿真，
    静态扫描无法推算，恒为 FALSE（注释保留源语义）。

--*/
BOOLEAN
TedAnalyzeRDTSC(
    _In_ ULONG ProcessId,
    _Out_ PTED_RDTSC_ANALYSIS Out
    )
{
    HANDLE hProcess;
    TED_PROCESS_MODULE_INFO module;
    PBYTE code = NULL;
    SIZE_T scanSize = 0;
    SIZE_T readSize = 0;
    DWORD bytesRead = 0;
    ULONGLONG rdtscCount = 0;
    ULONGLONG rdtscpCount = 0;
    ULONGLONG comboCount = 0;
    FLOAT confidence = 0.0f;

    if (Out == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ProcessId = ProcessId;

    hProcess = TedOpenProcess(ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    if (!TedGetMainModule(ProcessId, &module, NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    scanSize = (module.Size > TED_MAX_CODE_SCAN_SIZE)
        ? TED_MAX_CODE_SCAN_SIZE : module.Size;
    if (scanSize == 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    code = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, scanSize);
    if (code == NULL) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (ReadProcessMemory(hProcess, (LPCVOID)module.BaseAddress,
                          code, scanSize, &bytesRead)) {
        readSize = (SIZE_T)bytesRead;
    }

    rdtscCount = TedCountPatternOccurrences(code, readSize,
        g_TedRdtscPattern, TED_RDTSC_PATTERN_LEN);
    rdtscpCount = TedCountPatternOccurrences(code, readSize,
        g_TedRdtscpPattern, TED_RDTSCP_PATTERN_LEN);
    comboCount = TedCountRdtscCpuidCombos(code, readSize);

    /* --- 判定（对齐源回归结果；delta 类静态不可推） --- */
    if (rdtscCount > g_TedConfig.RdtscFrequencyThreshold) {
        Out->HighFrequencyDetected = TRUE;
    }
    Out->DeltaCheckDetected = FALSE;            /* 需反汇编时序仿真 */
    Out->FrequencyMeasurementDetected = FALSE;  /* 需反汇编模式识别 */

    /* --- 置信度（源 add-up 封顶风格） --- */
    if (Out->HighFrequencyDetected) {
        confidence += 40.0f;
    }
    if (comboCount > 0) {
        confidence += 30.0f;
    }
    if (rdtscpCount > 0) {
        confidence += 20.0f;
    }
    if (rdtscCount > 0 && confidence == 0.0f) {
        confidence += 10.0f;    /* 存在性低置信 */
    }
    Out->Confidence = TED_MIN(confidence, TED_MAX_CONFIDENCE_SCORE);

    Out->RdtscCount = rdtscCount;
    Out->RdtscpCount = rdtscpCount;
    Out->RdtscCpuidComboCount = comboCount;
    Out->AvgDeltaNs = 0;
    Out->MinDeltaNs = 0;
    Out->MaxDeltaNs = 0;
    Out->DeltaStdDev = 0.0;
    Out->CallsPerSecond = 0.0;
    Out->ObservationDurationMs = 0;

    HeapFree(GetProcessHeap(), 0, code);
    CloseHandle(hProcess);
    return TRUE;
}

/*++
 
TedAnalyzeSleep

    睡眠逃避分析（静态 PE 导入 + 监控上下文动态证据合成）。
    碎片化（FragmentationDetected）纯静态不可观测，恒为 FALSE。

--*/
BOOLEAN
TedAnalyzeSleep(
    _In_ ULONG ProcessId,
    _Out_ PTED_SLEEP_ANALYSIS Out
    )
{
    TED_PROCESS_MODULE_INFO module;
    PBYTE peData = NULL;
    SIZE_T peSize = 0;
    TED_PE_FILE pe;
    ULONG sleepApiHits = 0;
    ULONG i;
    BOOLEAN hasCtx = FALSE;
    BOOLEAN hasPe = FALSE;
    BOOLEAN hasNtDelayExecution = FALSE;
    BOOLEAN hasSleepEx = FALSE;
    FLOAT confidence = 0.0f;

    if (Out == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ProcessId = ProcessId;

    /* --- 监控上下文（动态证据） --- */
    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL) {
            hasCtx = TRUE;
            Out->SleepCallCount = ctx->SleepCallCount;
            Out->TotalRequestedDurationMs = ctx->TotalSleepDurationMs;
            Out->TotalActualDurationMs = ctx->TotalSleepDurationMs;
            Out->SleepBombingDetected = ctx->SleepBombingDetected;
            Out->AccelerationDetected = ctx->SleepAccelerationDetected;
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);

    /* --- 静态导入分析 --- */
    if (TedGetMainModule(ProcessId, &module, NULL) &&
        TedPeLoad(module.Path, &peData, &peSize, &pe)) {
        hasPe = TRUE;

        for (i = 0; i < TED_SLEEP_API_IMPORT_COUNT; ++i) {
            if (TedPeImportsContain(&pe, g_TedSleepApiImports[i], NULL, 0)) {
                ++sleepApiHits;
                if (sleepApiHits <= TED_MAX_SLEEP_APIS) {
                    wcsncpy_s(Out->SleepAPIsUsed[sleepApiHits - 1],
                              TED_MAX_IMPORT_NAME,
                              g_TedSleepApiImportsW[i], _TRUNCATE);
                }
                if (i == 2) {          /* NtDelayExecution */
                    hasNtDelayExecution = TRUE;
                }
                if (i == 1) {          /* SleepEx */
                    hasSleepEx = TRUE;
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, peData);
        peData = NULL;
    }
    Out->SleepAPICount = TED_MIN(sleepApiHits, TED_MAX_SLEEP_APIS);

    /* --- Sleep bombing 组合判定（对齐源 MonitoringTick 规则） --- */
    if (Out->SleepAPICount >= 3 && Out->SleepCallCount > TED_SLEEP_BOMBING_CALL_THRESHOLD) {
        Out->SleepBombingDetected = TRUE;
    } else if (Out->SleepAPICount >= 4 &&
               Out->TotalRequestedDurationMs > TED_SLEEP_BOMBING_DURATION_MS) {
        Out->SleepBombingDetected = TRUE;
    }

    Out->FragmentationDetected = FALSE;   /* 需动态碎片序列观测 */
    Out->AvgRequestedDurationMs = (Out->SleepCallCount > 0)
        ? (Out->TotalRequestedDurationMs / Out->SleepCallCount) : 0;
    Out->AvgActualDurationMs = (Out->SleepCallCount > 0)
        ? (Out->TotalActualDurationMs / Out->SleepCallCount) : 0;
    Out->MaxRequestedDurationMs = 0;
    Out->FragmentedSleepCount = 0;
    Out->AvgFragmentDurationMs = 0;

    /* --- 置信度合成 --- */
    if (Out->SleepCallCount > TED_SLEEP_BOMBING_CALL_THRESHOLD) {
        confidence += 30.0f;
    }
    if (Out->TotalRequestedDurationMs > TED_SLEEP_EVASION_THRESHOLD_MS) {
        confidence += 25.0f;
    }
    if (Out->SleepAPICount >= 3) {
        confidence += 20.0f;
    } else if (Out->SleepAPICount >= 2) {
        confidence += 10.0f;
    }
    if (hasNtDelayExecution) {
        confidence += 15.0f;
    }
    if (hasSleepEx) {
        confidence += 15.0f;
    }
    if (Out->SleepBombingDetected) {
        confidence = TED_MAX(confidence, 60.0f);
    }
    if (Out->AccelerationDetected) {
        confidence = TED_MAX(confidence, 75.0f);
    }
    Out->Confidence = TED_MIN(confidence, TED_MAX_CONFIDENCE_SCORE);

    /* 无主模块不可解析时，仅动态证据足够也视为成功 */
    return (hasPe || hasCtx) ? TRUE : FALSE;
}

/*++
 
TedAnalyzeAPITiming

    API 时序交叉校验分析：GetTickCount/QPC/系统时间的静态导入
    统计 + 监控上下文合并。Anomaly 阈值为导入计数（防误报，
    对齐源 Issue#8 修正）。

--*/
BOOLEAN
TedAnalyzeAPITiming(
    _In_ ULONG ProcessId,
    _Out_ PTED_API_TIMING_ANALYSIS Out
    )
{
    TED_PROCESS_MODULE_INFO module;
    PBYTE peData = NULL;
    SIZE_T peSize = 0;
    TED_PE_FILE pe;
    ULONG tickCount = 0;
    ULONG qpc = 0;
    ULONG sysTime = 0;
    ULONG precise = 0;
    ULONG timeGet = 0;
    BOOLEAN hasPe = FALSE;
    BOOLEAN hasCtx = FALSE;
    BOOLEAN hasQpcFreq = FALSE;
    FLOAT confidence = 0.0f;

    if (Out == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ProcessId = ProcessId;

    /* --- 监控上下文计数合并 --- */
    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL) {
            hasCtx = TRUE;
            Out->GetTickCountCalls = ctx->GetTickCountCalls;
            Out->QpcCalls = ctx->QpcCalls;
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);

    /* --- 静态导入统计 --- */
    if (TedGetMainModule(ProcessId, &module, NULL) &&
        TedPeLoad(module.Path, &peData, &peSize, &pe)) {
        hasPe = TRUE;

        if (TedPeImportsContain(&pe, "GetTickCount", NULL, 0)) {
            ++tickCount;
        }
        if (TedPeImportsContain(&pe, "GetTickCount64", NULL, 0)) {
            ++tickCount;
        }
        if (TedPeImportsContain(&pe, "QueryPerformanceCounter", NULL, 0)) {
            ++qpc;
        }
        hasQpcFreq = TedPeImportsContain(&pe, "QueryPerformanceFrequency", NULL, 0);
        if (TedPeImportsContain(&pe, "GetSystemTimeAsFileTime", NULL, 0)) {
            ++sysTime;
        }
        if (TedPeImportsContain(&pe, "GetSystemTimePreciseAsFileTime", NULL, 0)) {
            ++precise;
        }
        if (TedPeImportsContain(&pe, "timeGetTime", NULL, 0)) {
            ++timeGet;
        }
        HeapFree(GetProcessHeap(), 0, peData);
        peData = NULL;
    }

    /* --- 判定 --- */
    Out->TickCountAnomalyDetected =
        (tickCount > TED_HIGH_TICKCOUNT_IMPORT_THRESHOLD);
    Out->QpcAnomalyDetected =
        (qpc > TED_HIGH_QPC_IMPORT_THRESHOLD);

    if (tickCount > 0 && (qpc > 0 || sysTime > 0)) {
        Out->CrossCheckDetected = TRUE;
        Out->CrossCheckCount = (qpc > 0)
            ? TED_MIN(tickCount, qpc)
            : TED_MIN(tickCount, sysTime);
    }

    Out->SystemTimeCalls = sysTime;
    Out->PreciseTimeCalls = precise;
    Out->TimeGetTimeCalls = timeGet;
    Out->QpcFrequencyHz = 0;                /* 静态不可得 */
    Out->ExpectedQpcFrequencyHz = 0;
    Out->QpcFrequencyDeviation = 0.0;

    /* --- 置信度 --- */
    if (Out->TickCountAnomalyDetected) {
        confidence += 40.0f;
    }
    if (Out->QpcAnomalyDetected) {
        confidence += 40.0f;
    }
    if (Out->CrossCheckDetected) {
        confidence += 35.0f + TED_MIN(15.0f, (FLOAT)Out->CrossCheckCount);
    }
    if (hasQpcFreq && hasCtx && Out->QpcCalls == 0) {
        /* QPC 频率测量但无调用 → 仅背景 */
    }
    Out->Confidence = TED_MIN(confidence, TED_MAX_CONFIDENCE_SCORE);

    return (hasPe || hasCtx) ? TRUE : FALSE;
}

/*++
 
TedAnalyzeNTP

    NTP/网络时间校验分析：命令行服务器特征 + HTTP 主机提取
    + winhttp/wininet 导入（对齐源 registerNTPAnalysis 静态面）。
    漂移量（DetectedDriftSeconds）需轮询 NTP 服务器，静态置 0；
    Timezone 检测不在本模块（归入环境检测引擎）。

--*/
BOOLEAN
TedAnalyzeNTP(
    _In_ ULONG ProcessId,
    _Out_ PTED_NTP_ANALYSIS Out
    )
{
    TED_PROCESS_MODULE_INFO module;
    PBYTE peData = NULL;
    SIZE_T peSize = 0;
    TED_PE_FILE pe;
    WCHAR commandLine[TED_MAX_COMMAND_LINE];
    ULONG i;
    FLOAT confidence = 0.0f;

    if (Out == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ProcessId = ProcessId;

    /* --- 命令行分析 --- */
    if (TedGetProcessCommandLine(ProcessId, commandLine,
                                 TED_ARRAY_COUNT(commandLine))) {
        for (i = 0; i < TED_NTP_PATTERN_COUNT; ++i) {
            if (TedWcsContainsICase(commandLine, g_TedNtpPatterns[i])) {
                if (Out->NtpServerCount < TED_MAX_NTP_SERVERS) {
                    wcsncpy_s(Out->NtpServers[Out->NtpServerCount],
                              TED_MAX_HOSTNAME,
                              g_TedNtpPatterns[i], _TRUNCATE);
                    ++Out->NtpServerCount;
                }
                ++Out->NtpQueryCount;
            }
        }
        TedExtractHttpHosts(commandLine,
                            Out->HttpTimeHosts, &Out->HttpHostCount);
        Out->HttpTimeCheckCount = Out->HttpHostCount;
    }

    /* --- PE 导入（外部时间校验能力） --- */
    if (TedGetMainModule(ProcessId, &module, NULL) &&
        TedPeLoad(module.Path, &peData, &peSize, &pe)) {
        for (i = 0; i < TED_HTTP_TIME_DLL_COUNT; ++i) {
            if (TedPeDllImportsContain(&pe, g_TedHttpTimeDllPatterns[i],
                                       "WinHttpOpen") ||
                TedPeDllImportsContain(&pe, g_TedHttpTimeDllPatterns[i],
                                       "HttpOpenRequestW") ||
                TedPeDllImportsContain(&pe, g_TedHttpTimeDllPatterns[i],
                                       "InternetOpenW")) {
                ++Out->ExternalTimeAPICalls;
            }
        }
        if (TedPeDllImportsContain(&pe, g_TedNtpSocketDllPattern, "sendto")) {
            /* UDP 发送能力（仅背景，不参与判定） */
        }
        HeapFree(GetProcessHeap(), 0, peData);
        peData = NULL;
    }

    /* --- 判定与置信度 --- */
    if (Out->NtpQueryCount > 0) {
        Out->NtpEvasionDetected = TRUE;
        confidence = TED_MAX(confidence,
                             55.0f + TED_MIN(30.0f, (FLOAT)Out->NtpQueryCount * 5.0f));
    }
    if (Out->HttpTimeCheckCount > 0 || Out->ExternalTimeAPICalls > 0) {
        Out->ExternalValidationDetected = TRUE;
        confidence = TED_MAX(confidence, 40.0f);
    }
    Out->Confidence = TED_MIN(confidence, TED_MAX_CONFIDENCE_SCORE);
    Out->DetectedDriftSeconds = 0;

    return TRUE;
}

/**************************************************/
/*          Check* 链与结果编排（Part 4）          */
/*  对齐源 CheckRDTSC/CheckSleep/CheckAPITiming/   */
/*  CheckNTP → AnalyzeProcess 编排 → QuickScan     */
/**************************************************/

/*++
 
TedAddFinding

    向结果追加一条发现（含位图标记）。容量封顶返回 FALSE。

--*/
static BOOLEAN
TedAddFinding(
    _Inout_ PTED_RESULT Result,
    _In_ UINT8 Type,
    _In_ UINT8 Severity,
    _In_ FLOAT Confidence,
    _In_ PCWSTR Description,
    _In_opt_ PCWSTR TechnicalDetails
    )
{
    PTED_FINDING f;

    if (Result == NULL || Result->FindingCount >= TED_MAX_RESULT_FINDINGS) {
        return FALSE;
    }

    f = &Result->Findings[Result->FindingCount];
    RtlZeroMemory(f, sizeof(*f));
    f->Type = Type;
    f->Severity = Severity;
    f->DetectionMethod = TED_METHOD_STATIC_ANALYSIS;
    f->Confidence = Confidence;
    f->DetectionTimeMs = TedGetNowMs();
    TED_WCOPY(f->Description, Description, TED_MAX_DESC);
    if (TechnicalDetails != NULL) {
        TED_WCOPY(f->TechnicalDetails, TechnicalDetails,
                  TED_MAX_TECH_DETAILS);
    } else {
        f->TechnicalDetails[0] = L'\0';
    }
    ++Result->FindingCount;
    TED_BITMAP_SET(Result->DetectedTypes, Type);
    return TRUE;
}

/*++
 
TedSleepApiUsed

    睡眠分析结果中是否使用了指定 API（宽名精确比较）。

--*/
static BOOLEAN
TedSleepApiUsed(
    _In_ const TED_SLEEP_ANALYSIS* Ana,
    _In_ PCWSTR Name
    )
{
    ULONG n;
    ULONG i;

    if (Ana == NULL || Name == NULL) {
        return FALSE;
    }
    n = TED_MIN(Ana->SleepAPICount, TED_MAX_SLEEP_APIS);
    for (i = 0; i < n; ++i) {
        if (wcscmp(Ana->SleepAPIsUsed[i], Name) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
 
TedFillProcessInfo

    填充结果中的进程元信息（名称/路径/命令行/父进程/事件数）。
    返回是否有任一字段成功（false 时 ErrorMessage 置原因）。

--*/
static BOOLEAN
TedFillProcessInfo(
    _Inout_ PTED_RESULT Result
    )
{
    TED_PROCESS_MODULE_INFO module;
    BOOLEAN ok = FALSE;

    if (TedGetProcessNameByPid(Result->ProcessId, Result->ProcessName,
                               TED_MAX_PROCESS_NAME)) {
        ok = TRUE;
    }
    if (TedGetProcessCommandLine(Result->ProcessId, Result->CommandLine,
                                 TED_MAX_COMMAND_LINE)) {
        ok = TRUE;
    }
    if (TedGetMainModule(Result->ProcessId, &module, NULL)) {
        TED_WCOPY(Result->ProcessPath, module.Path, TED_MAX_PATH);
        ok = TRUE;
    }

    Result->ParentProcessId = TedGetParentProcessId(Result->ProcessId);
    if (Result->ParentProcessId != 0) {
        (void)TedGetProcessNameByPid(Result->ParentProcessId,
                                     Result->ParentProcessName,
                                     TED_MAX_PROCESS_NAME);
    }

    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(Result->ProcessId);
        if (ctx != NULL) {
            Result->EventsAnalyzed = ctx->EventCount;
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);

    if (!ok) {
        TED_WCOPY(Result->ErrorMessage,
                  L"进程无法访问（权限不足或已退出）", TED_MAX_ERROR);
    }
    return ok;
}

/*++
 
TedCheckRdtsc

    RDTSC 分析结果 → 发现列表。delta 类源依赖反汇编时序仿真，
    纯 C 静态面恒不产生（判定逻辑保留以保证对称性）。

--*/
static VOID
TedCheckRdtsc(
    _Inout_ PTED_RESULT Result,
    _In_ const TED_RDTSC_ANALYSIS* Ana
    )
{
    Result->RdtscCallCount = Ana->RdtscCount;

    if (Ana->DeltaCheckDetected) {
        (void)TedAddFinding(Result, TED_TYPE_RDTSC_DELTA_CHECK,
            TED_SEVERITY_MEDIUM, Ana->Confidence,
            L"RDTSC delta 校验：反 VM/沙箱超时探测",
            L"检测到 RDTSC 指令对之间 delta 校验模式（需反汇编时序仿真，"
            L"纯静态扫描下恒不触发）");
    }
    if (Ana->HighFrequencyDetected) {
        (void)TedAddFinding(Result, TED_TYPE_RDTSC_HIGH_FREQUENCY,
            TED_SEVERITY_HIGH, Ana->Confidence,
            L"高频 RDTSC：虚拟机/沙箱时序检测",
            L"主模块代码中 RDTSC 指令计数超过高频阈值，"
            L"典型于反虚拟化时序探测");
    }
    if (Ana->RdtscCpuidComboCount > 0) {
        (void)TedAddFinding(Result, TED_TYPE_RDTSC_CPUID_COMBO,
            TED_SEVERITY_HIGH, TED_MAX(
                Ana->Confidence, 75.0f),
            L"RDTSC+CPUID 组合：序列化时序探测",
            L"CPUID 串行化后紧邻 RDTSC 的指令模式，"
            L"用于精确测量虚拟化开销");
    } else if (Ana->RdtscpCount > 0) {
        (void)TedAddFinding(Result, TED_TYPE_RDTSCP_USAGE,
            TED_SEVERITY_LOW, Ana->Confidence,
            L"RDTSCP 使用：串行化时序指令",
            L"RDTSCP 为串行化时序指令，常见于时序测量代码");
    }
}

/*++
 
TedCheckSleep

    睡眠分析结果 → 发现列表（专项 + 通用高频睡眠降级）。

--*/
static VOID
TedCheckSleep(
    _Inout_ PTED_RESULT Result,
    _In_ const TED_SLEEP_ANALYSIS* Ana
    )
{
    Result->SleepCallCount = Ana->SleepCallCount;
    Result->TotalSleepDurationMs = Ana->TotalRequestedDurationMs;
    Result->ActualSleepDurationMs = Ana->TotalActualDurationMs;

    if (Ana->SleepBombingDetected) {
        (void)TedAddFinding(Result, TED_TYPE_SLEEP_BOMBING,
            TED_SEVERITY_HIGH, TED_MAX(Ana->Confidence, 60.0f),
            L"Sleep bombing：长时间睡眠规避分析窗口",
            L"睡眠 API 组合与运行时长满足轰炸式延迟判定");
    }
    if (Ana->AccelerationDetected) {
        (void)TedAddFinding(Result, TED_TYPE_SLEEP_ACCELERATION,
            TED_SEVERITY_CRITICAL, TED_MAX(Ana->Confidence, 75.0f),
            L"睡眠加速：沙箱时间快进检测",
            L"实际睡眠时长显著小于请求时长，疑似沙箱加速");
    }
    if (Ana->FragmentationDetected) {
        (void)TedAddFinding(Result, TED_TYPE_SLEEP_FRAGMENTATION,
            TED_SEVERITY_MEDIUM, Ana->Confidence,
            L"睡眠碎片化：规避加速检测",
            L"大量短睡眠替代长睡眠以规避单调加速判定");
    }

    /* 专项 API 发现（有调用证据时） */
    if (TedSleepApiUsed(Ana, L"NtDelayExecution") && Ana->SleepCallCount > 0) {
        (void)TedAddFinding(Result, TED_TYPE_NT_DELAY_EXECUTION_ABUSE,
            TED_SEVERITY_MEDIUM, TED_MAX(Ana->Confidence, 45.0f),
            L"NtDelayExecution 滥用：内核级延迟调用",
            L"导入 NtDelayExecution 并存在调用证据，"
            L"绕过用户态 Sleep 检测面");
    }
    if (TedSleepApiUsed(Ana, L"SleepEx") && Ana->SleepCallCount > 0) {
        (void)TedAddFinding(Result, TED_TYPE_SLEEPEX_ALERTABLE,
            TED_SEVERITY_LOW, TED_MAX(Ana->Confidence, 35.0f),
            L"SleepEx Alertable 睡眠",
            L"可唤醒睡眠调用可被 APC 打断，常用于恶意同步");
    }
    if (TedSleepApiUsed(Ana, L"WaitForSingleObjectEx") ||
        TedSleepApiUsed(Ana, L"WaitForSingleObject")) {
        (void)TedAddFinding(Result, TED_TYPE_WAITFOR_SINGLE_OBJECT_DELAY,
            TED_SEVERITY_LOW, TED_MAX(Ana->Confidence, 30.0f),
            L"WaitForSingleObject 延迟",
            L"等待句柄超时实现延迟执行");
    }
    if (TedSleepApiUsed(Ana, L"MsgWaitForMultipleObjects") ||
        TedSleepApiUsed(Ana, L"MsgWaitForMultipleObjectsEx")) {
        (void)TedAddFinding(Result, TED_TYPE_MSGWAIT_DELAY,
            TED_SEVERITY_LOW, TED_MAX(Ana->Confidence, 30.0f),
            L"MsgWait 延迟：消息等待超时",
            L"消息泵等待超时实现延迟执行");
    }
    if (TedSleepApiUsed(Ana, L"SetWaitableTimer") ||
        TedSleepApiUsed(Ana, L"SetWaitableTimerEx")) {
        (void)TedAddFinding(Result, TED_TYPE_WAITABLE_TIMER_DELAY,
            TED_SEVERITY_LOW, TED_MAX(Ana->Confidence, 35.0f),
            L"Waitable Timer 延迟",
            L"可等待定时器实现延迟执行");
    }

    /* 通用高频睡眠（未达轰炸判定但调用数高） */
    if (Ana->SleepCallCount > TED_SLEEP_BOMBING_CALL_THRESHOLD &&
        !Ana->SleepBombingDetected) {
        (void)TedAddFinding(Result, TED_TYPE_SLEEP_BOMBING,
            TED_SEVERITY_LOW, 45.0f,
            L"高频睡眠调用：潜在分析窗口规避",
            L"睡眠调用频率异常高但未达轰炸组合判定");
    }
}

/*++
 
TedCheckApiTiming

    API 时序分析结果 → 发现列表。
    系统/精确时间类仅在交叉校验成立时附加（防 GetSystemTimeAsFileTime
    等高普适 API 误报）。

--*/
static VOID
TedCheckApiTiming(
    _Inout_ PTED_RESULT Result,
    _In_ const TED_API_TIMING_ANALYSIS* Ana
    )
{
    Result->GetTickCountCalls = Ana->GetTickCountCalls;
    Result->QpcCallCount = Ana->QpcCalls;

    if (Ana->CrossCheckDetected) {
        (void)TedAddFinding(Result, TED_TYPE_TIMING_API_CROSS_CHECK,
            TED_SEVERITY_MEDIUM, TED_MAX(Ana->Confidence, 60.0f),
            L"时序 API 交叉校验：反调试定时检查",
            L"GetTickCount 与 QPC/系统时间同时使用，"
            L"典型于反虚拟化定时断点检测");
        if (Ana->PreciseTimeCalls > 0) {
            (void)TedAddFinding(Result, TED_TYPE_PRECISE_TIME_CHECK,
                TED_SEVERITY_INFO, Ana->Confidence,
                L"高精度时间 API：GetSystemTimePreciseAsFileTime",
                L"使用高精度系统时间获取");
        }
        if (Ana->SystemTimeCalls > 0) {
            (void)TedAddFinding(Result, TED_TYPE_SYSTEM_TIME_CHECK,
                TED_SEVERITY_INFO, Ana->Confidence,
                L"系统时间校验：外部时间源一致性检查",
                L"使用 GetSystemTimeAsFileTime 做时间一致性验证");
        }
    }
    if (Ana->TickCountAnomalyDetected) {
        (void)TedAddFinding(Result, TED_TYPE_GETTICKCOUNT_DELTA,
            TED_SEVERITY_MEDIUM, Ana->Confidence,
            L"GetTickCount 高频使用：单调时钟校验",
            L"GetTickCount 导入数超过异常阈值，"
            L"典型于运行时单调时钟差分检测");
    }
    if (Ana->QpcAnomalyDetected) {
        (void)TedAddFinding(Result, TED_TYPE_QPC_ANOMALY,
            TED_SEVERITY_MEDIUM, Ana->Confidence,
            L"QPC 高频使用：高精度时钟校验",
            L"QueryPerformanceCounter 导入数超过异常阈值");
    }
}

/*++
 
TedCheckNtp

    NTP 分析结果 → 发现列表。

--*/
static VOID
TedCheckNtp(
    _Inout_ PTED_RESULT Result,
    _In_ const TED_NTP_ANALYSIS* Ana
    )
{
    Result->NtpQueryCount = Ana->NtpQueryCount;

    if (Ana->NtpEvasionDetected) {
        (void)TedAddFinding(Result, TED_TYPE_NTP_QUERY,
            TED_SEVERITY_MEDIUM, Ana->Confidence,
            L"NTP 查询：外部时间源校验",
            L"命令行引用已知 NTP 服务器域名，"
            L"用于脱离沙箱时间线独立校时");
    }
    if (Ana->HttpTimeCheckCount > 0) {
        (void)TedAddFinding(Result, TED_TYPE_HTTP_DATE_CHECK,
            TED_SEVERITY_LOW, TED_MAX(Ana->Confidence, 35.0f),
            L"HTTP 日期头校验：外部时间验证",
            L"通过 HTTP 响应日期头校验本地时间");
    }
    if (Ana->ExternalValidationDetected) {
        (void)TedAddFinding(Result, TED_TYPE_EXTERNAL_TIME_VALIDATION,
            TED_SEVERITY_LOW, Ana->Confidence,
            L"外部时间校验能力：winhttp/wininet 时间 API",
            L"导入 HTTP 时间获取 API，具备外部校时能力");
    }
}

/*--
 
前向声明：Part 5 实现（TedCorrelateFindings/TedComputeThreatScore/
TedPopulateMitre）。调用点 TedAnalyzeProcess 位于本文件较早位置，
跨部分依赖无法满足"先定义后使用"，显式声明为该原则的受控例外。

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TedCorrelateFindings(
    _Inout_ PTED_RESULT Result
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TedComputeThreatScore(
    _Inout_ PTED_RESULT Result
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TedPopulateMitre(
    _Inout_ PTED_RESULT Result
    );

/*++
 
TedAnalyzeProcess

    单进程完整时序逃逸分析（同步）。
    流程：进程信息 → 缓存检查 → 专项分析（RDTSC/Sleep/API/NTP）
    → 相关性 → 评分 → MITRE → 统计 → 缓存写回。
    失败场景宽容处理：单项分析失败不中断整体。

--*/
BOOLEAN
TedAnalyzeProcess(
    _In_ ULONG ProcessId,
    _Out_ PTED_RESULT Result
    )
{
    ULONGLONG startMs;
    ULONGLONG endMs;
    ULONGLONG durationUs = 0;

    if (Result == NULL || !TedIsInitialized()) {
        return FALSE;
    }

    startMs = TedGetNowMs();
    RtlZeroMemory(Result, sizeof(*Result));
    Result->ProcessId = ProcessId;
    Result->AnalysisStartTimeMs = startMs;

    /* --- 进程元信息 --- */
    (void)TedFillProcessInfo(Result);

    /* --- 缓存命中 --- */
    if (g_TedConfig.EnableResultCache) {
        BOOLEAN cacheHit = FALSE;

        AcquireSRWLockShared(&g_TedCacheLock);
        {
            PTED_CACHE_ENTRY hit = TedCacheFind(ProcessId);

            if (hit != NULL) {
                RtlCopyMemory(Result, hit->Result, sizeof(*Result));
                Result->AnalysisStartTimeMs = startMs;
                Result->AnalysisEndTimeMs = TedGetNowMs();
                Result->AnalysisComplete = TRUE;
                cacheHit = TRUE;
            }
        }
        ReleaseSRWLockShared(&g_TedCacheLock);

        if (cacheHit) {
            TED_STATS_ADD(CacheHits, 1);
            return TRUE;
        }
        TED_STATS_ADD(CacheMisses, 1);
    }

    /* --- 专项分析 --- */
    if (g_TedConfig.DetectRDTSC) {
        TED_RDTSC_ANALYSIS ana;

        if (TedAnalyzeRDTSC(ProcessId, &ana)) {
            TedCheckRdtsc(Result, &ana);
        }
    }
    if (g_TedConfig.DetectSleepEvasion) {
        TED_SLEEP_ANALYSIS ana;

        if (TedAnalyzeSleep(ProcessId, &ana)) {
            TedCheckSleep(Result, &ana);
        }
    }
    if (g_TedConfig.DetectAPITiming) {
        TED_API_TIMING_ANALYSIS ana;

        if (TedAnalyzeAPITiming(ProcessId, &ana)) {
            TedCheckApiTiming(Result, &ana);
        }
    }
    if (g_TedConfig.DetectNTPEvasion) {
        TED_NTP_ANALYSIS ana;

        if (TedAnalyzeNTP(ProcessId, &ana)) {
            TedCheckNtp(Result, &ana);
        }
    }

    /* --- 相关性/评分/MITRE --- */
    TedCorrelateFindings(Result);
    TedComputeThreatScore(Result);
    if (g_TedConfig.EnableMitreMapping) {
        TedPopulateMitre(Result);
    }

    /* --- 结果汇总 --- */
    endMs = TedGetNowMs();
    Result->AnalysisEndTimeMs = endMs;
    Result->AnalysisDurationMs = endMs - startMs;
    Result->AnalysisComplete = TRUE;
    durationUs = (endMs - startMs) * 1000ULL;

    TED_STATS_ADD(TotalProcessesAnalyzed, 1);
    TED_STATS_ADD(TotalEventsProcessed, (LONGLONG)Result->EventsAnalyzed);
    TED_STATS_SET(LastAnalysisTimestamp, (LONGLONG)TedGetUnixSeconds());
    if (Result->IsEvasive) {
        TedBumpDetectionStats(Result->PrimaryEvasionType, durationUs);
    }

    /* --- 缓存写回 --- */
    if (g_TedConfig.EnableResultCache) {
        AcquireSRWLockExclusive(&g_TedCacheLock);
        (void)TedCacheInsert(ProcessId, Result);
        ReleaseSRWLockExclusive(&g_TedCacheLock);
    }

    return TRUE;
}

/*++
 
TedQuickScanProcess

    快速扫描：主模块时序 API 导入数 > 8 即判定明显逃避。
    对齐源 implementQuickScan（Issue#8 修正阈值）。

--*/
BOOLEAN
TedQuickScanProcess(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Evasive
    )
{
    TED_PROCESS_MODULE_INFO module;
    PBYTE peData = NULL;
    SIZE_T peSize = 0;
    TED_PE_FILE pe;
    ULONG timingHits = 0;
    ULONG i;
    BOOLEAN ok = FALSE;

    if (Evasive == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    *Evasive = FALSE;

    if (!TedGetMainModule(ProcessId, &module, NULL)) {
        return FALSE;
    }
    if (!TedPeLoad(module.Path, &peData, &peSize, &pe)) {
        return FALSE;
    }

    for (i = 0; i < TED_TIMING_API_IMPORT_COUNT; ++i) {
        if (TedPeImportsContain(&pe, g_TedTimingApiImports[i], NULL, 0)) {
            ++timingHits;
        }
    }
    if (peData != NULL) {
        HeapFree(GetProcessHeap(), 0, peData);
        peData = NULL;
    }

    *Evasive = (timingHits > TED_QUICKSCAN_TIMING_API_THRESHOLD);
    ok = TRUE;
    return ok;
}

/**************************************************/
/*          相关性/评分/MITRE/反调试（Part 5）      */
/*  对齐源 calculateThreatScore/populateMitre/     */
/*  DetectionTypeEnumMap/DetectedTimingAntiDebug    */
/**************************************************/

/*++
 
TedSeverityWeight

    严重度 → 威胁评分权重（对齐源 severityWeights 映射：
    Critical=40 High=30 Medium=20 Low=10 Info=5）。

--*/
static FLOAT
TedSeverityWeight(
    _In_ UINT8 Severity
    )
{
    switch (Severity) {
    case TED_SEVERITY_CRITICAL: return 40.0f;
    case TED_SEVERITY_HIGH:     return 30.0f;
    case TED_SEVERITY_MEDIUM:   return 20.0f;
    case TED_SEVERITY_LOW:      return 10.0f;
    default:                    return 5.0f;    /* Info 及未知 */
    }
}

/*++
 
TedMitreIdPresent

    MitreIds 中是否已存在该 ID（去重辅助）。

--*/
static BOOLEAN
TedMitreIdPresent(
    _In_ const TED_RESULT* Result,
    _In_ PCSTR Id
    )
{
    ULONG i;

    for (i = 0; i < Result->MitreIdCount; ++i) {
        if (strcmp(Result->MitreIds[i], Id) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
 
TedTypeToMitre

    时序逃逸类型 → MITRE 技术 ID（对齐源 DetectionTypeEnumMap）：
    None → 空串；TimingAntiDebug → T1622；TIMESTAMP 类其余 → T1497.003。

--*/
PCSTR
TedTypeToMitre(
    _In_ UINT8 Type
    )
{
    switch (Type) {
    case TED_TYPE_NONE:
        return "";
    case TED_TYPE_TIMING_ANTI_DEBUG:
        return "T1622";
    default:
        return "T1497.003";
    }
}

/*++
 
TedCorrelateFindings

    跨类别相关性：RDTSC/Sleep/API/NTP 四类中命中 >=2 类时
    追加多技术组合发现（对齐源 categories 判定）。

--*/
static VOID
TedCorrelateFindings(
    _Inout_ PTED_RESULT Result
    )
{
    BOOLEAN catRdtsc = FALSE;
    BOOLEAN catSleep = FALSE;
    BOOLEAN catApi = FALSE;
    BOOLEAN catNtp = FALSE;
    ULONG catCount;
    ULONG i;
    FLOAT confidence;

    if (Result == NULL) {
        return;
    }

    for (i = 0; i < Result->FindingCount; ++i) {
        UINT8 t = Result->Findings[i].Type;

        if (t >= 1 && t <= 5) {
            catRdtsc = TRUE;
        } else if (t >= 20 && t <= 27) {
            catSleep = TRUE;
        } else if (t >= 40 && t <= 45) {
            catApi = TRUE;
        } else if (t >= 60 && t <= 63) {
            catNtp = TRUE;
        }
    }

    catCount = (catRdtsc ? 1 : 0) + (catSleep ? 1 : 0) +
               (catApi ? 1 : 0) + (catNtp ? 1 : 0);

    if (catCount >= 2) {
        confidence = TED_MIN(100.0f, 70.0f + (FLOAT)catCount * 5.0f);
        (void)TedAddFinding(Result, TED_TYPE_MULTI_TECHNIQUE,
            TED_SEVERITY_HIGH, confidence,
            L"多技术组合逃逸：跨类别时序对抗",
            L"同时命中多个时序逃逸类别（RDTSC/睡眠/API/NTP），"
            L"威胁等级显著提升");
    }
}

/*++
 
TedComputeThreatScore

    计算威胁评分（加权和 / 4 归一，对齐源 CalculateThreatScore），
    同时汇总综合置信度、最高严重度、主逃逸类型与 IsEvasive。

--*/
static VOID
TedComputeThreatScore(
    _Inout_ PTED_RESULT Result
    )
{
    FLOAT weightedSum = 0.0f;
    FLOAT maxConfidence = 0.0f;
    FLOAT primaryConfidence = -1.0f;
    UINT8 maxSeverity = TED_SEVERITY_INFO;
    UINT8 primaryType = TED_TYPE_UNKNOWN;
    ULONG i;

    if (Result == NULL) {
        return;
    }

    for (i = 0; i < Result->FindingCount; ++i) {
        const TED_FINDING* f = &Result->Findings[i];

        weightedSum += TedSeverityWeight(f->Severity);
        if (f->Confidence > maxConfidence) {
            maxConfidence = f->Confidence;
        }
        if (f->Severity > maxSeverity) {
            maxSeverity = f->Severity;
        }
        if (f->Confidence > primaryConfidence) {
            primaryConfidence = f->Confidence;
            primaryType = f->Type;
        }
    }

    Result->ThreatScore =
        TED_MIN(100.0f, weightedSum / TED_THREAT_SCORE_DIVISOR);
    Result->Confidence = maxConfidence;
    Result->Severity = maxSeverity;
    Result->PrimaryEvasionType =
        (Result->FindingCount > 0) ? primaryType : TED_TYPE_UNKNOWN;
    Result->IsEvasive =
        (Result->ThreatScore >= TED_THREAT_EVASIVE_MIN_SCORE);
}

/*++
 
TedPopulateMitre

    填充 MITRE 技术 ID（去重，封顶 TED_MAX_MITRE_IDS）。
    非逃逸但有发现也映射；无已映射 ID 且判定逃逸时保底 T1497.003。

--*/
static VOID
TedPopulateMitre(
    _Inout_ PTED_RESULT Result
    )
{
    ULONG i;

    if (Result == NULL) {
        return;
    }
    TED_ACOPY(Result->MitreTactic, "TA0005", TED_MAX_MITRE_STR);
    Result->MitreIdCount = 0;

    for (i = 0;
         i < Result->FindingCount && Result->MitreIdCount < TED_MAX_MITRE_IDS;
         ++i) {
        PCSTR id = TedTypeToMitre(Result->Findings[i].Type);

        if (id != NULL && id[0] != '\0' && !TedMitreIdPresent(Result, id)) {
            TED_ACOPY(Result->MitreIds[Result->MitreIdCount],
                      id, TED_MAX_MITRE_STR);
            ++Result->MitreIdCount;
        }
    }

    if (Result->MitreIdCount == 0 && Result->IsEvasive) {
        TED_ACOPY(Result->MitreIds[0], "T1497.003", TED_MAX_MITRE_STR);
        Result->MitreIdCount = 1;
    }
}

/*++
 
TedDetectSleepAcceleration

    检测睡眠加速：静态面无法测（实际/请求比需动态观测），
    仅监控上下文证据可判定。对齐源 DetectedSleepAcceleration 语义。

--*/
BOOLEAN
TedDetectSleepAcceleration(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Detected
    )
{
    TED_SLEEP_ANALYSIS ana;

    if (Detected == NULL) {
        return FALSE;
    }
    *Detected = FALSE;

    if (!TedAnalyzeSleep(ProcessId, &ana)) {
        return FALSE;
    }
    *Detected = ana.AccelerationDetected;
    return TRUE;
}

/*++
 
TedDetectTimingAntiDebug

    时序反调试检测（对齐源 implementDetectTimingAntiDebug）：
    - RDTSC delta 校验（静态恒不可推）或 RDTSC+CPUID 组合
    - 高 QPC 调用数（>=5）与交叉校验组合

--*/
BOOLEAN
TedDetectTimingAntiDebug(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Detected
    )
{
    TED_RDTSC_ANALYSIS rd;
    TED_API_TIMING_ANALYSIS api;
    BOOLEAN d = FALSE;

    if (Detected == NULL) {
        return FALSE;
    }
    *Detected = FALSE;

    if (TedAnalyzeRDTSC(ProcessId, &rd)) {
        if (rd.DeltaCheckDetected) {
            d = TRUE;   /* 源亦包含此分支；静态面恒 FALSE */
        }
        if (rd.RdtscCpuidComboCount > 0) {
            d = TRUE;
        }
    }
    if (TedAnalyzeAPITiming(ProcessId, &api)) {
        if (api.QpcCalls >= TED_ANTIDEBUG_QPC_CALL_THRESHOLD &&
            api.CrossCheckDetected) {
            d = TRUE;
        }
    }

    *Detected = d;
    return TRUE;
}

/**************************************************/
/*          持续监控（Part 6）                      */
/*  对齐源 WorkerThread/MonitoringLoop/ProcessExit */
/*  发现。纯 C 无 API 插桩：动态信号来自周期性      */
/*  全量分析（轮询式）；回调带同类型 60s 防抖。      */
/**************************************************/

/* 监控线程 join 超时（毫秒） */
#define TED_MONITOR_JOIN_TIMEOUT_MS     15000

/* 同进程同主类型通知防抖窗口（毫秒） */
#define TED_NOTIFY_RETRIGGER_MS         60000

/*++
 
TedGetSampleIntervalMs

    读取配置中的采样间隔（毫秒）。独立工具函数避免各处加锁。

--*/
static ULONG
TedGetSampleIntervalMs(
    VOID
    )
{
    ULONG interval = TED_DEFAULT_SAMPLE_INTERVAL_MS;

    AcquireSRWLockShared(&g_TedConfigLock);
    interval = g_TedConfig.SampleIntervalMs;
    ReleaseSRWLockShared(&g_TedConfigLock);
    return interval;
}

/*++
 
TedNotifyEvasion

    通知全部注册的逃避回调（快照调用，避免持锁回调死锁）。
    防抖：同进程同主类型在 TED_NOTIFY_RETRIGGER_MS 内仅通知一次。

--*/
static VOID
TedNotifyEvasion(
    _In_ const TED_RESULT* Result
    )
{
    TED_EVASION_CALLBACK snapshot[TED_MAX_CALLBACKS];
    ULONGLONG now = TedGetNowMs();
    ULONG n = 0;
    ULONG i;
    BOOLEAN debounce = FALSE;

    if (Result == NULL) {
        return;
    }

    /* --- 防抖检查 --- */
    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(Result->ProcessId);

        if (ctx != NULL &&
            ctx->LastNotifiedType == Result->PrimaryEvasionType &&
            now - ctx->LastNotifyMs < TED_NOTIFY_RETRIGGER_MS) {
            debounce = TRUE;
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);
    if (debounce) {
        return;
    }

    /* --- 回调快照 --- */
    AcquireSRWLockShared(&g_TedCallbackLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCallbacks); ++i) {
        if (g_TedCallbacks[i].Active && g_TedCallbacks[i].Fn != NULL) {
            if (n < TED_ARRAY_COUNT(snapshot)) {
                snapshot[n++] = g_TedCallbacks[i].Fn;
            }
        }
    }
    ReleaseSRWLockShared(&g_TedCallbackLock);

    /* --- 更新防抖标记（有回调才更新，保证回调未就绪时可重试） --- */
    if (n > 0) {
        AcquireSRWLockExclusive(&g_TedMonitorLock);
        {
            PTED_MONITORING_CONTEXT ctx =
                TedContextFindUnlocked(Result->ProcessId);

            if (ctx != NULL) {
                ctx->LastNotifiedType = Result->PrimaryEvasionType;
                ctx->LastNotifyMs = now;
            }
        }
        ReleaseSRWLockExclusive(&g_TedMonitorLock);
    }

    for (i = 0; i < n; ++i) {
        snapshot[i](Result);
    }
}

/*++
 
TedMonitoringTick

    单次监控采样：
    1. 生命周期维护（进程退出 → COMPLETED）
    2. 对 Active 进程执行完整分析，逃避结果经防抖通知回调
    锁外执行分析体（避免长持有 monitor 锁）。

--*/
static VOID
TedMonitoringTick(
    VOID
    )
{
    ULONG activePids[TED_MAX_MONITORED_PROCESSES];
    ULONG count = 0;
    ULONGLONG now = TedGetNowMs();
    ULONG i;

    /* --- 快照 + 生命周期 --- */
    AcquireSRWLockExclusive(&g_TedMonitorLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedMonitoredProcesses); ++i) {
        PTED_MONITORING_CONTEXT ctx = &g_TedMonitoredProcesses[i];

        if (ctx->ProcessId == 0 ||
            ctx->State == TED_MON_STATE_INACTIVE ||
            ctx->State == TED_MON_STATE_COMPLETED ||
            ctx->State == TED_MON_STATE_FAILED) {
            continue;
        }
        if (ctx->State == TED_MON_STATE_ACTIVE) {
            if (!TedIsProcessRunning(ctx->ProcessId)) {
                ctx->State = TED_MON_STATE_COMPLETED;
                ctx->LastUpdateMs = now;
                continue;
            }
            if (count < TED_ARRAY_COUNT(activePids)) {
                activePids[count++] = ctx->ProcessId;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_TedMonitorLock);

    /* --- 完整分析（锁外） --- */
    for (i = 0; i < count; ++i) {
        TED_RESULT result;

        if (TedAnalyzeProcess(activePids[i], &result) && result.IsEvasive) {
            TedNotifyEvasion(&result);
        }
    }
}

/*++
 
TedMonitoringLoop

    监控线程主循环：等待间隔或停止事件。

--*/
static VOID
TedMonitoringLoop(
    VOID
    )
{
    for (;;) {
        DWORD waitMs = (DWORD)TedGetSampleIntervalMs();

        if (WaitForSingleObject(g_TedStopEvent, waitMs) != WAIT_TIMEOUT) {
            break;      /* 停止事件或异常 */
        }
        TedMonitoringTick();
    }
}

/*++
 
TedMonitorThreadProc

    监控线程入口（CreateThread 直接回调）。

--*/
static DWORD
WINAPI
TedMonitorThreadProc(
    _In_ LPVOID Context
    )
{
    (void)Context;

    InterlockedExchange(&g_TedMonitoringActive, 1);
    TedMonitoringLoop();
    InterlockedExchange(&g_TedMonitoringActive, 0);
    return 0;
}

/*++
 
TedStopMonitorThread

    请求停止监控线程并等待退出（调用者须已释放 monitor 锁）。
    无活跃线程时直接返回。

--*/
static VOID
TedStopMonitorThread(
    VOID
    )
{
    HANDLE hThread;

    if (g_TedStopEvent != NULL) {
        SetEvent(g_TedStopEvent);
    }
    hThread = (HANDLE)InterlockedExchangePointer(
        (PVOID volatile*)&g_TedMonitoringThread, NULL);
    if (hThread != NULL) {
        DWORD wait = WaitForSingleObject(hThread, TED_MONITOR_JOIN_TIMEOUT_MS);
        (void)wait;
        CloseHandle(hThread);
    }
}

/*++
 
TedEnsureMonitorThread

    确保监控线程存在（幂等）。已停止状态下重新创建；
    线程退出时主动清空句柄（避免悬空句柄被误 join）。

--*/
static BOOLEAN
TedEnsureMonitorThread(
    VOID
    )
{
    HANDLE hThread;

    if (g_TedStopEvent == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_TedMonitoringActive, 0, 0) != 0) {
        return TRUE;    /* 线程已在运行 */
    }

    ResetEvent(g_TedStopEvent);     /* 手动复位：清除停止标记 */
    hThread = CreateThread(NULL, 0, TedMonitorThreadProc, NULL, 0, NULL);
    if (hThread == NULL) {
        return FALSE;
    }
    {
        HANDLE old = (HANDLE)InterlockedExchangePointer(
            (PVOID volatile*)&g_TedMonitoringThread, hThread);
        if (old != NULL) {
            CloseHandle(old);   /* 理论竞态遗留句柄（旧线程已退出） */
        }
    }
    return TRUE;
}

/*++
 
TedStartMonitoring

    开始监控进程（幂等；COMPLETED/FAILED 状态可复活）。
    启动单例监控线程（必要时）。

--*/
BOOLEAN
TedStartMonitoring(
    _In_ ULONG ProcessId
    )
{
    PTED_MONITORING_CONTEXT slot = NULL;
    ULONG i;

    if (ProcessId == 0 || !TedIsInitialized()) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT existing = TedContextFindUnlocked(ProcessId);

        if (existing != NULL) {
            /* 已存在上下文：复活已完成/失败项，其余幂等 */
            if (existing->State == TED_MON_STATE_COMPLETED ||
                existing->State == TED_MON_STATE_FAILED) {
                existing->State = TED_MON_STATE_ACTIVE;
                existing->StartTimeMs = TedGetNowMs();
                existing->LastUpdateMs = existing->StartTimeMs;
            }
        } else {
            /* 找空闲槽 */
            for (i = 0; i < TED_ARRAY_COUNT(g_TedMonitoredProcesses); ++i) {
                if (g_TedMonitoredProcesses[i].State == TED_MON_STATE_INACTIVE) {
                    slot = &g_TedMonitoredProcesses[i];
                    break;
                }
            }
            if (slot == NULL) {
                ReleaseSRWLockExclusive(&g_TedMonitorLock);
                return FALSE;           /* 超限 */
            }
            if (!TedContextInit(slot, ProcessId,
                                g_TedConfig.MaxEventsPerProcess)) {
                ReleaseSRWLockExclusive(&g_TedMonitorLock);
                return FALSE;
            }
            slot->State = TED_MON_STATE_ACTIVE;
            slot->StartTimeMs = TedGetNowMs();
            slot->LastUpdateMs = slot->StartTimeMs;
        }
    }
    ReleaseSRWLockExclusive(&g_TedMonitorLock);

    (void)TedEnsureMonitorThread();
    return TRUE;
}

/*++
 
TedStopMonitoring

    停止对单进程的监控并释放上下文（含事件历史）。

--*/
VOID
TedStopMonitoring(
    _In_ ULONG ProcessId
    )
{
    if (!TedIsInitialized()) {
        return;
    }

    AcquireSRWLockExclusive(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL) {
            TedContextFree(ctx);
        }
    }
    ReleaseSRWLockExclusive(&g_TedMonitorLock);
}

/*++
 
TedStopAllMonitoring

    停止全部监控：释放全部上下文并停止监控线程。

--*/
VOID
TedStopAllMonitoring(
    VOID
    )
{
    ULONG i;

    if (!TedIsInitialized()) {
        return;
    }

    AcquireSRWLockExclusive(&g_TedMonitorLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedMonitoredProcesses); ++i) {
        TedContextFree(&g_TedMonitoredProcesses[i]);
    }
    ReleaseSRWLockExclusive(&g_TedMonitorLock);

    TedStopMonitorThread();
}

/*++
 
TedIsMonitoring

    查询进程是否处于监控中（Active 或 Paused）。

--*/
BOOLEAN
TedIsMonitoring(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN IsActive
    )
{
    if (IsActive == NULL) {
        return FALSE;
    }
    *IsActive = FALSE;

    if (!TedIsInitialized()) {
        return TRUE;    /* 查询本身成功（非监控态） */
    }

    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL) {
            *IsActive = (ctx->State == TED_MON_STATE_ACTIVE ||
                         ctx->State == TED_MON_STATE_PAUSED);
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);
    return TRUE;
}

/*++
 
TedGetMonitoringState

    查询进程当前监控状态（无记录返回 INACTIVE）。

--*/
TED_MONITORING_STATE
TedGetMonitoringState(
    _In_ ULONG ProcessId
    )
{
    TED_MONITORING_STATE state = TED_MON_STATE_INACTIVE;

    if (!TedIsInitialized()) {
        return state;
    }

    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL) {
            state = (TED_MONITORING_STATE)ctx->State;
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);
    return state;
}

/*++
 
TedPauseMonitoring

    暂停单进程监控（State → PAUSED，采样跳过）。

--*/
VOID
TedPauseMonitoring(
    _In_ ULONG ProcessId
    )
{
    if (!TedIsInitialized()) {
        return;
    }
    AcquireSRWLockExclusive(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL && ctx->State == TED_MON_STATE_ACTIVE) {
            ctx->State = TED_MON_STATE_PAUSED;
        }
    }
    ReleaseSRWLockExclusive(&g_TedMonitorLock);
}

/*++
 
TedResumeMonitoring

    恢复单进程监控（PAUSED → ACTIVE）。

--*/
VOID
TedResumeMonitoring(
    _In_ ULONG ProcessId
    )
{
    if (!TedIsInitialized()) {
        return;
    }
    AcquireSRWLockExclusive(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL && ctx->State == TED_MON_STATE_PAUSED) {
            ctx->State = TED_MON_STATE_ACTIVE;
            ctx->LastUpdateMs = TedGetNowMs();
        }
    }
    ReleaseSRWLockExclusive(&g_TedMonitorLock);
}

/*++
 
TedGetMonitoredProcesses

    获取监控中（Active/Paused）进程 ID 列表。

--*/
BOOLEAN
TedGetMonitoredProcesses(
    _Out_writes_(Count) PULONG Pids,
    _In_ ULONG Count,
    _Out_ PULONG OutCount
    )
{
    ULONG n = 0;
    ULONG i;

    if (Pids == NULL || OutCount == NULL || Count == 0) {
        return FALSE;
    }
    *OutCount = 0;

    if (!TedIsInitialized()) {
        return TRUE;
    }

    AcquireSRWLockShared(&g_TedMonitorLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedMonitoredProcesses) && n < Count; ++i) {
        PTED_MONITORING_CONTEXT ctx = &g_TedMonitoredProcesses[i];

        if (ctx->State == TED_MON_STATE_ACTIVE ||
            ctx->State == TED_MON_STATE_PAUSED) {
            Pids[n++] = ctx->ProcessId;
        }
    }
    *OutCount = n;
    ReleaseSRWLockShared(&g_TedMonitorLock);
    return TRUE;
}

/*++
 
TedShutdown

    关闭检测器：停止监控线程、清理上下文/回调/缓存/统计。
    可重复调用。

--*/
VOID
TedShutdown(
    VOID
    )
{
    ULONG i;

    if (!InterlockedExchange(&g_TedInitialized, 0)) {
        return;
    }

    /* 停止监控（释放上下文 + 停止线程） */
    TedStopAllMonitoring();

    /* 清理回调槽 */
    AcquireSRWLockExclusive(&g_TedCallbackLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCallbacks); ++i) {
        g_TedCallbacks[i].Active = FALSE;
        g_TedCallbacks[i].Fn = NULL;
        g_TedCallbacks[i].Id = 0;
    }
    for (i = 0; i < TED_ARRAY_COUNT(g_TedEventCallbacks); ++i) {
        g_TedEventCallbacks[i].Active = FALSE;
        g_TedEventCallbacks[i].Fn = NULL;
        g_TedEventCallbacks[i].Id = 0;
    }
    ReleaseSRWLockExclusive(&g_TedCallbackLock);

    /* 清理缓存 */
    AcquireSRWLockExclusive(&g_TedCacheLock);
    TedCacheClear();
    ReleaseSRWLockExclusive(&g_TedCacheLock);

    if (g_TedStopEvent != NULL) {
        CloseHandle(g_TedStopEvent);
        g_TedStopEvent = NULL;
    }

    g_TedNtQueryInfoProcess = NULL;
    RtlZeroMemory(&g_TedStats, sizeof(g_TedStats));
}

/**************************************************/
/*          回调/统计/缓存公共接口（Part 7）        */
/**************************************************/

/*++
 
TedRegisterCallback

    注册逃避检测回调。返回注册 ID（供 TedUnregisterCallback）。
    槽位耗尽返回 FALSE。

--*/
BOOLEAN
TedRegisterCallback(
    _In_ TED_EVASION_CALLBACK Callback,
    _Out_ PULONGLONG OutId
    )
{
    ULONG i;

    if (Callback == NULL || OutId == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    *OutId = 0;

    AcquireSRWLockExclusive(&g_TedCallbackLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCallbacks); ++i) {
        if (!g_TedCallbacks[i].Active) {
            g_TedCallbacks[i].Id = (ULONGLONG)InterlockedIncrement64(
                &g_TedNextCallbackId);
            g_TedCallbacks[i].Fn = Callback;
            g_TedCallbacks[i].Active = TRUE;
            *OutId = g_TedCallbacks[i].Id;
            ReleaseSRWLockExclusive(&g_TedCallbackLock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_TedCallbackLock);
    return FALSE;
}

/*++
 
TedUnregisterCallback

    按注册 ID 注销逃避回调。ID 不存在返回 FALSE。

--*/
BOOLEAN
TedUnregisterCallback(
    _In_ ULONGLONG CallbackId
    )
{
    ULONG i;

    if (!TedIsInitialized()) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_TedCallbackLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCallbacks); ++i) {
        if (g_TedCallbacks[i].Active &&
            g_TedCallbacks[i].Id == CallbackId) {
            g_TedCallbacks[i].Active = FALSE;
            g_TedCallbacks[i].Fn = NULL;
            g_TedCallbacks[i].Id = 0;
            ReleaseSRWLockExclusive(&g_TedCallbackLock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_TedCallbackLock);
    return FALSE;
}

/*++
 
TedRegisterEventCallback

    注册单条时序事件回调（事件量大，使用需谨慎）。

--*/
BOOLEAN
TedRegisterEventCallback(
    _In_ TED_EVENT_CALLBACK Callback,
    _Out_ PULONGLONG OutId
    )
{
    ULONG i;

    if (Callback == NULL || OutId == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    *OutId = 0;

    AcquireSRWLockExclusive(&g_TedCallbackLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedEventCallbacks); ++i) {
        if (!g_TedEventCallbacks[i].Active) {
            g_TedEventCallbacks[i].Id = (ULONGLONG)InterlockedIncrement64(
                &g_TedNextCallbackId);
            g_TedEventCallbacks[i].Fn = Callback;
            g_TedEventCallbacks[i].Active = TRUE;
            *OutId = g_TedEventCallbacks[i].Id;
            ReleaseSRWLockExclusive(&g_TedCallbackLock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_TedCallbackLock);
    return FALSE;
}

/*++
 
TedUnregisterEventCallback

    按注册 ID 注销事件回调。

--*/
BOOLEAN
TedUnregisterEventCallback(
    _In_ ULONGLONG CallbackId
    )
{
    ULONG i;

    if (!TedIsInitialized()) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_TedCallbackLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedEventCallbacks); ++i) {
        if (g_TedEventCallbacks[i].Active &&
            g_TedEventCallbacks[i].Id == CallbackId) {
            g_TedEventCallbacks[i].Active = FALSE;
            g_TedEventCallbacks[i].Fn = NULL;
            g_TedEventCallbacks[i].Id = 0;
            ReleaseSRWLockExclusive(&g_TedCallbackLock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_TedCallbackLock);
    return FALSE;
}

/*++
 
TedGetStats

    获取检测统计快照（原子字段整体拷贝，一致性可接受）。

--*/
BOOLEAN
TedGetStats(
    _Out_ PTED_STATS OutStats
    )
{
    if (OutStats == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    *OutStats = g_TedStats;
    return TRUE;
}

/*++
 
TedResetStats

    清空统计（不保证与并发计数器原子同步，分析间隙调用为宜）。

--*/
VOID
TedResetStats(
    VOID
    )
{
    if (!TedIsInitialized()) {
        return;
    }
    RtlZeroMemory(&g_TedStats, sizeof(g_TedStats));
}

/*++
 
TedGetCacheHitRatio

    缓存命中率 = CacheHits / (CacheHits + CacheMisses)；无样本返回 0。

--*/
DOUBLE
TedGetCacheHitRatio(
    _In_ const TED_STATS* Stats
    )
{
    LONGLONG total;

    if (Stats == NULL) {
        return 0.0;
    }
    total = Stats->CacheHits + Stats->CacheMisses;
    if (total <= 0) {
        return 0.0;
    }
    return (DOUBLE)Stats->CacheHits / (DOUBLE)total;
}

/*++
 
TedGetCachedResult

    获取缓存的分析结果（TTL 校验）。命中判定内部完成；
    统计计数由 AnalyzeProcess 统一维护，此处不重复累计。

--*/
BOOLEAN
TedGetCachedResult(
    _In_ ULONG ProcessId,
    _Out_ PTED_RESULT OutResult
    )
{
    BOOLEAN found = FALSE;

    if (OutResult == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    RtlZeroMemory(OutResult, sizeof(*OutResult));

    AcquireSRWLockShared(&g_TedCacheLock);
    {
        PTED_CACHE_ENTRY hit = TedCacheFind(ProcessId);

        if (hit != NULL) {
            RtlCopyMemory(OutResult, hit->Result, sizeof(*OutResult));
            found = TRUE;
        }
    }
    ReleaseSRWLockShared(&g_TedCacheLock);
    return found;
}

/*++
 
TedClearCache

    清空全部缓存条目。

--*/
VOID
TedClearCache(
    VOID
    )
{
    if (!TedIsInitialized()) {
        return;
    }
    AcquireSRWLockExclusive(&g_TedCacheLock);
    TedCacheClear();
    ReleaseSRWLockExclusive(&g_TedCacheLock);
}

/*++
 
TedClearCacheForProcess

    清空指定进程的缓存条目。

--*/
VOID
TedClearCacheForProcess(
    _In_ ULONG ProcessId
    )
{
    ULONG i;

    if (!TedIsInitialized()) {
        return;
    }
    AcquireSRWLockExclusive(&g_TedCacheLock);
    for (i = 0; i < TED_ARRAY_COUNT(g_TedCache); ++i) {
        if (g_TedCache[i].Valid && g_TedCache[i].ProcessId == ProcessId) {
            TedCacheEntryFree(&g_TedCache[i]);
        }
    }
    ReleaseSRWLockExclusive(&g_TedCacheLock);
}

/*++
 
TedGetEventHistory

    获取进程事件历史（环形缓冲逻辑顺序：最旧 → 最新）。
    MaxEvents=0 表示全部；Out 为 NULL 且 MaxEvents>0 返回 FALSE。
    事件拷贝在持有 monitor 锁内完成，避免悬垂访问。

--*/
BOOLEAN
TedGetEventHistory(
    _In_ ULONG ProcessId,
    _In_ ULONG MaxEvents,
    _Out_writes_opt_(MaxEvents) PTED_EVENT_RECORD Out,
    _Out_ PULONG OutCount
    )
{
    SIZE_T k;
    ULONG n = 0;

    if (OutCount == NULL || !TedIsInitialized()) {
        return FALSE;
    }
    *OutCount = 0;
    if (Out == NULL && MaxEvents > 0) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_TedMonitorLock);
    {
        PTED_MONITORING_CONTEXT ctx = TedContextFindUnlocked(ProcessId);

        if (ctx != NULL && ctx->Events != NULL && ctx->EventCount > 0) {
            SIZE_T total = ctx->EventCount;
            BOOLEAN ring = (total == ctx->EventCapacity);
            SIZE_T writeIndex = ctx->EventWriteIndex;

            for (k = 0; k < total; ++k) {
                SIZE_T idx = ring ? ((writeIndex + k) % total) : k;

                if (MaxEvents != 0 && n >= MaxEvents) {
                    break;
                }
                if (Out != NULL) {
                    Out[n] = ctx->Events[idx];
                }
                ++n;
            }
        }
    }
    ReleaseSRWLockShared(&g_TedMonitorLock);

    *OutCount = n;
    return TRUE;
}

/**************************************************/
/*          工具函数（对齐源 inline 工具）          */
/**************************************************/

/*++
 
TedCalculateSleepAccelerationRatio

    睡眠加速比 = 实际 / 请求（<1.0 表示加速）。
    请求为 0 返回 1.0（无对照，视为正常）。

--*/
DOUBLE
TedCalculateSleepAccelerationRatio(
    _In_ ULONGLONG RequestedMs,
    _In_ ULONGLONG ActualMs
    )
{
    if (RequestedMs == 0) {
        return 1.0;
    }
    return (DOUBLE)ActualMs / (DOUBLE)RequestedMs;
}

/*++
 
TedCalculateCombinedConfidence

    多因子加权置信度合成（0-100）。Weights 可少于 Factors
    （缺省权重 1.0）；因子钳制到 [0,100]，权重钳制到 >=0。

--*/
FLOAT
TedCalculateCombinedConfidence(
    _In_reads_(FactorCount) const FLOAT* Factors,
    _In_ ULONG FactorCount,
    _In_reads_opt_(WeightCount) const FLOAT* Weights,
    _In_ ULONG WeightCount
    )
{
    DOUBLE sum = 0.0;
    DOUBLE weightSum = 0.0;
    ULONG i;

    if (Factors == NULL || FactorCount == 0) {
        return 0.0f;
    }

    for (i = 0; i < FactorCount; ++i) {
        DOUBLE f = (DOUBLE)Factors[i];
        DOUBLE w = (Weights != NULL && i < WeightCount)
            ? (DOUBLE)Weights[i] : 1.0;

        f = TED_MIN(f, 100.0);
        f = TED_MAX(f, 0.0);
        w = TED_MAX(w, 0.0);

        sum += f * w;
        weightSum += w;
    }

    if (weightSum <= 0.0) {
        return 0.0f;
    }
    return (FLOAT)TED_MIN(100.0, sum / weightSum);
}

/*++
 
TedConfidenceToSeverity

    置信度 → 严重度：>=90 Critical, >=70 High, >=40 Medium,
    >=15 Low，其余 Info。

--*/
UINT8
TedConfidenceToSeverity(
    _In_ FLOAT Confidence
    )
{
    if (Confidence >= 90.0f) {
        return TED_SEVERITY_CRITICAL;
    }
    if (Confidence >= 70.0f) {
        return TED_SEVERITY_HIGH;
    }
    if (Confidence >= 40.0f) {
        return TED_SEVERITY_MEDIUM;
    }
    if (Confidence >= 15.0f) {
        return TED_SEVERITY_LOW;
    }
    return TED_SEVERITY_INFO;
}

/*++
 
TedTypeToString

    时序逃逸类型 → 人类可读名称（对齐源 TypeToString；
    覆盖全部 RDTSC/Sleep/API/NTP/硬件/侧信道/组合枚举）。

--*/
PCSTR
TedTypeToString(
    _In_ UINT8 Type
    )
{
    switch (Type) {
    case TED_TYPE_NONE:
        return "None";
    case TED_TYPE_RDTSC_HIGH_FREQUENCY:
        return "RDTSC High Frequency";
    case TED_TYPE_RDTSC_DELTA_CHECK:
        return "RDTSC Delta Check";
    case TED_TYPE_RDTSCP_USAGE:
        return "RDTSCP Usage";
    case TED_TYPE_RDTSC_CPUID_COMBO:
        return "RDTSC+CPUID Combo";
    case TED_TYPE_TSC_FREQUENCY_MEASUREMENT:
        return "TSC Frequency Measurement";
    case TED_TYPE_SLEEP_BOMBING:
        return "Sleep Bombing";
    case TED_TYPE_SLEEP_ACCELERATION:
        return "Sleep Acceleration Detection";
    case TED_TYPE_SLEEP_FRAGMENTATION:
        return "Sleep Fragmentation";
    case TED_TYPE_NT_DELAY_EXECUTION_ABUSE:
        return "NtDelayExecution Abuse";
    case TED_TYPE_SLEEPEX_ALERTABLE:
        return "SleepEx Alertable";
    case TED_TYPE_WAITFOR_SINGLE_OBJECT_DELAY:
        return "WaitForSingleObject Delay";
    case TED_TYPE_MSGWAIT_DELAY:
        return "MsgWait Delay";
    case TED_TYPE_WAITABLE_TIMER_DELAY:
        return "Waitable Timer Delay";
    case TED_TYPE_GETTICKCOUNT_DELTA:
        return "GetTickCount Delta";
    case TED_TYPE_QPC_ANOMALY:
        return "QPC Anomaly";
    case TED_TYPE_SYSTEM_TIME_CHECK:
        return "System Time Check";
    case TED_TYPE_TIMEGETTIME_CHECK:
        return "timeGetTime Check";
    case TED_TYPE_TIMING_API_CROSS_CHECK:
        return "Timing API Cross-Check";
    case TED_TYPE_PRECISE_TIME_CHECK:
        return "Precise Time Check";
    case TED_TYPE_NTP_QUERY:
        return "NTP Query";
    case TED_TYPE_EXTERNAL_TIME_VALIDATION:
        return "External Time Validation";
    case TED_TYPE_HTTP_DATE_CHECK:
        return "HTTP Date Check";
    case TED_TYPE_TIMEZONE_ANOMALY:
        return "Time Zone Anomaly";
    case TED_TYPE_HPET_ACCESS:
        return "HPET Access";
    case TED_TYPE_ACPI_PM_TIMER:
        return "ACPI PM Timer";
    case TED_TYPE_HARDWARE_TIMER_DIRECT:
        return "Hardware Timer Direct";
    case TED_TYPE_INTERRUPT_TIMING:
        return "Interrupt Timing";
    case TED_TYPE_INSTRUCTION_TIMING:
        return "Instruction Timing";
    case TED_TYPE_CACHE_TIMING:
        return "Cache Timing";
    case TED_TYPE_BRANCH_PREDICTION_TIMING:
        return "Branch Prediction Timing";
    case TED_TYPE_MEMORY_ACCESS_TIMING:
        return "Memory Access Timing";
    case TED_TYPE_MULTI_TECHNIQUE:
        return "Multi-Technique Evasion";
    case TED_TYPE_ADAPTIVE_TIMING:
        return "Adaptive Timing";
    case TED_TYPE_TIME_LOCKED_PAYLOAD:
        return "Time-Locked Payload";
    case TED_TYPE_TIMING_ANTI_DEBUG:
        return "Timing Anti-Debug";
    case TED_TYPE_RESERVED:
        return "Reserved";
    default:
        return "Unknown";
    }
}

/*++
 
TedSeverityToString

    严重度 → 字符串（对齐源 SeverityToString）。

--*/
PCSTR
TedSeverityToString(
    _In_ UINT8 Severity
    )
{
    switch (Severity) {
    case TED_SEVERITY_CRITICAL:
        return "Critical";
    case TED_SEVERITY_HIGH:
        return "High";
    case TED_SEVERITY_MEDIUM:
        return "Medium";
    case TED_SEVERITY_LOW:
        return "Low";
    case TED_SEVERITY_INFO:
        return "Info";
    default:
        return "Unknown";
    }
}

/**************************************************/
/*          文件尾（TimeBasedEvasionDetector.c）    */
/**************************************************/