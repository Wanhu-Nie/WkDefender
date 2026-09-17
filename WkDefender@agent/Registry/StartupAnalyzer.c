/**************************************************/
/*  WkDefender Agent — Registry\StartupAnalyzer    */
/*  启动项审计与优化引擎 (The Boot Guard)            */
/*                                                  */
/*  迁移来源: ShadowStrike PhantomCore/Core/Registry*/
/*  StartupAnalyzer.cpp (3421 行 + .hpp 991 行,   */
/*  2026-09-09 全量转写)                           */
/*                                                  */
/*  职责:                                            */
/*   - 启动项枚举: Run/RunOnce (HKLM/HKCU/HKU/WoW64)*/
/*     Startup 文件夹 (含 .lnk COM 解析), IFEO,     */
/*     AppInit_DLLs, LSA 包, PrintMonitor,          */
/*     BootExecute, ActiveSetup,                    */
/*     ShellServiceObjectDelay, ScreenSaver,        */
/*     ExplorerRun, RunServices, 计划任务/服务(委托  */
/*     PD 引擎)                                     */
/*   - 安全评估: Authenticode 签名 (IocVerifySignature)*/
/*     SHA256 (IocScanner_ComputeFileSha256),       */
/*     信誉 (PdAnalyzeRealTime 委托), 13 条风险规则 */
/*   - 管理写回: 禁用/启用/移除 (AutorunsDisabled   */
/*     子键备份 + .disabled.YYYYMMDDhhmmss 文件改   */
/*     名), 恢复                                    */
/*   - 变更历史 (环形缓冲) + 三阶段回滚            */
/*   - 实时接线: RmRegisterEventCallback 集成       */
/*   - CSV 导出 (公式注入防护 + 行注入防护)        */
/*                                                  */
/*  工程收敛 (虚标剔除/底座替代, 对齐迁移审计):      */
/*   - BootImpact 全链路: SS 假测量, 不迁移; 字段   */
/*     保留但恒 0 (GenerateRecommendation 中 High/  */
/*     Critical 分支恒不触发)                       */
/*   - DelayItem: SS 无系统延迟机制, 保留 API 面    */
/*     (仅内存状态标记 + 历史), 注释说明            */
/*   - WirePersistenceDetector: SS 空壳, 不迁移     */
/*   - OnKernelRegistryNotification: 保留 (未来驱动  */
/*     接线入口), NormalizeKernelRegistryPath 归一  */
/*   - HashStore/ThreatIntel/WhiteListStore/IPCManager */
/*     : 死依赖剔除, 信誉统一走 PdAnalyzeRealTime   */
/*   - RegistryUtils 封装 → 内联 Win32 API 静态助手 */
/*   - std::unordered_map 名称索引 → 线性扫描       */
/*     (条目 ≤10000, 查询低频, 文档注明)           */
/*   - shared_mutex/mutex → SRWLOCK/CRITICAL_SECTION*/
/*                                                  */
/*  依赖 (WkD 底座):                                 */
/*   Common\Utils (UtHexEncode/UtHeapAlloc/Free)    */
/*   Common\PathUtil (WkdNormalizePath)             */
/*   IOC\Signature (IocVerifySignature/IsMicrosoftSigned) */
/*   IOC\IocScanner (IocScanner_ComputeFileSha256,  */
/*     经 SignatureCatalog.h 前置声明)              */
/*   Registry 子系统 PD 引擎 (PdAnalyzeRealTime/    */
/*     PdScanScheduledTasks/PdScanServices)         */
/*   Registry 子系统 RM 引擎 (RmRegisterEventCallback) */
/**************************************************/

#include "RegistryInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <strsafe.h>

#include <shlobj.h>      /* SHGetFolderPathW / IShellLinkW */

#include "../Common/Utils.h"
#include "../Common/PathUtil.h"
#include "../IOC/Signature/SignatureVerifier.h"
#include "../IOC/Signature/SignatureCatalog.h"   /* IocScanner_ComputeFileSha256 前置声明 */

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

/* ==================================================
 * 内部上下文
 * ================================================== */

/* 条目指针池 (每条目独立堆分配, 对应 SS unordered_map) */
#define WKD_SA_POOL_INIT_CAPACITY  256

/* 告警环形 (对应 SS vector, cap 10000 / trim 5000) */
#define WKD_SA_ALERT_INIT_CAPACITY 64

typedef struct _SA_CONTEXT {
    /* 生命周期与配置 */
    volatile LONG   Initialized;
    WKD_SA_CONFIG   Config;
    SRWLOCK         Lock;             /* 保护 Init/Config */

    /* 条目池 */
    PWKD_SA_ITEM*   Items;            /* 指针数组 (动态) */
    ULONG           ItemCount;
    ULONG           ItemCapacity;
    SRWLOCK         ItemsLock;

    /* 历史环形 (对应 SS deque, 上限 WKD_SA_MAX_HISTORY) */
    WKD_SA_CHANGE   History[WKD_SA_MAX_HISTORY];
    ULONG           HistoryHead;      /* 最旧条目下标 */
    ULONG           HistoryCount;
    CRITICAL_SECTION HistoryLock;

    /* 告警 (动态数组, 逻辑同 SS vector) */
    PWKD_SA_ALERT   Alerts;
    ULONG           AlertCount;
    ULONG           AlertCapacity;
    CRITICAL_SECTION AlertsLock;

    /* 回调 (固定槽位, 对应 SS vector<pair<id,fn>>; id 槽支持精确注销) */
    PFN_SA_NEW_ITEM_CALLBACK NewItemCallbacks[WKD_SA_MAX_CALLBACKS];
    PVOID           NewItemContexts[WKD_SA_MAX_CALLBACKS];
    ULONG           NewItemCallbackIds[WKD_SA_MAX_CALLBACKS];
    BOOLEAN         NewItemSlotFree[WKD_SA_MAX_CALLBACKS];

    PFN_SA_ALERT_CALLBACK AlertCallbacks[WKD_SA_MAX_CALLBACKS];
    PVOID           AlertContexts[WKD_SA_MAX_CALLBACKS];
    ULONG           AlertCallbackIds[WKD_SA_MAX_CALLBACKS];
    BOOLEAN         AlertSlotFree[WKD_SA_MAX_CALLBACKS];

    PFN_SA_CHANGE_CALLBACK ChangeCallbacks[WKD_SA_MAX_CALLBACKS];
    PVOID           ChangeContexts[WKD_SA_MAX_CALLBACKS];
    ULONG           ChangeCallbackIds[WKD_SA_MAX_CALLBACKS];
    BOOLEAN         ChangeSlotFree[WKD_SA_MAX_CALLBACKS];
    CRITICAL_SECTION CallbacksLock;

    BOOLEAN         LocksInitialized;

    /* ID 分配 (Interlocked) */
    volatile LONG64 NextItemId;
    volatile LONG64 NextChangeId;
    volatile LONG64 NextAlertId;
    volatile LONG64 NextCallbackId;

    /* RM 接线回调 ID (0 = 未接线) */
    ULONG           RmCallbackId;

    /* Boot 基线 (ms) */
    volatile LONG   BootBaseline;

    /* 统计 */
    WKD_SA_STATS    Stats;
} SA_CONTEXT;

static SA_CONTEXT g_sa = { 0 };

/* ==================================================
 * 静态工具函数 (匿名命名空间辅助集)
 * ================================================== */

/* 日志输出 (开发排障: OutputDebugStringW; 事件面经
 * Notify 回调由上层编排; 生产接入 LogManager 由编排层完成) */
static
VOID SaDbgPrint(_In_ PCWSTR Format, ...) {
    WCHAR buf[1024];
    va_list args;
    va_start(args, Format);
    (VOID)vswprintf_s(buf, 1024, Format, args);
    va_end(args);
    OutputDebugStringW(buf);
}

/* 大小写不敏感前缀匹配 (对应 SS StartsWithI) */
static
BOOLEAN SaStartsWithI(_In_ PCWSTR Value, _In_ PCWSTR Prefix) {
    if (Value == NULL || Prefix == NULL) return FALSE;
    return _wcsnicmp(Value, Prefix, wcslen(Prefix)) == 0;
}

/* 空串判定 */
static
BOOLEAN SaWcsEmpty(_In_ PCWSTR S) {
    return (S == NULL || S[0] == L'\0');
}

/* 清洗宽串 → 窄串 (对应 SS SanitizeForLog 窄版):
 * 截断到 kMaxLogFieldChars(=WKD_SA_MAX_LOG_FIELD_CHARS), 追加截断标记;
 * 控制字符(<0x20 / 0x7F) 替换为 '?' */
static
VOID SaSanitizeNarrow(_In_ PCWSTR Wide, _Out_writes_(OutCch) PCHAR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    if (Wide == NULL) Wide = L"";
    CHAR buf[WKD_SA_MAX_LOG_FIELD_CHARS + 32];
    ULONG n = WideCharToMultiByte(CP_UTF8, 0, Wide, -1, buf, WKD_SA_MAX_LOG_FIELD_CHARS, NULL, NULL);
    if (n == 0 || n > WKD_SA_MAX_LOG_FIELD_CHARS) {
        /* 超出截断上限 → 截断 + 显式标记 */
        buf[WKD_SA_MAX_LOG_FIELD_CHARS - 1] = '\0';
        strncat_s(buf, _countof(buf), "...<truncated>", _TRUNCATE);
        n = (ULONG)strlen(buf);
    }
    for (ULONG i = 0; i < n; ++i) {
        const UCHAR uc = (UCHAR)buf[i];
        if (uc < 0x20 || uc == 0x7F) buf[i] = '?';
    }
    (VOID)StringCchCopyA(Out, OutCch, buf);
}

/* 生成 ".disabled.YYYYMMDDhhmmss" 后缀 (UTC, 对应 SS MakeDisabledSuffix) */
static
VOID SaMakeDisabledSuffix(_Out_writes_(64) PWSTR Out, _In_ ULONG OutCch) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    if (Out == NULL || OutCch < 32) return;
    (VOID)StringCchPrintfW(Out, OutCch, L".disabled.%04u%02u%02u%02u%02u%02u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* 返回 %WINDIR%\System32 绝对路径 (查询时拼尾斜杠, 对应 SS SystemDirectoryW) */
static
VOID SaSystemDirectoryW(_Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    WCHAR buf[MAX_PATH];
    if (Out == NULL || OutCch == 0) return;
    const UINT n = GetSystemDirectoryW(buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        (VOID)StringCchCopyW(Out, OutCch, L"C:\\Windows\\System32\\");
        return;
    }
    if (buf[n - 1] != L'\\') {
        (VOID)StringCchPrintfW(Out, OutCch, L"%.*s\\", (int)n, buf);
    } else {
        (VOID)StringCchCopyW(Out, OutCch, buf);
    }
}

/* CSV 注入防护 (对应 SS SanitizeCsvCell):
 * - 首字符 '='/'+'/'-'/'@' 前插单引号 (防公式注入)
 * - CR/LF/TAB → 空格, 其他 <0x20 → '?' (防行注入)
 * - 含逗号/引号时按 RFC 4180 引号包裹 + 引号翻倍 */
static
VOID SaSanitizeCsvCell(_In_ PCWSTR In, _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    if (In == NULL) In = L"";
    WCHAR cell[WKD_PD_MAX_CMD_BUFFER];
    (VOID)StringCchCopyW(cell, _countof(cell), In);

    const size_t len = wcslen(cell);
    for (size_t i = 0; i < len; ++i) {
        if (cell[i] == L'\r' || cell[i] == L'\n' || cell[i] == L'\t') {
            cell[i] = L' ';
        } else if (cell[i] < 0x20) {
            cell[i] = L'?';
        }
    }

    BOOLEAN needsQuote = FALSE;
    if (len > 0 && (cell[0] == L'=' || cell[0] == L'+' || cell[0] == L'-' || cell[0] == L'@')) {
        needsQuote = TRUE;
    }
    if (wcschr(cell, L',') != NULL || wcschr(cell, L'"') != NULL) {
        needsQuote = TRUE;
    }
    if (!needsQuote) {
        (VOID)StringCchCopyW(Out, OutCch, cell);
        return;
    }

    /* 引号包裹: 前缀 ' (若公式引导) 或 " (若含逗号/引号) */
    WCHAR out[WKD_PD_MAX_CMD_BUFFER + 8];
    size_t o = 0;
    if (len > 0 && (cell[0] == L'=' || cell[0] == L'+' || cell[0] == L'-' || cell[0] == L'@')) {
        out[o++] = L'\'';
    }
    out[o++] = L'"';
    for (size_t i = 0; i < len; ++i) {
        if (cell[i] == L'"' && o + 2 < _countof(out)) {
            out[o++] = L'"';
        }
        if (o + 1 < _countof(out)) {
            out[o++] = cell[i];
        }
    }
    out[o++] = L'"';
    out[o] = L'\0';
    (VOID)StringCchCopyW(Out, OutCch, out);
}

/* 去除首尾空白 (对应 SS TrimWide) */
static
VOID SaTrimWide(_In_ PCWSTR In, _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    if (In == NULL) In = L"";
    const size_t len = wcslen(In);
    size_t first = 0;
    while (first < len && (In[first] == L' ' || In[first] == L'\t' ||
                           In[first] == L'\r' || In[first] == L'\n')) {
        ++first;
    }
    size_t last = len;
    while (last > first && (In[last - 1] == L' ' || In[last - 1] == L'\t' ||
                            In[last - 1] == L'\r' || In[last - 1] == L'\n')) {
        --last;
    }
    if (first >= last) {
        Out[0] = L'\0';
        return;
    }
    const SIZE_T span = (last - first < OutCch - 1) ? (last - first) : (OutCch - 1);
    (VOID)wcsncpy_s(Out, OutCch, In + first, span);
}

/* 分割启动值列表 (逗号/空白 + 引号配对, 对应 SS SplitStartupValueList)
 * 最多输出 kMax 段, 返回段数。 */
#define WKD_SA_SPLIT_MAX_SEGMENTS 64

static
ULONG SaSplitStartupValueList(
    _In_ PCWSTR Value,
    _In_ BOOLEAN SplitOnComma,
    _In_ BOOLEAN SplitOnWhitespace,
    _Out_writes_(MaxSegments) PWSTR Segments[WKD_SA_SPLIT_MAX_SEGMENTS],
    _In_ SIZE_T SegmentCch,
    _In_ ULONG MaxSegments
    ) {
    ULONG count = 0;
    if (Value == NULL) return 0;

    WCHAR current[WKD_PD_MAX_CMD_BUFFER];
    size_t curLen = 0;
    BOOLEAN quoted = FALSE;
    const size_t len = wcslen(Value);

    for (size_t i = 0; i < len; ++i) {
        const WCHAR ch = Value[i];
        if (ch == L'"') {
            quoted = !quoted;
            if (curLen + 1 < _countof(current)) current[curLen++] = ch;
            continue;
        }
        const BOOLEAN isDelim =
            !quoted &&
            ((SplitOnComma && ch == L',') ||
             (SplitOnWhitespace && (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n')));
        if (isDelim) {
            /* flush */
            current[curLen] = L'\0';
            WCHAR trimmed[WKD_PD_MAX_CMD_BUFFER];
            SaTrimWide(current, trimmed, _countof(trimmed));
            if (trimmed[0] != L'\0' && count < MaxSegments) {
                if (Segments[count] != NULL) {
                    (VOID)StringCchCopyW(Segments[count], SegmentCch, trimmed);
                }
                ++count;
            }
            curLen = 0;
        } else {
            if (curLen + 1 < _countof(current)) current[curLen++] = ch;
        }
    }
    current[curLen] = L'\0';
    WCHAR trimmed[WKD_PD_MAX_CMD_BUFFER];
    SaTrimWide(current, trimmed, _countof(trimmed));
    if (trimmed[0] != L'\0' && count < MaxSegments) {
        if (Segments[count] != NULL) {
            (VOID)StringCchCopyW(Segments[count], SegmentCch, trimmed);
        }
        ++count;
    }

    /* 空结果回退: 整体去空白后单段 */
    if (count == 0) {
        WCHAR whole[WKD_PD_MAX_CMD_BUFFER];
        SaTrimWide(Value, whole, _countof(whole));
        if (whole[0] != L'\0' && MaxSegments > 0) {
            if (Segments[0] != NULL) {
                (VOID)StringCchCopyW(Segments[0], SegmentCch, whole);
            }
            count = 1;
        }
    }
    return count;
}

/* 内核路径 → Win32 注册表路径 (对应 SS NormalizeKernelRegistryPath):
 * \REGISTRY\MACHINE\X → HKEY_LOCAL_MACHINE\X
 * \REGISTRY\USER\X    → HKEY_USERS\X                               */
static
VOID SaNormalizeKernelRegistryPath(_In_ PCWSTR Path, _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    if (Path == NULL) { Out[0] = L'\0'; return; }
    if (SaStartsWithI(Path, L"\\REGISTRY\\MACHINE\\")) {
        (VOID)StringCchPrintfW(Out, OutCch, L"HKEY_LOCAL_MACHINE\\%s", Path + 18);
        return;
    }
    if (SaStartsWithI(Path, L"\\REGISTRY\\USER\\")) {
        (VOID)StringCchPrintfW(Out, OutCch, L"HKEY_USERS\\%s", Path + 15);
        return;
    }
    (VOID)StringCchCopyW(Out, OutCch, Path);
}

/* 名称索引键 (对应 SS NormalizeNameKey):
 * 小写化 + 剔除内嵌 NUL (防逃逸)。缓冲区需 ≥ WKD_REG_MAX_NAME_CHARS */
static
VOID SaNormalizeNameKey(_In_ PCWSTR Name, _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    WCHAR tmp[WKD_REG_MAX_NAME_CHARS];
    if (Name == NULL) Name = L"";
    (VOID)StringCchCopyW(tmp, _countof(tmp), Name);
    (VOID)_wcslwr_s(tmp, _countof(tmp));
    ULONG o = 0;
    for (const WCHAR* p = tmp; *p != L'\0' && o + 1 < OutCch; ++p) {
        if (*p != L'\0') Out[o++] = *p;   /* 内嵌 NUL 直接跳过 */
    }
    Out[o] = L'\0';
}

/* 名称键比较 (索引键相等即命中) */
static
BOOLEAN SaNameKeyEquals(_In_ PCWSTR A, _In_ PCWSTR B) {
    return (A != NULL && B != NULL) ? (wcscmp(A, B) == 0) : FALSE;
}

/* ==================================================
 * 路径规范化 (对应 SS CanonicalizePath):
 *   %ENV% 展开 (上限 32Ki WCHAR) → 8.3→长路径 →
 *   WkdNormalizePath 前缀/组件规范化 (失败回退原路径)
 * ================================================== */
static
VOID SaCanonicalizePath(_In_ PCWSTR RawPath, _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    if (SaWcsEmpty(RawPath)) {
        if (OutCch > 0) Out[0] = L'\0';
        return;
    }

    WCHAR path[WKD_SA_CANONICALIZE_CEIL];
    (VOID)StringCchCopyW(path, _countof(path), RawPath);

    /* 1) %ENV% 展开 (堆缓冲, 避免攻击者驱动输入上栈) */
    {
        const DWORD need = ExpandEnvironmentStringsW(path, NULL, 0);
        if (need > 0 && need <= WKD_SA_CANONICALIZE_CEIL) {
            PWSTR buf = (PWSTR)UtHeapAlloc(need * sizeof(WCHAR));
            if (buf != NULL) {
                const DWORD written = ExpandEnvironmentStringsW(path, buf, need);
                if (written > 0 && written <= need) {
                    DWORD len = written;
                    if (len > 0 && buf[len - 1] == L'\0') --len;
                    buf[len] = L'\0';
                    (VOID)StringCchCopyW(path, _countof(path), buf);
                }
                UtHeapFree(buf);
            }
        }
    }

    /* 2) 8.3 短名 → 长路径 (抵御路径混淆) */
    {
        const DWORD need = GetLongPathNameW(path, NULL, 0);
        if (need > 0 && need <= WKD_SA_CANONICALIZE_CEIL) {
            PWSTR buf = (PWSTR)UtHeapAlloc(need * sizeof(WCHAR));
            if (buf != NULL) {
                const DWORD written = GetLongPathNameW(path, buf, need);
                if (written > 0 && written < need) {
                    buf[written] = L'\0';
                    (VOID)StringCchCopyW(path, _countof(path), buf);
                }
                UtHeapFree(buf);
            }
        }
    }

    /* 3) 组件规范化 (\\?\ / \??\ / \\.\ / \SystemRoot\ / 设备前缀 + . .. 折叠) */
    WCHAR normalized[WKD_SA_CANONICALIZE_CEIL];
    NTSTATUS status = WkdNormalizePath(path, normalized, _countof(normalized));
    if (NT_SUCCESS(status) && normalized[0] != L'\0') {
        (VOID)StringCchCopyW(Out, OutCch, normalized);
        return;
    }

    (VOID)StringCchCopyW(Out, OutCch, path);
}

/* ==================================================
 * 命令解析 (对应 SS ParseCommand):
 *   引号包裹 → 引号内为目标路径; 否则第一个空格为界
 *   (SS 两分支行为相同, 收敛为直接空格分割)
 * ================================================== */
static
VOID SaParseCommand(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL || Item->Command[0] == L'\0') return;

    WCHAR cmd[WKD_PD_MAX_CMD_BUFFER];
    (VOID)StringCchCopyW(cmd, _countof(cmd), Item->Command);

    /* 去前导空白 */
    size_t start = wcsspn(cmd, L" \t");
    if (cmd[start] == L'\0') return;

    Item->TargetPath[0] = L'\0';
    Item->Arguments[0] = L'\0';

    if (cmd[start] == L'"') {
        /* 引号包裹: "path" [args] */
        const WCHAR* q = wcschr(cmd + start + 1, L'"');
        if (q != NULL) {
            const SIZE_T pathLen = (SIZE_T)(q - (cmd + start + 1));
            if (pathLen < WKD_REG_MAX_PATH_CHARS) {
                (VOID)wcsncpy_s(Item->TargetPath, _countof(Item->TargetPath),
                                cmd + start + 1, pathLen);
            }
            const WCHAR* rest = q + 1;
            while (*rest == L' ' || *rest == L'\t') ++rest;
            (VOID)StringCchCopyW(Item->Arguments, _countof(Item->Arguments), rest);
        } else {
            (VOID)StringCchCopyW(Item->TargetPath, _countof(Item->TargetPath), cmd + start + 1);
        }
    } else {
        /* 无引号: 第一个空格为界 */
        const WCHAR* sp = wcschr(cmd + start, L' ');
        if (sp != NULL) {
            const SIZE_T pathLen = (SIZE_T)(sp - (cmd + start));
            if (pathLen < WKD_REG_MAX_PATH_CHARS) {
                (VOID)wcsncpy_s(Item->TargetPath, _countof(Item->TargetPath), cmd + start, pathLen);
            }
            const WCHAR* rest = sp + 1;
            while (*rest == L' ' || *rest == L'\t') ++rest;
            (VOID)StringCchCopyW(Item->Arguments, _countof(Item->Arguments), rest);
        } else {
            (VOID)StringCchCopyW(Item->TargetPath, _countof(Item->TargetPath), cmd + start);
        }
    }

    /* 规范化解析出的目标路径 */
    if (Item->TargetPath[0] != L'\0') {
        WCHAR canonical[WKD_REG_MAX_PATH_CHARS];
        SaCanonicalizePath(Item->TargetPath, canonical, _countof(canonical));
        (VOID)StringCchCopyW(Item->TargetPath, _countof(Item->TargetPath), canonical);
    }
}

/* 从注册表数据缓冲安全提取宽串 (枚举值可能无 NUL 终止, 对应 SS SafeExtractRegString) */
static
VOID SaSafeExtractRegString(_In_opt_ const BYTE* Data, _In_ DWORD DataSize,
                            _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    Out[0] = L'\0';
    if (Data == NULL || DataSize < sizeof(WCHAR)) return;
    const SIZE_T maxChars = (DataSize >= OutCch * sizeof(WCHAR))
        ? (OutCch - 1) : (DataSize / sizeof(WCHAR));
    const WCHAR* wdata = (const WCHAR*)Data;
    SIZE_T len = 0;
    while (len < maxChars && wdata[len] != L'\0') {
        ++len;
    }
    (VOID)wcsncpy_s(Out, OutCch, wdata, len);
}

/* 文件存在性 (忽略错误码) */
static
BOOLEAN SaFileExists(_In_ PCWSTR Path) {
    if (SaWcsEmpty(Path)) return FALSE;
    const DWORD attr = GetFileAttributesW(Path);
    return (attr != INVALID_FILE_ATTRIBUTES);
}

/* ==================================================
 * 池化辅助: 条目池动态增长
 * ================================================== */
static
BOOLEAN SaPoolReserve(_In_ ULONG Required) {
    if (Required <= g_sa.ItemCapacity) return TRUE;
    ULONG newCap = (g_sa.ItemCapacity > 0) ? g_sa.ItemCapacity : WKD_SA_POOL_INIT_CAPACITY;
    while (newCap < Required) {
        newCap *= 2;
        if (newCap > WKD_SA_MAX_ITEMS) newCap = WKD_SA_MAX_ITEMS;
        break;
    }
    if (newCap < Required) newCap = Required;
    if (newCap > WKD_SA_MAX_ITEMS) return FALSE;

    PWKD_SA_ITEM* newItems = (PWKD_SA_ITEM*)UtHeapAlloc(newCap * sizeof(PWKD_SA_ITEM));
    if (newItems == NULL) return FALSE;
    if (g_sa.ItemCount > 0) {
        memcpy(newItems, g_sa.Items, g_sa.ItemCount * sizeof(PWKD_SA_ITEM));
    }
    if (g_sa.Items != NULL) {
        UtHeapFree(g_sa.Items);
    }
    g_sa.Items = newItems;
    g_sa.ItemCapacity = newCap;
    return TRUE;
}

/* ==================================================
 * 名称映射 (对应 SS Get*Name 系列, 返回静态窄串)
 * ================================================== */

PCSTR
SaLookupSourceName(_In_ ULONG Source) {
    switch (Source) {
        case WkdSaSrc_Unknown: return "Unknown";
        case WkdSaSrc_RegistryRun_HKLM: return "Registry Run (HKLM)";
        case WkdSaSrc_RegistryRun_HKCU: return "Registry Run (HKCU)";
        case WkdSaSrc_RegistryRunOnce_HKLM: return "Registry RunOnce (HKLM)";
        case WkdSaSrc_RegistryRunOnce_HKCU: return "Registry RunOnce (HKCU)";
        case WkdSaSrc_StartupFolder_User: return "Startup Folder (User)";
        case WkdSaSrc_StartupFolder_AllUsers: return "Startup Folder (All Users)";
        case WkdSaSrc_ScheduledTask: return "Scheduled Task";
        case WkdSaSrc_Service: return "Service";
        case WkdSaSrc_ShellExtension: return "Shell Extension";
        case WkdSaSrc_GroupPolicy: return "Group Policy";
        case WkdSaSrc_AppXPackage: return "AppX Package";
        case WkdSaSrc_RegistryRun_Wow64_HKLM: return "Registry Run WoW64 (HKLM)";
        case WkdSaSrc_RegistryRun_Wow64_HKCU: return "Registry Run WoW64 (HKCU)";
        case WkdSaSrc_RegistryRunOnce_Wow64_HKLM: return "Registry RunOnce WoW64 (HKLM)";
        case WkdSaSrc_RegistryRunOnce_Wow64_HKCU: return "Registry RunOnce WoW64 (HKCU)";
        case WkdSaSrc_RegistryRunServices_HKLM: return "RunServices (HKLM)";
        case WkdSaSrc_RegistryRunServices_HKCU: return "RunServices (HKCU)";
        case WkdSaSrc_Winlogon_Shell: return "Winlogon Shell";
        case WkdSaSrc_Winlogon_Userinit: return "Winlogon Userinit";
        case WkdSaSrc_Winlogon_Notify: return "Winlogon Notify";
        case WkdSaSrc_IFEO: return "Image File Execution Options";
        case WkdSaSrc_AppInit_DLLs: return "AppInit_DLLs";
        case WkdSaSrc_LSA_AuthenticationPackages: return "LSA Auth Packages";
        case WkdSaSrc_LSA_SecurityPackages: return "LSA Security Packages";
        case WkdSaSrc_PrintMonitor: return "Print Monitor";
        case WkdSaSrc_BootExecute: return "BootExecute";
        case WkdSaSrc_KnownDLLs: return "KnownDLLs";
        case WkdSaSrc_Winsock_Provider: return "Winsock Provider";
        case WkdSaSrc_ComHijack: return "COM Hijack";
        case WkdSaSrc_ShellServiceObjectDelay: return "Shell Service Object Delay Load";
        case WkdSaSrc_BrowserHelper: return "Browser Helper Object";
        case WkdSaSrc_ExplorerRun: return "Explorer Run";
        case WkdSaSrc_ActiveSetup: return "Active Setup";
        case WkdSaSrc_UserShellFolders: return "User Shell Folders";
        case WkdSaSrc_SessionManager_Execute: return "Session Manager Execute";
        case WkdSaSrc_TerminalServer_Startup: return "Terminal Server Startup";
        case WkdSaSrc_NaturalLanguage_DLL: return "Natural Language DLL";
        case WkdSaSrc_NetworkProvider: return "Network Provider";
        case WkdSaSrc_ProtocolHandler: return "Protocol Handler";
        case WkdSaSrc_ScreenSaver: return "Screen Saver";
        case WkdSaSrc_WmiSubscription: return "WMI Subscription";
        case WkdSaSrc_BitsJob: return "BITS Job";
        case WkdSaSrc_OfficeAddin: return "Office Add-in";
        case WkdSaSrc_DomainPolicy: return "Domain Policy";
        case WkdSaSrc_DriverService: return "Driver Service";
        default: return "Unknown";
    }
}

PCSTR
SaLookupStatusName(_In_ ULONG Status) {
    switch (Status) {
        case WkdSaStatus_Enabled: return "Enabled";
        case WkdSaStatus_Disabled: return "Disabled";
        case WkdSaStatus_Delayed: return "Delayed";
        case WkdSaStatus_Quarantined: return "Quarantined";
        case WkdSaStatus_Removed: return "Removed";
        case WkdSaStatus_Orphaned: return "Orphaned";
        case WkdSaStatus_Error: return "Error";
        default: return "Unknown";
    }
}

PCSTR
SaLookupCategoryName(_In_ ULONG Category) {
    switch (Category) {
        case WkdSaCat_Unknown: return "Unknown";
        case WkdSaCat_System: return "System";
        case WkdSaCat_Security: return "Security";
        case WkdSaCat_Hardware: return "Hardware";
        case WkdSaCat_Application: return "Application";
        case WkdSaCat_Utility: return "Utility";
        case WkdSaCat_Bloatware: return "Bloatware";
        case WkdSaCat_Malicious: return "Malicious";
        default: return "Unknown";
    }
}

PCSTR
SaLookupImpactName(_In_ ULONG Level) {
    switch (Level) {
        case WkdSaImpact_None: return "None";
        case WkdSaImpact_Low: return "Low";
        case WkdSaImpact_Medium: return "Medium";
        case WkdSaImpact_High: return "High";
        case WkdSaImpact_Critical: return "Critical";
        default: return "Unknown";
    }
}

PCSTR
SaLookupActionResultName(_In_ ULONG Result) {
    switch (Result) {
        case WkdSaAction_Success: return "Success";
        case WkdSaAction_Failed: return "Failed";
        case WkdSaAction_AccessDenied: return "Access Denied";
        case WkdSaAction_NotFound: return "Not Found";
        case WkdSaAction_AlreadyInState: return "Already In State";
        case WkdSaAction_RequiresReboot: return "Requires Reboot";
        case WkdSaAction_PartialSuccess: return "Partial Success";
        default: return "Unknown";
    }
}

PCSTR
SaLookupRecommendationName(_In_ ULONG Recommendation) {
    switch (Recommendation) {
        case WkdSaRec_Keep: return "Keep";
        case WkdSaRec_Delay: return "Delay";
        case WkdSaRec_Disable: return "Disable";
        case WkdSaRec_Remove: return "Remove";
        case WkdSaRec_Investigate: return "Investigate";
        default: return "Unknown";
    }
}

PCSTR
SaGetVersionString(VOID) {
    return "3.0.0";
}

/* ==================================================
 * 枚举集合容器 (对应 SS RefreshItems 中的局部 vector<StartupItem>)
 * 每条目独立堆分配; 分析完成后整体换入 g_sa.Items
 * ================================================== */
typedef struct _SA_COLLECTION {
    PWKD_SA_ITEM* Items;
    ULONG         Count;
    ULONG         Capacity;
} SA_COLLECTION;

#define WKD_SA_COLLECTION_INIT_CAP 256

static
BOOLEAN SaCollectionAppend(_Inout_ SA_COLLECTION* Coll, _In_ PCWKD_SA_ITEM Item) {
    if (Coll == NULL || Item == NULL) return FALSE;
    if (Coll->Count >= WKD_SA_MAX_ITEMS) return FALSE;
    if (Coll->Count >= Coll->Capacity) {
        ULONG newCap = (Coll->Capacity > 0) ? Coll->Capacity : WKD_SA_COLLECTION_INIT_CAP;
        newCap *= 2;
        if (newCap > WKD_SA_MAX_ITEMS) newCap = WKD_SA_MAX_ITEMS;
        if (newCap <= Coll->Capacity) return FALSE;
        PWKD_SA_ITEM* newArr = (PWKD_SA_ITEM*)UtHeapAlloc(newCap * sizeof(PWKD_SA_ITEM));
        if (newArr == NULL) return FALSE;
        if (Coll->Items != NULL) {
            memcpy(newArr, Coll->Items, Coll->Count * sizeof(PWKD_SA_ITEM));
            UtHeapFree(Coll->Items);
        }
        Coll->Items = newArr;
        Coll->Capacity = newCap;
    }
    PWKD_SA_ITEM copy = (PWKD_SA_ITEM)UtHeapAlloc(sizeof(WKD_SA_ITEM));
    if (copy == NULL) return FALSE;
    *copy = *Item;
    Coll->Items[Coll->Count++] = copy;
    return TRUE;
}

static
VOID SaCollectionFree(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;
    for (ULONG i = 0; i < Coll->Count; ++i) {
        if (Coll->Items != NULL && Coll->Items[i] != NULL) {
            UtHeapFree(Coll->Items[i]);
        }
    }
    if (Coll->Items != NULL) {
        UtHeapFree(Coll->Items);
    }
    Coll->Items = NULL;
    Coll->Count = 0;
    Coll->Capacity = 0;
}

/* ==================================================
 * 注册表静态助手 (RegistryUtils 封装内联)
 * ================================================== */

/* 打开注册表键 (KEY_READ 权限, 可选 WoW64 32 视图) */
static
BOOLEAN SaRegOpenKey(_In_ HKEY hRoot, _In_ PCWSTR SubPath, _In_ BOOLEAN Wow64,
                     _Out_ PHKEY hOut) {
    if (hOut == NULL) return FALSE;
    *hOut = NULL;
    if (hRoot == NULL) return FALSE;
    REGSAM access = KEY_READ;
    if (Wow64) access |= KEY_WOW64_32KEY;

    LSTATUS status;
    if (SaWcsEmpty(SubPath)) {
        /* 根键: 引用自身 (RegOpenKeyExW 空路径打开根) */
        status = RegOpenKeyExW(hRoot, NULL, 0, access, hOut);
    } else {
        status = RegOpenKeyExW(hRoot, SubPath, 0, access, hOut);
    }
    return (status == ERROR_SUCCESS && *hOut != NULL);
}

/* 读取注册表串值 (原始数据 + 类型; REG_SZ/REG_EXPAND_SZ, >64KiB 拒绝。
 * 对应 SS ReadStringValueCapped 之元数据检查) */
static
BOOLEAN SaRegQueryStringRaw(_In_ HKEY hKey, _In_ PCWSTR ValueName,
                            _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch,
                            _Out_ PDWORD OutType) {
    if (hKey == NULL || Out == NULL || OutCch == 0) return FALSE;
    Out[0] = L'\0';
    if (OutType != NULL) *OutType = REG_NONE;

    DWORD type = REG_NONE;
    DWORD size = 0;
    LSTATUS status = RegQueryValueExW(hKey, (ValueName != NULL) ? ValueName : L"",
                                      NULL, &type, NULL, &size);
    if (status != ERROR_SUCCESS) return FALSE;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return FALSE;
    if (size > WKD_SA_MAX_REG_PAYLOAD) {
        CHAR vn[WKD_SA_MAX_LOG_FIELD_CHARS + 32];
        SaSanitizeNarrow((ValueName != NULL) ? ValueName : L"", vn, _countof(vn));
        SaDbgPrint(L"[SA] Rejected oversized registry string value %hs (%lu bytes)",
                   vn, size);
        return FALSE;
    }

    if (size < sizeof(WCHAR)) {
        if (OutType != NULL) *OutType = type;
        return TRUE;   /* 空串合法 */
    }

    /* 分配堆缓冲读取 (避免栈上攻击者尺寸) */
    PWSTR buf = (PWSTR)UtHeapAlloc(size + sizeof(WCHAR));
    if (buf == NULL) return FALSE;
    status = RegQueryValueExW(hKey, (ValueName != NULL) ? ValueName : L"",
                              NULL, &type, (LPBYTE)buf, &size);
    if (status != ERROR_SUCCESS) {
        UtHeapFree(buf);
        return FALSE;
    }
    buf[size / sizeof(WCHAR)] = L'\0';
    /* 遇内嵌 NUL 截断 */
    buf[wcscspn(buf, L"") == 0 ? 0 : wcslen(buf)] = L'\0';
    (VOID)StringCchCopyW(Out, OutCch, buf);
    UtHeapFree(buf);

    if (OutType != NULL) *OutType = type;
    return TRUE;
}

/* 读取串值并按类型展开 %ENV% (对应 SS ReadExpandString 语义) */
static
BOOLEAN SaRegQueryStringExpanded(_In_ HKEY hKey, _In_ PCWSTR ValueName,
                                 _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch,
                                 _Out_ PDWORD OutType) {
    WCHAR raw[WKD_PD_MAX_CMD_BUFFER];
    DWORD type = REG_NONE;
    if (!SaRegQueryStringRaw(hKey, ValueName, raw, _countof(raw), &type)) return FALSE;
    if (OutType != NULL) *OutType = type;

    if (type == REG_EXPAND_SZ && wcschr(raw, L'%') != NULL) {
        const DWORD need = ExpandEnvironmentStringsW(raw, NULL, 0);
        if (need > 0 && need <= WKD_SA_CANONICALIZE_CEIL) {
            PWSTR buf = (PWSTR)UtHeapAlloc(need * sizeof(WCHAR));
            if (buf != NULL) {
                const DWORD written = ExpandEnvironmentStringsW(raw, buf, need);
                if (written > 0 && written < need) {
                    buf[written] = L'\0';
                    (VOID)StringCchCopyW(Out, OutCch, buf);
                    UtHeapFree(buf);
                    return TRUE;
                }
                UtHeapFree(buf);
            }
        }
    }
    (VOID)StringCchCopyW(Out, OutCch, raw);
    return TRUE;
}

/* 读取 REG_MULTI_SZ (→ 分段拷贝到调用方缓冲, 返回段数, >64KiB 拒绝) */
static
ULONG SaRegQueryMultiString(_In_ HKEY hKey, _In_ PCWSTR ValueName,
                            _Out_writes_(MaxSegments * SegmentCch) PWSTR Segments,
                            _In_ ULONG MaxSegments, _In_ ULONG SegmentCch) {
    if (hKey == NULL || Segments == NULL || MaxSegments == 0) return 0;
    DWORD type = REG_NONE;
    DWORD size = 0;
    LSTATUS status = RegQueryValueExW(hKey, (ValueName != NULL) ? ValueName : L"",
                                      NULL, &type, NULL, &size);
    if (status != ERROR_SUCCESS || type != REG_MULTI_SZ) return 0;
    if (size > WKD_SA_MAX_REG_PAYLOAD) {
        CHAR vn[WKD_SA_MAX_LOG_FIELD_CHARS + 32];
        SaSanitizeNarrow((ValueName != NULL) ? ValueName : L"", vn, _countof(vn));
        SaDbgPrint(L"[SA] Rejected oversized registry multi-string value %hs (%lu bytes)",
                   vn, size);
        return 0;
    }
    if (size < sizeof(WCHAR) * 2) return 0;

    PWSTR buf = (PWSTR)UtHeapAlloc(size + sizeof(WCHAR));
    if (buf == NULL) return 0;
    status = RegQueryValueExW(hKey, (ValueName != NULL) ? ValueName : L"",
                              NULL, &type, (LPBYTE)buf, &size);
    if (status != ERROR_SUCCESS) {
        UtHeapFree(buf);
        return 0;
    }
    buf[size / sizeof(WCHAR)] = L'\0';
    buf[(size / sizeof(WCHAR)) + 1] = L'\0';

    ULONG count = 0;
    PCWSTR p = buf;
    while (*p != L'\0' && count < MaxSegments) {
        (VOID)StringCchCopyW(&Segments[count * SegmentCch], SegmentCch, p);
        ++count;
        p += wcslen(p) + 1;
    }
    UtHeapFree(buf);
    return count;
}

/* 枚举值名列表 (调用方缓冲, 返回数量; 仅供值名遍历) */
static
ULONG SaRegEnumValueNames(_In_ HKEY hKey, _Out_writes_(MaxValues * WKD_REG_MAX_NAME_CHARS) PWSTR Names,
                          _In_ ULONG MaxValues) {
    if (hKey == NULL || Names == NULL || MaxValues == 0) return 0;
    ULONG count = 0;
    for (ULONG index = 0; count < MaxValues; ++index) {
        WCHAR name[WKD_REG_MAX_NAME_CHARS];
        DWORD nameCch = WKD_REG_MAX_NAME_CHARS;
        LSTATUS status = RegEnumValueW(hKey, index, name, &nameCch, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;
        (VOID)StringCchCopyW(&Names[count * WKD_REG_MAX_NAME_CHARS], WKD_REG_MAX_NAME_CHARS, name);
        ++count;
    }
    return count;
}

/* 枚举子键名列表 (调用方缓冲, 返回数量) */
static
ULONG SaRegEnumSubKeys(_In_ HKEY hKey, _Out_writes_(MaxKeys * WKD_REG_MAX_NAME_CHARS) PWSTR Keys,
                       _In_ ULONG MaxKeys) {
    if (hKey == NULL || Keys == NULL || MaxKeys == 0) return 0;
    ULONG count = 0;
    for (ULONG index = 0; count < MaxKeys; ++index) {
        WCHAR name[WKD_REG_MAX_NAME_CHARS];
        DWORD nameCch = WKD_REG_MAX_NAME_CHARS;
        LSTATUS status = RegEnumKeyExW(hKey, index, name, &nameCch, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;
        (VOID)StringCchCopyW(&Keys[count * WKD_REG_MAX_NAME_CHARS], WKD_REG_MAX_NAME_CHARS, name);
        ++count;
    }
    return count;
}

/* ==================================================
 * 快捷方式解析 (对应 SS ResolveShortcut, IShellLinkW COM)
 * ================================================== */
static
BOOLEAN SaResolveShortcut(_In_ PCWSTR LnkPath, _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return FALSE;
    Out[0] = L'\0';
    if (SaWcsEmpty(LnkPath)) return FALSE;

    /* STA 单线程套间 + 禁用 OLE1DDE; 仅在本线程成功初始化时清理 */
    const HRESULT coInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const BOOLEAN weInitialised = SUCCEEDED(coInit);

    BOOLEAN resolved = FALSE;
    IShellLinkW* psl = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                                  &IID_IShellLinkW, (void**)&psl);
    if (SUCCEEDED(hr) && psl != NULL) {
        IPersistFile* ppf = NULL;
        hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void**)&ppf);
        if (SUCCEEDED(hr) && ppf != NULL) {
            hr = ppf->lpVtbl->Load(ppf, LnkPath, STGM_READ);
            if (SUCCEEDED(hr)) {
                WCHAR szPath[MAX_PATH];
                WIN32_FIND_DATAW wfd;
                memset(&wfd, 0, sizeof(wfd));
                hr = psl->lpVtbl->GetPath(psl, szPath, MAX_PATH, &wfd, SLGP_RAWPATH);
                if (SUCCEEDED(hr) && szPath[0] != L'\0') {
                    (VOID)StringCchCopyW(Out, OutCch, szPath);
                    resolved = TRUE;
                }
            }
            ppf->lpVtbl->Release(ppf);
        }
        psl->lpVtbl->Release(psl);
    }

    if (weInitialised) {
        CoUninitialize();
    }
    return resolved;
}

/* ==================================================
 * 条目构造辅助 (对应 SS AppendStartupValueItem)
 * ================================================== */
static
VOID SaAppendStartupValueItem(_Inout_ SA_COLLECTION* Coll, _In_ ULONG Source,
                              _In_ PCWSTR KeyPath, _In_ PCWSTR ValueName,
                              _In_ PCWSTR Command, _In_ ULONG Ordinal) {
    if (Coll == NULL || SaWcsEmpty(Command)) return;
    if (Coll->Count >= WKD_SA_MAX_ITEMS) return;

    WKD_SA_ITEM item;
    memset(&item, 0, sizeof(item));
    item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
    if (Ordinal == 0) {
        (VOID)StringCchCopyW(item.Name, _countof(item.Name), ValueName);
    } else {
        (VOID)StringCchPrintfW(item.Name, _countof(item.Name), L"%s[%lu]",
                                (ValueName != NULL) ? ValueName : L"", Ordinal);
    }
    (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName), item.Name);
    item.Source = Source;
    (VOID)StringCchCopyW(item.Location, _countof(item.Location), (KeyPath != NULL) ? KeyPath : L"");
    (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), (ValueName != NULL) ? ValueName : L"");
    (VOID)StringCchCopyW(item.Command, _countof(item.Command), Command);

    SaParseCommand(&item);
    if (item.TargetPath[0] != L'\0') {
        item.TargetExists = SaFileExists(item.TargetPath);
    }
    item.Status = WkdSaStatus_Enabled;
    item.IsEnabled = TRUE;
    (VOID)SaCollectionAppend(Coll, &item);
}

/* ==================================================
 * 核心枚举器
 * ================================================== */

/* Run/RunOnce 键枚举 (对应 SS EnumerateRegistryRun)
 * LocationPrefix: 非 NULL 时写入条目 Location 的根前缀
 * (如 L"HKEY_USERS\\"), 供管理回写 ResolveRegistryItemRootAndPath
 * 精准定位; SS 对 HKU/HKLM 无前缀时 fallback 错写 HKCU 的隐患修正 */
static
VOID SaEnumerateRegistryRun(_Inout_ SA_COLLECTION* Coll, _In_ HKEY hRoot,
                            _In_ ULONG Source, _In_ PCWSTR KeyPath, _In_ BOOLEAN Wow64,
                            _In_opt_ PCWSTR LocationPrefix) {
    if (Coll == NULL) return;

    HKEY hKey = NULL;
    if (!SaRegOpenKey(hRoot, KeyPath, Wow64, &hKey)) return;

    /* 遍历值: 先收集值名, 再逐一按类型读串 (值名缓冲统一 256) */
    WCHAR names[256][WKD_REG_MAX_NAME_CHARS];
    const ULONG nameCount = SaRegEnumValueNames(hKey, &names[0][0], 256);

    for (ULONG i = 0; i < nameCount && Coll->Count < WKD_SA_MAX_ITEMS; ++i) {
        WCHAR raw[WKD_PD_MAX_CMD_BUFFER];
        DWORD type = REG_NONE;
        if (!SaRegQueryStringExpanded(hKey, names[i], raw, _countof(raw), &type)) {
            continue;
        }
        if (raw[0] == L'\0') continue;

        WKD_SA_ITEM item;
        memset(&item, 0, sizeof(item));
        item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
        (VOID)StringCchCopyW(item.Name, _countof(item.Name), names[i]);
        (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName), names[i]);
        item.Source = Source;
        if (LocationPrefix != NULL && LocationPrefix[0] != L'\0') {
            (VOID)StringCchPrintfW(item.Location, _countof(item.Location),
                                   L"%s%s", LocationPrefix, KeyPath);
        } else {
            (VOID)StringCchCopyW(item.Location, _countof(item.Location), KeyPath);
        }
        (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), names[i]);
        (VOID)StringCchCopyW(item.Command, _countof(item.Command), raw);

        SaParseCommand(&item);
        if (item.TargetPath[0] != L'\0') {
            item.TargetExists = SaFileExists(item.TargetPath);
        }
        item.Status = WkdSaStatus_Enabled;
        item.IsEnabled = TRUE;
        (VOID)SaCollectionAppend(Coll, &item);
    }

    RegCloseKey(hKey);
}

/* 启动文件夹枚举 (用户 + 公共) */
static
VOID SaEnumerateStartupFolder(_Inout_ SA_COLLECTION* Coll, _In_ PCWSTR FolderPath,
                              _In_ ULONG Source);

static
VOID SaEnumerateStartupFolders(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;
    WCHAR path[MAX_PATH];

    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path) == S_OK) {
        SaEnumerateStartupFolder(Coll, path, WkdSaSrc_StartupFolder_User);
    }
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, path) == S_OK) {
        SaEnumerateStartupFolder(Coll, path, WkdSaSrc_StartupFolder_AllUsers);
    }
}

/* 单文件夹条目枚举 (对应 SS EnumerateStartupFolder):
 * - 仅常规文件 (跳过目录)
 * - .lnk 经 IShellLinkW 解析目标, 失败回退 lnk 路径本身
 * - 其他文件 targetPath = 规范化自身路径                               */
static
VOID SaEnumerateStartupFolder(_Inout_ SA_COLLECTION* Coll, _In_ PCWSTR FolderPath,
                              _In_ ULONG Source) {
    if (Coll == NULL || SaWcsEmpty(FolderPath)) return;

    WCHAR pattern[MAX_PATH * 2];
    (VOID)StringCchPrintfW(pattern, _countof(pattern), L"%s\\*", FolderPath);

    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (Coll->Count >= WKD_SA_MAX_ITEMS) break;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        WCHAR fullPath[MAX_PATH * 2];
        (VOID)StringCchPrintfW(fullPath, _countof(fullPath), L"%s\\%s",
                                FolderPath, ffd.cFileName);

        WKD_SA_ITEM item;
        memset(&item, 0, sizeof(item));
        item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
        (VOID)StringCchCopyW(item.Name, _countof(item.Name), ffd.cFileName);
        (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName), ffd.cFileName);
        item.Source = Source;
        (VOID)StringCchCopyW(item.Location, _countof(item.Location), FolderPath);
        (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), ffd.cFileName);

        /* .lnk 快捷方式解析 */
        const WCHAR* dot = wcsrchr(ffd.cFileName, L'.');
        BOOLEAN isLnk = FALSE;
        if (dot != NULL && _wcsicmp(dot, L".lnk") == 0) isLnk = TRUE;

        if (isLnk) {
            WCHAR target[WKD_REG_MAX_PATH_CHARS];
            if (SaResolveShortcut(fullPath, target, _countof(target)) && target[0] != L'\0') {
                SaCanonicalizePath(target, item.TargetPath, _countof(item.TargetPath));
            } else {
                (VOID)StringCchCopyW(item.TargetPath, _countof(item.TargetPath), fullPath);
            }
        } else {
            SaCanonicalizePath(fullPath, item.TargetPath, _countof(item.TargetPath));
        }

        item.TargetExists = (item.TargetPath[0] != L'\0') ? SaFileExists(item.TargetPath) : FALSE;
        item.Status = WkdSaStatus_Enabled;
        item.IsEnabled = TRUE;
        (VOID)SaCollectionAppend(Coll, &item);
    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);
}

/* 单值枚举 (对应 SS EnumerateSingleValue):
 * - LSA 包/BootExecute 为 REG_MULTI_SZ → 逐段
 * - Winlogon Shell/Userinit → 逗号分割; AppInit → 逗号+空白分割
 * - 其余 → 单段                                                       */
static
VOID SaEnumerateSingleValue(_Inout_ SA_COLLECTION* Coll, _In_ HKEY hRoot,
                            _In_ ULONG Source, _In_ PCWSTR KeyPath,
                            _In_ PCWSTR ValueName, _In_ BOOLEAN Wow64) {
    if (Coll == NULL) return;

    HKEY hKey = NULL;
    if (!SaRegOpenKey(hRoot, KeyPath, Wow64, &hKey)) return;

    /* REG_MULTI_SZ 源 (LSA/Security Packages/BootExecute) */
    if (Source == WkdSaSrc_LSA_AuthenticationPackages ||
        Source == WkdSaSrc_LSA_SecurityPackages ||
        Source == WkdSaSrc_BootExecute) {
        WCHAR segments[WKD_SA_SPLIT_MAX_SEGMENTS][WKD_REG_MAX_PATH_CHARS];
        const ULONG segCount = SaRegQueryMultiString(hKey, ValueName,
                                                     &segments[0][0], WKD_SA_SPLIT_MAX_SEGMENTS,
                                                     WKD_REG_MAX_PATH_CHARS);
        for (ULONG i = 0; i < segCount; ++i) {
            SaAppendStartupValueItem(Coll, Source, KeyPath, ValueName, segments[i], i);
        }
        RegCloseKey(hKey);
        return;
    }

    WCHAR value[WKD_PD_MAX_CMD_BUFFER];
    DWORD type = REG_NONE;
    if (!SaRegQueryStringExpanded(hKey, ValueName, value, _countof(value), &type)) {
        RegCloseKey(hKey);
        return;
    }
    if (value[0] == L'\0') {
        RegCloseKey(hKey);
        return;
    }

    BOOLEAN splitComma = FALSE;
    BOOLEAN splitWhitespace = FALSE;
    switch (Source) {
        case WkdSaSrc_Winlogon_Shell:
        case WkdSaSrc_Winlogon_Userinit:
            splitComma = TRUE;
            break;
        case WkdSaSrc_AppInit_DLLs:
            splitComma = TRUE;
            splitWhitespace = TRUE;
            break;
        default:
            break;
    }

    if (splitComma || splitWhitespace) {
        PWSTR segPtrs[WKD_SA_SPLIT_MAX_SEGMENTS];
        WCHAR segBufs[WKD_SA_SPLIT_MAX_SEGMENTS][WKD_PD_MAX_CMD_BUFFER];
        for (ULONG i = 0; i < WKD_SA_SPLIT_MAX_SEGMENTS; ++i) segPtrs[i] = segBufs[i];
        const ULONG segCount = SaSplitStartupValueList(
            value, splitComma, splitWhitespace, segPtrs, WKD_PD_MAX_CMD_BUFFER,
            WKD_SA_SPLIT_MAX_SEGMENTS);
        for (ULONG i = 0; i < segCount; ++i) {
            SaAppendStartupValueItem(Coll, Source, KeyPath, ValueName, segBufs[i], i);
        }
    } else {
        SaAppendStartupValueItem(Coll, Source, KeyPath, ValueName, value, 0);
    }

    RegCloseKey(hKey);
}

/* IFEO 枚举 (对应 SS EnumerateIFEO, T1546.012) */
static
VOID SaEnumerateIFEO(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;
    const WCHAR ifeoPath[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    HKEY hIfeo = NULL;
    if (!SaRegOpenKey(HKEY_LOCAL_MACHINE, ifeoPath, FALSE, &hIfeo)) return;

    WCHAR exeNames[128][WKD_REG_MAX_NAME_CHARS];
    const ULONG subKeyCount = SaRegEnumSubKeys(hIfeo, &exeNames[0][0], 128);

    for (ULONG i = 0; i < subKeyCount && Coll->Count < WKD_SA_MAX_ITEMS; ++i) {
        WCHAR subPath[MAX_PATH * 2];
        (VOID)StringCchPrintfW(subPath, _countof(subPath), L"%s\\%s", ifeoPath, exeNames[i]);

        HKEY hExe = NULL;
        if (!SaRegOpenKey(HKEY_LOCAL_MACHINE, subPath, FALSE, &hExe)) continue;

        WCHAR debugger[WKD_PD_MAX_CMD_BUFFER];
        DWORD type = REG_NONE;
        const BOOLEAN haveDebugger = SaRegQueryStringExpanded(hExe, L"Debugger",
                                                              debugger, _countof(debugger), &type);
        RegCloseKey(hExe);
        if (!haveDebugger || debugger[0] == L'\0') continue;

        WKD_SA_ITEM item;
        memset(&item, 0, sizeof(item));
        item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
        (VOID)StringCchPrintfW(item.Name, _countof(item.Name), L"IFEO:%s", exeNames[i]);
        (VOID)StringCchPrintfW(item.DisplayName, _countof(item.DisplayName),
                               L"Image File Execution Options: %s", exeNames[i]);
        item.Source = WkdSaSrc_IFEO;
        (VOID)StringCchCopyW(item.Location, _countof(item.Location), subPath);
        (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), L"Debugger");
        (VOID)StringCchCopyW(item.Command, _countof(item.Command), debugger);
        item.IsHidden = TRUE;   /* IFEO 条目天然隐蔽 */

        SaParseCommand(&item);
        if (item.TargetPath[0] != L'\0') {
            item.TargetExists = SaFileExists(item.TargetPath);
        }
        item.Status = WkdSaStatus_Enabled;
        item.IsEnabled = TRUE;
        (VOID)SaCollectionAppend(Coll, &item);
    }

    RegCloseKey(hIfeo);
}

/* Print Monitor 枚举 (对应 SS EnumeratePrintMonitors, T1547.010) */
static
VOID SaEnumeratePrintMonitors(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;
    const WCHAR monPath[] = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";

    HKEY hMon = NULL;
    if (!SaRegOpenKey(HKEY_LOCAL_MACHINE, monPath, FALSE, &hMon)) return;

    WCHAR monNames[64][WKD_REG_MAX_NAME_CHARS];
    const ULONG subKeyCount = SaRegEnumSubKeys(hMon, &monNames[0][0], 64);

    for (ULONG i = 0; i < subKeyCount && Coll->Count < WKD_SA_MAX_ITEMS; ++i) {
        WCHAR subPath[MAX_PATH * 2];
        (VOID)StringCchPrintfW(subPath, _countof(subPath), L"%s\\%s", monPath, monNames[i]);

        HKEY hMonKey = NULL;
        if (!SaRegOpenKey(HKEY_LOCAL_MACHINE, subPath, FALSE, &hMonKey)) continue;

        WCHAR driver[WKD_REG_MAX_PATH_CHARS];
        DWORD type = REG_NONE;
        const BOOLEAN haveDriver = SaRegQueryStringExpanded(hMonKey, L"Driver",
                                                            driver, _countof(driver), &type);
        RegCloseKey(hMonKey);
        if (!haveDriver || driver[0] == L'\0') continue;

        WKD_SA_ITEM item;
        memset(&item, 0, sizeof(item));
        item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
        (VOID)StringCchPrintfW(item.Name, _countof(item.Name), L"PrintMon:%s", monNames[i]);
        (VOID)StringCchPrintfW(item.DisplayName, _countof(item.DisplayName),
                               L"Print Monitor: %s", monNames[i]);
        item.Source = WkdSaSrc_PrintMonitor;
        (VOID)StringCchCopyW(item.Location, _countof(item.Location), subPath);
        (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), L"Driver");
        (VOID)StringCchCopyW(item.Command, _countof(item.Command), driver);

        /* 打印监视器 DLL 相对系统目录加载 (运行时查询, 不硬编码 C:\) */
        WCHAR sysDir[MAX_PATH];
        WCHAR fullPath[WKD_REG_MAX_PATH_CHARS];
        SaSystemDirectoryW(sysDir, _countof(sysDir));
        (VOID)StringCchPrintfW(fullPath, _countof(fullPath), L"%s%s", sysDir, driver);
        SaCanonicalizePath(fullPath, item.TargetPath, _countof(item.TargetPath));
        item.TargetExists = (item.TargetPath[0] != L'\0') ? SaFileExists(item.TargetPath) : FALSE;
        item.Status = WkdSaStatus_Enabled;
        item.IsEnabled = TRUE;
        (VOID)SaCollectionAppend(Coll, &item);
    }

    RegCloseKey(hMon);
}

/* Active Setup 枚举 (对应 SS EnumerateActiveSetup, T1547.014) */
static
VOID SaEnumerateActiveSetup(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;
    const WCHAR asPath[] = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";

    HKEY hAs = NULL;
    if (!SaRegOpenKey(HKEY_LOCAL_MACHINE, asPath, FALSE, &hAs)) return;

    WCHAR clsidNames[128][WKD_REG_MAX_NAME_CHARS];
    const ULONG subKeyCount = SaRegEnumSubKeys(hAs, &clsidNames[0][0], 128);

    for (ULONG i = 0; i < subKeyCount && Coll->Count < WKD_SA_MAX_ITEMS; ++i) {
        WCHAR subPath[MAX_PATH * 2];
        (VOID)StringCchPrintfW(subPath, _countof(subPath), L"%s\\%s", asPath, clsidNames[i]);

        HKEY hComp = NULL;
        if (!SaRegOpenKey(HKEY_LOCAL_MACHINE, subPath, FALSE, &hComp)) continue;

        WCHAR stubPath[WKD_PD_MAX_CMD_BUFFER];
        DWORD type = REG_NONE;
        const BOOLEAN haveStub = SaRegQueryStringExpanded(hComp, L"StubPath",
                                                          stubPath, _countof(stubPath), &type);
        if (!haveStub || stubPath[0] == L'\0') {
            RegCloseKey(hComp);
            continue;
        }

        WCHAR displayName[WKD_REG_MAX_NAME_CHARS];
        DWORD dnType = REG_NONE;
        const BOOLEAN haveDisplay = SaRegQueryStringExpanded(hComp, L"",
                                                             displayName, _countof(displayName), &dnType);
        RegCloseKey(hComp);

        WKD_SA_ITEM item;
        memset(&item, 0, sizeof(item));
        item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
        (VOID)StringCchPrintfW(item.Name, _countof(item.Name), L"ActiveSetup:%s", clsidNames[i]);
        if (haveDisplay && displayName[0] != L'\0') {
            (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName), displayName);
        } else {
            (VOID)StringCchPrintfW(item.DisplayName, _countof(item.DisplayName),
                                   L"Active Setup: %s", clsidNames[i]);
        }
        item.Source = WkdSaSrc_ActiveSetup;
        (VOID)StringCchCopyW(item.Location, _countof(item.Location), subPath);
        (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), L"StubPath");
        (VOID)StringCchCopyW(item.Command, _countof(item.Command), stubPath);

        SaParseCommand(&item);
        if (item.TargetPath[0] != L'\0') {
            item.TargetExists = SaFileExists(item.TargetPath);
        }
        item.Status = WkdSaStatus_Enabled;
        item.IsEnabled = TRUE;
        (VOID)SaCollectionAppend(Coll, &item);
    }

    RegCloseKey(hAs);
}

/* HKEY_USERS 全域 Run 键枚举 (对应 SS EnumerateAllUserRunKeys, SID 上限 512) */
static
VOID SaEnumerateAllUserRunKeys(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;

    HKEY hUsers = NULL;
    if (!SaRegOpenKey(HKEY_USERS, L"", FALSE, &hUsers)) return;

    WCHAR sids[WKD_SA_HKU_SID_CAP][WKD_REG_MAX_NAME_CHARS];
    const ULONG sidCount = SaRegEnumSubKeys(hUsers, &sids[0][0], WKD_SA_HKU_SID_CAP);
    if (sidCount >= WKD_SA_HKU_SID_CAP) {
        SaDbgPrint(L"[SA] HKEY_USERS SID enumeration cap reached");
    }

    for (ULONG i = 0; i < sidCount; ++i) {
        /* 跳过 *_Classes 视图 */
        if (wcsstr(sids[i], L"_Classes") != NULL) continue;
        if (sids[i][0] == L'\0') continue;

        WCHAR runPath[MAX_PATH * 2];
        WCHAR runOncePath[MAX_PATH * 2];
        (VOID)StringCchPrintfW(runPath, _countof(runPath),
                               L"%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", sids[i]);
        (VOID)StringCchPrintfW(runOncePath, _countof(runOncePath),
                               L"%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", sids[i]);
        SaEnumerateRegistryRun(Coll, HKEY_USERS, WkdSaSrc_RegistryRun_HKCU, runPath, FALSE,
                               L"HKEY_USERS\\");
        SaEnumerateRegistryRun(Coll, HKEY_USERS, WkdSaSrc_RegistryRunOnce_HKCU, runOncePath, FALSE,
                               L"HKEY_USERS\\");
    }

    RegCloseKey(hUsers);
}

/* 计划任务枚举 (委托 PD, 对应 SS EnumerateScheduledTasks)
 * 仅保留: Enabled + Logon/Boot/Registration 触发器 + Exec 动作         */
#define WKD_SA_TASK_BUFFER 512

static
VOID SaEnumerateScheduledTasks(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;

    PWKD_SCHEDULED_TASK_ENTRY tasks = (PWKD_SCHEDULED_TASK_ENTRY)
        UtHeapAlloc(WKD_SA_TASK_BUFFER * sizeof(WKD_SCHEDULED_TASK_ENTRY));
    if (tasks == NULL) return;

    ULONG taskCount = 0;
    if (NT_SUCCESS(PdScanScheduledTasks(WKD_SA_TASK_BUFFER, tasks, &taskCount))) {
        for (ULONG t = 0; t < taskCount && Coll->Count < WKD_SA_MAX_ITEMS; ++t) {
            const WKD_SCHEDULED_TASK_ENTRY* task = &tasks[t];
            if (!task->Enabled) continue;

            BOOLEAN autostartTrigger = FALSE;
            for (ULONG tr = 0; tr < task->TriggerCount; ++tr) {
                if (task->Triggers[tr].Enabled &&
                    (_wcsicmp(task->Triggers[tr].Type, L"Logon") == 0 ||
                     _wcsicmp(task->Triggers[tr].Type, L"Boot") == 0 ||
                     _wcsicmp(task->Triggers[tr].Type, L"Registration") == 0)) {
                    autostartTrigger = TRUE;
                    break;
                }
            }
            if (!autostartTrigger) continue;

            ULONG actionIndex = 0;
            for (ULONG a = 0; a < task->ActionCount; ++a) {
                if (Coll->Count >= WKD_SA_MAX_ITEMS) break;
                const WKD_TASK_ACTION* action = &task->Actions[a];
                if (_wcsicmp(action->Type, L"Exec") != 0 || action->Path[0] == L'\0') continue;

                WKD_SA_ITEM item;
                memset(&item, 0, sizeof(item));
                item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
                if (task->TaskPath[0] != L'\0') {
                    (VOID)StringCchCopyW(item.Name, _countof(item.Name), task->TaskPath);
                } else {
                    (VOID)StringCchCopyW(item.Name, _countof(item.Name), task->TaskName);
                }
                if (actionIndex > 0) {
                    WCHAR base[WKD_REG_MAX_NAME_CHARS];
                    (VOID)StringCchCopyW(base, _countof(base), item.Name);
                    (VOID)StringCchPrintfW(item.Name, _countof(item.Name), L"%s[%lu]",
                                           base, actionIndex);
                }
                (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName),
                                     (task->TaskName[0] != L'\0') ? task->TaskName : item.Name);
                (VOID)StringCchCopyW(item.Description, _countof(item.Description), task->Description);
                item.Source = WkdSaSrc_ScheduledTask;
                (VOID)StringCchCopyW(item.Location, _countof(item.Location), task->TaskPath);
                (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), task->TaskName);
                if (action->Arguments[0] != L'\0') {
                    (VOID)StringCchPrintfW(item.Command, _countof(item.Command),
                                           L"%s %s", action->Path, action->Arguments);
                } else {
                    (VOID)StringCchCopyW(item.Command, _countof(item.Command), action->Path);
                }
                (VOID)StringCchCopyW(item.WorkingDirectory, _countof(item.WorkingDirectory),
                                     action->WorkingDirectory);
                item.IsEnabled = TRUE;
                item.Status = WkdSaStatus_Enabled;

                SaParseCommand(&item);
                if (item.TargetPath[0] != L'\0') {
                    item.TargetExists = SaFileExists(item.TargetPath);
                }
                (VOID)SaCollectionAppend(Coll, &item);
                ++actionIndex;
            }
        }
    }

    UtHeapFree(tasks);
}

/* 服务枚举 (委托 PD, 对应 SS EnumerateServices)
 * 仅保留: AUTO/BOOT/SYSTEM 启动 + ImagePath 非空                          */
#define WKD_SA_SERVICE_BUFFER 512

static
VOID SaEnumerateServices(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;

    PWKD_SERVICE_ENTRY services = (PWKD_SERVICE_ENTRY)
        UtHeapAlloc(WKD_SA_SERVICE_BUFFER * sizeof(WKD_SERVICE_ENTRY));
    if (services == NULL) return;

    ULONG serviceCount = 0;
    if (NT_SUCCESS(PdScanServices(WKD_SA_SERVICE_BUFFER, services, &serviceCount))) {
        for (ULONG s = 0; s < serviceCount && Coll->Count < WKD_SA_MAX_ITEMS; ++s) {
            const WKD_SERVICE_ENTRY* service = &services[s];
            if (service->StartType != SERVICE_AUTO_START &&
                service->StartType != SERVICE_BOOT_START &&
                service->StartType != SERVICE_SYSTEM_START) {
                continue;
            }
            if (service->ImagePath[0] == L'\0') continue;

            WKD_SA_ITEM item;
            memset(&item, 0, sizeof(item));
            item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
            (VOID)StringCchCopyW(item.Name, _countof(item.Name), service->ServiceName);
            (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName),
                                 (service->DisplayName[0] != L'\0') ? service->DisplayName
                                                                    : service->ServiceName);
            (VOID)StringCchCopyW(item.Description, _countof(item.Description), service->Description);
            item.Source = (service->ServiceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER))
                ? WkdSaSrc_DriverService : WkdSaSrc_Service;
            (VOID)StringCchCopyW(item.Location, _countof(item.Location), L"SCM");
            (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName), service->ServiceName);
            (VOID)StringCchCopyW(item.Command, _countof(item.Command), service->ImagePath);
            item.Status = WkdSaStatus_Enabled;
            item.IsEnabled = TRUE;

            SaParseCommand(&item);
            if (item.TargetPath[0] != L'\0') {
                item.TargetExists = SaFileExists(item.TargetPath);
            }
            (VOID)SaCollectionAppend(Coll, &item);
        }
    }

    UtHeapFree(services);
}

/* 扩展自启动位置全集 (对应 SS EnumerateExtendedAutostartKeys, APT 覆盖) */
static
VOID SaEnumerateExtendedAutostartKeys(_Inout_ SA_COLLECTION* Coll) {
    if (Coll == NULL) return;

    /* WoW64 32 位 Run/RunOnce (x64 上恶意软件藏匿 32 位视图) */
    SaEnumerateRegistryRun(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_RegistryRun_Wow64_HKLM,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", TRUE, NULL);
    SaEnumerateRegistryRun(Coll, HKEY_CURRENT_USER, WkdSaSrc_RegistryRun_Wow64_HKCU,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", TRUE, NULL);
    SaEnumerateRegistryRun(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_RegistryRunOnce_Wow64_HKLM,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", TRUE, NULL);
    SaEnumerateRegistryRun(Coll, HKEY_CURRENT_USER, WkdSaSrc_RegistryRunOnce_Wow64_HKCU,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", TRUE, NULL);

    /* RunServices (遗留但部分系统仍生效) */
    SaEnumerateRegistryRun(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_RegistryRunServices_HKLM,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", FALSE, NULL);
    SaEnumerateRegistryRun(Coll, HKEY_CURRENT_USER, WkdSaSrc_RegistryRunServices_HKCU,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", FALSE, NULL);

    /* Explorer\Run (策略级自启动)
     * HKLM 变体需显式根前缀: SS 对 HKLM ExplorerRun 无前缀时
     * ResolveRegistryItemRootAndPath fallback 到 HKCU 会错写 (WkD 修正) */
    SaEnumerateRegistryRun(Coll, HKEY_CURRENT_USER, WkdSaSrc_ExplorerRun,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", FALSE,
                           NULL);
    SaEnumerateRegistryRun(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_ExplorerRun,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", FALSE,
                           L"HKEY_LOCAL_MACHINE\\");

    /* Winlogon Shell/Userinit (T1547.004 — 国家级攻击者偏好) */
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_Winlogon_Shell,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", FALSE);
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_Winlogon_Userinit,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", FALSE);

    /* IFEO Debugger (T1546.012) */
    SaEnumerateIFEO(Coll);

    /* AppInit_DLLs (T1546.010, 64 位 + 32 位视图) */
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_AppInit_DLLs,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                           L"AppInit_DLLs", FALSE);
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_AppInit_DLLs,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                           L"AppInit_DLLs", TRUE);

    /* LSA 认证/安全包 (APT 持久化) */
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_LSA_AuthenticationPackages,
                           L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", FALSE);
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_LSA_SecurityPackages,
                           L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", FALSE);

    /* Print Monitors (T1547.010) */
    SaEnumeratePrintMonitors(Coll);

    /* BootExecute (T1547.012) */
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_BootExecute,
                           L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"BootExecute", FALSE);

    /* Active Setup (T1547.014) */
    SaEnumerateActiveSetup(Coll);

    /* Shell Service Object Delay Load */
    SaEnumerateRegistryRun(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_ShellServiceObjectDelay,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", FALSE, NULL);

    /* ScreenSaver 持久化 */
    SaEnumerateSingleValue(Coll, HKEY_CURRENT_USER, WkdSaSrc_ScreenSaver,
                           L"Control Panel\\Desktop", L"SCRNSAVE.EXE", FALSE);

    /* Natural Language DLL 覆盖 */
    SaEnumerateSingleValue(Coll, HKEY_LOCAL_MACHINE, WkdSaSrc_NaturalLanguage_DLL,
                           L"SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Language\\English_US",
                           L"DLLOverridePath", FALSE);

    /* HKEY_USERS 全 SID Run 键 */
    SaEnumerateAllUserRunKeys(Coll);

    /* 计划任务 / 服务 (委托 PD) */
    SaEnumerateScheduledTasks(Coll);
    SaEnumerateServices(Coll);
}

/* ==================================================
 * 安全分析 (对应 SS AnalyzeItemSecurity 全链路)
 * ================================================== */

static
VOID SaAppendRiskFactor(_Inout_ PWKD_SA_ITEM Item, _In_ PCSTR Text) {
    if (Item == NULL || Text == NULL) return;
    if (Item->RiskFactorCount >= WKD_SA_MAX_RISK_FACTORS) return;
    (VOID)StringCchCopyA(Item->RiskFactors[Item->RiskFactorCount],
                         _countof(Item->RiskFactors[0]), Text);
    ++Item->RiskFactorCount;
}

/* 大小写不敏感子串匹配 (SS ToLowerCopy+find 迁移) */
static
BOOLEAN SaContainsI(_In_ PCWSTR Str, _In_ PCWSTR Needle) {
    if (Str == NULL || Needle == NULL || *Needle == L'\0') return FALSE;
    const SIZE_T needleLen = wcslen(Needle);
    for (PCWSTR p = Str; *p != L'\0'; ++p) {
        if (_wcsnicmp(p, Needle, needleLen) == 0) return TRUE;
    }
    return FALSE;
}

/* 签名分析 (对应 SS AnalyzeSignature, 迁移到 IocVerifySignature) */
static
VOID SaAnalyzeSignature(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL || Item->TargetPath[0] == L'\0') return;
    if (!Item->TargetExists) return;

    IOC_SCAN_RESULT scanResult;
    memset(&scanResult, 0, sizeof(scanResult));
    scanResult.CertStatus = DefCertStatus_Unknown;

    if (!NT_SUCCESS(IocVerifySignature(Item->TargetPath, &scanResult))) {
        SaDbgPrint(L"[SA] Signature verification failed for %hs",
                   Item->Name[0] != L'\0' ? L"item" : L"item");
        return;
    }

    Item->Signature.IsSigned =
        (scanResult.CertStatus != DefCertStatus_Unsigned &&
         scanResult.CertStatus != DefCertStatus_Unknown);
    Item->Signature.IsValid = (scanResult.CertValid == TRUE);
    Item->Signature.IsTrusted = (scanResult.CertTrusted == TRUE);
    Item->Signature.IsMicrosoftSigned = IocScan_IsMicrosoftSigned(&scanResult);
    (VOID)StringCchCopyW(Item->Signature.SignerName, _countof(Item->Signature.SignerName),
                         scanResult.SignerName);
    (VOID)StringCchCopyW(Item->Signature.IssuerName, _countof(Item->Signature.IssuerName),
                         scanResult.IssuerName);
    if (scanResult.Thumbprint[0] != '\0') {
        (VOID)StringCchCopyA(Item->Signature.Thumbprint, _countof(Item->Signature.Thumbprint),
                             scanResult.Thumbprint);
    }
    Item->Signature.IsExpired = (scanResult.CertStatus == DefCertStatus_Expired);
    Item->Signature.IsRevoked = (scanResult.CertStatus == DefCertStatus_Revoked);
    Item->Signature.SignatureTime = 0;   /* 无对应源, 恒 0 */
}

/* 信誉分析 (对应 SS CheckReputation, 委托 PD 实时分析) */
static
VOID SaCheckReputation(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL) return;

    if (Item->Sha256Hex[0] == '\0') {
        Item->Reputation.TrustScore = 50;
        (VOID)StringCchCopyA(Item->Reputation.Reputation, _countof(Item->Reputation.Reputation),
                             "Unknown");
        return;
    }

    /* 委托 PD 该路径/命令行的实时信誉判定 (哈希+签名+白名单基建) */
    const ULONG dataSize = (ULONG)((wcslen(Item->Command) + 1) * sizeof(WCHAR));
    const WKD_REG_RISK_LEVEL risk = PdAnalyzeRealTime(
        Item->Location, Item->EntryName,
        (const BYTE*)Item->Command, dataSize);

    switch (risk) {
        case WkdRegRisk_Safe:       /* 0 */
            Item->Reputation.IsKnownGood = TRUE;
            Item->Reputation.TrustScore = 95;
            (VOID)StringCchCopyA(Item->Reputation.Reputation, _countof(Item->Reputation.Reputation),
                                 "Good");
            return;
        case WkdRegRisk_Malicious:  /* 4 */
            Item->Reputation.IsKnownBad = TRUE;
            Item->Reputation.TrustScore = 0;
            (VOID)StringCchCopyA(Item->Reputation.Reputation, _countof(Item->Reputation.Reputation),
                                 "Malicious");
            return;
        case WkdRegRisk_Suspicious: /* 3 */
            Item->Reputation.TrustScore = 30;
            (VOID)StringCchCopyA(Item->Reputation.Reputation, _countof(Item->Reputation.Reputation),
                                 "Suspicious");
            return;
        case WkdRegRisk_Low:        /* 1 */
            Item->Reputation.TrustScore = 70;
            (VOID)StringCchCopyA(Item->Reputation.Reputation, _countof(Item->Reputation.Reputation),
                                 "Low Risk");
            return;
        default:                    /* Unknown=2 / 失败 */
            break;
    }

    Item->Reputation.TrustScore = 50;
    (VOID)StringCchCopyA(Item->Reputation.Reputation, _countof(Item->Reputation.Reputation),
                         "Unknown");
}

/* 风险评分 (对应 SS CalculateRiskScore, 13 条规则逐一对齐) */
static
VOID SaCalculateRiskScore(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL) return;

    ULONG score = 0;
    Item->RiskFactorCount = 0;

    /* 已知恶意 — 短路到最大值 */
    if (Item->Reputation.IsKnownBad) {
        Item->RiskScore = 100;
        Item->IsMalicious = TRUE;
        SaAppendRiskFactor(Item, "Known malware hash");
        if (Item->Reputation.MalwareFamily[0] != '\0') {
            CHAR family[64 + 8];
            (VOID)StringCchPrintfA(family, _countof(family), "Family: %s",
                                   Item->Reputation.MalwareFamily);
            SaAppendRiskFactor(Item, family);
        }
        return;
    }

    if (!Item->Signature.IsSigned) {
        score += 20;
        SaAppendRiskFactor(Item, "Unsigned binary");
    }
    if (Item->Signature.IsSigned && !Item->Signature.IsValid) {
        score += 30;
        SaAppendRiskFactor(Item, "Invalid digital signature");
    }
    if (Item->Signature.IsSigned && Item->Signature.IsValid && !Item->Signature.IsTrusted) {
        score += 15;
        SaAppendRiskFactor(Item, "Untrusted certificate chain");
    }
    if (Item->Signature.IsExpired) {
        score += 10;
        SaAppendRiskFactor(Item, "Expired certificate");
    }
    if (Item->Signature.IsRevoked) {
        score += 40;
        SaAppendRiskFactor(Item, "Revoked certificate");
    }
    if (Item->IsHidden) {
        score += 15;
        SaAppendRiskFactor(Item, "Hidden startup item");
    }
    if (Item->Source == WkdSaSrc_IFEO) {
        score += 25;
        SaAppendRiskFactor(Item, "IFEO debugger persistence (T1546.012)");
    }
    if (Item->Source == WkdSaSrc_AppInit_DLLs) {
        score += 20;
        SaAppendRiskFactor(Item, "AppInit_DLLs injection (T1546.010)");
    }
    if (Item->Source == WkdSaSrc_LSA_AuthenticationPackages ||
        Item->Source == WkdSaSrc_LSA_SecurityPackages) {
        score += 25;
        SaAppendRiskFactor(Item, "LSA persistence (credential access)");
    }
    if (Item->Source == WkdSaSrc_PrintMonitor) {
        score += 15;
        SaAppendRiskFactor(Item, "Print Monitor persistence (T1547.010)");
    }
    if (!Item->TargetExists && Item->TargetPath[0] != L'\0') {
        score += 10;
        SaAppendRiskFactor(Item, "Target file not found");
    }
    if (!Item->Reputation.IsKnownGood && !Item->Reputation.IsKnownBad) {
        score += 10;
        SaAppendRiskFactor(Item, "Unknown reputation");
    }

    score = (score > 100) ? 100 : score;
    Item->RiskScore = (UCHAR)score;

    if (Item->RiskScore >= 80) {
        Item->IsMalicious = TRUE;
    }
}

/* 条目分类 (对应 SS ClassifyItem, 签名者关键字判定) */
static
VOID SaClassifyItem(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL) return;

    if (Item->IsMalicious) {
        Item->Category = WkdSaCat_Malicious;
        return;
    }

    if (Item->Signature.IsMicrosoftSigned) {
        Item->Category = WkdSaCat_System;
        Item->IsCritical = TRUE;
        return;
    }

    if (Item->Signature.SignerName[0] != L'\0') {
        const PCWSTR signer = Item->Signature.SignerName;
        if (SaContainsI(signer, L"microsoft")) {
            Item->Category = WkdSaCat_System;
            Item->IsCritical = TRUE;
        } else if (SaContainsI(signer, L"antivirus") ||
                   SaContainsI(signer, L"security") ||
                   SaContainsI(signer, L"kaspersky") ||
                   SaContainsI(signer, L"symantec") ||
                   SaContainsI(signer, L"norton") ||
                   SaContainsI(signer, L"mcafee") ||
                   SaContainsI(signer, L"crowdstrike") ||
                   SaContainsI(signer, L"sophos") ||
                   SaContainsI(signer, L"bitdefender") ||
                   SaContainsI(signer, L"trend micro")) {
            Item->Category = WkdSaCat_Security;
        } else if (SaContainsI(signer, L"intel") ||
                   SaContainsI(signer, L"nvidia") ||
                   SaContainsI(signer, L"amd") ||
                   SaContainsI(signer, L"realtek")) {
            Item->Category = WkdSaCat_Hardware;
        } else {
            Item->Category = WkdSaCat_Application;
        }
    } else {
        Item->Category = WkdSaCat_Unknown;
    }
}

/* 优化建议生成 (对应 SS GenerateRecommendation; bootImpact 恒 0, High/Critical 分支保留不触发) */
static
VOID SaGenerateRecommendation(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL) return;

    if (Item->IsMalicious) {
        Item->Recommendation = WkdSaRec_Remove;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "Detected as malicious");
        return;
    }

    if (!Item->TargetExists && Item->TargetPath[0] != L'\0') {
        Item->Recommendation = WkdSaRec_Remove;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "Target file not found");
        return;
    }

    if (Item->IsCritical) {
        Item->Recommendation = WkdSaRec_Keep;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "Critical system component");
        return;
    }

    if (Item->Category == WkdSaCat_Security) {
        Item->Recommendation = WkdSaRec_Keep;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "Security software");
        return;
    }

    if (Item->BootImpact.Level == WkdSaImpact_High ||
        Item->BootImpact.Level == WkdSaImpact_Critical) {
        Item->Recommendation = WkdSaRec_Delay;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "High boot impact");
        return;
    }

    if (Item->Category == WkdSaCat_Bloatware) {
        Item->Recommendation = WkdSaRec_Disable;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "Unnecessary software");
        return;
    }

    if (Item->RiskScore >= 50) {
        Item->Recommendation = WkdSaRec_Investigate;
        (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                             "Suspicious item");
        return;
    }

    Item->Recommendation = WkdSaRec_Keep;
    (VOID)StringCchCopyA(Item->RecommendationReason, _countof(Item->RecommendationReason),
                         "Normal application");
}

/* 条目完整安全分析 (对应 SS AnalyzeItemSecurity 调用顺序) */
static
VOID SaAnalyzeItemSecurity(_Inout_ PWKD_SA_ITEM Item) {
    if (Item == NULL) return;

    /* 目标缺失 → 孤儿态 + 直接评分分类 (不进入签名/哈希/信誉链路) */
    if (Item->TargetPath[0] == L'\0' || !Item->TargetExists) {
        if (Item->TargetPath[0] != L'\0') {
            Item->Status = WkdSaStatus_Orphaned;
        }
        SaCalculateRiskScore(Item);
        SaClassifyItem(Item);
        return;
    }

    /* 数字签名 (IocVerifySignature, 统一认证 + 分类) */
    if (g_sa.Config.AnalyzeSignatures) {
        SaAnalyzeSignature(Item);
    }

    /* SHA-256 哈希 (IocScanner_ComputeFileSha256, 依赖畸形路径拒绝) */
    DEF_SHA256_HASH hash;
    if (IocScanner_ComputeFileSha256(Item->TargetPath, &hash)) {
        memcpy(Item->Sha256, hash.Data, DEF_SHA256_SIZE);
        (VOID)UtHexEncode(Item->Sha256, DEF_SHA256_SIZE,
                          Item->Sha256Hex, _countof(Item->Sha256Hex), FALSE);
    } else {
        SaDbgPrint(L"[SA] SHA256 computation failed for %hs",
                   (Item->DisplayName[0] != L'\0') ? L"item" : L"item");
    }

    /* 信誉 (委托 PD 实时分析) */
    if (g_sa.Config.CheckReputation) {
        SaCheckReputation(Item);
    }

    SaCalculateRiskScore(Item);
    SaClassifyItem(Item);
}

/* ==================================================
 * 回调派发 (SS Invoke*Callbacks: 锁内快照, 锁外派发)
 * ================================================== */
static
VOID SaInvokeNewItemCallbacks(_In_ PCWKD_SA_ITEM Item) {
    if (Item == NULL) return;
    PFN_SA_NEW_ITEM_CALLBACK cbs[WKD_SA_MAX_CALLBACKS];
    PVOID ctxs[WKD_SA_MAX_CALLBACKS];
    ULONG snapCount = 0;
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (!g_sa.NewItemSlotFree[i] && g_sa.NewItemCallbacks[i] != NULL) {
            cbs[snapCount] = g_sa.NewItemCallbacks[i];
            ctxs[snapCount] = g_sa.NewItemContexts[i];
            ++snapCount;
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);

    for (ULONG i = 0; i < snapCount; ++i) {
        __try { cbs[i](Item, ctxs[i]); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SaDbgPrint(L"[SA] NewItem callback %lu faulted", i);
        }
    }
}

static
VOID SaInvokeAlertCallbacks(_In_ PCWKD_SA_ALERT Alert) {
    if (Alert == NULL) return;
    PFN_SA_ALERT_CALLBACK cbs[WKD_SA_MAX_CALLBACKS];
    PVOID ctxs[WKD_SA_MAX_CALLBACKS];
    ULONG snapCount = 0;
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (!g_sa.AlertSlotFree[i] && g_sa.AlertCallbacks[i] != NULL) {
            cbs[snapCount] = g_sa.AlertCallbacks[i];
            ctxs[snapCount] = g_sa.AlertContexts[i];
            ++snapCount;
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);

    for (ULONG i = 0; i < snapCount; ++i) {
        __try { cbs[i](Alert, ctxs[i]); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SaDbgPrint(L"[SA] Alert callback %lu faulted", i);
        }
    }
}

static
VOID SaInvokeChangeCallbacks(_In_ PCWKD_SA_CHANGE Change) {
    if (Change == NULL) return;
    PFN_SA_CHANGE_CALLBACK cbs[WKD_SA_MAX_CALLBACKS];
    PVOID ctxs[WKD_SA_MAX_CALLBACKS];
    ULONG snapCount = 0;
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (!g_sa.ChangeSlotFree[i] && g_sa.ChangeCallbacks[i] != NULL) {
            cbs[snapCount] = g_sa.ChangeCallbacks[i];
            ctxs[snapCount] = g_sa.ChangeContexts[i];
            ++snapCount;
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);

    for (ULONG i = 0; i < snapCount; ++i) {
        __try { cbs[i](Change, ctxs[i]); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SaDbgPrint(L"[SA] Change callback %lu faulted", i);
        }
    }
}

/* ==================================================
 * 告警生成 (对应 SS GenerateAlert)
 * ================================================== */
static
VOID SaGenerateAlert(_In_ PCWKD_SA_ITEM Item, _In_ PCSTR AlertType) {
    if (Item == NULL || AlertType == NULL) return;

    WKD_SA_ALERT alert;
    memset(&alert, 0, sizeof(alert));
    alert.AlertId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextAlertId);
    GetSystemTimeAsFileTime((LPFILETIME)&alert.Timestamp);
    (VOID)StringCchCopyA(alert.AlertType, _countof(alert.AlertType), AlertType);
    alert.ItemId = Item->ItemId;
    (VOID)StringCchCopyW(alert.ItemName, _countof(alert.ItemName), Item->Name);
    (VOID)StringCchCopyW(alert.TargetPath, _countof(alert.TargetPath), Item->TargetPath);
    alert.RiskScore = Item->RiskScore;
    alert.RiskFactorCount = Item->RiskFactorCount;
    for (ULONG i = 0; i < Item->RiskFactorCount && i < WKD_SA_MAX_RISK_FACTORS; ++i) {
        (VOID)StringCchCopyA(alert.RiskFactors[i], _countof(alert.RiskFactors[0]),
                             Item->RiskFactors[i]);
    }
    alert.Recommendation = Item->Recommendation;

    if (Item->RiskScore >= 80) {
        alert.Severity = 4;
        (VOID)StringCchCopyA(alert.Description, _countof(alert.Description),
                             "Critical-risk startup item detected");
    } else if (Item->RiskScore >= 60) {
        alert.Severity = 3;
        (VOID)StringCchCopyA(alert.Description, _countof(alert.Description),
                             "Suspicious startup item detected");
    } else if (Item->RiskScore >= 40) {
        alert.Severity = 2;
        (VOID)StringCchCopyA(alert.Description, _countof(alert.Description),
                             "Potentially unwanted startup item");
    } else {
        alert.Severity = 1;
        (VOID)StringCchCopyA(alert.Description, _countof(alert.Description),
                             "New startup item detected");
    }

    {
        EnterCriticalSection(&g_sa.AlertsLock);
        /* 满 → 等 SS trim: 删最旧 (WKD_SA_MAX_ALERTS - TRIM_TO) 条 */
        if (g_sa.AlertCount >= WKD_SA_MAX_ALERTS) {
            const ULONG keep = WKD_SA_ALERT_TRIM_TO;
            memmove(&g_sa.Alerts[0], &g_sa.Alerts[WKD_SA_MAX_ALERTS - keep],
                    keep * sizeof(WKD_SA_ALERT));
            g_sa.AlertCount = keep;
        }
        /* 动态扩容 (初始 64, 翻倍, 上限 10000) */
        if (g_sa.AlertCount >= g_sa.AlertCapacity) {
            ULONG newCap = (g_sa.AlertCapacity > 0) ? g_sa.AlertCapacity
                                                     : WKD_SA_ALERT_INIT_CAPACITY;
            newCap *= 2;
            if (newCap > WKD_SA_MAX_ALERTS) newCap = WKD_SA_MAX_ALERTS;
            if (newCap > g_sa.AlertCapacity) {
                PWKD_SA_ALERT newArr = (PWKD_SA_ALERT)
                    UtHeapAlloc(newCap * sizeof(WKD_SA_ALERT));
                if (newArr != NULL) {
                    if (g_sa.Alerts != NULL) {
                        memcpy(newArr, g_sa.Alerts, g_sa.AlertCount * sizeof(WKD_SA_ALERT));
                        UtHeapFree(g_sa.Alerts);
                    }
                    g_sa.Alerts = newArr;
                    g_sa.AlertCapacity = newCap;
                }
            }
        }
        if (g_sa.AlertCount < g_sa.AlertCapacity && g_sa.Alerts != NULL) {
            g_sa.Alerts[g_sa.AlertCount++] = alert;
        }
        LeaveCriticalSection(&g_sa.AlertsLock);
    }

    InterlockedIncrement(&g_sa.Stats.AlertsGenerated);

    SaInvokeAlertCallbacks(&alert);

    SaDbgPrint(L"[SA] Alert #%I64u [%hs] - Item: %s, Risk: %u",
               alert.AlertId, alert.Description, Item->Name, Item->RiskScore);
}

/* ==================================================
 * 变更记录 (对应 SS RecordChange)
 * ================================================== */
static
VOID SaRecordChange(_In_ PCWKD_SA_ITEM Item, _In_ PCSTR ChangeType,
                    _In_ ULONG PreviousStatus, _In_ ULONG NewStatus) {
    if (Item == NULL || ChangeType == NULL) return;
    if (!g_sa.Config.TrackHistory) return;

    WKD_SA_CHANGE change;
    memset(&change, 0, sizeof(change));
    change.ChangeId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextChangeId);
    GetSystemTimeAsFileTime((LPFILETIME)&change.Timestamp);
    change.ItemId = Item->ItemId;
    (VOID)StringCchCopyW(change.ItemName, _countof(change.ItemName), Item->Name);
    change.Source = Item->Source;
    (VOID)StringCchCopyA(change.ChangeType, _countof(change.ChangeType), ChangeType);
    change.PreviousStatus = PreviousStatus;
    change.NewStatus = NewStatus;
    (VOID)StringCchCopyA(change.ChangedBy, _countof(change.ChangedBy), "ShadowStrike");
    change.ProcessId = GetCurrentProcessId();
    change.HasBackup = g_sa.Config.CreateBackups;
    change.CanRollback = TRUE;

    {
        EnterCriticalSection(&g_sa.HistoryLock);
        /* 环形写入 (Head 指向最旧); 满则覆盖最旧, 等价 SS pop_front */
        g_sa.History[g_sa.HistoryHead] = change;
        g_sa.HistoryHead = (g_sa.HistoryHead + 1) % WKD_SA_MAX_HISTORY;
        if (g_sa.HistoryCount < WKD_SA_MAX_HISTORY) {
            ++g_sa.HistoryCount;
        }
        /* 已落盘的本地副本, 无需锁内读回 */
        WKD_SA_CHANGE last = change;
        LeaveCriticalSection(&g_sa.HistoryLock);

        SaInvokeChangeCallbacks(&last);
    }
}

/* ==================================================
 * 管理写回 (对应 SS WriteDisable/WriteEnable/WriteRemove)
 * ================================================== */

/* 源 → 默认根键 (对应 SS GetRootKeyForSource; 无根键源返回 NULL) */
static
HKEY SaGetRootKeyForSource(_In_ ULONG Source) {
    switch (Source) {
        /* HKLM 族 */
        case WkdSaSrc_RegistryRun_HKLM:
        case WkdSaSrc_RegistryRunOnce_HKLM:
        case WkdSaSrc_RegistryRun_Wow64_HKLM:
        case WkdSaSrc_RegistryRunOnce_Wow64_HKLM:
        case WkdSaSrc_RegistryRunServices_HKLM:
        case WkdSaSrc_Winlogon_Shell:
        case WkdSaSrc_Winlogon_Userinit:
        case WkdSaSrc_IFEO:
        case WkdSaSrc_AppInit_DLLs:
        case WkdSaSrc_LSA_AuthenticationPackages:
        case WkdSaSrc_LSA_SecurityPackages:
        case WkdSaSrc_PrintMonitor:
        case WkdSaSrc_BootExecute:
        case WkdSaSrc_ActiveSetup:
        case WkdSaSrc_ShellServiceObjectDelay:
        case WkdSaSrc_NaturalLanguage_DLL:
            return HKEY_LOCAL_MACHINE;

        /* HKCU 族 */
        case WkdSaSrc_RegistryRun_HKCU:
        case WkdSaSrc_RegistryRunOnce_HKCU:
        case WkdSaSrc_RegistryRun_Wow64_HKCU:
        case WkdSaSrc_RegistryRunOnce_Wow64_HKCU:
        case WkdSaSrc_RegistryRunServices_HKCU:
        case WkdSaSrc_ExplorerRun:
        case WkdSaSrc_ScreenSaver:
            return HKEY_CURRENT_USER;

        default:
            /* 文件夹/任务/服务/无实现源: 无默认注册表根 */
            return NULL;
    }
}

/* 解析条目的注册表根键与相对键路径 (对应 SS ResolveRegistryItemRootAndPath) */
static
BOOLEAN SaResolveRegistryItemRootAndPath(_In_ PCWKD_SA_ITEM Item,
                                         _Out_ PHKEY pHRoot,
                                         _Out_writes_(KeyPathCch) PWSTR KeyPath,
                                         _In_ ULONG KeyPathCch) {
    if (Item == NULL || pHRoot == NULL || KeyPath == NULL || KeyPathCch == 0) return FALSE;
    *pHRoot = NULL;
    KeyPath[0] = L'\0';

    const WCHAR* location = Item->Location;
    const WCHAR* rest = NULL;

    if (SaStartsWithI(location, L"HKEY_USERS\\")) {
        *pHRoot = HKEY_USERS;
        rest = location + 11;   /* 长度 L"HKEY_USERS\\" == 11 */
    } else if (SaStartsWithI(location, L"HKEY_LOCAL_MACHINE\\")) {
        *pHRoot = HKEY_LOCAL_MACHINE;
        rest = location + 19;   /* 长度 L"HKEY_LOCAL_MACHINE\\" == 19 */
    } else if (SaStartsWithI(location, L"HKEY_CURRENT_USER\\")) {
        *pHRoot = HKEY_CURRENT_USER;
        rest = location + 18;   /* 长度 L"HKEY_CURRENT_USER\\" == 18 */
    } else {
        *pHRoot = SaGetRootKeyForSource(Item->Source);
        rest = location;
        if (*pHRoot == NULL || rest[0] == L'\0') return FALSE;
    }

    (VOID)StringCchCopyW(KeyPath, KeyPathCch, rest);
    return KeyPath[0] != L'\0';
}

/* 写回打开选项 (WoW64 32 位视图) */
static
REGSAM SaWriteOptionsForSource(_In_ ULONG Source) {
    if (Source == WkdSaSrc_RegistryRun_Wow64_HKLM ||
        Source == WkdSaSrc_RegistryRun_Wow64_HKCU ||
        Source == WkdSaSrc_RegistryRunOnce_Wow64_HKLM ||
        Source == WkdSaSrc_RegistryRunOnce_Wow64_HKCU) {
        return KEY_READ | KEY_WRITE | KEY_WOW64_32KEY;
    }
    return KEY_READ | KEY_WRITE;
}

/* 读取值 + 类型 (原始, 不展开; 用于备份/恢复保持 REG_EXPAND_SZ 语义) */
static
BOOLEAN SaReadValueRaw(_In_ HKEY hKey, _In_ PCWSTR ValueName,
                       _Out_writes_(OutCch) PWSTR Out, _In_ ULONG OutCch,
                       _Out_ PDWORD OutType) {
    return SaRegQueryStringRaw(hKey, ValueName, Out, OutCch, OutType);
}

/* 向键写入值 (保留原 REG_EXPAND_SZ 类型) */
static
BOOLEAN SaWriteValuePreservingType(_In_ HKEY hKey, _In_ PCWSTR ValueName,
                                   _In_ PCWSTR Value, _In_ DWORD ValueType) {
    if (hKey == NULL || ValueName == NULL || Value == NULL) return FALSE;
    const DWORD bytes = (DWORD)((wcslen(Value) + 1) * sizeof(WCHAR));
    if (ValueType != REG_EXPAND_SZ && ValueType != REG_SZ) ValueType = REG_SZ;
    return (RegSetValueExW(hKey, ValueName, 0, ValueType, (const BYTE*)Value, bytes) == ERROR_SUCCESS);
}

/* 禁用条目 (注册表 → AutorunsDisabled 备份 + 删原值; 文件夹 → .disabled 改名) */
static
BOOLEAN SaWriteDisableToRegistry(_In_ PCWKD_SA_ITEM Item) {
    if (Item == NULL) return FALSE;

    /* 文件夹条目: 带时间戳的 .disabled 后缀改名 */
    if (Item->Source == WkdSaSrc_StartupFolder_User ||
        Item->Source == WkdSaSrc_StartupFolder_AllUsers) {
        WCHAR srcPath[WKD_REG_MAX_PATH_CHARS * 2];
        WCHAR dstPath[WKD_REG_MAX_PATH_CHARS * 2];
        (VOID)StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\%s",
                               Item->Location, Item->EntryName);
        (VOID)StringCchPrintfW(dstPath, _countof(dstPath), L"%s.disabled", srcPath);
        if (GetFileAttributesW(dstPath) != INVALID_FILE_ATTRIBUTES) {
            /* 已存在备份 → 追加时间戳后缀, 绝不覆盖历史 */
            WCHAR suffix[WKD_SA_DIAG_LINE_CHARS];
            SaMakeDisabledSuffix(suffix, _countof(suffix));
            (VOID)StringCchPrintfW(dstPath, _countof(dstPath), L"%s%s", srcPath, suffix);
        }
        return MoveFileW(srcPath, dstPath) != FALSE;
    }

    /* 注册表条目 */
    HKEY hRoot = NULL;
    WCHAR keyPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR value[WKD_PD_MAX_CMD_BUFFER];
    if (!SaResolveRegistryItemRootAndPath(Item, &hRoot, keyPath, _countof(keyPath))) return FALSE;

    HKEY hSrc = NULL;
    {
        REGSAM access = SaWriteOptionsForSource(Item->Source);
        if (RegOpenKeyExW(hRoot, keyPath, 0, access, &hSrc) != ERROR_SUCCESS) return FALSE;
    }

    DWORD valueType = REG_NONE;
    if (!SaReadValueRaw(hSrc, Item->EntryName, value, _countof(value), &valueType)) {
        RegCloseKey(hSrc);
        return FALSE;
    }
    const BOOLEAN isExpand = (valueType == REG_EXPAND_SZ);

    /* 打开/创建 per-key 备份容器 */
    WCHAR disabledPath[WKD_REG_MAX_PATH_CHARS * 2];
    (VOID)StringCchPrintfW(disabledPath, _countof(disabledPath), L"%s\\%s",
                           keyPath, WKD_SA_SAFE_DISABLE_SUBKEY);
    HKEY hDis = NULL;
    if (RegCreateKeyExW(hRoot, disabledPath, 0, NULL, 0,
                        SaWriteOptionsForSource(Item->Source), NULL, &hDis, NULL) != ERROR_SUCCESS) {
        RegCloseKey(hSrc);
        return FALSE;
    }

    /* 同名备份已存在 → 时间戳后缀, 不覆盖历史 */
    WCHAR backupName[WKD_REG_MAX_NAME_CHARS];
    (VOID)StringCchCopyW(backupName, _countof(backupName), Item->EntryName);
    {
        WCHAR existing[WKD_PD_MAX_CMD_BUFFER];
        DWORD existingType = REG_NONE;
        if (SaReadValueRaw(hDis, Item->EntryName, existing, _countof(existing), &existingType)) {
            WCHAR suffix[WKD_SA_DIAG_LINE_CHARS];
            SaMakeDisabledSuffix(suffix, _countof(suffix));
            WCHAR tmp[WKD_REG_MAX_NAME_CHARS * 2];
            (VOID)StringCchPrintfW(tmp, _countof(tmp), L"%s%s", backupName, suffix);
            (VOID)StringCchCopyW(backupName, _countof(backupName), tmp);
        }
    }

    const DWORD backupType = isExpand ? REG_EXPAND_SZ : REG_SZ;
    const BOOLEAN wroteBackup = SaWriteValuePreservingType(hDis, backupName, value, backupType);
    RegCloseKey(hDis);
    if (!wroteBackup) {
        RegCloseKey(hSrc);
        return FALSE;
    }

    const LSTATUS delStatus = RegDeleteValueW(hSrc, Item->EntryName);
    RegCloseKey(hSrc);
    return (delStatus == ERROR_SUCCESS);
}

/* 启用条目 (反向恢复) */
static
BOOLEAN SaWriteEnableToRegistry(_In_ PCWKD_SA_ITEM Item) {
    if (Item == NULL) return FALSE;

    if (Item->Source == WkdSaSrc_StartupFolder_User ||
        Item->Source == WkdSaSrc_StartupFolder_AllUsers) {
        WCHAR srcPath[WKD_REG_MAX_PATH_CHARS * 2];
        WCHAR dstPath[WKD_REG_MAX_PATH_CHARS * 2];
        (VOID)StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\%s.disabled",
                               Item->Location, Item->EntryName);
        (VOID)StringCchPrintfW(dstPath, _countof(dstPath), L"%s\\%s",
                               Item->Location, Item->EntryName);
        if (GetFileAttributesW(srcPath) == INVALID_FILE_ATTRIBUTES) return FALSE;
        return MoveFileW(srcPath, dstPath) != FALSE;
    }

    HKEY hRoot = NULL;
    WCHAR keyPath[WKD_REG_MAX_PATH_CHARS];
    if (!SaResolveRegistryItemRootAndPath(Item, &hRoot, keyPath, _countof(keyPath))) return FALSE;

    WCHAR disabledPath[WKD_REG_MAX_PATH_CHARS * 2];
    (VOID)StringCchPrintfW(disabledPath, _countof(disabledPath), L"%s\\%s",
                           keyPath, WKD_SA_SAFE_DISABLE_SUBKEY);

    /* 从备份键读回原始值 + 类型 */
    HKEY hDis = NULL;
    if (RegOpenKeyExW(hRoot, disabledPath, 0, KEY_READ, &hDis) != ERROR_SUCCESS) return FALSE;
    WCHAR value[WKD_PD_MAX_CMD_BUFFER];
    DWORD valueType = REG_NONE;
    const BOOLEAN haveBackup = SaReadValueRaw(hDis, Item->EntryName, value, _countof(value), &valueType);
    RegCloseKey(hDis);
    if (!haveBackup) return FALSE;

    /* 写回原键 */
    HKEY hSrc = NULL;
    if (RegOpenKeyExW(hRoot, keyPath, 0, SaWriteOptionsForSource(Item->Source), &hSrc) != ERROR_SUCCESS)
        return FALSE;
    const BOOLEAN wrote = SaWriteValuePreservingType(hSrc, Item->EntryName, value, valueType);
    if (!wrote) {
        RegCloseKey(hSrc);
        return FALSE;
    }
    RegCloseKey(hSrc);

    /* 清理备份 */
    HKEY hDis2 = NULL;
    if (RegOpenKeyExW(hRoot, disabledPath, 0, KEY_SET_VALUE, &hDis2) == ERROR_SUCCESS) {
        (VOID)RegDeleteValueW(hDis2, Item->EntryName);
        RegCloseKey(hDis2);
    }
    return TRUE;
}

/* 移除条目 */
static
BOOLEAN SaWriteRemoveFromRegistry(_In_ PCWKD_SA_ITEM Item) {
    if (Item == NULL) return FALSE;

    if (Item->Source == WkdSaSrc_StartupFolder_User ||
        Item->Source == WkdSaSrc_StartupFolder_AllUsers) {
        WCHAR filePath[WKD_REG_MAX_PATH_CHARS * 2];
        (VOID)StringCchPrintfW(filePath, _countof(filePath), L"%s\\%s",
                               Item->Location, Item->EntryName);
        return DeleteFileW(filePath) != FALSE;
    }

    HKEY hRoot = NULL;
    WCHAR keyPath[WKD_REG_MAX_PATH_CHARS];
    if (!SaResolveRegistryItemRootAndPath(Item, &hRoot, keyPath, _countof(keyPath))) return FALSE;

    HKEY hSrc = NULL;
    if (RegOpenKeyExW(hRoot, keyPath, 0, SaWriteOptionsForSource(Item->Source), &hSrc) != ERROR_SUCCESS)
        return FALSE;
    const LSTATUS delStatus = RegDeleteValueW(hSrc, Item->EntryName);
    RegCloseKey(hSrc);
    return (delStatus == ERROR_SUCCESS);
}

/* ==================================================
 * RefreshItems (对应 SS RefreshItems 全流程)
 * ================================================== */

/* 按规范化名称在线性条目池中查找 (SS unordered_map nameIndex 替代) */
static
BOOLEAN SaFindItemByName(_In_ PCWSTR Name, _Out_opt_ PULONGLONG PItemId) {
    WCHAR nameKey[WKD_REG_MAX_NAME_CHARS];
    SaNormalizeNameKey(Name, nameKey, _countof(nameKey));

    SRWLOCK* lock = &g_sa.ItemsLock;
    AcquireSRWLockShared(lock);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] == NULL) continue;
        if (SaNameKeyEquals(g_sa.Items[i]->Name, nameKey)) {
            if (PItemId != NULL) *PItemId = g_sa.Items[i]->ItemId;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(lock);
    return found;
}

NTSTATUS
SaRefreshItems(VOID) {
    if (g_sa.Initialized == FALSE) return STATUS_NOT_INITIALIZED;

    SA_COLLECTION coll = { 0 };
    coll.Capacity = WKD_SA_COLLECTION_INIT_CAP;
    coll.Items = (PWKD_SA_ITEM*)UtHeapAlloc(coll.Capacity * sizeof(PWKD_SA_ITEM));
    if (coll.Items == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    /* 核心 Run/RunOnce 键 */
    SaEnumerateRegistryRun(&coll, HKEY_LOCAL_MACHINE, WkdSaSrc_RegistryRun_HKLM,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", FALSE, NULL);
    SaEnumerateRegistryRun(&coll, HKEY_CURRENT_USER, WkdSaSrc_RegistryRun_HKCU,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", FALSE, NULL);
    SaEnumerateRegistryRun(&coll, HKEY_LOCAL_MACHINE, WkdSaSrc_RegistryRunOnce_HKLM,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", FALSE, NULL);
    SaEnumerateRegistryRun(&coll, HKEY_CURRENT_USER, WkdSaSrc_RegistryRunOnce_HKCU,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", FALSE, NULL);

    /* 启动文件夹 */
    SaEnumerateStartupFolders(&coll);

    /* 扩展自启动位置 */
    SaEnumerateExtendedAutostartKeys(&coll);

    /* 逐条安全分析 + 推荐 + 新条目告警 + 恶意自动隔离 */
    for (ULONG i = 0; i < coll.Count; ++i) {
        PWKD_SA_ITEM item = coll.Items[i];
        SaAnalyzeItemSecurity(item);
        SaGenerateRecommendation(item);

        /* 新条目判定 (规范化名称索引) */
        BOOLEAN isNew = !SaFindItemByName(item->Name, NULL);

        /* 告警: 新条目 / 恶意 / 可疑 */
        if (isNew && g_sa.Config.AlertOnNewItems) {
            SaGenerateAlert(item, "NewItem");
            SaInvokeNewItemCallbacks(item);
        } else if (item->IsMalicious ||
                   (item->RiskScore >= 50 && g_sa.Config.AlertOnSuspicious)) {
            SaGenerateAlert(item, "Suspicious");
        }

        /* 自动隔离恶意条目 (真删注册表值) */
        if (item->IsMalicious && g_sa.Config.AutoQuarantineMalicious) {
            SaDbgPrint(L"[SA] Auto-quarantining malicious startup item: %s", item->Name);
            if (SaWriteRemoveFromRegistry(item)) {
                item->Status = WkdSaStatus_Quarantined;
                item->IsEnabled = FALSE;
                InterlockedIncrement(&g_sa.Stats.ItemsQuarantined);
            }
        }
    }

    /* 整体换入条目池 (写锁; 释放旧条目) */
    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL) {
            UtHeapFree(g_sa.Items[i]);
        }
    }
    UtHeapFree(g_sa.Items);
    g_sa.Items = coll.Items;
    g_sa.ItemCount = coll.Count;
    g_sa.ItemCapacity = coll.Capacity;
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    /* 统计更新 */
    LONG enabled = 0, disabled = 0, malicious = 0;
    for (ULONG i = 0; i < coll.Count; ++i) {
        if (coll.Items[i]->IsEnabled) ++enabled; else ++disabled;
        if (coll.Items[i]->IsMalicious) ++malicious;
    }
    InterlockedExchange(&g_sa.Stats.TotalItemsAnalyzed, (LONG)coll.Count);
    InterlockedExchange(&g_sa.Stats.EnabledItems, enabled);
    InterlockedExchange(&g_sa.Stats.DisabledItems, disabled);
    InterlockedExchange(&g_sa.Stats.MaliciousItems, malicious);

    SaDbgPrint(L"[SA] Refreshed %lu startup items (%lu enabled, %lu disabled, %lu malicious)",
               coll.Count, enabled, disabled, malicious);
    return STATUS_SUCCESS;
}

/* ==================================================
 * 配置工厂 (对应 SS StartupAnalyzerConfig::Create*)
 * ================================================== */
VOID
SaCreateDefaultConfig(_Out_ PWKD_SA_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->AnalyzeSignatures = TRUE;
    Config->CheckReputation = TRUE;
    Config->MeasureBootImpact = TRUE;
    Config->DetectHidden = TRUE;
    Config->AutoDisableMalicious = FALSE;
    Config->AutoQuarantineMalicious = TRUE;
    Config->AlertOnNewItems = TRUE;
    Config->AlertOnSuspicious = TRUE;
    Config->EnableOptimization = FALSE;
    Config->AutoDelayNonCritical = FALSE;
    Config->DefaultDelaySeconds = WKD_SA_DEFAULT_DELAY_SECONDS;
    Config->TrackHistory = TRUE;
    Config->MaxHistoryEntries = WKD_SA_MAX_HISTORY;
    Config->CreateBackups = TRUE;
    Config->BackupPath[0] = L'\0';
}

VOID
SaCreateSecurityConfig(_Out_ PWKD_SA_CONFIG Config) {
    if (Config == NULL) return;
    SaCreateDefaultConfig(Config);
    Config->AutoDisableMalicious = TRUE;
    Config->AutoQuarantineMalicious = TRUE;
    Config->AlertOnNewItems = TRUE;
    Config->AlertOnSuspicious = TRUE;
    Config->CreateBackups = TRUE;
}

VOID
SaCreatePerformanceConfig(_Out_ PWKD_SA_CONFIG Config) {
    if (Config == NULL) return;
    SaCreateDefaultConfig(Config);
    Config->AnalyzeSignatures = FALSE;
    Config->CheckReputation = FALSE;
    Config->MeasureBootImpact = TRUE;
    Config->EnableOptimization = TRUE;
    Config->AutoDelayNonCritical = TRUE;
}

/* ==================================================
 * 生命周期 (对应 SS Initialize/Shutdown/IsInitialized)
 * ================================================== */
NTSTATUS
SaInitialize(_In_opt_ PCWKD_SA_CONFIG Config) {
    AcquireSRWLockExclusive(&g_sa.Lock);

    if (g_sa.Initialized) {
        ReleaseSRWLockExclusive(&g_sa.Lock);
        SaDbgPrint(L"[SA] Already initialized");
        return STATUS_SUCCESS;
    }

    WKD_SA_CONFIG cfg;
    if (Config != NULL) {
        cfg = *Config;
        if (cfg.MaxHistoryEntries == 0 || cfg.MaxHistoryEntries > WKD_SA_MAX_HISTORY) {
            cfg.MaxHistoryEntries = WKD_SA_MAX_HISTORY;
        }
        if (cfg.DefaultDelaySeconds > WKD_SA_MAX_DELAY_SECONDS) {
            cfg.DefaultDelaySeconds = WKD_SA_MAX_DELAY_SECONDS;
        }
    } else {
        SaCreateDefaultConfig(&cfg);
    }
    g_sa.Config = cfg;

    /* 备份目录 (SS create_directories) */
    if (cfg.CreateBackups && cfg.BackupPath[0] != L'\0') {
        (VOID)CreateDirectoryW(cfg.BackupPath, NULL);
    }

    /* 锁初始化 (只做一次, 幂等) */
    if (!g_sa.LocksInitialized) {
        InitializeCriticalSection(&g_sa.HistoryLock);
        InitializeCriticalSection(&g_sa.AlertsLock);
        InitializeCriticalSection(&g_sa.CallbacksLock);
        g_sa.LocksInitialized = TRUE;
    }

    g_sa.Initialized = TRUE;
    ReleaseSRWLockExclusive(&g_sa.Lock);

    SaDbgPrint(L"[SA] Initialized successfully (v%hs)", SaGetVersionString());
    return STATUS_SUCCESS;
}

VOID
SaShutdown(VOID) {
    AcquireSRWLockExclusive(&g_sa.Lock);
    if (!g_sa.Initialized) {
        ReleaseSRWLockExclusive(&g_sa.Lock);
        return;
    }

    /* 注销 RM 事件回调 */
    if (g_sa.RmCallbackId != 0) {
        (VOID)RmUnregisterCallback(g_sa.RmCallbackId);
        g_sa.RmCallbackId = 0;
    }

    /* 清条目池 */
    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL) UtHeapFree(g_sa.Items[i]);
    }
    UtHeapFree(g_sa.Items);
    g_sa.Items = NULL;
    g_sa.ItemCount = 0;
    g_sa.ItemCapacity = 0;
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    /* 清历史 */
    EnterCriticalSection(&g_sa.HistoryLock);
    memset(g_sa.History, 0, sizeof(g_sa.History));
    g_sa.HistoryHead = 0;
    g_sa.HistoryCount = 0;
    LeaveCriticalSection(&g_sa.HistoryLock);

    /* 清告警 */
    EnterCriticalSection(&g_sa.AlertsLock);
    UtHeapFree(g_sa.Alerts);
    g_sa.Alerts = NULL;
    g_sa.AlertCount = 0;
    g_sa.AlertCapacity = 0;
    LeaveCriticalSection(&g_sa.AlertsLock);

    /* 清回调槽 */
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        g_sa.NewItemCallbacks[i] = NULL;
        g_sa.NewItemContexts[i] = NULL;
        g_sa.NewItemCallbackIds[i] = 0;
        g_sa.NewItemSlotFree[i] = TRUE;
        g_sa.AlertCallbacks[i] = NULL;
        g_sa.AlertContexts[i] = NULL;
        g_sa.AlertCallbackIds[i] = 0;
        g_sa.AlertSlotFree[i] = TRUE;
        g_sa.ChangeCallbacks[i] = NULL;
        g_sa.ChangeContexts[i] = NULL;
        g_sa.ChangeCallbackIds[i] = 0;
        g_sa.ChangeSlotFree[i] = TRUE;
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);

    g_sa.Initialized = FALSE;
    ReleaseSRWLockExclusive(&g_sa.Lock);

    SaDbgPrint(L"[SA] Shutdown complete");
}

BOOLEAN
SaIsInitialized(VOID) {
    return (g_sa.Initialized != FALSE);
}

/* ==================================================
 * 配置访问 (对应 SS UpdateConfig/GetConfig)
 * ================================================== */
NTSTATUS
SaUpdateConfig(_In_ PCWKD_SA_CONFIG Config) {
    if (Config == NULL) return STATUS_INVALID_PARAMETER;

    WKD_SA_CONFIG cfg = *Config;
    if (cfg.MaxHistoryEntries == 0 || cfg.MaxHistoryEntries > WKD_SA_MAX_HISTORY) {
        cfg.MaxHistoryEntries = WKD_SA_MAX_HISTORY;
    }
    if (cfg.DefaultDelaySeconds > WKD_SA_MAX_DELAY_SECONDS) {
        cfg.DefaultDelaySeconds = WKD_SA_MAX_DELAY_SECONDS;
    }

    AcquireSRWLockExclusive(&g_sa.Lock);
    g_sa.Config = cfg;
    ReleaseSRWLockExclusive(&g_sa.Lock);
    SaDbgPrint(L"[SA] Configuration updated");
    return STATUS_SUCCESS;
}

VOID
SaGetConfig(_Out_ PWKD_SA_CONFIG Config) {
    if (Config == NULL) return;
    AcquireSRWLockShared(&g_sa.Lock);
    *Config = g_sa.Config;
    ReleaseSRWLockShared(&g_sa.Lock);
}

/* ==================================================
 * 条目查询 (对外批量缓冲模式: Items 可 NULL 只查 Count)
 * ================================================== */
NTSTATUS
SaGetStartupItems(_Out_opt_ PWKD_SA_ITEM Items, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);
    const ULONG total = g_sa.ItemCount;
    NTSTATUS status;
    if (Capacity < total) {
        *Count = total;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (total > 0 && Items == NULL) {
        *Count = total;
        status = STATUS_BUFFER_TOO_SMALL;
    } else {
        for (ULONG i = 0; i < total; ++i) {
            Items[i] = *g_sa.Items[i];
        }
        *Count = total;
        status = STATUS_SUCCESS;
    }
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return status;
}

NTSTATUS
SaGetItemByName(_In_ PCWSTR Name, _Out_ PWKD_SA_ITEM Item) {
    if (Name == NULL || Item == NULL) return STATUS_INVALID_PARAMETER;
    WCHAR nameKey[WKD_REG_MAX_NAME_CHARS];
    SaNormalizeNameKey(Name, nameKey, _countof(nameKey));

    AcquireSRWLockShared(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && SaNameKeyEquals(g_sa.Items[i]->Name, nameKey)) {
            *Item = *g_sa.Items[i];
            ReleaseSRWLockShared(&g_sa.ItemsLock);
            return STATUS_SUCCESS;
        }
    }
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_NOT_FOUND;
}

NTSTATUS
SaGetItemById(_In_ ULONGLONG ItemId, _Out_ PWKD_SA_ITEM Item) {
    if (Item == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->ItemId == ItemId) {
            *Item = *g_sa.Items[i];
            ReleaseSRWLockShared(&g_sa.ItemsLock);
            return STATUS_SUCCESS;
        }
    }
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_NOT_FOUND;
}

NTSTATUS
SaGetItemsBySource(_In_ ULONG Source, _Out_opt_ PWKD_SA_ITEM Items,
                   _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);

    /* 第一遍: 计数与容量校验 */
    ULONG total = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->Source == Source) ++total;
    }
    if (Capacity < total) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (total > 0 && Items == NULL) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 第二遍: 拷贝 */
    ULONG written = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->Source == Source) {
            Items[written++] = *g_sa.Items[i];
        }
    }
    *Count = written;
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_SUCCESS;
}

NTSTATUS
SaGetItemsByCategory(_In_ ULONG Category, _Out_opt_ PWKD_SA_ITEM Items,
                     _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);

    ULONG total = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->Category == Category) ++total;
    }
    if (Capacity < total) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (total > 0 && Items == NULL) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->Category == Category) {
            Items[written++] = *g_sa.Items[i];
        }
    }
    *Count = written;
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_SUCCESS;
}

/* ==================================================
 * 条目池原位更新辅助 (ItemsLock 互斥调用方持有)
 * ================================================== */

/* 按 itemId 更新池内条目状态; 找到返回 TRUE */
static
BOOLEAN SaPoolUpdateStatusById(_In_ ULONGLONG ItemId, _In_ ULONG NewStatus,
                               _In_ BOOLEAN IsEnabled) {
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->ItemId == ItemId) {
            g_sa.Items[i]->Status = NewStatus;
            g_sa.Items[i]->IsEnabled = IsEnabled;
            return TRUE;
        }
    }
    return FALSE;
}

/* 池内插入或按 nameKey 更新 (OnRegistryChange 实时路径) */
static
BOOLEAN SaPoolInsertOrUpdate(_In_ PCWKD_SA_ITEM Item) {
    if (Item == NULL) return FALSE;
    WCHAR nameKey[WKD_REG_MAX_NAME_CHARS];
    SaNormalizeNameKey(Item->Name, nameKey, _countof(nameKey));

    /* 更新现有 */
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && SaNameKeyEquals(g_sa.Items[i]->Name, nameKey)) {
            PWKD_SA_ITEM dst = g_sa.Items[i];
            (VOID)StringCchCopyW(dst->Command, _countof(dst->Command), Item->Command);
            (VOID)StringCchCopyW(dst->TargetPath, _countof(dst->TargetPath), Item->TargetPath);
            dst->TargetExists = Item->TargetExists;
            dst->Signature = Item->Signature;
            dst->Reputation = Item->Reputation;
            dst->RiskScore = Item->RiskScore;
            dst->RiskFactorCount = Item->RiskFactorCount;
            for (ULONG r = 0; r < Item->RiskFactorCount; ++r) {
                (VOID)StringCchCopyA(dst->RiskFactors[r], _countof(dst->RiskFactors[0]),
                                     Item->RiskFactors[r]);
            }
            dst->IsMalicious = Item->IsMalicious;
            dst->Category = Item->Category;
            dst->Recommendation = Item->Recommendation;
            (VOID)StringCchCopyA(dst->RecommendationReason, _countof(dst->RecommendationReason),
                                 Item->RecommendationReason);
            GetSystemTimeAsFileTime((LPFILETIME)&dst->ModifiedTime);
            return TRUE;
        }
    }

    /* 新增: 扩容后追加 */
    if (g_sa.ItemCount >= WKD_SA_MAX_ITEMS) return FALSE;
    if (g_sa.ItemCount >= g_sa.ItemCapacity) {
        ULONG newCap = (g_sa.ItemCapacity > 0) ? g_sa.ItemCapacity : WKD_SA_POOL_INIT_CAPACITY;
        newCap *= 2;
        if (newCap > WKD_SA_MAX_ITEMS) newCap = WKD_SA_MAX_ITEMS;
        if (newCap <= g_sa.ItemCapacity) return FALSE;
        PWKD_SA_ITEM* newArr = (PWKD_SA_ITEM*)UtHeapAlloc(newCap * sizeof(PWKD_SA_ITEM));
        if (newArr == NULL) return FALSE;
        if (g_sa.Items != NULL) {
            memcpy(newArr, g_sa.Items, g_sa.ItemCount * sizeof(PWKD_SA_ITEM));
            UtHeapFree(g_sa.Items);
        }
        g_sa.Items = newArr;
        g_sa.ItemCapacity = newCap;
    }
    PWKD_SA_ITEM copy = (PWKD_SA_ITEM)UtHeapAlloc(sizeof(WKD_SA_ITEM));
    if (copy == NULL) return FALSE;
    *copy = *Item;
    g_sa.Items[g_sa.ItemCount++] = copy;
    return TRUE;
}

/* ==================================================
 * 管理写回 API (对应 SS Disable/Enable/Remove/Delay/Restore)
 * ================================================== */
WKD_SA_ACTION_RESULT
SaDisableItem(_In_ PCWSTR Name) {
    if (Name == NULL) return WkdSaAction_Failed;
    if (!g_sa.Initialized) return WkdSaAction_Failed;

    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemByName(Name, &item))) return WkdSaAction_NotFound;

    if (!item.IsEnabled) return WkdSaAction_AlreadyInState;

    if (!SaWriteDisableToRegistry(&item)) {
        SaDbgPrint(L"[SA] Failed to write disable for item %s", item.Name);
        return WkdSaAction_AccessDenied;
    }

    /* 先记录变更 (SS: 避免锁序问题) */
    SaRecordChange(&item, "Disable", item.Status, WkdSaStatus_Disabled);

    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    (VOID)SaPoolUpdateStatusById(item.ItemId, WkdSaStatus_Disabled, FALSE);
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    InterlockedIncrement(&g_sa.Stats.ItemsDisabled);
    SaDbgPrint(L"[SA] Disabled item: %s", item.Name);
    return WkdSaAction_Success;
}

WKD_SA_ACTION_RESULT
SaEnableItem(_In_ PCWSTR Name) {
    if (Name == NULL) return WkdSaAction_Failed;
    if (!g_sa.Initialized) return WkdSaAction_Failed;

    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemByName(Name, &item))) return WkdSaAction_NotFound;

    if (item.IsEnabled) return WkdSaAction_AlreadyInState;

    if (!SaWriteEnableToRegistry(&item)) {
        SaDbgPrint(L"[SA] Failed to write enable for item %s", item.Name);
        return WkdSaAction_AccessDenied;
    }

    SaRecordChange(&item, "Enable", item.Status, WkdSaStatus_Enabled);

    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    (VOID)SaPoolUpdateStatusById(item.ItemId, WkdSaStatus_Enabled, TRUE);
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    InterlockedIncrement(&g_sa.Stats.ItemsEnabled);
    SaDbgPrint(L"[SA] Enabled item: %s", item.Name);
    return WkdSaAction_Success;
}

WKD_SA_ACTION_RESULT
SaRemoveItem(_In_ PCWSTR Name, _In_ BOOLEAN Quarantine) {
    if (Name == NULL) return WkdSaAction_Failed;
    if (!g_sa.Initialized) return WkdSaAction_Failed;

    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemByName(Name, &item))) return WkdSaAction_NotFound;

    if (!SaWriteRemoveFromRegistry(&item)) {
        SaDbgPrint(L"[SA] Failed to remove item %s from registry", item.Name);
        return WkdSaAction_AccessDenied;
    }

    const ULONG newStatus = Quarantine ? WkdSaStatus_Quarantined : WkdSaStatus_Removed;
    SaRecordChange(&item, "Remove", item.Status, newStatus);

    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    (VOID)SaPoolUpdateStatusById(item.ItemId, newStatus, FALSE);
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    if (Quarantine) {
        InterlockedIncrement(&g_sa.Stats.ItemsQuarantined);
    }
    InterlockedIncrement(&g_sa.Stats.ItemsRemoved);
    SaDbgPrint(L"[SA] Removed item: %s (quarantine: %s)",
               item.Name, Quarantine ? L"yes" : L"no");
    return WkdSaAction_Success;
}

WKD_SA_ACTION_RESULT
SaDelayItem(_In_ PCWSTR Name, _In_ ULONG DelaySeconds) {
    if (Name == NULL) return WkdSaAction_Failed;
    if (!g_sa.Initialized) return WkdSaAction_Failed;

    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemByName(Name, &item))) return WkdSaAction_NotFound;

    if (DelaySeconds > WKD_SA_MAX_DELAY_SECONDS) {
        DelaySeconds = WKD_SA_MAX_DELAY_SECONDS;
    }

    SaRecordChange(&item, "Delay", item.Status, WkdSaStatus_Delayed);

    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->ItemId == item.ItemId) {
            g_sa.Items[i]->Status = WkdSaStatus_Delayed;
            g_sa.Items[i]->IsDelayed = TRUE;
            g_sa.Items[i]->DelaySeconds = DelaySeconds;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    SaDbgPrint(L"[SA] Delayed item: %s (%lu seconds)", item.Name, DelaySeconds);
    return WkdSaAction_Success;
}

WKD_SA_ACTION_RESULT
SaRestoreItem(_In_ PCWSTR Name) {
    if (Name == NULL) return WkdSaAction_Failed;
    if (!g_sa.Initialized) return WkdSaAction_Failed;

    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemByName(Name, &item))) return WkdSaAction_NotFound;

    if (item.Status != WkdSaStatus_Quarantined &&
        item.Status != WkdSaStatus_Disabled) {
        return WkdSaAction_AlreadyInState;
    }

    if (!SaWriteEnableToRegistry(&item)) {
        return WkdSaAction_AccessDenied;
    }

    SaRecordChange(&item, "Restore", item.Status, WkdSaStatus_Enabled);

    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    (VOID)SaPoolUpdateStatusById(item.ItemId, WkdSaStatus_Enabled, TRUE);
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    SaDbgPrint(L"[SA] Restored item: %s", item.Name);
    return WkdSaAction_Success;
}

/* ==================================================
 * 安全查询 (对应 SS GetMaliciousItems/GetSuspiciousItems/ScanItem)
 * ================================================== */
NTSTATUS
SaGetMaliciousItems(_Out_opt_ PWKD_SA_ITEM Items, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);

    ULONG total = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->IsMalicious) ++total;
    }
    if (Capacity < total) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (total > 0 && Items == NULL) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->IsMalicious) {
            Items[written++] = *g_sa.Items[i];
        }
    }
    *Count = written;
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_SUCCESS;
}

NTSTATUS
SaGetSuspiciousItems(_In_ UCHAR MinRiskScore, _Out_opt_ PWKD_SA_ITEM Items,
                     _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);

    ULONG total = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->RiskScore >= MinRiskScore) ++total;
    }
    if (Capacity < total) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (total > 0 && Items == NULL) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->RiskScore >= MinRiskScore) {
            Items[written++] = *g_sa.Items[i];
        }
    }
    *Count = written;
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_SUCCESS;
}

NTSTATUS
SaScanItemByName(_In_ PCWSTR Name, _Out_ PWKD_SA_ITEM Item) {
    if (Name == NULL || Item == NULL) return STATUS_INVALID_PARAMETER;

    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemByName(Name, &item))) {
        return STATUS_NOT_FOUND;
    }

    /* 重跑完整安全分析 (含状态修正) */
    SaAnalyzeItemSecurity(&item);
    SaGenerateRecommendation(&item);

    /* 分析结果回写池 (替换整个条目的 SS 语义) */
    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->ItemId == item.ItemId) {
            *g_sa.Items[i] = item;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    *Item = item;
    return STATUS_SUCCESS;
}

/* ==================================================
 * 历史与回滚 (对应 SS GetHistory/RollbackChange; 无嵌套锁)
 * ================================================== */
NTSTATUS
SaGetHistory(_In_ ULONG MaxCount, _Out_opt_ PWKD_SA_CHANGE Changes,
             _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_sa.HistoryLock);
    const ULONG available = g_sa.HistoryCount;
    const ULONG want = (MaxCount < available) ? MaxCount : available;
    if (Capacity < want) {
        *Count = want;
        LeaveCriticalSection(&g_sa.HistoryLock);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (want > 0 && Changes == NULL) {
        *Count = want;
        LeaveCriticalSection(&g_sa.HistoryLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 最新优先 (环形: Head-1 为最新) */
    ULONG idx = (g_sa.HistoryHead + WKD_SA_MAX_HISTORY - 1) % WKD_SA_MAX_HISTORY;
    for (ULONG i = 0; i < want; ++i) {
        Changes[i] = g_sa.History[idx];
        idx = (idx + WKD_SA_MAX_HISTORY - 1) % WKD_SA_MAX_HISTORY;
    }
    *Count = want;
    LeaveCriticalSection(&g_sa.HistoryLock);
    return STATUS_SUCCESS;
}

BOOLEAN
SaRollbackChange(_In_ ULONGLONG ChangeId) {
    if (!g_sa.Initialized) return FALSE;

    /* Phase 1: 仅锁历史, 提取回滚信息后立即释放 */
    BOOLEAN found = FALSE;
    BOOLEAN canRollback = FALSE;
    ULONGLONG targetItemId = 0;
    ULONG previousStatus = WkdSaStatus_Enabled;
    CHAR changeType[16];

    EnterCriticalSection(&g_sa.HistoryLock);
    for (ULONG i = 0; i < g_sa.HistoryCount; ++i) {
        if (g_sa.History[i].ChangeId == ChangeId) {
            found = TRUE;
            canRollback = g_sa.History[i].CanRollback;
            targetItemId = g_sa.History[i].ItemId;
            previousStatus = g_sa.History[i].PreviousStatus;
            (VOID)StringCchCopyA(changeType, _countof(changeType),
                                 g_sa.History[i].ChangeType);
            break;
        }
    }
    LeaveCriticalSection(&g_sa.HistoryLock);

    if (!found) return FALSE;
    if (!canRollback) {
        SaDbgPrint(L"[SA] Change %I64u cannot be rolled back", ChangeId);
        return FALSE;
    }

    /* Phase 2: 仅锁条目 (无嵌套历史锁) */
    WKD_SA_ITEM item;
    if (!NT_SUCCESS(SaGetItemById(targetItemId, &item))) return FALSE;

    BOOLEAN registryUpdated = FALSE;
    switch (previousStatus) {
        case WkdSaStatus_Enabled:
            registryUpdated = SaWriteEnableToRegistry(&item);
            break;
        case WkdSaStatus_Disabled:
            registryUpdated = SaWriteDisableToRegistry(&item);
            break;
        case WkdSaStatus_Removed:
        case WkdSaStatus_Quarantined:
            registryUpdated = SaWriteRemoveFromRegistry(&item);
            break;
        default:
            registryUpdated = TRUE;   /* 纯内存状态, 无系统写回 */
            break;
    }
    if (!registryUpdated) {
        SaDbgPrint(L"[SA] Rollback change %I64u could not restore state for item %s after %hs",
                   ChangeId, item.Name, changeType);
        return FALSE;
    }

    SaRecordChange(&item, "Rollback", item.Status, previousStatus);

    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->ItemId == targetItemId) {
            g_sa.Items[i]->Status = previousStatus;
            g_sa.Items[i]->IsEnabled = (previousStatus == WkdSaStatus_Enabled);
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    SaDbgPrint(L"[SA] Rolled back change %I64u", ChangeId);
    return TRUE;
}

/* ==================================================
 * 引导分析 (对应 SS GetBootAnalysis/SetBootBaseline/GetBootBaseline)
 * 说明: BootImpact 无系统测量机制, 相关字段恒 0 (忠实 SS)
 * ================================================== */
NTSTATUS
SaGetBootAnalysis(_Out_ PWKD_SA_BOOT_ANALYSIS Analysis) {
    if (Analysis == NULL) return STATUS_INVALID_PARAMETER;
    memset(Analysis, 0, sizeof(*Analysis));

    GetSystemTimeAsFileTime((LPFILETIME)&Analysis->BootTime);

    AcquireSRWLockShared(&g_sa.ItemsLock);
    Analysis->TotalStartupItems = g_sa.ItemCount;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        PWKD_SA_ITEM item = g_sa.Items[i];
        if (item == NULL) continue;
        if (item->IsEnabled) ++Analysis->EnabledItems;
        if (item->IsDelayed) ++Analysis->DelayedItems;
        if (item->IsCritical) ++Analysis->CriticalItems;
        if (item->BootImpact.Level == WkdSaImpact_High ||
            item->BootImpact.Level == WkdSaImpact_Critical) {
            ++Analysis->HighImpactItems;
        }
        Analysis->TotalStartupImpactMs += item->BootImpact.EstimatedMs;
    }
    ReleaseSRWLockShared(&g_sa.ItemsLock);

    /* 恒定 0 (无系统测量): changeFromBaseline 条件恒不触发, 保留语义 */
    const ULONG baseline = (ULONG)g_sa.BootBaseline;
    if (baseline > 0 && Analysis->TotalBootTimeMs > 0) {
        Analysis->ChangeFromBaselineMs = (LONG)Analysis->TotalBootTimeMs - (LONG)baseline;
        if (baseline != 0) {
            Analysis->ChangePercent = ((double)Analysis->ChangeFromBaselineMs /
                                       (double)baseline) * 100.0;
        }
    }
    return STATUS_SUCCESS;
}

VOID
SaSetBootBaseline(VOID) {
    WKD_SA_BOOT_ANALYSIS analysis;
    if (!NT_SUCCESS(SaGetBootAnalysis(&analysis))) return;
    InterlockedExchange(&g_sa.BootBaseline, (LONG)analysis.TotalBootTimeMs);
    InterlockedExchange(&g_sa.Stats.BaselineBootTimeMs, (LONG)analysis.TotalBootTimeMs);
    SaDbgPrint(L"[SA] Boot baseline set to %lu ms", analysis.TotalBootTimeMs);
}

ULONG
SaGetBootBaseline(VOID) {
    return (ULONG)g_sa.BootBaseline;
}

/* ==================================================
 * 优化 (对应 SS GetOptimizationPlan/Apply/Delay/Disable 建议)
 * ================================================== */
NTSTATUS
SaGetOptimizationPlan(_Out_ PWKD_SA_OPT_PLAN Plan) {
    if (Plan == NULL) return STATUS_INVALID_PARAMETER;
    memset(Plan, 0, sizeof(*Plan));
    Plan->IsSafe = TRUE;

    AcquireSRWLockShared(&g_sa.ItemsLock);
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        PWKD_SA_ITEM item = g_sa.Items[i];
        if (item == NULL) continue;

        switch (item->Recommendation) {
            case WkdSaRec_Delay:
                if (Plan->DelayItemCount < WKD_SA_MAX_OPT_ITEMS) {
                    Plan->DelayItems[Plan->DelayItemCount++] = item->ItemId;
                }
                ++Plan->ItemsToDelay;
                Plan->EstimatedTimeSavedMs += item->BootImpact.EstimatedMs;
                break;
            case WkdSaRec_Disable:
                if (Plan->DisableItemCount < WKD_SA_MAX_OPT_ITEMS) {
                    Plan->DisableItems[Plan->DisableItemCount++] = item->ItemId;
                }
                ++Plan->ItemsToDisable;
                Plan->EstimatedTimeSavedMs += item->BootImpact.EstimatedMs;
                break;
            case WkdSaRec_Remove:
                if (Plan->RemoveItemCount < WKD_SA_MAX_OPT_ITEMS) {
                    Plan->RemoveItems[Plan->RemoveItemCount++] = item->ItemId;
                }
                ++Plan->ItemsToRemove;
                Plan->EstimatedTimeSavedMs += item->BootImpact.EstimatedMs;
                break;
            default:
                break;
        }

        if (item->IsCritical && item->Recommendation != WkdSaRec_Keep) {
            Plan->IsSafe = FALSE;
            if (Plan->WarningCount < WKD_SA_MAX_PLAN_WARNINGS) {
                CHAR line[WKD_REG_MAX_DESC_CHARS];
                (VOID)StringCchPrintfA(line, _countof(line),
                                       "Critical system item recommended for modification: %ls",
                                       item->Name);
                (VOID)StringCchCopyA(Plan->Warnings[Plan->WarningCount],
                                     _countof(Plan->Warnings[0]), line);
                ++Plan->WarningCount;
            }
        }
    }
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_SUCCESS;
}

BOOLEAN
SaApplyOptimizationPlan(_In_ PCWKD_SA_OPT_PLAN Plan) {
    if (Plan == NULL) return FALSE;
    if (!Plan->IsSafe) {
        SaDbgPrint(L"[SA] Optimization plan is not safe — aborting");
        return FALSE;
    }

    const ULONG defaultDelay = g_sa.Config.DefaultDelaySeconds;
    for (ULONG i = 0; i < Plan->DelayItemCount; ++i) {
        WKD_SA_ITEM item;
        if (NT_SUCCESS(SaGetItemById(Plan->DelayItems[i], &item))) {
            (VOID)SaDelayItem(item.Name, defaultDelay);
        }
    }
    for (ULONG i = 0; i < Plan->DisableItemCount; ++i) {
        WKD_SA_ITEM item;
        if (NT_SUCCESS(SaGetItemById(Plan->DisableItems[i], &item))) {
            (VOID)SaDisableItem(item.Name);
        }
    }
    for (ULONG i = 0; i < Plan->RemoveItemCount; ++i) {
        WKD_SA_ITEM item;
        if (NT_SUCCESS(SaGetItemById(Plan->RemoveItems[i], &item))) {
            (VOID)SaRemoveItem(item.Name, TRUE);
        }
    }

    SaDbgPrint(L"[SA] Applied optimization plan: %lu delayed, %lu disabled, %lu removed",
               Plan->ItemsToDelay, Plan->ItemsToDisable, Plan->ItemsToRemove);
    return TRUE;
}

/* 推荐收集通用内联 (Delay/Disable 变体) */
static
NTSTATUS SaGetRecommendationIds(_In_ ULONG Recommendation,
                                _Out_opt_ PULONGLONG Ids, _In_ ULONG Capacity,
                                _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_sa.ItemsLock);

    ULONG total = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->Recommendation == Recommendation) ++total;
    }
    if (Capacity < total) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (total > 0 && Ids == NULL) {
        *Count = total;
        ReleaseSRWLockShared(&g_sa.ItemsLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && g_sa.Items[i]->Recommendation == Recommendation) {
            Ids[written++] = g_sa.Items[i]->ItemId;
        }
    }
    *Count = written;
    ReleaseSRWLockShared(&g_sa.ItemsLock);
    return STATUS_SUCCESS;
}

NTSTATUS
SaGetDelayRecommendations(_Out_opt_ PULONGLONG Ids, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    return SaGetRecommendationIds(WkdSaRec_Delay, Ids, Capacity, Count);
}

NTSTATUS
SaGetDisableRecommendations(_Out_opt_ PULONGLONG Ids, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    return SaGetRecommendationIds(WkdSaRec_Disable, Ids, Capacity, Count);
}

/* ==================================================
 * 实时接线 (RM 集成; 对应 SS WireRegistryMonitor/OnRegistryChange/
 * OnKernelRegistryNotification)
 * ================================================== */

/* RM 事件回调 (过滤 + 转发) */
static
VOID SaRmEventCallback(_In_ PCWKD_RM_EVENT Event, _In_ WKD_RM_VERDICT Verdict,
                       _In_opt_ PVOID Context) {
    UNREFERENCED_PARAMETER(Verdict);
    UNREFERENCED_PARAMETER(Context);
    if (Event == NULL) return;

    /* 仅关注持久化键上的写类操作 */
    if (Event->Operation != WkdRmOp_SetValue &&
        Event->Operation != WkdRmOp_DeleteValue &&
        Event->Operation != WkdRmOp_CreateKey) {
        return;
    }
    if (!RmEventIsPersistenceKey(Event)) return;

    SaOnRegistryChange(Event->KeyPath, Event->ValueName,
                       Event->ValueData, Event->ValueDataSize,
                       Event->ProcessId, Event->ProcessPath);
}

ULONG
SaWireRegistryMonitor(VOID) {
    if (!g_sa.Initialized) {
        SaDbgPrint(L"[SA] Cannot wire RegistryMonitor: not initialized");
        return 0;
    }
    if (g_sa.RmCallbackId != 0) {
        return g_sa.RmCallbackId;   /* 已接线 */
    }
    if (!RmIsRunning()) {
        SaDbgPrint(L"[SA] RegistryMonitor not running, deferring wiring");
        return 0;
    }

    const ULONG id = RmRegisterEventCallback(SaRmEventCallback, NULL);
    if (id != 0) {
        g_sa.RmCallbackId = id;
        SaDbgPrint(L"[SA] Wired to RegistryMonitor (callback ID: %lu)", id);
    }
    return id;
}

/* 实时自启动变更处理 (对应 SS OnRegistryChange) */
VOID
SaOnRegistryChange(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName,
                   _In_opt_ const BYTE* Data, _In_ ULONG DataSize,
                   _In_ ULONG ProcessId, _In_opt_ PCWSTR ProcessPath) {
    if (!g_sa.Initialized) return;

    /* 事件载荷校验 (截断自卫, 防日志/回调放大) */
    if (DataSize > WKD_SA_MAX_REG_PAYLOAD) {
        SaDbgPrint(L"[SA] Rejected oversized real-time registry payload for %s\\%s (%lu bytes)",
                   KeyPath, ValueName, DataSize);
        return;
    }

    WKD_SA_ITEM item;
    memset(&item, 0, sizeof(item));
    item.ItemId = (ULONGLONG)InterlockedIncrement64(&g_sa.NextItemId);
    (VOID)StringCchCopyW(item.Name, _countof(item.Name),
                         (ValueName != NULL) ? ValueName : L"");
    (VOID)StringCchCopyW(item.DisplayName, _countof(item.DisplayName),
                         (ValueName != NULL) ? ValueName : L"");
    (VOID)StringCchCopyW(item.Location, _countof(item.Location),
                         (KeyPath != NULL) ? KeyPath : L"");
    (VOID)StringCchCopyW(item.EntryName, _countof(item.EntryName),
                         (ValueName != NULL) ? ValueName : L"");

    /* 从事件数据提取命令 (SafeExtractRegString) */
    if (Data != NULL && DataSize >= sizeof(WCHAR)) {
        SaSafeExtractRegString(Data, DataSize, item.Command, _countof(item.Command));
    }

    /* 来源判定: 键路径含 \Run (对齐 SS) */
    if (KeyPath != NULL && SaContainsI(KeyPath, L"\\Run")) {
        item.Source = (SaContainsI(KeyPath, L"HKEY_LOCAL_MACHINE") ||
                       SaContainsI(KeyPath, L"HKLM"))
            ? WkdSaSrc_RegistryRun_HKLM : WkdSaSrc_RegistryRun_HKCU;
    }

    SaParseCommand(&item);
    if (item.TargetPath[0] != L'\0') {
        item.TargetExists = SaFileExists(item.TargetPath);
    }
    item.Status = WkdSaStatus_Enabled;
    item.IsEnabled = TRUE;

    SaAnalyzeItemSecurity(&item);
    SaGenerateRecommendation(&item);

    /* 新条目判定 + 插入/更新 */
    BOOLEAN isNew = FALSE;
    AcquireSRWLockExclusive(&g_sa.ItemsLock);
    WCHAR nameKey[WKD_REG_MAX_NAME_CHARS];
    SaNormalizeNameKey(item.Name, nameKey, _countof(nameKey));
    isNew = TRUE;
    for (ULONG i = 0; i < g_sa.ItemCount; ++i) {
        if (g_sa.Items[i] != NULL && SaNameKeyEquals(g_sa.Items[i]->Name, nameKey)) {
            isNew = FALSE;
            break;
        }
    }
    (VOID)SaPoolInsertOrUpdate(&item);
    ReleaseSRWLockExclusive(&g_sa.ItemsLock);

    /* 告警与自动处理 */
    if (isNew && g_sa.Config.AlertOnNewItems) {
        SaGenerateAlert(&item, "NewItem");
        SaInvokeNewItemCallbacks(&item);
    }
    if (item.IsMalicious) {
        SaGenerateAlert(&item, "Malicious");
        if (g_sa.Config.AutoQuarantineMalicious) {
            SaDbgPrint(L"[SA] Auto-quarantining real-time malicious autostart: %s (PID: %lu)",
                       item.Name, ProcessId);
            (VOID)SaWriteRemoveFromRegistry(&item);
            InterlockedIncrement(&g_sa.Stats.ItemsQuarantined);
        }
    } else if (item.RiskScore >= 50 && g_sa.Config.AlertOnSuspicious) {
        SaGenerateAlert(&item, "Suspicious");
    }
}

/* 内核注册表通知入口 (对应 SS OnKernelRegistryNotification, 归一化路径) */
VOID
SaHandleKernelNotification(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName,
                           _In_ ULONG ProcessId) {
    if (!g_sa.Initialized) return;

    WCHAR normalized[WKD_SA_DIAG_LINE_CHARS];
    SaNormalizeKernelRegistryPath(KeyPath, normalized, _countof(normalized));

    /* 解析进程路径 (仅供日志/告警上下文) */
    WCHAR processPath[WKD_REG_MAX_PATH_CHARS];
    processPath[0] = L'\0';
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProc != NULL) {
        DWORD pathLen = WKD_REG_MAX_PATH_CHARS;
        if (QueryFullProcessImageNameW(hProc, 0, processPath, &pathLen)) {
            processPath[pathLen] = L'\0';
        }
        CloseHandle(hProc);
    }

    SaOnRegistryChange(normalized, ValueName, NULL, 0, ProcessId,
                       (processPath[0] != L'\0') ? processPath : NULL);
}

/* ==================================================
 * 回调注册 (对应 SS Register*Callback/UnregisterCallback)
 * ================================================== */
ULONG
SaRegisterNewItemCallback(_In_ PFN_SA_NEW_ITEM_CALLBACK Callback, _In_opt_ PVOID Context) {
    if (Callback == NULL) return 0;
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (g_sa.NewItemSlotFree[i]) {
            const ULONG id = (ULONG)InterlockedIncrement64(&g_sa.NextCallbackId);
            g_sa.NewItemCallbacks[i] = Callback;
            g_sa.NewItemContexts[i] = Context;
            g_sa.NewItemCallbackIds[i] = id ? id : (ULONG)InterlockedIncrement64(&g_sa.NextCallbackId);
            g_sa.NewItemSlotFree[i] = FALSE;
            LeaveCriticalSection(&g_sa.CallbacksLock);
            return g_sa.NewItemCallbackIds[i];   /* 防 0 哨兵重叠 */
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);
    return 0;   /* 槽满 */
}

ULONG
SaRegisterAlertCallback(_In_ PFN_SA_ALERT_CALLBACK Callback, _In_opt_ PVOID Context) {
    if (Callback == NULL) return 0;
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (g_sa.AlertSlotFree[i]) {
            const ULONG id = (ULONG)InterlockedIncrement64(&g_sa.NextCallbackId);
            g_sa.AlertCallbacks[i] = Callback;
            g_sa.AlertContexts[i] = Context;
            g_sa.AlertCallbackIds[i] = id ? id : (ULONG)InterlockedIncrement64(&g_sa.NextCallbackId);
            g_sa.AlertSlotFree[i] = FALSE;
            LeaveCriticalSection(&g_sa.CallbacksLock);
            return g_sa.AlertCallbackIds[i];   /* 防 0 哨兵重叠 */
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);
    return 0;   /* 槽满 */
}

ULONG
SaRegisterChangeCallback(_In_ PFN_SA_CHANGE_CALLBACK Callback, _In_opt_ PVOID Context) {
    if (Callback == NULL) return 0;
    EnterCriticalSection(&g_sa.CallbacksLock);
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (g_sa.ChangeSlotFree[i]) {
            const ULONG id = (ULONG)InterlockedIncrement64(&g_sa.NextCallbackId);
            g_sa.ChangeCallbacks[i] = Callback;
            g_sa.ChangeContexts[i] = Context;
            g_sa.ChangeCallbackIds[i] = id ? id : (ULONG)InterlockedIncrement64(&g_sa.NextCallbackId);
            g_sa.ChangeSlotFree[i] = FALSE;
            LeaveCriticalSection(&g_sa.CallbacksLock);
            return g_sa.ChangeCallbackIds[i];   /* 防 0 哨兵重叠 */
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);
    return 0;   /* 槽满 */
}

BOOLEAN
SaUnregisterCallback(_In_ ULONG CallbackId) {
    if (CallbackId == 0) return FALSE;
    EnterCriticalSection(&g_sa.CallbacksLock);

    /* 三类平行槽逐一按注册 id 精确匹配 (对齐 SS: 按 id erase) */
    for (ULONG i = 0; i < WKD_SA_MAX_CALLBACKS; ++i) {
        if (!g_sa.NewItemSlotFree[i] && g_sa.NewItemCallbackIds[i] == CallbackId) {
            g_sa.NewItemCallbacks[i] = NULL;
            g_sa.NewItemContexts[i] = NULL;
            g_sa.NewItemCallbackIds[i] = 0;
            g_sa.NewItemSlotFree[i] = TRUE;
            LeaveCriticalSection(&g_sa.CallbacksLock);
            SaDbgPrint(L"[SA] Unregistered new-item callback (ID: %lu)", CallbackId);
            return TRUE;
        }
        if (!g_sa.AlertSlotFree[i] && g_sa.AlertCallbackIds[i] == CallbackId) {
            g_sa.AlertCallbacks[i] = NULL;
            g_sa.AlertContexts[i] = NULL;
            g_sa.AlertCallbackIds[i] = 0;
            g_sa.AlertSlotFree[i] = TRUE;
            LeaveCriticalSection(&g_sa.CallbacksLock);
            SaDbgPrint(L"[SA] Unregistered alert callback (ID: %lu)", CallbackId);
            return TRUE;
        }
        if (!g_sa.ChangeSlotFree[i] && g_sa.ChangeCallbackIds[i] == CallbackId) {
            g_sa.ChangeCallbacks[i] = NULL;
            g_sa.ChangeContexts[i] = NULL;
            g_sa.ChangeCallbackIds[i] = 0;
            g_sa.ChangeSlotFree[i] = TRUE;
            LeaveCriticalSection(&g_sa.CallbacksLock);
            SaDbgPrint(L"[SA] Unregistered change callback (ID: %lu)", CallbackId);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_sa.CallbacksLock);
    return FALSE;
}

/* ==================================================
 * 统计与诊断 (对应 SS GetStatistics/ResetStatistics/SelfTest/
 * RunDiagnostics/ExportReport/ExportItems)
 * ================================================== */
VOID
SaGetStatistics(_Out_ PWKD_SA_STATS Statistics) {
    if (Statistics == NULL) return;
    memset(Statistics, 0, sizeof(*Statistics));

    Statistics->TotalItemsAnalyzed = g_sa.Stats.TotalItemsAnalyzed;
    Statistics->EnabledItems = g_sa.Stats.EnabledItems;
    Statistics->DisabledItems = g_sa.Stats.DisabledItems;
    Statistics->MaliciousItems = g_sa.Stats.MaliciousItems;
    Statistics->ItemsEnabled = g_sa.Stats.ItemsEnabled;
    Statistics->ItemsDisabled = g_sa.Stats.ItemsDisabled;
    Statistics->ItemsRemoved = g_sa.Stats.ItemsRemoved;
    Statistics->ItemsQuarantined = g_sa.Stats.ItemsQuarantined;
    Statistics->AlertsGenerated = g_sa.Stats.AlertsGenerated;
    Statistics->LastBootTimeMs = g_sa.Stats.LastBootTimeMs;
    Statistics->BaselineBootTimeMs = g_sa.Stats.BaselineBootTimeMs;
}

VOID
SaResetStatistics(VOID) {
    memset(&g_sa.Stats, 0, sizeof(g_sa.Stats));
    SaDbgPrint(L"[SA] Statistics reset");
}

BOOLEAN
SaSelfTest(VOID) {
    SaDbgPrint(L"[SA] Starting self-test");

    WKD_SA_CONFIG defCfg;
    WKD_SA_CONFIG secCfg;
    WKD_SA_CONFIG perfCfg;
    SaCreateDefaultConfig(&defCfg);
    SaCreateSecurityConfig(&secCfg);
    SaCreatePerformanceConfig(&perfCfg);

    if (!defCfg.AnalyzeSignatures || !secCfg.AutoQuarantineMalicious ||
        !perfCfg.EnableOptimization) {
        SaDbgPrint(L"[SA] Config factory test failed");
        return FALSE;
    }

    /* 分析链路冒烟 (notepad 基准: 不得判为 Remove) */
    WKD_SA_ITEM testItem;
    memset(&testItem, 0, sizeof(testItem));
    (VOID)StringCchCopyW(testItem.Name, _countof(testItem.Name), L"TestItem");
    (VOID)StringCchCopyW(testItem.TargetPath, _countof(testItem.TargetPath),
                         L"C:\\Windows\\System32\\notepad.exe");
    testItem.TargetExists = SaFileExists(testItem.TargetPath);
    testItem.Status = WkdSaStatus_Enabled;
    testItem.IsEnabled = TRUE;

    SaCalculateRiskScore(&testItem);
    SaGenerateRecommendation(&testItem);
    if (testItem.Recommendation == WkdSaRec_Remove) {
        SaDbgPrint(L"[SA] Item analysis test failed");
        return FALSE;
    }

    /* 名称规范化大小写不敏感 */
    WCHAR key1[WKD_REG_MAX_NAME_CHARS];
    WCHAR key2[WKD_REG_MAX_NAME_CHARS];
    SaNormalizeNameKey(L"TestEntry", key1, _countof(key1));
    SaNormalizeNameKey(L"testentry", key2, _countof(key2));
    if (wcscmp(key1, key2) != 0) {
        SaDbgPrint(L"[SA] Case-insensitive name normalization test failed");
        return FALSE;
    }

    SaDbgPrint(L"[SA] Self-test passed");
    return TRUE;
}

BOOLEAN
SaRunDiagnostics(_Out_opt_ PWSTR Lines, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return FALSE;
    const ULONG NEEDED = 10;   /* 固定诊断行数 (对齐 SS) */
    if (Capacity < NEEDED) {
        *Count = NEEDED;
        return FALSE;
    }
    if (Lines == NULL) {
        *Count = NEEDED;
        return FALSE;
    }

    ULONG n = 0;
    (VOID)StringCchCopyW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                         WKD_SA_DIAG_LINE_CHARS, L"StartupAnalyzer Diagnostics");
    (VOID)StringCchCopyW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                         WKD_SA_DIAG_LINE_CHARS, L"============================");
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Initialized: %s",
                           g_sa.Initialized ? L"Yes" : L"No");
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Total Items: %lu",
                           g_sa.Stats.TotalItemsAnalyzed);
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Enabled Items: %lu",
                           g_sa.Stats.EnabledItems);
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Disabled Items: %lu",
                           g_sa.Stats.DisabledItems);
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Malicious Items: %lu",
                           g_sa.Stats.MaliciousItems);
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Alerts Generated: %lu",
                           g_sa.Stats.AlertsGenerated);
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"Boot Baseline: %lu ms",
                           g_sa.BootBaseline);
    (VOID)StringCchPrintfW(&Lines[n++ * WKD_SA_DIAG_LINE_CHARS],
                           WKD_SA_DIAG_LINE_CHARS, L"RegistryMonitor Wired: %s",
                           g_sa.RmCallbackId != 0 ? L"Yes" : L"No");
    *Count = n;
    return TRUE;
}

BOOLEAN
SaExportReport(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL || OutputPath[0] == L'\0') return FALSE;

    FILE* file = NULL;
    if (_wfopen_s(&file, OutputPath, L"w, ccs=UTF-8") != 0 || file == NULL) {
        SaDbgPrint(L"[SA] Failed to open report file");
        return FALSE;
    }

    fwprintf(file, L"StartupAnalyzer Report\n");
    fwprintf(file, L"======================\n\n");

    WKD_SA_BOOT_ANALYSIS analysis;
    if (NT_SUCCESS(SaGetBootAnalysis(&analysis))) {
        fwprintf(file, L"Boot Analysis:\n");
        fwprintf(file, L"  Total Items: %lu\n", analysis.TotalStartupItems);
        fwprintf(file, L"  Enabled Items: %lu\n", analysis.EnabledItems);
        fwprintf(file, L"  Delayed Items: %lu\n", analysis.DelayedItems);
        fwprintf(file, L"  Critical Items: %lu\n", analysis.CriticalItems);
        fwprintf(file, L"  High Impact Items: %lu\n\n", analysis.HighImpactItems);
    }

    fwprintf(file, L"Security:\n");
    fwprintf(file, L"  Malicious Items: %lu\n\n", g_sa.Stats.MaliciousItems);

    fclose(file);
    return TRUE;
}

BOOLEAN
SaExportItems(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL || OutputPath[0] == L'\0') return FALSE;

    FILE* file = NULL;
    if (_wfopen_s(&file, OutputPath, L"w, ccs=UTF-8") != 0 || file == NULL) {
        SaDbgPrint(L"[SA] Failed to open items export file");
        return FALSE;
    }

    /* 快照条目 */
    AcquireSRWLockShared(&g_sa.ItemsLock);
    const ULONG total = g_sa.ItemCount;

    fwprintf(file, L"Name,Source,Status,Category,Risk Score,Malicious,Target Path\n");
    for (ULONG i = 0; i < total; ++i) {
        PWKD_SA_ITEM item = g_sa.Items[i];
        if (item == NULL) continue;
        WCHAR nameCell[WKD_REG_MAX_PATH_CHARS];
        WCHAR pathCell[WKD_REG_MAX_PATH_CHARS];
        SaSanitizeCsvCell(item->Name, nameCell, _countof(nameCell));
        SaSanitizeCsvCell(item->TargetPath, pathCell, _countof(pathCell));
        fwprintf(file, L"%s,%hs,%hs,%hs,%u,%hs,%s\n",
                 nameCell,
                 SaLookupSourceName(item->Source),
                 SaLookupStatusName(item->Status),
                 SaLookupCategoryName(item->Category),
                 (UINT)item->RiskScore,
                 item->IsMalicious ? "Yes" : "No",
                 pathCell);
    }
    ReleaseSRWLockShared(&g_sa.ItemsLock);

    fclose(file);
    return TRUE;
}

/* ==================================================
 * The Boot Guard — StartupAnalyzer 迁移完成
 * ================================================== */