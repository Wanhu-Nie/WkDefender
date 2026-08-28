/**************************************************/
/*  NamedPipeMonitor 命名管道 C2/横向移动监控        */
/*  迁移自 SS NamedPipeMonitor.c（重功能实现）       */
/*                                                   */
/*  活代码：分类引擎（C2 表/系统管道冒充/熵）+ 限速   */
/*          + boot 窗口 + 统计 + 阻断判定            */
/*  死代码：管道跟踪表 + LRU + 连接检测（见分区注释） */
/**************************************************/

#include "NamedPipeMonitor.h"
#include <ntstrsafe.h>

/**************************************************/
/*                      常量定义                   */
/**************************************************/

#define WKD_NPM_ENTROPY_THRESHOLD_FIXED 4300    /* 4.2 bits * 1024 */

/**************************************************/
/*                      内部结构                   */
/**************************************************/

/* 已知 C2 管道模式项（对齐 SS NPM_KNOWN_PATTERN） */
typedef struct _WKD_NPM_KNOWN_PATTERN {
    PCWSTR             Pattern;
    USHORT             PatternLengthBytes;      /* 不含 NUL */
    UCHAR              MatchType;               /* 0=精确 1=前缀 2=包含 */
    WKD_NPM_PIPE_CLASS Classification;
    ULONG              BaseThreatScore;
} WKD_NPM_KNOWN_PATTERN, *PWKD_NPM_KNOWN_PATTERN;

/* 系统管道→预期创建者映射（对齐 SS NPM_SYSTEM_PIPE_MAP） */
typedef struct _WKD_NPM_SYSTEM_PIPE_MAP {
    PCWSTR PipeName;
    PCSTR  ExpectedCreators[4];
} WKD_NPM_SYSTEM_PIPE_MAP, *PWKD_NPM_SYSTEM_PIPE_MAP;

/* 已知 C2 管道模式表（对齐 SS g_KnownC2Patterns 39 条） */
static const WKD_NPM_KNOWN_PATTERN g_WkdNpmC2Patterns[] = {
    /* CobaltStrike */
    { L"MSSE-",         8,  1, WkdNpmClass_C2_CobaltStrike, 90 },
    { L"msagent_",      10, 1, WkdNpmClass_C2_CobaltStrike, 90 },
    { L"postex_",       10, 1, WkdNpmClass_C2_CobaltStrike, 95 },
    { L"postex_ssh_",   14, 1, WkdNpmClass_C2_CobaltStrike, 95 },
    { L"status_",       10, 1, WkdNpmClass_C2_CobaltStrike, 70 },
    { L"DserNamePipe",  16, 1, WkdNpmClass_C2_CobaltStrike, 85 },
    { L"srvsvc_",       10, 1, WkdNpmClass_C2_CobaltStrike, 80 },
    { L"wkssvc_",       10, 1, WkdNpmClass_C2_CobaltStrike, 80 },
    { L"ntsvcs_",       10, 1, WkdNpmClass_C2_CobaltStrike, 80 },
    { L"scerpc_",       10, 1, WkdNpmClass_C2_CobaltStrike, 80 },
    { L"interprocess_", 16, 2, WkdNpmClass_C2_CobaltStrike, 80 },

    /* PsExec 服务管道 */
    { L"PSEXESVC",      10, 0, WkdNpmClass_C2_PsExec, 70 },
    { L"psexesvc",      10, 0, WkdNpmClass_C2_PsExec, 70 },
    { L"PSEXECSVC",     10, 0, WkdNpmClass_C2_PsExec, 70 },
    { L"csexec",        8,  1, WkdNpmClass_C2_PsExec, 65 },
    { L"PAExec",        8,  1, WkdNpmClass_C2_PsExec, 65 },
    { L"remcom",        8,  1, WkdNpmClass_C2_PsExec, 60 },
    { L"RemCom_comm",   12, 1, WkdNpmClass_C2_PsExec, 70 },

    /* Meterpreter */
    { L"meterpreter",   12, 1, WkdNpmClass_C2_Meterpreter, 95 },
    { L"metsrv",        8,  1, WkdNpmClass_C2_Meterpreter, 90 },

    /* Impacket */
    { L"__output",      10, 1, WkdNpmClass_C2_Impacket, 75 },
    { L"__aexec",       10, 1, WkdNpmClass_C2_Impacket, 75 },

    /* 通用 C2（Havoc/BruteRatel/Sliver/Mythic/Covenant 等） */
    { L"havoc",         8,  1, WkdNpmClass_C2_Generic, 90 },
    { L"demon_",        8,  1, WkdNpmClass_C2_Generic, 85 },
    { L"demoagent_",    12, 1, WkdNpmClass_C2_Generic, 85 },
    { L"brc4_",         8,  1, WkdNpmClass_C2_Generic, 90 },
    { L"sliver",        8,  1, WkdNpmClass_C2_Generic, 85 },
    { L"mythic",        8,  1, WkdNpmClass_C2_Generic, 85 },
    { L"gruntsvc",      10, 1, WkdNpmClass_C2_Generic, 85 },
    { L"dceservice",    12, 1, WkdNpmClass_C2_Generic, 80 },
    { L"poshc2",        8,  1, WkdNpmClass_C2_Generic, 80 },
    { L"nimplant",      10, 1, WkdNpmClass_C2_Generic, 85 },

    /* 可疑（通用包含匹配） */
    { L"SpoolSS_LPC",   12, 1, WkdNpmClass_Suspicious, 65 },
    { L"beacon",        8,  2, WkdNpmClass_Suspicious, 55 },
    { L"implant",       8,  2, WkdNpmClass_Suspicious, 55 },
    { L"payload",       8,  2, WkdNpmClass_Suspicious, 50 },
    { L"backdoor",      10, 2, WkdNpmClass_Suspicious, 60 },
    { L"c2pipe",        8,  2, WkdNpmClass_Suspicious, 55 },
    { L"evil",          6,  2, WkdNpmClass_Suspicious, 50 },
};

/* 系统管道→预期创建者映射表（对齐 SS g_SystemPipeMappings 20 条，T1036 防御） */
static const WKD_NPM_SYSTEM_PIPE_MAP g_WkdNpmSystemPipes[] = {
    /* LSASS 专属 */
    { L"lsass",             { "lsass.exe", NULL } },
    { L"lsarpc",            { "lsass.exe", NULL } },
    { L"samr",              { "lsass.exe", NULL } },
    { L"netlogon",          { "lsass.exe", NULL } },
    { L"protected_storage", { "lsass.exe", NULL } },

    /* 服务控制管理器 */
    { L"scerpc",            { "services.exe", NULL } },
    { L"svcctl",            { "services.exe", NULL } },
    { L"ntsvcs",            { "services.exe", "svchost.exe", NULL } },

    /* 通用 Windows 服务（svchost 承载） */
    { L"browser",           { "svchost.exe", NULL } },
    { L"wkssvc",            { "svchost.exe", NULL } },
    { L"srvsvc",            { "svchost.exe", NULL } },
    { L"winreg",            { "svchost.exe", "services.exe", NULL } },
    { L"eventlog",          { "svchost.exe", NULL } },
    { L"epmapper",          { "svchost.exe", NULL } },
    { L"atsvc",             { "svchost.exe", NULL } },
    { L"DAV RPC SERVICE",   { "svchost.exe", NULL } },

    /* 打印后台 */
    { L"spoolss",           { "spoolsv.exe", NULL } },

    /* 系统初始化 */
    { L"InitShutdown",      { "wininit.exe", NULL } },

    /* Windows Search */
    { L"MsFteWds",          { "SearchIndexer", NULL } },
    { L"msfte",             { "SearchIndexer", NULL } },
};

/**************************************************/
/*                 生命周期状态 / 统计              */
/**************************************************/

static volatile LONG g_NpmState = WKD_NPM_STATE_UNINITIALIZED;
static WKD_NPM_STATISTICS g_NpmStats;

/* boot 期窗口（对齐 SS ShadowFsIsBootPhase）：系统启动后 120s 内跳过分析，
 * 防 csrss/lsass/services 早期管道洪泛挂起。窗口结束后原子锁死为 0。 */
static volatile LONG g_NpmBootPhaseActive = FALSE;

/* 速率限制（1s 窗口 CAS，对齐 SS NpmCheckRateLimit） */
static LARGE_INTEGER g_NpmRateWindowStart;
static volatile LONG g_NpmRateWindowCount;

/**************************************************/
/*                 boot 窗口 / 限速                 */
/**************************************************/

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdNpmIsBootPhase(
    VOID
    )
{
    if (ReadNoFence(&g_NpmBootPhaseActive)) {
        LARGE_INTEGER now;
        now.QuadPart = KeQueryUnbiasedInterruptTime();
        if (now.QuadPart >= (LONGLONG)WKD_NPM_BOOT_PHASE_MS * 10000LL) {
            InterlockedExchange(&g_NpmBootPhaseActive, FALSE);
        } else {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdNpmCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER now;
    LONGLONG oldStart;

    KeQuerySystemTime(&now);
    oldStart = InterlockedCompareExchange64(&g_NpmRateWindowStart.QuadPart, 0, 0);

    if (now.QuadPart - oldStart > (LONGLONG)WKD_NPM_RATE_LIMIT_WINDOW_MS * 10000LL) {
        LONGLONG swapped = InterlockedCompareExchange64(
            &g_NpmRateWindowStart.QuadPart, now.QuadPart, oldStart);
        if (swapped == oldStart) {
            InterlockedExchange(&g_NpmRateWindowCount, 1);
            return TRUE;
        }
    }
    return (InterlockedIncrement(&g_NpmRateWindowCount) <= WKD_NPM_RATE_LIMIT_MAX_CREATES);
}

/**************************************************/
/*                熵计算（整数查表）               */
/**************************************************/

/* 定点 log2 表：log2_table[n] = round(log2(n)*1024)，n=1..256 */
static const USHORT g_WkdNpmLog2Table[257] = {
       0,    0, 1024, 1623, 2048, 2378, 2647, 2874,
    3072, 3247, 3402, 3542, 3671, 3789, 3898, 4001,
    4096, 4186, 4271, 4351, 4427, 4499, 4568, 4634,
    4697, 4757, 4815, 4871, 4925, 4977, 5027, 5075,
    5120, 5165, 5208, 5249, 5290, 5329, 5367, 5404,
    5440, 5475, 5509, 5542, 5574, 5606, 5637, 5667,
    5696, 5725, 5753, 5781, 5808, 5834, 5860, 5886,
    5910, 5935, 5959, 5982, 6006, 6028, 6051, 6073,
    6094, 6116, 6136, 6157, 6177, 6197, 6217, 6236,
    6255, 6274, 6293, 6311, 6329, 6347, 6365, 6382,
    6400, 6417, 6434, 6450, 6467, 6483, 6499, 6515,
    6531, 6546, 6562, 6577, 6592, 6607, 6621, 6636,
    6650, 6665, 6679, 6693, 6706, 6720, 6734, 6747,
    6760, 6773, 6786, 6799, 6812, 6824, 6837, 6849,
    6861, 6873, 6885, 6897, 6909, 6921, 6932, 6944,
    6955, 6966, 6977, 6989, 6999, 7010, 7021, 7032,
    7042, 7053, 7063, 7073, 7084, 7094, 7104, 7114,
    7124, 7134, 7143, 7153, 7163, 7172, 7182, 7191,
    7201, 7210, 7219, 7228, 7237, 7247, 7256, 7264,
    7273, 7282, 7291, 7300, 7308, 7317, 7325, 7334,
    7342, 7350, 7359, 7367, 7375, 7383, 7391, 7399,
    7407, 7415, 7423, 7431, 7438, 7446, 7454, 7461,
    7469, 7476, 7484, 7491, 7499, 7506, 7513, 7521,
    7528, 7535, 7542, 7549, 7556, 7563, 7570, 7577,
    7584, 7591, 7597, 7604, 7611, 7618, 7624, 7631,
    7637, 7644, 7650, 7657, 7663, 7669, 7676, 7682,
    7688, 7694, 7700, 7707, 7713, 7719, 7725, 7731,
    7737, 7743, 7749, 7754, 7760, 7766, 7772, 7778,
    7783, 7789, 7795, 7800, 7806, 7812, 7817, 7823,
    7828, 7834, 7839, 7844, 7850, 7855, 7861, 7866,
    7871, 7877, 7882, 7887, 7892, 7897, 7903, 7908,
    7913, 7918, 7923, 7928, 7933, 7938, 7943, 7948,
    7953
};

/* 定点 log2：>256 通过右移缩小后查表插值（对齐 SS NpmLog2Fixed） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static USHORT
WkdNpmLog2Fixed(
    _In_ ULONG Value
    )
{
    ULONG shift = 0;

    if (Value <= 256) {
        return g_WkdNpmLog2Table[Value];
    }
    while (Value > 256) {
        Value >>= 1;
        shift++;
    }
    return g_WkdNpmLog2Table[Value] + (USHORT)(shift * 1024);
}

/*
 * Shannon 熵（定点 ×1024，仅统计 ASCII 0-127，对齐 SS NpmCalculateEntropy）：
 *   H*1024 = log2(N)*1024 - (1/N) * Σ freq[i]*log2(freq[i])*1024
 */
_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
WkdNpmCalculateEntropy(
    _In_ PCWSTR String,
    _In_ USHORT LengthChars
    )
{
    ULONG freq[128];
    ULONG entropy1024 = 0;
    ULONG logLen;
    USHORT i;

    if (String == NULL || LengthChars < 2) {
        return 0;
    }

    RtlZeroMemory(freq, sizeof(freq));
    for (i = 0; i < LengthChars; i++) {
        WCHAR c = String[i];
        if (c < 128) {
            freq[(ULONG)c]++;
        }
    }

    logLen = WkdNpmLog2Fixed(LengthChars);
    for (i = 0; i < 128; i++) {
        if (freq[i] > 0 && freq[i] <= 256) {
            entropy1024 += freq[i] * g_WkdNpmLog2Table[freq[i]];
        } else if (freq[i] > 256) {
            entropy1024 += freq[i] * WkdNpmLog2Fixed(freq[i]);
        }
    }

    entropy1024 = logLen - (entropy1024 / LengthChars);
    return entropy1024;
}

/**************************************************/
/*                管道分类 / 验证                  */
/**************************************************/

/* ANSI 大小写不敏感相等（对齐 SS NpmImageNameEquals） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdNpmImageNameEquals(
    _In_z_ PCSTR A,
    _In_z_ PCSTR B
    )
{
    CHAR ca, cb;

    if (A == NULL || B == NULL) {
        return FALSE;
    }
    while (*A != '\0' && *B != '\0') {
        ca = *A;
        cb = *B;
        if (ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
        if (cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
        if (ca != cb) {
            return FALSE;
        }
        A++;
        B++;
    }
    return (*A == '\0' && *B == '\0');
}

/*
 * 管道分类（对齐 SS NpmClassifyPipe）：
 *   先精确/前缀/包含匹配 39 条 C2 模式；未命中则高熵判定
 *   （熵>4.2bit 且名长≥8 → HighEntropy，Score=55+(熵-4300)/100 cap 85）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static WKD_NPM_PIPE_CLASS
WkdNpmClassifyPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _Out_ PULONG ThreatScore
    )
{
    USHORT nameChars = NameLengthBytes / sizeof(WCHAR);
    ULONG entropy1024;
    ULONG i;

    *ThreatScore = 0;
    if (PipeName == NULL || nameChars == 0) {
        return WkdNpmClass_Unknown;
    }

    for (i = 0; i < ARRAYSIZE(g_WkdNpmC2Patterns); i++) {
        const WKD_NPM_KNOWN_PATTERN* pat = &g_WkdNpmC2Patterns[i];
        USHORT patChars = pat->PatternLengthBytes / sizeof(WCHAR);

        switch (pat->MatchType) {
        case 0: /* 精确 */
            if (nameChars == patChars &&
                _wcsnicmp(PipeName, pat->Pattern, patChars) == 0) {
                *ThreatScore = pat->BaseThreatScore;
                return pat->Classification;
            }
            break;
        case 1: /* 前缀 */
            if (nameChars >= patChars &&
                _wcsnicmp(PipeName, pat->Pattern, patChars) == 0) {
                *ThreatScore = pat->BaseThreatScore;
                return pat->Classification;
            }
            break;
        case 2: /* 包含 */
            if (nameChars >= patChars) {
                USHORT j;
                for (j = 0; j <= nameChars - patChars; j++) {
                    if (_wcsnicmp(&PipeName[j], pat->Pattern, patChars) == 0) {
                        *ThreatScore = pat->BaseThreatScore;
                        return pat->Classification;
                    }
                }
            }
            break;
        }
    }

    entropy1024 = WkdNpmCalculateEntropy(PipeName, nameChars);
    if (entropy1024 > WKD_NPM_ENTROPY_THRESHOLD_FIXED && nameChars >= 8) {
        *ThreatScore = 55 + (entropy1024 - WKD_NPM_ENTROPY_THRESHOLD_FIXED) / 100;
        if (*ThreatScore > 85) {
            *ThreatScore = 85;
        }
        return WkdNpmClass_HighEntropy;
    }

    return WkdNpmClass_Unknown;
}

/*
 * 系统管道冒充验证（对齐 SS NpmValidateSystemPipe，T1036）：
 *   管道名匹配系统表且创建者匹配预期 → Validated；名匹配但创建者不符 → Spoofed。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static WKD_NPM_SYS_PIPE_RESULT
WkdNpmValidateSystemPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthChars,
    _In_z_ PCSTR CreatorImageName
    )
{
    ULONG i, j;

    for (i = 0; i < ARRAYSIZE(g_WkdNpmSystemPipes); i++) {
        SIZE_T sysLen = wcslen(g_WkdNpmSystemPipes[i].PipeName);
        if (NameLengthChars == (USHORT)sysLen &&
            _wcsnicmp(PipeName, g_WkdNpmSystemPipes[i].PipeName, sysLen) == 0) {
            for (j = 0; g_WkdNpmSystemPipes[i].ExpectedCreators[j] != NULL; j++) {
                if (WkdNpmImageNameEquals(CreatorImageName,
                                          g_WkdNpmSystemPipes[i].ExpectedCreators[j])) {
                    return WkdNpmSysPipe_Validated;
                }
            }
            return WkdNpmSysPipe_Spoofed;
        }
    }
    return WkdNpmSysPipe_NotSystem;
}

/**************************************************/
/*              主分析入口（分类引擎）              */
/**************************************************/

/*
 * WkdNpmPreCreateNamedPipe — 命名管道创建分析（纯分类引擎）。
 * 内部编排（对齐 SS NpMonPreCreateNamedPipe 语义）：
 *   Phase 1 系统管道验证（限速豁免）→ Spoofed 直接返回并计数；
 *   Phase 2 速率限制 → C2 模式/熵分类 → 计数。
 * 阻断/上送/评分由接入层（Filter.c FspPreCreatePipe）决策。
 */
_Use_decl_annotations_
WKD_NPM_PIPE_CLASS
WkdNpmPreCreateNamedPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_z_ PCSTR CreatorImageName,
    _Out_ PULONG OutThreatScore
    )
{
    WKD_NPM_PIPE_CLASS cls;
    USHORT nameChars = NameLengthBytes / sizeof(WCHAR);
    WKD_NPM_SYS_PIPE_RESULT sysResult;

    if (OutThreatScore) {
        *OutThreatScore = 0;
    }
    if (PipeName == NULL || CreatorImageName == NULL || nameChars == 0) {
        return WkdNpmClass_Unknown;
    }

    /* Phase 1: 系统管道验证（限速豁免路径 — 冒充检测不可被限速绕过） */
    sysResult = WkdNpmValidateSystemPipe(PipeName, nameChars, CreatorImageName);
    if (sysResult == WkdNpmSysPipe_Validated) {
        return WkdNpmClass_System;
    }
    if (sysResult == WkdNpmSysPipe_Spoofed) {
        InterlockedIncrement64(&g_NpmStats.TotalPipesCreated);
        InterlockedIncrement64(&g_NpmStats.SpoofedSystemPipes);
        InterlockedIncrement64(&g_NpmStats.SuspiciousPipesDetected);
        if (OutThreatScore) {
            *OutThreatScore = 95;   /* 对齐 SS 冒充阻断分 */
        }
        return WkdNpmClass_SpoofedSystem;
    }

    /* Phase 2: 速率限制（防管道创建洪泛 DoS） */
    if (!WkdNpmCheckRateLimit()) {
        return WkdNpmClass_Unknown;
    }

    /* Phase 3: 通用分类（C2 模式 + 熵） */
    InterlockedIncrement64(&g_NpmStats.TotalPipesCreated);
    cls = WkdNpmClassifyPipe(PipeName, NameLengthBytes, OutThreatScore);

    switch (cls) {
    case WkdNpmClass_C2_CobaltStrike:
    case WkdNpmClass_C2_Meterpreter:
    case WkdNpmClass_C2_PsExec:
    case WkdNpmClass_C2_Impacket:
    case WkdNpmClass_C2_Generic:
        InterlockedIncrement64(&g_NpmStats.C2PipesDetected);
        InterlockedIncrement64(&g_NpmStats.SuspiciousPipesDetected);
        break;
    case WkdNpmClass_HighEntropy:
        InterlockedIncrement64(&g_NpmStats.HighEntropyPipesDetected);
        InterlockedIncrement64(&g_NpmStats.SuspiciousPipesDetected);
        break;
    case WkdNpmClass_Suspicious:
        InterlockedIncrement64(&g_NpmStats.SuspiciousPipesDetected);
        break;
    default:
        break;
    }
    return cls;
}

/**************************************************/
/*             阻断判定 / 威胁等级 / 统计            */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
WkdNpmIsBlockworthy(
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    )
{
    /* 系统管道冒充：无条件阻断（对齐 SS，T1036） */
    if (Classification == WkdNpmClass_SpoofedSystem) {
        return TRUE;
    }
    /* 已知 C2 管道且威胁分达标：阻断（对齐 SS threatScore >= 90） */
    if (Classification >= WkdNpmClass_C2_CobaltStrike &&
        Classification <= WkdNpmClass_C2_Generic &&
        ThreatScore >= 90) {
        return TRUE;
    }
    return FALSE;
}

_Use_decl_annotations_
WKD_NPM_THREAT_LEVEL
WkdNpmClassToThreatLevel(
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    )
{
    if (Classification == WkdNpmClass_SpoofedSystem) {
        return WkdNpmThreat_Critical;
    }
    if (ThreatScore >= 90) return WkdNpmThreat_Critical;
    if (ThreatScore >= 70) return WkdNpmThreat_High;
    if (ThreatScore >= 50) return WkdNpmThreat_Medium;
    if (ThreatScore >= 25) return WkdNpmThreat_Low;
    return WkdNpmThreat_None;
}

_Use_decl_annotations_
VOID
WkdNpmNoteBlocked(
    VOID
    )
{
    InterlockedIncrement64(&g_NpmStats.TotalPipesBlocked);
}

_Use_decl_annotations_
VOID
WkdNpmGetStatistics(
    _Out_ PWKD_NPM_STATISTICS Stats
    )
{
    RtlZeroMemory(Stats, sizeof(*Stats));
    if (ReadNoFence(&g_NpmState) != WKD_NPM_STATE_READY) {
        return;
    }
    Stats->TotalPipesCreated       = InterlockedCompareExchange64(&g_NpmStats.TotalPipesCreated,       0, 0);
    Stats->TotalPipesConnected     = InterlockedCompareExchange64(&g_NpmStats.TotalPipesConnected,     0, 0);
    Stats->TotalPipesBlocked       = InterlockedCompareExchange64(&g_NpmStats.TotalPipesBlocked,       0, 0);
    Stats->SuspiciousPipesDetected = InterlockedCompareExchange64(&g_NpmStats.SuspiciousPipesDetected, 0, 0);
    Stats->C2PipesDetected         = InterlockedCompareExchange64(&g_NpmStats.C2PipesDetected,         0, 0);
    Stats->HighEntropyPipesDetected = InterlockedCompareExchange64(&g_NpmStats.HighEntropyPipesDetected, 0, 0);
    Stats->CrossProcessConnections = InterlockedCompareExchange64(&g_NpmStats.CrossProcessConnections,  0, 0);
    Stats->SpoofedSystemPipes      = InterlockedCompareExchange64(&g_NpmStats.SpoofedSystemPipes,       0, 0);
    Stats->EventsQueued            = InterlockedCompareExchange64(&g_NpmStats.EventsQueued,             0, 0);
    Stats->EventsDropped           = InterlockedCompareExchange64(&g_NpmStats.EventsDropped,            0, 0);
}

_Use_decl_annotations_
VOID
WkdNpmNoteEventQueued(
    VOID
    )
{
    InterlockedIncrement64(&g_NpmStats.EventsQueued);
}

_Use_decl_annotations_
VOID
WkdNpmNoteEventDropped(
    VOID
    )
{
    InterlockedIncrement64(&g_NpmStats.EventsDropped);
}

/**************************************************/
/*              初始化 / 清理                      */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdNpmInitialize(
    VOID
    )
{
    LONG prevState;

    prevState = InterlockedCompareExchange(
        &g_NpmState, WKD_NPM_STATE_INITIALIZING, WKD_NPM_STATE_UNINITIALIZED);
    if (prevState != WKD_NPM_STATE_UNINITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_NpmStats, sizeof(g_NpmStats));
    KeQuerySystemTime(&g_NpmRateWindowStart);
    g_NpmRateWindowCount = 0;
    InterlockedExchange(&g_NpmBootPhaseActive, TRUE);

    MemoryBarrier();
    InterlockedExchange(&g_NpmState, WKD_NPM_STATE_READY);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] NamedPipeMonitor initialized (%u C2 patterns, %u system pipes)\n",
        (ULONG)ARRAYSIZE(g_WkdNpmC2Patterns),
        (ULONG)ARRAYSIZE(g_WkdNpmSystemPipes));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdNpmShutdown(
    VOID
    )
{
    LONG prevState;

    prevState = InterlockedCompareExchange(
        &g_NpmState, WKD_NPM_STATE_UNINITIALIZED, WKD_NPM_STATE_READY);
    if (prevState != WKD_NPM_STATE_READY) {
        return;
    }
    InterlockedExchange(&g_NpmBootPhaseActive, FALSE);
}

_Use_decl_annotations_
BOOLEAN
WkdNpmIsActive(
    VOID
    )
{
    return (ReadNoFence(&g_NpmState) == WKD_NPM_STATE_READY && !WkdNpmIsBootPhase());
}

/**************************************************/
/*  死代码分区：管道跟踪表 + LRU + 连接检测          */
/*                                                   */
/*  功能面完整落位（对齐 SS NPM_PIPE_ENTRY +         */
/*  NpmTrackPipe + NpmEvictLruEntries），未接入：     */
/*    - wkd 管道事件一次性上送 agent（消息总线覆盖）， */
/*      agent 因果图承担跨进程关联，内核无消费方；    */
/*    - SS 连接检测本身亦未实现（NPM_PIPE_EVENT.      */
/*      ConnectorProcessId 恒 NULL，无写入者）。      */
/*  接入前提：需在 Filter.c 连接路径（IRP_MJ_CREATE  */
/*  on \Device\NamedPipe\）追踪 ConnectorPid。        */
/**************************************************/

#pragma warning(push)
#pragma warning(disable: 4505)  /* unreferenced local function */
#pragma warning(disable: 4100)  /* unreferenced formal parameter */

#define WKD_NPM_HASH_TABLE_SIZE          128
#define WKD_NPM_MAX_TRACKED_PIPES        2048
#define WKD_NPM_MAX_CONNECTIONS_PER_PIPE 64

typedef struct _WKD_NPM_PIPE_ENTRY {
    LIST_ENTRY ListEntry;               /* 哈希桶链 */
    LIST_ENTRY LruEntry;                /* LRU 链 */

    WCHAR PipeName[WKD_NPM_MAX_PIPE_NAME_CCH];
    USHORT PipeNameLength;
    HANDLE CreatorProcessId;
    CHAR CreatorImageName[16];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastAccessTime;

    WKD_NPM_PIPE_CLASS Classification;
    WKD_NPM_THREAT_LEVEL ThreatLevel;
    ULONG ThreatScore;

    volatile LONG ConnectionCount;      /* 连接计数（死代码：连接检测未接入） */
    volatile LONG ReferenceCount;
    BOOLEAN IsBlocked;
    BOOLEAN IsMonitored;
} WKD_NPM_PIPE_ENTRY, *PWKD_NPM_PIPE_ENTRY;

typedef struct _WKD_NPM_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;
} WKD_NPM_HASH_BUCKET, *PWKD_NPM_HASH_BUCKET;

/* 前向声明：WkdNpmTrackPipe 调用定义于其后的 WkdNpmEvictLruEntries */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdNpmEvictLruEntries(
    _In_ ULONG Count
    );

static WKD_NPM_HASH_BUCKET g_NpmHashTable[WKD_NPM_HASH_TABLE_SIZE];
static LIST_ENTRY g_NpmLruList;
static EX_PUSH_LOCK g_NpmLruLock;
static volatile LONG g_NpmTotalEntries;

/* DJB2 哈希（大小写不敏感，对齐 SS NpmHashPipeName） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
WkdNpmHashPipeName(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes
    )
{
    ULONG hash = 5381;
    USHORT chars = NameLengthBytes / sizeof(WCHAR);

    for (USHORT i = 0; i < chars; i++) {
        WCHAR c = PipeName[i];
        if (c >= L'A' && c <= L'Z') {
            c += (L'a' - L'A');
        }
        hash = ((hash << 5) + hash) + (ULONG)c;
    }
    return hash % WKD_NPM_HASH_TABLE_SIZE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static PWKD_NPM_PIPE_ENTRY
WkdNpmAllocateEntry(
    VOID
    )
{
    PWKD_NPM_PIPE_ENTRY entry = (PWKD_NPM_PIPE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_NPM_PIPE_ENTRY), WKD_NPM_POOL_TAG);
    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(WKD_NPM_PIPE_ENTRY));
        entry->ReferenceCount = 1;
    }
    return entry;
}

/* 创建跟踪（去重 + LRU 插入；对齐 SS NpmTrackPipe）。死代码：接入层未调用。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdNpmTrackPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE CreatorPid,
    _In_z_ PCSTR CreatorImageName,
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    )
{
    ULONG bucket;
    PWKD_NPM_PIPE_ENTRY entry;
    USHORT copyLen;
    PLIST_ENTRY listEntry;
    BOOLEAN duplicate = FALSE;

    if (InterlockedCompareExchange(&g_NpmTotalEntries, 0, 0) >= WKD_NPM_MAX_TRACKED_PIPES) {
        WkdNpmEvictLruEntries(64);
    }

    bucket = WkdNpmHashPipeName(PipeName, NameLengthBytes);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmHashTable[bucket].Lock);

    for (listEntry = g_NpmHashTable[bucket].List.Flink;
         listEntry != &g_NpmHashTable[bucket].List;
         listEntry = listEntry->Flink) {
        PWKD_NPM_PIPE_ENTRY existing = CONTAINING_RECORD(listEntry, WKD_NPM_PIPE_ENTRY, ListEntry);
        if (existing->PipeNameLength == NameLengthBytes &&
            _wcsnicmp(existing->PipeName, PipeName, NameLengthBytes / sizeof(WCHAR)) == 0) {
            InterlockedIncrement(&existing->ConnectionCount);
            KeQuerySystemTime(&existing->LastAccessTime);
            if (ThreatScore > existing->ThreatScore) {
                existing->ThreatScore = ThreatScore;
                existing->Classification = Classification;
            }
            duplicate = TRUE;
            break;
        }
    }

    if (duplicate) {
        ExReleasePushLockExclusive(&g_NpmHashTable[bucket].Lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    entry = WkdNpmAllocateEntry();
    if (entry == NULL) {
        ExReleasePushLockExclusive(&g_NpmHashTable[bucket].Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    copyLen = NameLengthBytes;
    if (copyLen > (WKD_NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR)) {
        copyLen = (WKD_NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR);
    }
    RtlCopyMemory(entry->PipeName, PipeName, copyLen);
    entry->PipeName[copyLen / sizeof(WCHAR)] = L'\0';
    entry->PipeNameLength = copyLen;
    entry->CreatorProcessId = CreatorPid;
    RtlCopyMemory(entry->CreatorImageName, CreatorImageName, 16);
    entry->Classification = Classification;
    entry->ThreatLevel = WkdNpmClassToThreatLevel(Classification, ThreatScore);
    entry->ThreatScore = ThreatScore;
    entry->ConnectionCount = 0;
    entry->IsBlocked = (ThreatScore >= 90);
    entry->IsMonitored = (ThreatScore >= 25);
    KeQuerySystemTime(&entry->CreateTime);
    entry->LastAccessTime = entry->CreateTime;

    InsertTailList(&g_NpmHashTable[bucket].List, &entry->ListEntry);
    InterlockedIncrement(&g_NpmHashTable[bucket].Count);
    InterlockedIncrement(&g_NpmTotalEntries);

    ExReleasePushLockExclusive(&g_NpmHashTable[bucket].Lock);
    KeLeaveCriticalRegion();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmLruLock);
    InsertTailList(&g_NpmLruList, &entry->LruEntry);
    ExReleasePushLockExclusive(&g_NpmLruLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/* LRU 淘汰（对齐 SS NpmEvictLruEntries：LRU 锁收集 → 桶锁移除）。死代码。 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdNpmEvictLruEntries(
    _In_ ULONG Count
    )
{
    ULONG collected = 0;
    PWKD_NPM_PIPE_ENTRY victims[64];

    if (Count > 64) {
        Count = 64;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmLruLock);
    while (!IsListEmpty(&g_NpmLruList) && collected < Count) {
        PLIST_ENTRY lruEntry = RemoveHeadList(&g_NpmLruList);
        victims[collected] = CONTAINING_RECORD(lruEntry, WKD_NPM_PIPE_ENTRY, LruEntry);
        collected++;
    }
    ExReleasePushLockExclusive(&g_NpmLruLock);
    KeLeaveCriticalRegion();

    for (ULONG i = 0; i < collected; i++) {
        PWKD_NPM_PIPE_ENTRY pipeEntry = victims[i];
        ULONG bucket = WkdNpmHashPipeName(pipeEntry->PipeName, pipeEntry->PipeNameLength);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_NpmHashTable[bucket].Lock);
        RemoveEntryList(&pipeEntry->ListEntry);
        InterlockedDecrement(&g_NpmHashTable[bucket].Count);
        InterlockedDecrement(&g_NpmTotalEntries);
        ExReleasePushLockExclusive(&g_NpmHashTable[bucket].Lock);
        KeLeaveCriticalRegion();

        ExFreePoolWithTag(pipeEntry, WKD_NPM_POOL_TAG);
    }
}

/* 连接计数入口（跨进程连接检测预留）。死代码：
 * wkd 未在连接路径（IRP_MJ_CREATE on \Device\NamedPipe\）追踪 ConnectorPid；
 * SS 亦未实现（ConnectorProcessId 恒 NULL）。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdNpmOnPipeConnected(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE ConnectorPid
    )
{
    UNREFERENCED_PARAMETER(ConnectorPid);
    InterlockedIncrement64(&g_NpmStats.TotalPipesConnected);
    return STATUS_NOT_IMPLEMENTED;
}

/* 周期清理常量（对齐 SS NPM_CLEANUP_INTERVAL_MS / NPM_PIPE_IDLE_TIMEOUT_100NS）。
 * SS 亦仅在 .h 预留，.c 未实现周期清理线程（LRU 仅容量超限驱逐）；wkd 同标死代码。 */
#define WKD_NPM_CLEANUP_INTERVAL_MS      120000
#define WKD_NPM_PIPE_IDLE_TIMEOUT_100NS  (-(LONGLONG)300 * 10000000LL)   /* 5 min */

/* 独立条目释放（对齐 SS NpmFreeEntry）。死代码：由 TrackCleanup / EvictLruEntries 消费。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdNpmFreeEntry(
    _In_opt_ PWKD_NPM_PIPE_ENTRY Entry
    )
{
    if (Entry != NULL) {
        ExFreePoolWithTag(Entry, WKD_NPM_POOL_TAG);
    }
}

/* 跟踪表初始化（对齐 SS NpMonInitialize 的哈希表 + LRU 段）。死代码：
 * 接入前提——WkdNpmTrackPipe 激活时在 WkdNpmInitialize 调用。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdNpmTrackInitialize(
    VOID
    )
{
    for (ULONG i = 0; i < WKD_NPM_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&g_NpmHashTable[i].List);
        ExInitializePushLock(&g_NpmHashTable[i].Lock);
        g_NpmHashTable[i].Count = 0;
    }
    InitializeListHead(&g_NpmLruList);
    ExInitializePushLock(&g_NpmLruLock);
    InterlockedExchange(&g_NpmTotalEntries, 0);
    return STATUS_SUCCESS;
}

/* 跟踪表清理（对齐 SS NpMonShutdown 的哈希表排空 + LRU 释放）。死代码。 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdNpmTrackCleanup(
    VOID
    )
{
    for (ULONG i = 0; i < WKD_NPM_HASH_TABLE_SIZE; i++) {
        while (!IsListEmpty(&g_NpmHashTable[i].List)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_NpmHashTable[i].List);
            PWKD_NPM_PIPE_ENTRY pipeEntry =
                CONTAINING_RECORD(entry, WKD_NPM_PIPE_ENTRY, ListEntry);
            WkdNpmFreeEntry(pipeEntry);
        }
        g_NpmHashTable[i].Count = 0;
    }
    InterlockedExchange(&g_NpmTotalEntries, 0);
}

#pragma warning(pop)
