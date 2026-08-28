/**************************************************/
/*  WkDefender IOC 引擎 — LOLBin 检测数据库         */
/**************************************************/

#pragma once

#include <windows.h>

typedef struct _LOLBIN_ENTRY {
    PCWSTR  FileName;
    ULONG   RiskScore;
    ULONG   Category;
} LOLBIN_ENTRY, *PLOLBIN_ENTRY;

#define LOLBIN_CAT_EXECUTION    0x0001
#define LOLBIN_CAT_DOWNLOAD     0x0002
#define LOLBIN_CAT_COPY         0x0004
#define LOLBIN_CAT_SCRIPTING    0x0008
#define LOLBIN_CAT_COMPILE      0x0010
#define LOLBIN_CAT_UAC_BYPASS   0x0020
#define LOLBIN_CAT_DLL_LOAD     0x0040
#define LOLBIN_CAT_CREDENTIAL   0x0080
#define LOLBIN_CAT_DISCOVERY    0x0100

static const LOLBIN_ENTRY g_IocLolbinDb[] = {
    { L"powershell.exe",        60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"pwsh.exe",              60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"cmd.exe",               40, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"wscript.exe",           70, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"cscript.exe",           70, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"mshta.exe",             80, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"wmic.exe",              70, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DISCOVERY },
    { L"rundll32.exe",          75, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DLL_LOAD },
    { L"regsvr32.exe",          80, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DLL_LOAD },
    { L"msbuild.exe",           80, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_COMPILE },
    { L"csc.exe",               70, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_COMPILE },
    { L"installutil.exe",       50, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_COMPILE },
    { L"regasm.exe",            60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_COMPILE },
    { L"regsvcs.exe",           60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_COMPILE },
    { L"msxsl.exe",             65, LOLBIN_CAT_EXECUTION },
    { L"certutil.exe",          85, LOLBIN_CAT_DOWNLOAD | LOLBIN_CAT_EXECUTION },
    { L"bitsadmin.exe",         75, LOLBIN_CAT_DOWNLOAD },
    { L"cmstp.exe",             75, LOLBIN_CAT_UAC_BYPASS | LOLBIN_CAT_EXECUTION },
    { L"fodhelper.exe",         70, LOLBIN_CAT_UAC_BYPASS | LOLBIN_CAT_EXECUTION },
    { L"msiexec.exe",           70, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DLL_LOAD },
    { L"msdt.exe",              75, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"pcalua.exe",            65, LOLBIN_CAT_EXECUTION },
    { L"forfiles.exe",          50, LOLBIN_CAT_EXECUTION },
    { L"odbcconf.exe",          60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DLL_LOAD },
    { L"control.exe",           50, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DLL_LOAD },
    { L"diskshadow.exe",        60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"hh.exe",                65, LOLBIN_CAT_EXECUTION },
    { L"xwizard.exe",           50, LOLBIN_CAT_EXECUTION },
    { L"sqldumper.exe",         60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_CREDENTIAL },
    { L"schtasks.exe",          55, LOLBIN_CAT_EXECUTION },
    { L"net.exe",               30, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DISCOVERY },
    { L"net1.exe",              30, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DISCOVERY },
    { L"nltest.exe",            35, LOLBIN_CAT_DISCOVERY },
    { L"dsquery.exe",           35, LOLBIN_CAT_DISCOVERY },
    { L"takeown.exe",           25, LOLBIN_CAT_EXECUTION },
    { L"icacls.exe",            25, LOLBIN_CAT_EXECUTION },

    /* ── 补充 CmdLineAnalyzer 库独有条目（统一后覆盖并集）── */
    { L"msconfig.exe",          60, LOLBIN_CAT_UAC_BYPASS | LOLBIN_CAT_EXECUTION },
    { L"mmc.exe",               50, LOLBIN_CAT_EXECUTION },
    { L"infdefaultinstall.exe", 50, LOLBIN_CAT_EXECUTION },
    { L"syncappvpublishingserver.exe", 50, LOLBIN_CAT_EXECUTION },
    { L"ieexec.exe",            60, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_DOWNLOAD },
    { L"dnscmd.exe",            50, LOLBIN_CAT_EXECUTION },
    { L"ftp.exe",               50, LOLBIN_CAT_DOWNLOAD },
    { L"replace.exe",           50, LOLBIN_CAT_COPY },
    { L"eudcedit.exe",          55, LOLBIN_CAT_UAC_BYPASS },
    { L"eventvwr.exe",          55, LOLBIN_CAT_UAC_BYPASS },
    { L"computerdefaults.exe",  55, LOLBIN_CAT_UAC_BYPASS },
    { L"slui.exe",              55, LOLBIN_CAT_UAC_BYPASS },
    { L"sdclt.exe",             55, LOLBIN_CAT_UAC_BYPASS },
    { L"at.exe",                40, LOLBIN_CAT_EXECUTION },
    { L"sc.exe",                40, LOLBIN_CAT_EXECUTION },
    { L"reg.exe",               40, LOLBIN_CAT_EXECUTION },
    { L"netsh.exe",             40, LOLBIN_CAT_EXECUTION },
    { L"curl.exe",              40, LOLBIN_CAT_DOWNLOAD },
    { L"wget.exe",              40, LOLBIN_CAT_DOWNLOAD },
    { L"expand.exe",            40, LOLBIN_CAT_COPY },
    { L"extrac32.exe",          40, LOLBIN_CAT_COPY },
    { L"makecab.exe",           40, LOLBIN_CAT_COPY },
    { L"esentutl.exe",          40, LOLBIN_CAT_COPY },
    { L"findstr.exe",           40, LOLBIN_CAT_COPY },
    { L"print.exe",             40, LOLBIN_CAT_COPY },
    { L"presentationhost.exe",  40, LOLBIN_CAT_EXECUTION },
    { L"bash.exe",              45, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { L"wsl.exe",               45, LOLBIN_CAT_EXECUTION | LOLBIN_CAT_SCRIPTING },
    { NULL, 0, 0 }
};

static inline const LOLBIN_ENTRY*
IocLolbinLookup(PCWSTR FileName)
{
    if (!FileName || !FileName[0]) return NULL;
    for (ULONG i = 0; g_IocLolbinDb[i].FileName; i++) {
        if (_wcsicmp(FileName, g_IocLolbinDb[i].FileName) == 0)
            return &g_IocLolbinDb[i];
    }
    return NULL;
}
