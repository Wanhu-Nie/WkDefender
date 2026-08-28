/**************************************************/
/*  WkDefender IOA — MITRE ATT&CK 行为→技术映射    */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               MITRE 映射条目                     */
/**************************************************/

typedef struct _IOA_MITRE_ENTRY {
    ULONG           BehaviorFlag;
    const WCHAR*    TechniqueId;
    const WCHAR*    TacticId;
    const WCHAR*    Description;
} IOA_MITRE_ENTRY, *PIOA_MITRE_ENTRY;

static const IOA_MITRE_ENTRY g_IoaMitreMap[] = {
    { DEF_BEHAVIOR_FLAG_INJECTION,          L"T1055.001", L"TA0005", L"Process Injection: DLL Injection" },
    { DEF_BEHAVIOR_FLAG_HOLLOWING,          L"T1055.012", L"TA0005", L"Process Injection: Process Hollowing" },
    { DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD,    L"T1620",     L"TA0005", L"Reflective Code Loading" },
    { DEF_BEHAVIOR_FLAG_REMOTE_THREAD,      L"T1055.001", L"TA0005", L"Process Injection: Remote Thread" },
    { DEF_BEHAVIOR_FLAG_APC_INJECTION,      L"T1055.004", L"TA0005", L"Process Injection: APC Injection" },
    { DEF_BEHAVIOR_FLAG_SET_CONTEXT,        L"T1055.012", L"TA0005", L"Process Injection: Thread Context" },
    { DEF_BEHAVIOR_FLAG_SECTION_MAP_REMOTE, L"T1055.002", L"TA0005", L"Process Injection: Section Mapping" },
    { DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE,   L"T1134.001", L"TA0004", L"Access Token Manipulation" },
    { DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE,    L"T1134",     L"TA0004", L"Access Token Manipulation" },
    { DEF_BEHAVIOR_FLAG_ELEVATED,           L"T1548.002", L"TA0004", L"Abuse Elevation Control: Bypass UAC" },
    { DEF_BEHAVIOR_FLAG_PPID_SPOOF,         L"T1055.012", L"TA0005", L"PPID Spoofing" },
    { DEF_BEHAVIOR_FLAG_CROSS_SESSION,      L"T1564.004", L"TA0003", L"Hide Artifacts: Cross-Session" },
    { DEF_BEHAVIOR_FLAG_DLL_SIDE_LOAD,      L"T1574.002", L"TA0003", L"Hijack Execution Flow: DLL Side-Loading" },
    { DEF_BEHAVIOR_FLAG_PATH_HIJACK,        L"T1574.001", L"TA0003", L"Hijack Execution Flow: DLL Search Order" },
    { DEF_BEHAVIOR_FLAG_LOLBIN,             L"T1218",     L"TA0005", L"System Binary Proxy Execution" },
    { DEF_BEHAVIOR_FLAG_POWERSHELL_ENCODED, L"T1059.001", L"TA0002", L"PowerShell with Encoded Command" },
    { DEF_BEHAVIOR_FLAG_DOWNLOADER,         L"T1105",     L"TA0011", L"Ingress Tool Transfer" },
    { DEF_BEHAVIOR_FLAG_MEMORY_READ_REMOTE, L"T1003.001", L"TA0006", L"OS Credential Dumping: LSASS Memory" },
    { DEF_BEHAVIOR_FLAG_PROCESS_OPEN,       L"T1057",     L"TA0007", L"Process Discovery" },
    { DEF_BEHAVIOR_FLAG_SUSPICIOUS_CHAIN,   L"T1070",     L"TA0005", L"Indicator Removal on Host" },
    { DEF_BEHAVIOR_FLAG_AMSI_BYPASS,         L"T1562.001", L"TA0005", L"Disable or Modify Tools: AMSI Bypass" },

    /* ── 新检测类别 (死代码预留, 迁移自 SS BehaviorAnalyzer) ── */
    { DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC,       L"T1486",     L"TA0040", L"Data Encrypted for Impact" },
    { DEF_BEHAVIOR_FLAG_RANSOMWARE_DELETE,    L"T1485",     L"TA0040", L"Data Destruction" },
    { DEF_BEHAVIOR_FLAG_RANSOMWARE_SHADOW,    L"T1490",     L"TA0040", L"Inhibit System Recovery" },
    { DEF_BEHAVIOR_FLAG_PERSISTENCE,          L"T1547.001", L"TA0003", L"Boot or Logon Autostart Execution" },
    { DEF_BEHAVIOR_FLAG_C2_COMMUNICATION,     L"T1071.001", L"TA0011", L"Application Layer Protocol: Web Protocols" },
    { DEF_BEHAVIOR_FLAG_EXFILTRATION,         L"T1048.003", L"TA0010", L"Exfiltration Over Alternative Protocol" },
    { DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT,     L"T1021.002", L"TA0008", L"Remote Services: SMB/Windows Admin Shares" },
    { DEF_BEHAVIOR_FLAG_EVASION,              L"T1070.001", L"TA0005", L"Indicator Removal: Clear Windows Event Logs" },
    { DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET,    L"T1003.001", L"TA0006", L"OS Credential Dumping: LSASS Memory" },
    { DEF_BEHAVIOR_FLAG_MASQUERADE,           L"T1036",     L"TA0005", L"Masquerading" },
    { 0, NULL, NULL, NULL }
};

/**************************************************/
/*               查找函数                           */
/**************************************************/

static
inline
PCWSTR
IoaMitreLookupTechnique(
    _In_ ULONG Flag
    )
{
    for (ULONG i = 0; g_IoaMitreMap[i].TechniqueId; i++) {
        if (g_IoaMitreMap[i].BehaviorFlag == Flag) {
            return g_IoaMitreMap[i].TechniqueId;
        }
    }
    return L"T0000";
}

static
inline
VOID
IoaMitreLookupBest(
    _In_ ULONG      Flags,
    _Out_ PCWSTR*   TechId,
    _Out_ PCWSTR*   TacticId
    )
{
    *TechId   = L"T0000";
    *TacticId = L"TA0000";

    for (ULONG i = 0; g_IoaMitreMap[i].TechniqueId; i++) {
        if (Flags & g_IoaMitreMap[i].BehaviorFlag) {
            *TechId   = g_IoaMitreMap[i].TechniqueId;
            *TacticId = g_IoaMitreMap[i].TacticId;
            return;
        }
    }
}

/**************************************************/
/*           战术位索引枚举 (TA000X → bit)           */
/*                                                   */
/*  对齐 MITRE ATT&CK 战术标准顺序 (Enterprise v13+).*/
/*  TacticMask = 1 << IoATactic_xxx, 全部 14 战术    */
/*  覆盖 0x0000~0x3FFF。                             */
/**************************************************/

typedef enum _IOA_TACTIC_ID {
    IoATactic_Reconnaissance = 0,        /* TA0043 */
    IoATactic_ResourceDevelopment = 1,   /* TA0042 */
    IoATactic_InitialAccess = 2,         /* TA0001 */
    IoATactic_Execution = 3,             /* TA0002 */
    IoATactic_Persistence = 4,           /* TA0003 */
    IoATactic_PrivilegeEscalation = 5,   /* TA0004 */
    IoATactic_DefenseEvasion = 6,        /* TA0005 */
    IoATactic_CredentialAccess = 7,      /* TA0006 */
    IoATactic_Discovery = 8,             /* TA0007 */
    IoATactic_LateralMovement = 9,       /* TA0008 */
    IoATactic_Collection = 10,           /* TA0009 */
    IoATactic_CommandAndControl = 11,    /* TA0011 */
    IoATactic_Exfiltration = 12,         /* TA0010 */
    IoATactic_Impact = 13,               /* TA0040 */
    IoATactic_Max
} IOA_TACTIC_ID;

static const PCWSTR g_IoaTacticIdList[IoATactic_Max] = {
    L"TA0043", L"TA0042", L"TA0001", L"TA0002", L"TA0003", L"TA0004",
    L"TA0005", L"TA0006", L"TA0007", L"TA0008", L"TA0009", L"TA0011",
    L"TA0010", L"TA0040"
};

/**************************************************/
/*           战术定义库 (14 战术)                    */
/*                                                   */
/*  ShadowStrike MITREMapper.c g_TacticDefinitions  */
/*  (L79-95) 迁移。TacticBit 对齐 IOA_TACTIC_ID.     */
/**************************************************/

typedef struct _IOA_TACTIC_DEF {
    PCWSTR TacticId;
    PCWSTR Name;
    ULONG  TacticBit;
} IOA_TACTIC_DEF, *PIOA_TACTIC_DEF;

/**************************************************/
/*           技术定义条目                           */
/*                                                   */
/*  ShadowStrike MITREMapper.c g_TechniqueDefinitions */
/*  (L115-689) 全量 513 条迁移:                      */
/*    - StringId 主键 ("T1055.001", 基技术无点号)     */
/*    - TacticId/TacticBit 战术归属                  */
/*    - BaseScore 攻击链权重 (/5 换算, 以 wkd          */
/*      g_IoaTacticTable 34 条基技术为权威, 子技术     */
/*      继承父值, 其余默认 10)                        */
/*    - DetectionScore SS 原生 0-100 (无 wkd 消费者)   */
/*    - CanBeDetected 原值                            */
/*    - ParentId 父技术串 (无父 = NULL)               */
/*  T1055 系列按 wkd 现有映射归 TA0005 (SS 原 TA0004, */
/*  MITRE 官方双战术, 迁移不改 wkd 已定行为).         */
/*  Description 裁剪, 仅保留 Name.                    */
/**************************************************/

typedef struct _IOA_TECHNIQUE_ENTRY {
    PCWSTR   StringId;
    PCWSTR   Name;
    PCWSTR   TacticId;
    ULONG    TacticBit;
    ULONG    BaseScore;
    ULONG    DetectionScore;
    BOOLEAN  CanBeDetected;
    PCWSTR   ParentId;
} IOA_TECHNIQUE_ENTRY, *PIOA_TECHNIQUE_ENTRY;

/* 战术定义 (SS MITREMapper.c g_TacticDefinitions L79-95 迁移) */
static const IOA_TACTIC_DEF g_IoaTacticDefinitions[] = {
    { L"TA0043", L"Reconnaissance", IoATactic_Reconnaissance },
    { L"TA0042", L"Resource Development", IoATactic_ResourceDevelopment },
    { L"TA0001", L"Initial Access", IoATactic_InitialAccess },
    { L"TA0002", L"Execution", IoATactic_Execution },
    { L"TA0003", L"Persistence", IoATactic_Persistence },
    { L"TA0004", L"Privilege Escalation", IoATactic_PrivilegeEscalation },
    { L"TA0005", L"Defense Evasion", IoATactic_DefenseEvasion },
    { L"TA0006", L"Credential Access", IoATactic_CredentialAccess },
    { L"TA0007", L"Discovery", IoATactic_Discovery },
    { L"TA0008", L"Lateral Movement", IoATactic_LateralMovement },
    { L"TA0009", L"Collection", IoATactic_Collection },
    { L"TA0011", L"Command and Control", IoATactic_CommandAndControl },
    { L"TA0010", L"Exfiltration", IoATactic_Exfiltration },
    { L"TA0040", L"Impact", IoATactic_Impact },
    { NULL, NULL, 0 }
};

/* 技术数据库 (SS MITREMapper.c g_TechniqueDefinitions L115-689 迁移, 全量 513 条) */
/* TacticBit/BaseScore 以 wkd g_IoaTacticTable 34 条基技术为权威; T1055 系列按 wkd 归 TA0005 (SS 原 TA0004); */
/* DetectionScore/CanBeDetected 原值; ParentId 由 ParentTechnique 宏反查; Description 裁剪仅留 Name. */
static const IOA_TECHNIQUE_ENTRY g_IoaTechniqueTable[] = {

    /* TA0043 */
    { L"T1595", L"Active Scanning", L"TA0043", 0, 5, 30, TRUE, NULL },
    { L"T1595.001", L"Scanning IP Blocks", L"TA0043", 0, 5, 25, TRUE, L"T1595" },
    { L"T1595.002", L"Vulnerability Scanning", L"TA0043", 0, 5, 35, TRUE, L"T1595" },
    { L"T1595.003", L"Wordlist Scanning", L"TA0043", 0, 5, 30, TRUE, L"T1595" },
    { L"T1592", L"Gather Victim Host Information", L"TA0043", 0, 5, 25, FALSE, NULL },
    { L"T1592.001", L"Hardware", L"TA0043", 0, 5, 20, FALSE, L"T1592" },
    { L"T1592.002", L"Software", L"TA0043", 0, 5, 25, FALSE, L"T1592" },
    { L"T1592.003", L"Firmware", L"TA0043", 0, 5, 20, FALSE, L"T1592" },
    { L"T1592.004", L"Client Configurations", L"TA0043", 0, 5, 25, FALSE, L"T1592" },
    { L"T1589", L"Gather Victim Identity Information", L"TA0043", 0, 10, 20, FALSE, NULL },
    { L"T1589.001", L"Credentials", L"TA0043", 0, 10, 30, FALSE, L"T1589" },
    { L"T1589.002", L"Email Addresses", L"TA0043", 0, 10, 20, FALSE, L"T1589" },
    { L"T1589.003", L"Employee Names", L"TA0043", 0, 10, 15, FALSE, L"T1589" },
    { L"T1590", L"Gather Victim Network Information", L"TA0043", 0, 5, 25, FALSE, NULL },
    { L"T1590.001", L"Domain Properties", L"TA0043", 0, 5, 20, FALSE, L"T1590" },
    { L"T1590.002", L"DNS", L"TA0043", 0, 5, 30, TRUE, L"T1590" },
    { L"T1590.003", L"Network Trust Dependencies", L"TA0043", 0, 5, 25, FALSE, L"T1590" },
    { L"T1590.004", L"Network Topology", L"TA0043", 0, 5, 20, FALSE, L"T1590" },
    { L"T1590.005", L"IP Addresses", L"TA0043", 0, 5, 25, TRUE, L"T1590" },
    { L"T1590.006", L"Network Security Appliances", L"TA0043", 0, 5, 30, FALSE, L"T1590" },
    { L"T1591", L"Gather Victim Org Information", L"TA0043", 0, 10, 15, FALSE, NULL },
    { L"T1591.001", L"Determine Physical Locations", L"TA0043", 0, 10, 10, FALSE, L"T1591" },
    { L"T1591.002", L"Business Relationships", L"TA0043", 0, 10, 15, FALSE, L"T1591" },
    { L"T1591.003", L"Identify Business Tempo", L"TA0043", 0, 10, 10, FALSE, L"T1591" },
    { L"T1591.004", L"Identify Roles", L"TA0043", 0, 10, 15, FALSE, L"T1591" },
    { L"T1593", L"Search Open Websites/Domains", L"TA0043", 0, 10, 20, FALSE, NULL },
    { L"T1593.001", L"Social Media", L"TA0043", 0, 10, 15, FALSE, L"T1593" },
    { L"T1593.002", L"Search Engines", L"TA0043", 0, 10, 15, FALSE, L"T1593" },
    { L"T1593.003", L"Code Repositories", L"TA0043", 0, 10, 25, FALSE, L"T1593" },
    { L"T1594", L"Search Victim-Owned Websites", L"TA0043", 0, 10, 20, FALSE, NULL },
    { L"T1596", L"Search Open Technical Databases", L"TA0043", 0, 10, 25, FALSE, NULL },
    { L"T1596.001", L"DNS/Passive DNS", L"TA0043", 0, 10, 30, TRUE, L"T1596" },
    { L"T1596.002", L"WHOIS", L"TA0043", 0, 10, 20, FALSE, L"T1596" },
    { L"T1596.003", L"Digital Certificates", L"TA0043", 0, 10, 25, FALSE, L"T1596" },
    { L"T1596.004", L"CDNs", L"TA0043", 0, 10, 20, FALSE, L"T1596" },
    { L"T1596.005", L"Scan Databases", L"TA0043", 0, 10, 25, FALSE, L"T1596" },
    { L"T1597", L"Search Closed Sources", L"TA0043", 0, 10, 20, FALSE, NULL },
    { L"T1597.001", L"Threat Intel Vendors", L"TA0043", 0, 10, 25, FALSE, L"T1597" },
    { L"T1597.002", L"Purchase Technical Data", L"TA0043", 0, 10, 20, FALSE, L"T1597" },
    { L"T1598", L"Phishing for Information", L"TA0043", 0, 10, 50, TRUE, NULL },
    { L"T1598.001", L"Spearphishing Service", L"TA0043", 0, 10, 45, TRUE, L"T1598" },
    { L"T1598.002", L"Spearphishing Attachment", L"TA0043", 0, 10, 55, TRUE, L"T1598" },
    { L"T1598.003", L"Spearphishing Link", L"TA0043", 0, 10, 50, TRUE, L"T1598" },
    { L"T1681", L"Search Threat Vendor Data", L"TA0043", 0, 10, 20, FALSE, NULL },

    /* TA0042 */
    { L"T1583", L"Acquire Infrastructure", L"TA0042", 1, 10, 30, FALSE, NULL },
    { L"T1583.001", L"Domains", L"TA0042", 1, 10, 35, TRUE, L"T1583" },
    { L"T1583.002", L"DNS Server", L"TA0042", 1, 10, 30, TRUE, L"T1583" },
    { L"T1583.003", L"Virtual Private Server", L"TA0042", 1, 10, 25, FALSE, L"T1583" },
    { L"T1583.004", L"Server", L"TA0042", 1, 10, 20, FALSE, L"T1583" },
    { L"T1583.005", L"Botnet", L"TA0042", 1, 10, 40, TRUE, L"T1583" },
    { L"T1583.006", L"Web Services", L"TA0042", 1, 10, 30, TRUE, L"T1583" },
    { L"T1584", L"Compromise Infrastructure", L"TA0042", 1, 10, 35, FALSE, NULL },
    { L"T1584.001", L"Domains", L"TA0042", 1, 10, 35, TRUE, L"T1584" },
    { L"T1584.002", L"DNS Server", L"TA0042", 1, 10, 30, TRUE, L"T1584" },
    { L"T1584.003", L"Virtual Private Server", L"TA0042", 1, 10, 25, FALSE, L"T1584" },
    { L"T1584.004", L"Server", L"TA0042", 1, 10, 30, FALSE, L"T1584" },
    { L"T1584.005", L"Botnet", L"TA0042", 1, 10, 35, TRUE, L"T1584" },
    { L"T1584.006", L"Web Services", L"TA0042", 1, 10, 30, TRUE, L"T1584" },
    { L"T1584.008", L"Network Devices", L"TA0042", 1, 10, 40, TRUE, L"T1584" },
    { L"T1585", L"Establish Accounts", L"TA0042", 1, 10, 25, FALSE, NULL },
    { L"T1585.001", L"Social Media Accounts", L"TA0042", 1, 10, 20, FALSE, L"T1585" },
    { L"T1585.002", L"Email Accounts", L"TA0042", 1, 10, 25, FALSE, L"T1585" },
    { L"T1585.003", L"Cloud Accounts", L"TA0042", 1, 10, 30, FALSE, L"T1585" },
    { L"T1586", L"Compromise Accounts", L"TA0042", 1, 10, 35, FALSE, NULL },
    { L"T1586.001", L"Social Media Accounts", L"TA0042", 1, 10, 25, FALSE, L"T1586" },
    { L"T1586.002", L"Email Accounts", L"TA0042", 1, 10, 35, TRUE, L"T1586" },
    { L"T1586.003", L"Cloud Accounts", L"TA0042", 1, 10, 40, TRUE, L"T1586" },
    { L"T1587", L"Develop Capabilities", L"TA0042", 1, 10, 30, FALSE, NULL },
    { L"T1587.001", L"Malware", L"TA0042", 1, 10, 40, TRUE, L"T1587" },
    { L"T1587.002", L"Code Signing Certificates", L"TA0042", 1, 10, 45, TRUE, L"T1587" },
    { L"T1587.003", L"Digital Certificates", L"TA0042", 1, 10, 35, TRUE, L"T1587" },
    { L"T1587.004", L"Exploits", L"TA0042", 1, 10, 50, TRUE, L"T1587" },
    { L"T1588", L"Obtain Capabilities", L"TA0042", 1, 10, 35, FALSE, NULL },
    { L"T1588.001", L"Malware", L"TA0042", 1, 10, 40, TRUE, L"T1588" },
    { L"T1588.002", L"Tool", L"TA0042", 1, 10, 45, TRUE, L"T1588" },
    { L"T1588.003", L"Code Signing Certificates", L"TA0042", 1, 10, 50, TRUE, L"T1588" },
    { L"T1588.004", L"Digital Certificates", L"TA0042", 1, 10, 35, TRUE, L"T1588" },
    { L"T1588.005", L"Exploits", L"TA0042", 1, 10, 50, TRUE, L"T1588" },
    { L"T1588.006", L"Vulnerabilities", L"TA0042", 1, 10, 40, TRUE, L"T1588" },
    { L"T1608", L"Stage Capabilities", L"TA0042", 1, 10, 35, FALSE, NULL },
    { L"T1608.001", L"Upload Malware", L"TA0042", 1, 10, 40, TRUE, L"T1608" },
    { L"T1608.002", L"Upload Tool", L"TA0042", 1, 10, 35, TRUE, L"T1608" },
    { L"T1608.003", L"Install Digital Certificate", L"TA0042", 1, 10, 30, FALSE, L"T1608" },
    { L"T1608.004", L"Drive-by Target", L"TA0042", 1, 10, 45, TRUE, L"T1608" },
    { L"T1608.005", L"Link Target", L"TA0042", 1, 10, 40, TRUE, L"T1608" },
    { L"T1608.006", L"SEO Poisoning", L"TA0042", 1, 10, 45, TRUE, L"T1608" },
    { L"T1650", L"Acquire Access", L"TA0042", 1, 10, 40, FALSE, NULL },
    { L"T1672", L"Email Spoofing", L"TA0042", 1, 10, 50, TRUE, NULL },

    /* TA0001 */
    { L"T1566", L"Phishing", L"TA0001", 2, 8, 70, TRUE, NULL },
    { L"T1566.001", L"Spearphishing Attachment", L"TA0001", 2, 8, 80, TRUE, L"T1566" },
    { L"T1566.002", L"Spearphishing Link", L"TA0001", 2, 8, 75, TRUE, L"T1566" },
    { L"T1189", L"Drive-by Compromise", L"TA0001", 2, 10, 65, TRUE, NULL },
    { L"T1190", L"Exploit Public-Facing Application", L"TA0001", 2, 12, 70, TRUE, NULL },
    { L"T1133", L"External Remote Services", L"TA0001", 2, 10, 50, TRUE, NULL },
    { L"T1091", L"Replication Through Removable Media", L"TA0001", 2, 7, 60, TRUE, NULL },
    { L"T1078", L"Valid Accounts", L"TA0001", 2, 10, 40, TRUE, NULL },
    { L"T1078.001", L"Default Accounts", L"TA0001", 2, 10, 55, TRUE, L"T1078" },
    { L"T1078.002", L"Domain Accounts", L"TA0001", 2, 10, 45, TRUE, L"T1078" },
    { L"T1078.003", L"Local Accounts", L"TA0001", 2, 10, 45, TRUE, L"T1078" },
    { L"T1566.003", L"Spearphishing via Service", L"TA0001", 2, 8, 70, TRUE, L"T1566" },
    { L"T1195", L"Supply Chain Compromise", L"TA0001", 2, 10, 80, TRUE, NULL },
    { L"T1195.001", L"Compromise Software Dependencies", L"TA0001", 2, 10, 85, TRUE, L"T1195" },
    { L"T1195.002", L"Compromise Software Supply Chain", L"TA0001", 2, 10, 90, TRUE, L"T1195" },
    { L"T1199", L"Trusted Relationship", L"TA0001", 2, 10, 60, TRUE, NULL },
    { L"T1200", L"Hardware Additions", L"TA0001", 2, 10, 55, TRUE, NULL },

    /* TA0002 */
    { L"T1059", L"Command and Scripting Interpreter", L"TA0002", 3, 6, 75, TRUE, NULL },
    { L"T1059.001", L"PowerShell", L"TA0002", 3, 6, 85, TRUE, L"T1059" },
    { L"T1059.003", L"Windows Command Shell", L"TA0002", 3, 6, 80, TRUE, L"T1059" },
    { L"T1059.005", L"Visual Basic", L"TA0002", 3, 6, 75, TRUE, L"T1059" },
    { L"T1059.007", L"JavaScript", L"TA0002", 3, 6, 70, TRUE, L"T1059" },
    { L"T1106", L"Native API", L"TA0002", 3, 10, 60, TRUE, NULL },
    { L"T1053", L"Scheduled Task/Job", L"TA0002", 3, 10, 70, TRUE, NULL },
    { L"T1053.005", L"Scheduled Task", L"TA0002", 3, 10, 75, TRUE, L"T1053" },
    { L"T1047", L"Windows Management Instrumentation", L"TA0002", 3, 10, 80, TRUE, NULL },
    { L"T1204", L"User Execution", L"TA0002", 3, 10, 55, TRUE, NULL },
    { L"T1204.002", L"Malicious File", L"TA0002", 3, 10, 65, TRUE, L"T1204" },
    { L"T1569", L"System Services", L"TA0002", 3, 10, 70, TRUE, NULL },
    { L"T1569.002", L"Service Execution", L"TA0002", 3, 10, 75, TRUE, L"T1569" },
    { L"T1204.001", L"Malicious Link", L"TA0002", 3, 10, 60, TRUE, L"T1204" },
    { L"T1059.006", L"Python", L"TA0002", 3, 6, 70, TRUE, L"T1059" },
    { L"T1059.008", L"Network Device CLI", L"TA0002", 3, 6, 65, TRUE, L"T1059" },
    { L"T1059.013", L"Container CLI/API", L"TA0002", 3, 6, 60, TRUE, L"T1059" },
    { L"T1203", L"Exploitation for Client Execution", L"TA0002", 3, 10, 80, TRUE, NULL },
    { L"T1559", L"Inter-Process Communication", L"TA0002", 3, 10, 70, TRUE, NULL },
    { L"T1559.001", L"Component Object Model", L"TA0002", 3, 10, 75, TRUE, L"T1559" },
    { L"T1559.002", L"Dynamic Data Exchange", L"TA0002", 3, 10, 80, TRUE, L"T1559" },
    { L"T1129", L"Shared Modules", L"TA0002", 3, 10, 55, TRUE, NULL },
    { L"T1072", L"Software Deployment Tools", L"TA0002", 3, 10, 65, TRUE, NULL },
    { L"T1053.002", L"At", L"TA0002", 3, 10, 70, TRUE, L"T1053" },
    { L"T1204.005", L"Malicious Library", L"TA0002", 3, 10, 75, TRUE, L"T1204" },
    { L"T1204.004", L"Malicious Copy and Paste", L"TA0002", 3, 10, 60, TRUE, L"T1204" },

    /* TA0003 */
    { L"T1547", L"Boot or Logon Autostart Execution", L"TA0003", 4, 10, 85, TRUE, NULL },
    { L"T1547.001", L"Registry Run Keys / Startup Folder", L"TA0003", 4, 10, 90, TRUE, L"T1547" },
    { L"T1547.004", L"Winlogon Helper DLL", L"TA0003", 4, 10, 85, TRUE, L"T1547" },
    { L"T1547.005", L"Security Support Provider", L"TA0003", 4, 10, 80, TRUE, L"T1547" },
    { L"T1547.009", L"Shortcut Modification", L"TA0003", 4, 10, 70, TRUE, L"T1547" },
    { L"T1543", L"Create or Modify System Process", L"TA0003", 4, 10, 80, TRUE, NULL },
    { L"T1543.003", L"Windows Service", L"TA0003", 4, 10, 85, TRUE, L"T1543" },
    { L"T1546", L"Event Triggered Execution", L"TA0003", 4, 10, 75, TRUE, NULL },
    { L"T1546.001", L"Change Default File Association", L"TA0003", 4, 10, 70, TRUE, L"T1546" },
    { L"T1546.008", L"Accessibility Features", L"TA0003", 4, 10, 80, TRUE, L"T1546" },
    { L"T1546.010", L"AppInit DLLs", L"TA0003", 4, 10, 85, TRUE, L"T1546" },
    { L"T1546.011", L"Application Shimming", L"TA0003", 4, 10, 75, TRUE, L"T1546" },
    { L"T1546.012", L"Image File Execution Options Injection", L"TA0003", 4, 10, 85, TRUE, L"T1546" },
    { L"T1546.015", L"Component Object Model Hijacking", L"TA0003", 4, 10, 80, TRUE, L"T1546" },
    { L"T1574", L"Hijack Execution Flow", L"TA0003", 4, 10, 80, TRUE, NULL },
    { L"T1574.001", L"DLL Search Order Hijacking", L"TA0003", 4, 10, 85, TRUE, L"T1574" },
    { L"T1574.002", L"DLL Side-Loading", L"TA0003", 4, 10, 80, TRUE, L"T1574" },
    { L"T1197", L"BITS Jobs", L"TA0003", 4, 10, 70, TRUE, NULL },
    { L"T1505", L"Server Software Component", L"TA0003", 4, 10, 85, TRUE, NULL },
    { L"T1505.003", L"Web Shell", L"TA0003", 4, 10, 90, TRUE, L"T1505" },
    { L"T1542", L"Pre-OS Boot", L"TA0003", 4, 10, 90, TRUE, NULL },
    { L"T1542.003", L"Bootkit", L"TA0003", 4, 10, 95, TRUE, L"T1542" },
    { L"T1098", L"Account Manipulation", L"TA0003", 4, 10, 75, TRUE, NULL },
    { L"T1037", L"Boot or Logon Initialization Scripts", L"TA0003", 4, 10, 75, TRUE, NULL },
    { L"T1037.001", L"Logon Script (Windows)", L"TA0003", 4, 10, 80, TRUE, L"T1037" },
    { L"T1547.002", L"Authentication Package", L"TA0003", 4, 10, 85, TRUE, L"T1547" },
    { L"T1547.003", L"Time Providers", L"TA0003", 4, 10, 80, TRUE, L"T1547" },
    { L"T1547.006", L"Kernel Modules and Extensions", L"TA0003", 4, 10, 95, TRUE, L"T1547" },
    { L"T1547.008", L"LSASS Driver", L"TA0003", 4, 10, 90, TRUE, L"T1547" },
    { L"T1547.010", L"Port Monitors", L"TA0003", 4, 10, 80, TRUE, L"T1547" },
    { L"T1547.012", L"Print Processors", L"TA0003", 4, 10, 80, TRUE, L"T1547" },
    { L"T1547.014", L"Active Setup", L"TA0003", 4, 10, 75, TRUE, L"T1547" },
    { L"T1543.002", L"Systemd Service", L"TA0003", 4, 10, 80, FALSE, L"T1543" },
    { L"T1546.002", L"Screensaver", L"TA0003", 4, 10, 70, TRUE, L"T1546" },
    { L"T1546.003", L"WMI Event Subscription", L"TA0003", 4, 10, 85, TRUE, L"T1546" },
    { L"T1546.007", L"Netsh Helper DLL", L"TA0003", 4, 10, 80, TRUE, L"T1546" },
    { L"T1546.009", L"AppCert DLLs", L"TA0003", 4, 10, 85, TRUE, L"T1546" },
    { L"T1546.013", L"PowerShell Profile", L"TA0003", 4, 10, 75, TRUE, L"T1546" },
    { L"T1546.018", L"Python Startup Hooks", L"TA0003", 4, 10, 70, TRUE, L"T1546" },
    { L"T1574.007", L"Path Interception by PATH Environment Variable", L"TA0003", 4, 10, 75, TRUE, L"T1574" },
    { L"T1574.008", L"Path Interception by Search Order Hijacking", L"TA0003", 4, 10, 80, TRUE, L"T1574" },
    { L"T1574.009", L"Path Interception by Unquoted Path", L"TA0003", 4, 10, 80, TRUE, L"T1574" },
    { L"T1574.010", L"Services File Permissions Weakness", L"TA0003", 4, 10, 85, TRUE, L"T1574" },
    { L"T1574.011", L"Services Registry Permissions Weakness", L"TA0003", 4, 10, 85, TRUE, L"T1574" },
    { L"T1574.012", L"COR_PROFILER", L"TA0003", 4, 10, 80, TRUE, L"T1574" },
    { L"T1556", L"Modify Authentication Process", L"TA0003", 4, 10, 90, TRUE, NULL },
    { L"T1556.001", L"Domain Controller Authentication", L"TA0003", 4, 10, 95, TRUE, L"T1556" },
    { L"T1556.002", L"Password Filter DLL", L"TA0003", 4, 10, 90, TRUE, L"T1556" },
    { L"T1556.003", L"Pluggable Authentication Modules", L"TA0003", 4, 10, 85, FALSE, L"T1556" },
    { L"T1556.004", L"Network Device Authentication", L"TA0003", 4, 10, 85, TRUE, L"T1556" },
    { L"T1137", L"Office Application Startup", L"TA0003", 4, 10, 75, TRUE, NULL },
    { L"T1505.001", L"SQL Stored Procedures", L"TA0003", 4, 10, 80, TRUE, L"T1505" },
    { L"T1542.001", L"System Firmware", L"TA0003", 4, 10, 95, TRUE, L"T1542" },
    { L"T1136", L"Create Account", L"TA0003", 4, 10, 70, TRUE, NULL },
    { L"T1136.001", L"Local Account", L"TA0003", 4, 10, 75, TRUE, L"T1136" },
    { L"T1136.002", L"Domain Account", L"TA0003", 4, 10, 80, TRUE, L"T1136" },
    { L"T1136.003", L"Cloud Account", L"TA0003", 4, 10, 75, TRUE, L"T1136" },
    { L"T1554", L"Compromise Host Software Binary", L"TA0003", 4, 10, 85, TRUE, NULL },
    { L"T1176", L"Software Extensions", L"TA0003", 4, 10, 70, TRUE, NULL },
    { L"T1176.001", L"Browser Extensions", L"TA0003", 4, 10, 75, TRUE, L"T1176" },

    /* TA0004 */
    { L"T1548", L"Abuse Elevation Control Mechanism", L"TA0004", 5, 12, 85, TRUE, NULL },
    { L"T1548.002", L"Bypass User Account Control", L"TA0004", 5, 12, 90, TRUE, L"T1548" },
    { L"T1134", L"Access Token Manipulation", L"TA0004", 5, 11, 85, TRUE, NULL },
    { L"T1134.001", L"Token Impersonation/Theft", L"TA0004", 5, 11, 90, TRUE, L"T1134" },
    { L"T1134.002", L"Create Process with Token", L"TA0004", 5, 11, 85, TRUE, L"T1134" },
    { L"T1134.004", L"Parent PID Spoofing", L"TA0004", 5, 11, 80, TRUE, L"T1134" },
    { L"T1068", L"Exploitation for Privilege Escalation", L"TA0004", 5, 10, 95, TRUE, NULL },
    { L"T1134.003", L"Make and Impersonate Token", L"TA0004", 5, 11, 85, TRUE, L"T1134" },
    { L"T1134.005", L"SID-History Injection", L"TA0004", 5, 11, 90, TRUE, L"T1134" },
    { L"T1548.003", L"Sudo", L"TA0004", 5, 12, 75, FALSE, L"T1548" },

    /* TA0005 */
    { L"T1055", L"Process Injection", L"TA0005", 6, 13, 90, TRUE, NULL },
    { L"T1055.001", L"Dynamic-link Library Injection", L"TA0005", 6, 13, 90, TRUE, L"T1055" },
    { L"T1055.002", L"Portable Executable Injection", L"TA0005", 6, 13, 90, TRUE, L"T1055" },
    { L"T1055.003", L"Thread Execution Hijacking", L"TA0005", 6, 13, 85, TRUE, L"T1055" },
    { L"T1055.004", L"Asynchronous Procedure Call", L"TA0005", 6, 13, 85, TRUE, L"T1055" },
    { L"T1055.012", L"Process Hollowing", L"TA0005", 6, 13, 95, TRUE, L"T1055" },
    { L"T1055.013", L"Process Doppelganging", L"TA0005", 6, 13, 95, TRUE, L"T1055" },
    { L"T1055.005", L"Thread Local Storage", L"TA0005", 6, 13, 85, TRUE, L"T1055" },
    { L"T1055.008", L"Ptrace", L"TA0005", 6, 13, 80, FALSE, L"T1055" },
    { L"T1055.009", L"Proc Memory", L"TA0005", 6, 13, 85, FALSE, L"T1055" },
    { L"T1055.011", L"EWM Injection", L"TA0005", 6, 13, 85, TRUE, L"T1055" },
    { L"T1055.014", L"VDSO Hijacking", L"TA0005", 6, 13, 80, FALSE, L"T1055" },
    { L"T1055.015", L"ListPlanting", L"TA0005", 6, 13, 80, TRUE, L"T1055" },
    { L"T1140", L"Deobfuscate/Decode Files or Information", L"TA0005", 6, 10, 60, TRUE, NULL },
    { L"T1562", L"Impair Defenses", L"TA0005", 6, 14, 95, TRUE, NULL },
    { L"T1562.001", L"Disable or Modify Tools", L"TA0005", 6, 14, 95, TRUE, L"T1562" },
    { L"T1562.002", L"Disable Windows Event Logging", L"TA0005", 6, 14, 90, TRUE, L"T1562" },
    { L"T1562.004", L"Disable or Modify System Firewall", L"TA0005", 6, 14, 85, TRUE, L"T1562" },
    { L"T1070", L"Indicator Removal", L"TA0005", 6, 11, 80, TRUE, NULL },
    { L"T1070.001", L"Clear Windows Event Logs", L"TA0005", 6, 11, 90, TRUE, L"T1070" },
    { L"T1070.004", L"File Deletion", L"TA0005", 6, 11, 70, TRUE, L"T1070" },
    { L"T1070.006", L"Timestomp", L"TA0005", 6, 11, 75, TRUE, L"T1070" },
    { L"T1036", L"Masquerading", L"TA0005", 6, 9, 80, TRUE, NULL },
    { L"T1036.003", L"Rename System Utilities", L"TA0005", 6, 9, 75, TRUE, L"T1036" },
    { L"T1036.005", L"Match Legitimate Name or Location", L"TA0005", 6, 9, 80, TRUE, L"T1036" },
    { L"T1036.007", L"Double File Extension", L"TA0005", 6, 9, 70, TRUE, L"T1036" },
    { L"T1027", L"Obfuscated Files or Information", L"TA0005", 6, 10, 75, TRUE, NULL },
    { L"T1027.002", L"Software Packing", L"TA0005", 6, 10, 80, TRUE, L"T1027" },
    { L"T1027.005", L"Indicator Removal from Tools", L"TA0005", 6, 10, 70, TRUE, L"T1027" },
    { L"T1112", L"Modify Registry", L"TA0005", 6, 10, 65, TRUE, NULL },
    { L"T1218", L"System Binary Proxy Execution", L"TA0005", 6, 10, 85, TRUE, NULL },
    { L"T1218.001", L"Compiled HTML File", L"TA0005", 6, 10, 80, TRUE, L"T1218" },
    { L"T1218.005", L"Mshta", L"TA0005", 6, 10, 90, TRUE, L"T1218" },
    { L"T1218.010", L"Regsvr32", L"TA0005", 6, 10, 90, TRUE, L"T1218" },
    { L"T1218.011", L"Rundll32", L"TA0005", 6, 10, 85, TRUE, L"T1218" },
    { L"T1497", L"Virtualization/Sandbox Evasion", L"TA0005", 6, 10, 70, TRUE, NULL },
    { L"T1497.001", L"System Checks", L"TA0005", 6, 10, 75, TRUE, L"T1497" },
    { L"T1497.003", L"Time Based Evasion", L"TA0005", 6, 10, 65, TRUE, L"T1497" },
    { L"T1014", L"Rootkit", L"TA0005", 6, 10, 95, TRUE, NULL },
    { L"T1620", L"Reflective Code Loading", L"TA0005", 6, 11, 90, TRUE, NULL },
    { L"T1006", L"Direct Volume Access", L"TA0005", 6, 10, 85, TRUE, NULL },
    { L"T1484", L"Domain Policy Modification", L"TA0005", 6, 10, 85, TRUE, NULL },
    { L"T1480", L"Execution Guardrails", L"TA0005", 6, 10, 65, TRUE, NULL },
    { L"T1211", L"Exploitation for Defense Evasion", L"TA0005", 6, 10, 85, TRUE, NULL },
    { L"T1222", L"File and Directory Permissions Modification", L"TA0005", 6, 10, 60, TRUE, NULL },
    { L"T1564", L"Hide Artifacts", L"TA0005", 6, 10, 75, TRUE, NULL },
    { L"T1564.001", L"Hidden Files and Directories", L"TA0005", 6, 10, 65, TRUE, L"T1564" },
    { L"T1564.002", L"Hidden Users", L"TA0005", 6, 10, 70, TRUE, L"T1564" },
    { L"T1564.003", L"Hidden Window", L"TA0005", 6, 10, 65, TRUE, L"T1564" },
    { L"T1564.004", L"NTFS File Attributes", L"TA0005", 6, 10, 80, TRUE, L"T1564" },
    { L"T1564.005", L"Hidden File System", L"TA0005", 6, 10, 85, TRUE, L"T1564" },
    { L"T1564.006", L"Run Virtual Instance", L"TA0005", 6, 10, 70, TRUE, L"T1564" },
    { L"T1564.007", L"VBA Stomping", L"TA0005", 6, 10, 75, TRUE, L"T1564" },
    { L"T1562.003", L"Impair Command History Logging", L"TA0005", 6, 14, 75, TRUE, L"T1562" },
    { L"T1562.006", L"Indicator Blocking", L"TA0005", 6, 14, 85, TRUE, L"T1562" },
    { L"T1562.009", L"Safe Mode Boot", L"TA0005", 6, 14, 80, TRUE, L"T1562" },
    { L"T1562.010", L"Downgrade Attack", L"TA0005", 6, 14, 80, TRUE, L"T1562" },
    { L"T1562.013", L"Disable or Modify Network Device Firewall", L"TA0005", 6, 14, 85, TRUE, L"T1562" },
    { L"T1070.003", L"Clear Command History", L"TA0005", 6, 11, 70, TRUE, L"T1070" },
    { L"T1070.005", L"Network Share Connection Removal", L"TA0005", 6, 11, 65, TRUE, L"T1070" },
    { L"T1070.010", L"Relocate Malware", L"TA0005", 6, 11, 70, TRUE, L"T1070" },
    { L"T1202", L"Indirect Command Execution", L"TA0005", 6, 10, 80, TRUE, NULL },
    { L"T1036.001", L"Invalid Code Signature", L"TA0005", 6, 9, 70, TRUE, L"T1036" },
    { L"T1036.004", L"Masquerade Task or Service", L"TA0005", 6, 9, 75, TRUE, L"T1036" },
    { L"T1036.006", L"Space after Filename", L"TA0005", 6, 9, 65, TRUE, L"T1036" },
    { L"T1036.008", L"Masquerade File Type", L"TA0005", 6, 9, 65, TRUE, L"T1036" },
    { L"T1036.012", L"Browser Fingerprint", L"TA0005", 6, 9, 60, TRUE, L"T1036" },
    { L"T1027.001", L"Binary Padding", L"TA0005", 6, 10, 60, TRUE, L"T1027" },
    { L"T1027.003", L"Steganography", L"TA0005", 6, 10, 70, TRUE, L"T1027" },
    { L"T1027.004", L"Compile After Delivery", L"TA0005", 6, 10, 75, TRUE, L"T1027" },
    { L"T1027.006", L"HTML Smuggling", L"TA0005", 6, 10, 80, TRUE, L"T1027" },
    { L"T1027.007", L"Dynamic API Resolution", L"TA0005", 6, 10, 75, TRUE, L"T1027" },
    { L"T1027.009", L"Embedded Payloads", L"TA0005", 6, 10, 70, TRUE, L"T1027" },
    { L"T1027.010", L"Command Obfuscation", L"TA0005", 6, 10, 75, TRUE, L"T1027" },
    { L"T1027.011", L"Fileless Storage", L"TA0005", 6, 10, 80, TRUE, L"T1027" },
    { L"T1497.002", L"User Activity Based Checks", L"TA0005", 6, 10, 70, TRUE, L"T1497" },
    { L"T1218.002", L"Control Panel", L"TA0005", 6, 10, 75, TRUE, L"T1218" },
    { L"T1218.003", L"CMSTP", L"TA0005", 6, 10, 80, TRUE, L"T1218" },
    { L"T1218.004", L"InstallUtil", L"TA0005", 6, 10, 80, TRUE, L"T1218" },
    { L"T1218.007", L"Msiexec", L"TA0005", 6, 10, 80, TRUE, L"T1218" },
    { L"T1218.008", L"Odbcconf", L"TA0005", 6, 10, 75, TRUE, L"T1218" },
    { L"T1218.009", L"Regsvcs/Regasm", L"TA0005", 6, 10, 80, TRUE, L"T1218" },
    { L"T1218.012", L"Verclsid", L"TA0005", 6, 10, 75, TRUE, L"T1218" },
    { L"T1218.013", L"Mavinject", L"TA0005", 6, 10, 85, TRUE, L"T1218" },
    { L"T1218.014", L"MMC", L"TA0005", 6, 10, 75, TRUE, L"T1218" },
    { L"T1216", L"System Script Proxy Execution", L"TA0005", 6, 10, 75, TRUE, NULL },
    { L"T1216.001", L"PubPrn", L"TA0005", 6, 10, 80, TRUE, L"T1216" },
    { L"T1221", L"Template Injection", L"TA0005", 6, 10, 80, TRUE, NULL },
    { L"T1205", L"Traffic Signaling", L"TA0005", 6, 10, 70, TRUE, NULL },
    { L"T1127", L"Trusted Developer Utilities Proxy Execution", L"TA0005", 6, 10, 80, TRUE, NULL },
    { L"T1127.001", L"MSBuild", L"TA0005", 6, 10, 85, TRUE, L"T1127" },
    { L"T1220", L"XSL Script Processing", L"TA0005", 6, 10, 80, TRUE, NULL },
    { L"T1207", L"Rogue Domain Controller", L"TA0005", 6, 10, 95, TRUE, NULL },
    { L"T1550.001", L"Application Access Token", L"TA0005", 6, 10, 70, TRUE, L"T1550" },
    { L"T1550.004", L"Web Session Cookie", L"TA0005", 6, 10, 70, TRUE, L"T1550" },
    { L"T1610", L"Deploy Container", L"TA0005", 6, 10, 75, TRUE, NULL },
    { L"T1601", L"Modify System Image", L"TA0005", 6, 10, 90, TRUE, NULL },
    { L"T1600", L"Weaken Encryption", L"TA0005", 6, 10, 80, TRUE, NULL },
    { L"T1647", L"Plist File Modification", L"TA0005", 6, 10, 65, FALSE, NULL },
    { L"T1665", L"Hide Infrastructure", L"TA0005", 6, 10, 70, TRUE, NULL },
    { L"T1678", L"Delay Execution", L"TA0005", 6, 10, 60, TRUE, NULL },
    { L"T1679", L"Selective Exclusion", L"TA0005", 6, 10, 55, TRUE, NULL },

    /* TA0006 */
    { L"T1003", L"OS Credential Dumping", L"TA0006", 7, 15, 95, TRUE, NULL },
    { L"T1003.001", L"LSASS Memory", L"TA0006", 7, 15, 98, TRUE, L"T1003" },
    { L"T1003.002", L"Security Account Manager", L"TA0006", 7, 15, 95, TRUE, L"T1003" },
    { L"T1003.003", L"NTDS", L"TA0006", 7, 15, 95, TRUE, L"T1003" },
    { L"T1003.004", L"LSA Secrets", L"TA0006", 7, 15, 90, TRUE, L"T1003" },
    { L"T1003.006", L"DCSync", L"TA0006", 7, 15, 95, TRUE, L"T1003" },
    { L"T1555", L"Credentials from Password Stores", L"TA0006", 7, 10, 85, TRUE, NULL },
    { L"T1555.003", L"Credentials from Web Browsers", L"TA0006", 7, 10, 85, TRUE, L"T1555" },
    { L"T1555.004", L"Windows Credential Manager", L"TA0006", 7, 10, 80, TRUE, L"T1555" },
    { L"T1056", L"Input Capture", L"TA0006", 7, 10, 85, TRUE, NULL },
    { L"T1056.001", L"Keylogging", L"TA0006", 7, 10, 90, TRUE, L"T1056" },
    { L"T1558", L"Steal or Forge Kerberos Tickets", L"TA0006", 7, 10, 90, TRUE, NULL },
    { L"T1558.001", L"Golden Ticket", L"TA0006", 7, 10, 95, TRUE, L"T1558" },
    { L"T1558.002", L"Silver Ticket", L"TA0006", 7, 10, 90, TRUE, L"T1558" },
    { L"T1558.003", L"Kerberoasting", L"TA0006", 7, 10, 90, TRUE, L"T1558" },
    { L"T1110", L"Brute Force", L"TA0006", 7, 10, 75, TRUE, NULL },
    { L"T1110.003", L"Password Spraying", L"TA0006", 7, 10, 80, TRUE, L"T1110" },
    { L"T1557", L"Adversary-in-the-Middle", L"TA0006", 7, 10, 80, TRUE, NULL },
    { L"T1003.005", L"Cached Domain Credentials", L"TA0006", 7, 15, 85, TRUE, L"T1003" },
    { L"T1003.007", L"Proc Filesystem", L"TA0006", 7, 15, 80, FALSE, L"T1003" },
    { L"T1003.008", L"/etc/passwd and /etc/shadow", L"TA0006", 7, 15, 85, FALSE, L"T1003" },
    { L"T1110.001", L"Password Guessing", L"TA0006", 7, 10, 70, TRUE, L"T1110" },
    { L"T1110.002", L"Password Cracking", L"TA0006", 7, 10, 75, TRUE, L"T1110" },
    { L"T1110.004", L"Credential Stuffing", L"TA0006", 7, 10, 75, TRUE, L"T1110" },
    { L"T1555.001", L"Keychain", L"TA0006", 7, 10, 80, FALSE, L"T1555" },
    { L"T1555.005", L"Password Managers", L"TA0006", 7, 10, 85, TRUE, L"T1555" },
    { L"T1056.002", L"GUI Input Capture", L"TA0006", 7, 10, 80, TRUE, L"T1056" },
    { L"T1056.003", L"Web Portal Capture", L"TA0006", 7, 10, 80, TRUE, L"T1056" },
    { L"T1056.004", L"Credential API Hooking", L"TA0006", 7, 10, 85, TRUE, L"T1056" },
    { L"T1558.004", L"AS-REP Roasting", L"TA0006", 7, 10, 85, TRUE, L"T1558" },
    { L"T1557.001", L"LLMNR/NBT-NS Poisoning and SMB Relay", L"TA0006", 7, 10, 85, TRUE, L"T1557" },
    { L"T1557.002", L"ARP Cache Poisoning", L"TA0006", 7, 10, 80, TRUE, L"T1557" },
    { L"T1557.003", L"DHCP Spoofing", L"TA0006", 7, 10, 75, TRUE, L"T1557" },
    { L"T1557.004", L"Evil Twin", L"TA0006", 7, 10, 80, TRUE, L"T1557" },
    { L"T1212", L"Exploitation for Credential Access", L"TA0006", 7, 10, 85, TRUE, NULL },
    { L"T1187", L"Forced Authentication", L"TA0006", 7, 10, 80, TRUE, NULL },
    { L"T1606", L"Forge Web Credentials", L"TA0006", 7, 10, 85, TRUE, NULL },
    { L"T1606.001", L"Web Cookies", L"TA0006", 7, 10, 80, TRUE, L"T1606" },
    { L"T1606.002", L"SAML Tokens", L"TA0006", 7, 10, 90, TRUE, L"T1606" },
    { L"T1111", L"Two-Factor Authentication Interception", L"TA0006", 7, 10, 80, TRUE, NULL },
    { L"T1528", L"Steal Application Access Token", L"TA0006", 7, 10, 80, TRUE, NULL },
    { L"T1539", L"Steal Web Session Cookie", L"TA0006", 7, 10, 80, TRUE, NULL },
    { L"T1552", L"Unsecured Credentials", L"TA0006", 7, 10, 75, TRUE, NULL },
    { L"T1552.001", L"Credentials In Files", L"TA0006", 7, 10, 80, TRUE, L"T1552" },
    { L"T1552.002", L"Credentials in Registry", L"TA0006", 7, 10, 80, TRUE, L"T1552" },
    { L"T1552.003", L"Bash History", L"TA0006", 7, 10, 70, FALSE, L"T1552" },
    { L"T1552.004", L"Private Keys", L"TA0006", 7, 10, 85, TRUE, L"T1552" },
    { L"T1552.005", L"Cloud Instance Metadata API", L"TA0006", 7, 10, 80, FALSE, L"T1552" },
    { L"T1552.006", L"Group Policy Preferences", L"TA0006", 7, 10, 85, TRUE, L"T1552" },
    { L"T1621", L"Multi-Factor Authentication Request Generation", L"TA0006", 7, 10, 75, TRUE, NULL },
    { L"T1040", L"Network Sniffing", L"TA0006", 7, 10, 70, TRUE, NULL },

    /* TA0007 */
    { L"T1087", L"Account Discovery", L"TA0007", 8, 10, 60, TRUE, NULL },
    { L"T1087.001", L"Local Account", L"TA0007", 8, 10, 65, TRUE, L"T1087" },
    { L"T1087.002", L"Domain Account", L"TA0007", 8, 10, 70, TRUE, L"T1087" },
    { L"T1083", L"File and Directory Discovery", L"TA0007", 8, 10, 50, TRUE, NULL },
    { L"T1057", L"Process Discovery", L"TA0007", 8, 3, 50, TRUE, NULL },
    { L"T1082", L"System Information Discovery", L"TA0007", 8, 10, 55, TRUE, NULL },
    { L"T1016", L"System Network Configuration Discovery", L"TA0007", 8, 10, 60, TRUE, NULL },
    { L"T1018", L"Remote System Discovery", L"TA0007", 8, 10, 70, TRUE, NULL },
    { L"T1135", L"Network Share Discovery", L"TA0007", 8, 10, 65, TRUE, NULL },
    { L"T1069", L"Permission Groups Discovery", L"TA0007", 8, 10, 60, TRUE, NULL },
    { L"T1069.001", L"Local Groups", L"TA0007", 8, 10, 55, TRUE, L"T1069" },
    { L"T1069.002", L"Domain Groups", L"TA0007", 8, 10, 65, TRUE, L"T1069" },
    { L"T1012", L"Query Registry", L"TA0007", 8, 10, 45, TRUE, NULL },
    { L"T1518", L"Software Discovery", L"TA0007", 8, 10, 50, TRUE, NULL },
    { L"T1518.001", L"Security Software Discovery", L"TA0007", 8, 10, 75, TRUE, L"T1518" },
    { L"T1033", L"System Owner/User Discovery", L"TA0007", 8, 10, 50, TRUE, NULL },
    { L"T1049", L"System Network Connections Discovery", L"TA0007", 8, 10, 55, TRUE, NULL },
    { L"T1482", L"Domain Trust Discovery", L"TA0007", 8, 10, 70, TRUE, NULL },
    { L"T1010", L"Application Window Discovery", L"TA0007", 8, 10, 45, TRUE, NULL },
    { L"T1087.003", L"Email Account", L"TA0007", 8, 10, 60, TRUE, L"T1087" },
    { L"T1087.004", L"Cloud Account", L"TA0007", 8, 10, 65, TRUE, L"T1087" },
    { L"T1069.003", L"Cloud Groups", L"TA0007", 8, 10, 60, TRUE, L"T1069" },
    { L"T1217", L"Browser Information Discovery", L"TA0007", 8, 10, 55, TRUE, NULL },
    { L"T1046", L"Network Service Discovery", L"TA0007", 8, 10, 70, TRUE, NULL },
    { L"T1007", L"System Service Discovery", L"TA0007", 8, 10, 55, TRUE, NULL },
    { L"T1124", L"System Time Discovery", L"TA0007", 8, 10, 40, TRUE, NULL },
    { L"T1120", L"Peripheral Device Discovery", L"TA0007", 8, 10, 45, TRUE, NULL },
    { L"T1201", L"Password Policy Discovery", L"TA0007", 8, 10, 55, TRUE, NULL },
    { L"T1614", L"System Location Discovery", L"TA0007", 8, 10, 45, TRUE, NULL },
    { L"T1615", L"Group Policy Discovery", L"TA0007", 8, 10, 55, TRUE, NULL },
    { L"T1580", L"Cloud Infrastructure Discovery", L"TA0007", 8, 10, 60, FALSE, NULL },
    { L"T1526", L"Cloud Service Discovery", L"TA0007", 8, 10, 55, FALSE, NULL },
    { L"T1538", L"Cloud Service Dashboard", L"TA0007", 8, 10, 50, FALSE, NULL },
    { L"T1613", L"Container and Resource Discovery", L"TA0007", 8, 10, 55, FALSE, NULL },
    { L"T1680", L"Local Storage Discovery", L"TA0007", 8, 10, 40, TRUE, NULL },
    { L"T1518.002", L"Backup Software Discovery", L"TA0007", 8, 10, 60, TRUE, L"T1518" },
    { L"T1016.001", L"Internet Connection Discovery", L"TA0007", 8, 10, 45, TRUE, L"T1016" },
    { L"T1016.002", L"Wi-Fi Discovery", L"TA0007", 8, 10, 50, TRUE, L"T1016" },

    /* TA0008 */
    { L"T1021", L"Remote Services", L"TA0008", 9, 11, 80, TRUE, NULL },
    { L"T1021.001", L"Remote Desktop Protocol", L"TA0008", 9, 11, 75, TRUE, L"T1021" },
    { L"T1021.002", L"SMB/Windows Admin Shares", L"TA0008", 9, 11, 85, TRUE, L"T1021" },
    { L"T1021.003", L"Distributed Component Object Model", L"TA0008", 9, 11, 80, TRUE, L"T1021" },
    { L"T1021.006", L"Windows Remote Management", L"TA0008", 9, 11, 80, TRUE, L"T1021" },
    { L"T1210", L"Exploitation of Remote Services", L"TA0008", 9, 10, 90, TRUE, NULL },
    { L"T1570", L"Lateral Tool Transfer", L"TA0008", 9, 10, 70, TRUE, NULL },
    { L"T1080", L"Taint Shared Content", L"TA0008", 9, 10, 65, TRUE, NULL },
    { L"T1550", L"Use Alternate Authentication Material", L"TA0008", 9, 10, 90, TRUE, NULL },
    { L"T1550.002", L"Pass the Hash", L"TA0008", 9, 10, 95, TRUE, L"T1550" },
    { L"T1550.003", L"Pass the Ticket", L"TA0008", 9, 10, 95, TRUE, L"T1550" },
    { L"T1021.004", L"SSH", L"TA0008", 9, 11, 70, TRUE, L"T1021" },
    { L"T1021.005", L"VNC", L"TA0008", 9, 11, 70, TRUE, L"T1021" },
    { L"T1534", L"Internal Spearphishing", L"TA0008", 9, 10, 75, TRUE, NULL },
    { L"T1092", L"Communication Through Removable Media", L"TA0008", 9, 10, 55, TRUE, NULL },
    { L"T1677", L"Poisoned Pipeline Execution", L"TA0008", 9, 10, 80, TRUE, NULL },

    /* TA0009 */
    { L"T1560", L"Archive Collected Data", L"TA0009", 10, 8, 70, TRUE, NULL },
    { L"T1560.001", L"Archive via Utility", L"TA0009", 10, 8, 75, TRUE, L"T1560" },
    { L"T1005", L"Data from Local System", L"TA0009", 10, 6, 60, TRUE, NULL },
    { L"T1039", L"Data from Network Shared Drive", L"TA0009", 10, 7, 65, TRUE, NULL },
    { L"T1113", L"Screen Capture", L"TA0009", 10, 7, 75, TRUE, NULL },
    { L"T1115", L"Clipboard Data", L"TA0009", 10, 5, 70, TRUE, NULL },
    { L"T1114", L"Email Collection", L"TA0009", 10, 8, 80, TRUE, NULL },
    { L"T1074", L"Data Staged", L"TA0009", 10, 10, 70, TRUE, NULL },
    { L"T1074.001", L"Local Data Staging", L"TA0009", 10, 10, 65, TRUE, L"T1074" },
    { L"T1119", L"Automated Collection", L"TA0009", 10, 10, 75, TRUE, NULL },
    { L"T1125", L"Video Capture", L"TA0009", 10, 10, 80, TRUE, NULL },
    { L"T1123", L"Audio Capture", L"TA0009", 10, 10, 80, TRUE, NULL },
    { L"T1560.002", L"Archive via Library", L"TA0009", 10, 8, 70, TRUE, L"T1560" },
    { L"T1560.003", L"Archive via Custom Method", L"TA0009", 10, 8, 75, TRUE, L"T1560" },
    { L"T1074.002", L"Remote Data Staging", L"TA0009", 10, 10, 70, TRUE, L"T1074" },
    { L"T1114.001", L"Local Email Collection", L"TA0009", 10, 8, 75, TRUE, L"T1114" },
    { L"T1114.002", L"Remote Email Collection", L"TA0009", 10, 8, 80, TRUE, L"T1114" },
    { L"T1114.003", L"Email Forwarding Rule", L"TA0009", 10, 8, 80, TRUE, L"T1114" },
    { L"T1185", L"Browser Session Hijacking", L"TA0009", 10, 10, 80, TRUE, NULL },
    { L"T1025", L"Data from Removable Media", L"TA0009", 10, 10, 60, TRUE, NULL },
    { L"T1530", L"Data from Cloud Storage", L"TA0009", 10, 10, 75, FALSE, NULL },
    { L"T1602", L"Data from Configuration Repository", L"TA0009", 10, 10, 70, TRUE, NULL },
    { L"T1213", L"Data from Information Repositories", L"TA0009", 10, 10, 65, TRUE, NULL },
    { L"T1213.001", L"Confluence", L"TA0009", 10, 10, 65, TRUE, L"T1213" },
    { L"T1213.002", L"Sharepoint", L"TA0009", 10, 10, 65, TRUE, L"T1213" },
    { L"T1213.003", L"Code Repositories", L"TA0009", 10, 10, 70, TRUE, L"T1213" },
    { L"T1213.006", L"Databases", L"TA0009", 10, 10, 70, TRUE, L"T1213" },

    /* TA0011 */
    { L"T1071", L"Application Layer Protocol", L"TA0011", 11, 8, 70, TRUE, NULL },
    { L"T1071.001", L"Web Protocols", L"TA0011", 11, 8, 75, TRUE, L"T1071" },
    { L"T1071.004", L"DNS", L"TA0011", 11, 8, 85, TRUE, L"T1071" },
    { L"T1573", L"Encrypted Channel", L"TA0011", 11, 10, 65, TRUE, NULL },
    { L"T1573.001", L"Symmetric Cryptography", L"TA0011", 11, 10, 60, TRUE, L"T1573" },
    { L"T1573.002", L"Asymmetric Cryptography", L"TA0011", 11, 10, 65, TRUE, L"T1573" },
    { L"T1105", L"Ingress Tool Transfer", L"TA0011", 11, 9, 75, TRUE, NULL },
    { L"T1571", L"Non-Standard Port", L"TA0011", 11, 10, 70, TRUE, NULL },
    { L"T1572", L"Protocol Tunneling", L"TA0011", 11, 10, 80, TRUE, NULL },
    { L"T1090", L"Proxy", L"TA0011", 11, 10, 70, TRUE, NULL },
    { L"T1090.003", L"Multi-hop Proxy", L"TA0011", 11, 10, 80, TRUE, L"T1090" },
    { L"T1568", L"Dynamic Resolution", L"TA0011", 11, 10, 85, TRUE, NULL },
    { L"T1568.002", L"Domain Generation Algorithms", L"TA0011", 11, 10, 90, TRUE, L"T1568" },
    { L"T1102", L"Web Service", L"TA0011", 11, 10, 75, TRUE, NULL },
    { L"T1219", L"Remote Access Software", L"TA0011", 11, 10, 70, TRUE, NULL },
    { L"T1071.002", L"File Transfer Protocols", L"TA0011", 11, 8, 70, TRUE, L"T1071" },
    { L"T1071.003", L"Mail Protocols", L"TA0011", 11, 8, 70, TRUE, L"T1071" },
    { L"T1071.005", L"Publish/Subscribe Protocols", L"TA0011", 11, 8, 65, TRUE, L"T1071" },
    { L"T1001", L"Data Obfuscation", L"TA0011", 11, 10, 70, TRUE, NULL },
    { L"T1001.001", L"Junk Data", L"TA0011", 11, 10, 60, TRUE, L"T1001" },
    { L"T1001.002", L"Steganography", L"TA0011", 11, 10, 75, TRUE, L"T1001" },
    { L"T1001.003", L"Protocol Impersonation", L"TA0011", 11, 10, 70, TRUE, L"T1001" },
    { L"T1132", L"Data Encoding", L"TA0011", 11, 10, 60, TRUE, NULL },
    { L"T1132.001", L"Standard Encoding", L"TA0011", 11, 10, 55, TRUE, L"T1132" },
    { L"T1132.002", L"Non-Standard Encoding", L"TA0011", 11, 10, 65, TRUE, L"T1132" },
    { L"T1008", L"Fallback Channels", L"TA0011", 11, 10, 70, TRUE, NULL },
    { L"T1104", L"Multi-Stage Channels", L"TA0011", 11, 10, 75, TRUE, NULL },
    { L"T1095", L"Non-Application Layer Protocol", L"TA0011", 11, 10, 75, TRUE, NULL },
    { L"T1090.001", L"Internal Proxy", L"TA0011", 11, 10, 70, TRUE, L"T1090" },
    { L"T1090.002", L"External Proxy", L"TA0011", 11, 10, 70, TRUE, L"T1090" },
    { L"T1090.004", L"Domain Fronting", L"TA0011", 11, 10, 85, TRUE, L"T1090" },
    { L"T1568.001", L"Fast Flux DNS", L"TA0011", 11, 10, 85, TRUE, L"T1568" },
    { L"T1568.003", L"DNS Calculation", L"TA0011", 11, 10, 80, TRUE, L"T1568" },
    { L"T1102.001", L"Dead Drop Resolver", L"TA0011", 11, 10, 80, TRUE, L"T1102" },
    { L"T1102.002", L"Bidirectional Communication", L"TA0011", 11, 10, 75, TRUE, L"T1102" },
    { L"T1102.003", L"One-Way Communication", L"TA0011", 11, 10, 70, TRUE, L"T1102" },

    /* TA0010 */
    { L"T1041", L"Exfiltration Over C2 Channel", L"TA0010", 12, 12, 75, TRUE, NULL },
    { L"T1048", L"Exfiltration Over Alternative Protocol", L"TA0010", 12, 11, 80, TRUE, NULL },
    { L"T1567", L"Exfiltration Over Web Service", L"TA0010", 12, 10, 75, TRUE, NULL },
    { L"T1567.002", L"Exfiltration to Cloud Storage", L"TA0010", 12, 10, 80, TRUE, L"T1567" },
    { L"T1020", L"Automated Exfiltration", L"TA0010", 12, 10, 80, TRUE, NULL },
    { L"T1030", L"Data Transfer Size Limits", L"TA0010", 12, 10, 65, TRUE, NULL },
    { L"T1052", L"Exfiltration Over Physical Medium", L"TA0010", 12, 10, 60, TRUE, NULL },
    { L"T1020.001", L"Traffic Duplication", L"TA0010", 12, 10, 75, TRUE, L"T1020" },
    { L"T1048.001", L"Exfiltration Over Symmetric Encrypted Non-C2 Protocol", L"TA0010", 12, 11, 80, TRUE, L"T1048" },
    { L"T1048.002", L"Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", L"TA0010", 12, 11, 80, TRUE, L"T1048" },
    { L"T1048.003", L"Exfiltration Over Unencrypted Non-C2 Protocol", L"TA0010", 12, 11, 75, TRUE, L"T1048" },
    { L"T1567.001", L"Exfiltration to Code Repository", L"TA0010", 12, 10, 75, TRUE, L"T1567" },
    { L"T1011", L"Exfiltration Over Other Network Medium", L"TA0010", 12, 10, 65, TRUE, NULL },
    { L"T1011.001", L"Exfiltration Over Bluetooth", L"TA0010", 12, 10, 60, TRUE, L"T1011" },
    { L"T1052.001", L"Exfiltration over USB", L"TA0010", 12, 10, 65, TRUE, L"T1052" },
    { L"T1029", L"Scheduled Transfer", L"TA0010", 12, 10, 70, TRUE, NULL },
    { L"T1537", L"Transfer Data to Cloud Account", L"TA0010", 12, 10, 75, TRUE, NULL },

    /* TA0040 */
    { L"T1486", L"Data Encrypted for Impact", L"TA0040", 13, 20, 100, TRUE, NULL },
    { L"T1485", L"Data Destruction", L"TA0040", 13, 18, 100, TRUE, NULL },
    { L"T1490", L"Inhibit System Recovery", L"TA0040", 13, 17, 95, TRUE, NULL },
    { L"T1489", L"Service Stop", L"TA0040", 13, 10, 80, TRUE, NULL },
    { L"T1561", L"Disk Wipe", L"TA0040", 13, 10, 100, TRUE, NULL },
    { L"T1561.001", L"Disk Content Wipe", L"TA0040", 13, 10, 100, TRUE, L"T1561" },
    { L"T1561.002", L"Disk Structure Wipe", L"TA0040", 13, 10, 100, TRUE, L"T1561" },
    { L"T1496", L"Resource Hijacking", L"TA0040", 13, 10, 70, TRUE, NULL },
    { L"T1531", L"Account Access Removal", L"TA0040", 13, 10, 85, TRUE, NULL },
    { L"T1529", L"System Shutdown/Reboot", L"TA0040", 13, 10, 75, TRUE, NULL },
    { L"T1565", L"Data Manipulation", L"TA0040", 13, 10, 85, TRUE, NULL },
    { L"T1499", L"Endpoint Denial of Service", L"TA0040", 13, 10, 80, TRUE, NULL },
    { L"T1491", L"Defacement", L"TA0040", 13, 10, 75, TRUE, NULL },
    { L"T1491.001", L"Internal Defacement", L"TA0040", 13, 10, 70, TRUE, L"T1491" },
    { L"T1491.002", L"External Defacement", L"TA0040", 13, 10, 80, TRUE, L"T1491" },
    { L"T1495", L"Firmware Corruption", L"TA0040", 13, 10, 95, TRUE, NULL },
    { L"T1498", L"Network Denial of Service", L"TA0040", 13, 10, 80, TRUE, NULL },
    { L"T1498.001", L"Direct Network Flood", L"TA0040", 13, 10, 75, TRUE, L"T1498" },
    { L"T1498.002", L"Reflection Amplification", L"TA0040", 13, 10, 80, TRUE, L"T1498" },
    { L"T1499.001", L"OS Exhaustion Flood", L"TA0040", 13, 10, 75, TRUE, L"T1499" },
    { L"T1499.002", L"Service Exhaustion Flood", L"TA0040", 13, 10, 75, TRUE, L"T1499" },
    { L"T1499.003", L"Application Exhaustion Flood", L"TA0040", 13, 10, 80, TRUE, L"T1499" },
    { L"T1499.004", L"Application or System Exploitation", L"TA0040", 13, 10, 85, TRUE, L"T1499" },
    { L"T1565.001", L"Stored Data Manipulation", L"TA0040", 13, 10, 85, TRUE, L"T1565" },
    { L"T1565.002", L"Transmitted Data Manipulation", L"TA0040", 13, 10, 85, TRUE, L"T1565" },
    { L"T1565.003", L"Runtime Data Manipulation", L"TA0040", 13, 10, 90, TRUE, L"T1565" },

    { NULL, NULL, NULL, 0, 0, 0, FALSE, NULL }
};


/**************************************************/
/*           技术 ID → 表项 精确查找                 */
/*                                                   */
/*  线性查 g_IoaTechniqueTable.StringId, 返回表项     */
/*  指针一次取全字段 (对齐 SS MmLookupTechnique       */
/*  L1308; wkd 用户态静态表无需 O(1) 哈希).          */
/**************************************************/

static
inline
const IOA_TECHNIQUE_ENTRY*
IoaMitreLookupById(
    _In_ PCWSTR StringId
    )
{
    for (ULONG i = 0; g_IoaTechniqueTable[i].StringId != NULL; i++) {
        if (wcscmp(StringId, g_IoaTechniqueTable[i].StringId) == 0) {
            return &g_IoaTechniqueTable[i];
        }
    }
    return NULL;
}

/**************************************************/
/*           技术→战术 反查                         */
/*                                                   */
/*  对齐 SS ActpGetPhaseForTechnique (L1534-1554).   */
/*  入参 "T1055.001" → 截断基技术 "T1055" → 查表.    */
/*  未命中: TacticId=NULL, BaseScore=10 (SS 默认).   */
/**************************************************/

static
inline
BOOLEAN
IoaMitreLookupTactic(
    _In_  PCWSTR TechniqueId,
    _Out_ PCWSTR* TacticId,
    _Out_ ULONG*  BaseScore
    )
{
    WCHAR base[16];
    ULONG len = 0;
    const IOA_TECHNIQUE_ENTRY* entry;

    if (TechniqueId == NULL || TacticId == NULL || BaseScore == NULL) {
        return FALSE;
    }

    *TacticId = NULL;
    *BaseScore = 10;    /* 对齐 SS ActpGetPhaseForTechnique 默认 base=10 */

    /* 截断子技术: "T1055.001" → "T1055" */
    while (TechniqueId[len] != 0 && TechniqueId[len] != L'.' && len < 15) {
        base[len] = TechniqueId[len];
        len++;
    }
    base[len] = 0;

    entry = IoaMitreLookupById(base);
    if (entry == NULL) {
        return FALSE;
    }
    *TacticId  = entry->TacticId;
    *BaseScore = entry->BaseScore;
    return TRUE;
}

/**************************************************/
/*           技术名/StringId → 表项 查找 (死代码)     */
/*                                                   */
/*  对齐 SS MmLookupByName (L1380). 无当前消费方,     */
/*  供未来攻击链叙事/报告按名称反查技术.              */
/**************************************************/

static
inline
const IOA_TECHNIQUE_ENTRY*
IoaMitreLookupByName(
    _In_ PCWSTR Name
    )
{
    for (ULONG i = 0; g_IoaTechniqueTable[i].StringId != NULL; i++) {
        if (wcscmp(Name, g_IoaTechniqueTable[i].StringId) == 0 ||
            wcscmp(Name, g_IoaTechniqueTable[i].Name) == 0) {
            return &g_IoaTechniqueTable[i];
        }
    }
    return NULL;
}

/**************************************************/
/*           危险技术组合表                         */
/*                                                   */
/*  ShadowStrike g_DangerousCombos (AttackChainTracker.c */
/*  L296-326) 迁移, bonus / 5 换算到 wkd 0-100 尺度.  */
/*  ComboIndex 用作 AppliedComboMask 位 (1<<index).   */
/*                                                   */
/*  死代码预留: 供 T3Chain_IngestTechnique 增量匹配.  */
/**************************************************/

typedef struct _IOA_DANGEROUS_COMBO {
    ULONG   ComboIndex;                 /* 0-4, AppliedComboMask 位 */
    PCWSTR  Technique1;                 /* 基技术 */
    PCWSTR  Technique2;
    ULONG   BonusScore;                 /* /5 换算 */
    PCWSTR  Description;
} IOA_DANGEROUS_COMBO, *PIOA_DANGEROUS_COMBO;

static const IOA_DANGEROUS_COMBO g_IoaDangerousCombos[] = {
    { 0, L"T1003", L"T1021", 20, L"Credential theft with lateral movement" },    /* SS L300=100 */
    { 1, L"T1562", L"T1055", 16, L"Defense evasion with process injection" },    /* SS L305=80 */
    { 2, L"T1547", L"T1548", 14, L"Persistence with privilege escalation" },     /* SS L310=70 */
    { 3, L"T1560", L"T1041", 18, L"Data archiving with exfiltration" },          /* SS L315=90 */
    { 4, L"T1486", L"T1490", 30, L"Ransomware with recovery inhibition" },       /* SS L320=150 */
    { 0, NULL, NULL, 0, NULL }
};

/**************************************************/
/*           按战术枚举技术 (死代码)                 */
/*                                                   */
/*  对齐 SS MmGetTechniquesByTactic (L1719).         */
/*  返回该战术下技术 StringId 数组, 无当前消费方.     */
/**************************************************/

static
inline
ULONG
IoaMitreGetTechniquesByTactic(
    _In_  ULONG    TacticBit,
    _Out_ PCWSTR*  TechniqueIds,
    _In_  ULONG    Max
    )
{
    ULONG count = 0;

    if (TechniqueIds == NULL || Max == 0) {
        return 0;
    }

    for (ULONG i = 0; g_IoaTechniqueTable[i].StringId != NULL && count < Max; i++) {
        if (g_IoaTechniqueTable[i].TacticBit == TacticBit) {
            TechniqueIds[count++] = g_IoaTechniqueTable[i].StringId;
        }
    }
    return count;
}

/**************************************************/
/*           战术 ID → 位索引                       */
/*                                                   */
/*  "TA0005" → IoATactic_DefenseEvasion(6).         */
/*  未识别返回 (ULONG)-1.                            */
/**************************************************/

static
inline
ULONG
IoaTacticIdToBit(
    _In_ PCWSTR TacticId
    )
{
    ULONG i;

    if (TacticId == NULL) {
        return (ULONG)-1;
    }

    for (i = 0; i < IoATactic_Max; i++) {
        PCWSTR p = TacticId;
        PCWSTR q = g_IoaTacticIdList[i];
        while (*p != 0 && *q != 0 && *p == *q) { p++; q++; }
        if (*p == 0 && *q == 0) {
            return i;
        }
    }

    return (ULONG)-1;
}

/**************************************************/
/*           检测记录器 (死代码)                     */
/*                                                   */
/*  ShadowStrike MITREMapper 检测记录功能             */
/*  (MmRecordDetection L1583 / MmGetRecentDetections  */
/*   L1810) 迁移, 用户态重实现 (无锁环形 LRU, 见      */
/*  IoaMitreDetection.c).                            */
/*                                                   */
/*  死代码原因: wkd 告警链路 IOA_ALERT→cg_alerts 已   */
/*  覆盖"检测→单 MITRE 技术落库"; 本记录器补内存态     */
/*  逐技术记录 + 时间窗查询 + 技术维度统计缺口         */
/*  (SS MITRE 仪表板对应物), 接入前不消费.            */
/*  ProcessName 定长拷贝替代 SS 堆 UNICODE_STRING.    */
/**************************************************/

#define IOA_MITRE_DETECTION_MAX       4096
#define IOA_MITRE_PROCESS_NAME_LEN    64

typedef struct _IOA_MITRE_DETECTION {
    const WCHAR* StringId;              /* 指向 g_IoaTechniqueTable 静态串 */
    HANDLE       ProcessId;
    WCHAR        ProcessName[IOA_MITRE_PROCESS_NAME_LEN];
    ULONG        ConfidenceScore;
    FILETIME     DetectionTime;
    BOOLEAN      Valid;
} IOA_MITRE_DETECTION, *PIOA_MITRE_DETECTION;

NTSTATUS
IoaMitreRecordDetection(
    _In_      PCWSTR    StringId,
    _In_opt_  HANDLE    ProcessId,
    _In_opt_  PCWSTR    ProcessName,
    _In_      ULONG     ConfidenceScore
    );

ULONG
IoaMitreGetRecentDetections(
    _In_  ULONG                  MaxAgeSeconds,
    _Out_ PIOA_MITRE_DETECTION   Detections,
    _In_  ULONG                  Max,
    _Out_ ULONG*                 Count
    );

VOID
IoaMitreGetStats(
    _Out_opt_ ULONG* TotalCount,
    _Out_opt_ ULONG* PerTacticHistogram
    );
