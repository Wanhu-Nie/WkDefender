/**************************************************/
/*  WkDefender IOC — 统一证书验证入口                */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  融合 SS PE_sig_verf/DSV 多点校验                 */
/**************************************************/

#pragma once

#include "../IocTypes.h"
#include "SignatureDetails.h"      /* ExtractCertDetails / CertHasTimestamp (签名时间豁免) */
#include "SignatureCatalog.h"      /* CatalogFindForFile / CatalogVerify (catalog fallback) */
#include "SignatureCache.h"        /* 验证结果缓存 */
#include "SignatureReputation.h"   /* ReputationScore (分类 + 信誉) */

/**************************************************/
/*   SS 证书/签名消费点对照 (2026-08-09)            */
/*   ShadowStrike 签名验证消费链迁移落点:            */
/*   1 KernelExploitDetector::VerifyDriverSignature (:576)
/*     → BYOVD 脆弱驱动哈希库 wkd 未迁 (无消费方);    */
/*       签名维度已由 IocScanner_ScanFile CertVerify 覆盖。
/*   2 ExecutableAnalyzer::VerifySignatureImpl (:2585)
/*     → 纯信息性签名状态, IocScanner_ScanFile 已覆盖。
/*   3 DriverAnalyzer::VerifySignature (:650)       */
/*     → Unsigned→Suspicious / MS·WHQL→Safe 语义;   */
/*       单句柄 TOCTOU 由 ScanManager 结果缓存 mtime 校验兜底。
/*   4 FileReputation::GetCertificateReputation (:797)
/*     → IocScan_ReputationScore 等价 (EV/有效/吊销   */
/*       /过期权重一致, 见 SignatureReputation.h)。  */
/*   5 DriverInstaller::VerifyDriverSignatureByHandle (:148)
/*     → wkd 无驱动安装链; CERT_E_UNTRUSTEDROOT/     */
/*       CHAINING 开发证书放行语义无对应场景, 注释不迁。
/*   6 IPCManager::VerifyDriverSignature (:2554)    */
/*     → SS 无内部调用者 (导出工具), 不迁。          */
/*   7 UpdateVerifier 包级公钥签名 (RSA/ECDSA 主判,  */
/*     Authenticode 仅辅助, 非同一信任根)            */
/*     → wkd 无 ProgramUpdater 更新链; 裸数据验签     */
/*       复用 IocCert_VerifySignature 死代码 (IocCertUtils.c)。
/*   8 FileIntegrityMonitor::DoVerifyFile (:830)    */
/*     → 基线比对属合规/篡改检测, wkd DirectoryMonitor 目录级部分覆盖。
/*   9 ProcessEvasionDetector::IsSignatureValid (:816)
/*     → 签名失败作为反规避加权信号, 并入 IoaEvasionDetect masquerade 判定。
/**************************************************/

/**************************************************/
/*           门控开关 (定义于 SignatureVerifier.c)  */
/**************************************************/

/* 吊销 + Authenticode 策略验证门控 (SS CheckRevocationOnline 迁移) */
extern BOOLEAN g_IocRevocationCheckEnabled;
/* catalog 目录签名 fallback 门控 (SS VerifyCatalogSignature 迁移) */
extern BOOLEAN g_IocCatalogEnabled;
/* 签名时间豁免门控 (SS ValidateTimestamp 迁移) */
extern BOOLEAN g_IocSignTimeExemptionEnabled;
/* cert_reputation 表接线门控 (SS GetCertificateTrust 迁移) */
extern BOOLEAN g_IocCertReputationEnabled;
/* 证书验证缓存门控 (SS DSV 缓存 L1766-1819 轻量迁移) */
extern BOOLEAN g_IocCertCacheEnabled;

/**************************************************/
/*                  函数声明                       */
/**************************************************/

/*++
Routine Description:
    WinVerifyTrust 主验证 + 签名状态细分 + 证书详情提取。
    (catalog fallback / 吊销 / 签名时间豁免由门控控制)
    完整扫描 (IocScanner_ScanFile) 与统一入口 (VerifySignature) 均调用。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果 (证书字段)。

Return Value:
    无。
--*/
NTSTATUS
IocVerifyTrust(
    _In_ PCWSTR FilePath,
    _In_ ULONG VerifyMode,
    _In_ ULONG VerifyFlags,
    _In_ BOOLEAN StrictSignature,
    _Inout_ PIOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    统一证书验证入口 (2026-08 融合 SS 多点校验)。
    签名状态细分 + 证书详情提取 + 签名者分类 + 信誉评分, 一步输出完整证书字段。
    门控 g_IocCertCacheEnabled 开启时按 文件路径+LastWriteTime 缓存证书结果。
    不触发哈希/LOLBin/命令行等其余静态扫描。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果（证书+信誉字段有效）。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocVerifySignature(
    _In_ PCWSTR FilePath,
    _Out_ PIOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    内存缓冲证书验证 (SS DSV VerifyMemory 迁移)。
    写临时文件 (DELETE_ON_CLOSE 持句柄防替换) → 复用统一 CertVerify + ReputationScore。

Arguments:
    Data   - 待验签的 PE 内存镜像。
    Size   - 缓冲长度。
    Result - 输出扫描结果 (证书+信誉字段)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocScanner_VerifyMemoryBuffer(
    _In_  const BYTE*      Data,
    _In_  ULONG            Size,
    _Out_ IOC_SCAN_RESULT* Result
    );

/*++
Routine Description:
    统一判定辅助: 签名者是否为微软 (ClassifySigner 名称+指纹双通道产出)。

Arguments:
    Result - 扫描结果 (经统一入口填充 SignerCategory)。

Return Value:
    TRUE=微软签名。
--*/
BOOLEAN
IocScan_IsMicrosoftSigned(
    _In_ PIOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    统一判定辅助: 签名者是否为可信发行商。

Arguments:
    Result - 扫描结果。

Return Value:
    TRUE=可信发行商签名。
--*/
BOOLEAN
IocScan_IsTrustedPublisher(
    _In_ PIOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    统一判定辅助: 是否为 EV 证书签名。

Arguments:
    Result - 扫描结果。

Return Value:
    TRUE=EV 签名。
--*/
BOOLEAN
IocScan_IsEvSigned(
    _In_ PIOC_SCAN_RESULT Result
    );
