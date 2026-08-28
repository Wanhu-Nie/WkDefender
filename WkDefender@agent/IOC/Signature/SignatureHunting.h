/**************************************************/
/*  WkDefender IOC — 签名 APT 狩猎引擎              */
/*  SS DigitalSignatureValidator 迁移 (2026-08-09)   */
/*  AnalyzeSignature 9 类 anomaly + 被盗证书库       */
/**************************************************/

#pragma once

#include "../IocTypes.h"

/**************************************************/
/*           门控开关 (定义于 SignatureHunting.c)   */
/**************************************************/

/* 签名狩猎分析门控 (SS DSV AnalyzeSignature 迁移, 死代码开关默认关闭,
 * 对齐 g_IoaCmdLineAnalyzerEnabled 惯例)。置 TRUE 后统一证书验证入口
 * 尾部追加 9 类签名异常分析, 输出 WKD_SIGNATURE_HUNT_RESULT.RiskScore。 */
extern BOOLEAN g_IoaSignatureHuntingEnabled;

/**************************************************/
/*                  函数声明                       */
/**************************************************/

/*++
Routine Description:
    被盗证书数据库: 追加单条 (SHA1 指纹 hex 小写为键)。
    对齐 SS DigitalSignatureValidator::AddStolenCertificate L1961。
    数据库定长数组 (WKD_STOLEN_CERT_MAX), 满时返回 INSUFFICIENT_RESOURCES。
    空库启动, 由外部威胁情报注入 (LoadStolenCertDb 批量)。

Arguments:
    Entry - 被盗证书条目 (指纹/威胁组织/活动/MITRE 组/严重度)。

Return Value:
    STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES。
--*/
NTSTATUS
IoaSigHunt_AddStolenCert(
    _In_ PCWKD_STOLEN_CERT_ENTRY Entry
    );

/*++
Routine Description:
    被盗证书数据库: 批量导入 (威胁情报 feed)。
    对齐 SS DigitalSignatureValidator::LoadStolenCertDatabase L1971。

Arguments:
    Entries - 条目数组。
    Count   - 条目数。

Return Value:
    实际加载条数。
--*/
ULONG
IoaSigHunt_LoadStolenCertDb(
    _In_reads_(Count) PCWKD_STOLEN_CERT_ENTRY Entries,
    _In_              ULONG                Count
    );

/*++
Routine Description:
    被盗证书数据库: 清空。

Return Value:
    无。
--*/
VOID
IoaSigHunt_ClearStolenCertDb(
    VOID
    );

/*++
Routine Description:
    签名 APT 狩猎核心分析: 9 类签名异常 + WHQL/测试签名标志 + 风险聚合。
    对齐 SS DigitalSignatureValidator::AnalyzeSignature L1998-2268。

    Check1  被盗证书 (叶+链指纹命中库)         → 100  Critical T1553.002
    Check2  非系统目录自签名                    → 70   High     T1553.002
    Check3  短有效期 (<30 天, burner cert)      → 65   High     T1588.003
    Check4  刚签发 (<7 天)                      → 50   Medium   T1588.003
    Check5  弱哈希算法 (合并 wkd IsWeakSignature)→ 40   Medium   T1553.002
    Check6  测试签名 (不受信根/CN 关键字/测试根) → 75   High     T1553.006
    Check7  catalog-only PE (仅目录签名)        → 25   Low      T1553.002
    Check8  未来时间戳 (>now+300s)              → 70   High     T1070.006
    Check9  吊销证书仍使用                       → 95   Critical T1553.002

    RiskScore 取各 anomaly 贡献最大值 (对齐 SS std::max 聚合; 被盗证书 100/
    吊销 95 的高分值在 max 语义下自然优先, 等价 SS 直置/覆盖式赋值)。

Arguments:
    FilePath   - 文件完整路径 (扩展名/系统目录判定)。
    CertResult - 扫描结果, 须先经 IocVerifyTrust (+ IocScan_ExtractCertDetails
                 填充 IsSelfSigned/有效期/链指纹/WHQL) 后方可调用。
    HuntResult - 输出签名狩猎结果 (RiskScore/异常列表/被盗标志/WHQL/测试签名)。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
IoaSigHunt_AnalyzeSignature(
    _In_    PCWSTR                    FilePath,
    _In_    PIOC_SCAN_RESULT          CertResult,
    _Out_   PWKD_SIGNATURE_HUNT_RESULT HuntResult
    );

/*++
Routine Description:
    镜像加载签名异常分析 (SS DSV OnKernelImageLoad L2274-2338 迁移, 2026-08-09)。
    供镜像加载链 (Orchestrator/Engine.c 阶段4b) 调用, 在 9 类异常之上叠加两个
    镜像链专属信号:

      未签名驱动加载    CertStatus==Unsigned && .sys → RiskScore=100, Critical, T1014
                      (rootkit 线索, 对齐 SS "Unsigned driver loaded")
      签名等级不匹配    内核判 IMG_SIGNATURE_UNSIGNED 但用户态签名有效 → +80,
                      High, T1553.006 (SupplyChainAnomaly: catalog-only/cross-signed 绕过)

    若 CertResult->SignatureHunt.Ran==FALSE (统一入口未做狩猎), 内部先补跑
    IoaSigHunt_AnalyzeSignature。

Arguments:
    FilePath        - 镜像完整路径。
    KernelSigStatus - 内核 CI 签名判定 (IMG_SIGNATURE_*: UNEVALUATED=0/VALID=1/UNSIGNED=2)。
    CertResult      - 扫描结果 (已经 IocVerifyTrust); SignatureHunt 内嵌被填充/追加。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
IoaSigHunt_AnalyzeImageLoad(
    _In_    PCWSTR           FilePath,
    _In_    UCHAR            KernelSigStatus,
    _Inout_ PIOC_SCAN_RESULT CertResult
    );
