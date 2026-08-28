/**************************************************/
/*  WkDefender IOC — .NET 深度分析 (静态子集)       */
/*                                                  */
/*  迁移自 ShadowStrike DotNetAnalyzer.cpp           */
/*  (PhantomEmulator/Analysis, 1837 行) 按功能融合   */
/*  重实现, 纯 C 非复制 (仅静态子集)。               */
/*                                                  */
/*  能力面:                                         */
/*    - CLR 元数据表解析 (根 BSJB + #~ 流 +          */
/*      TypeDef/MethodDef/MemberRef/AssemblyRef/     */
/*      ImplMap/FieldRVA)                           */
/*    - AnalyzeMetadata: 程序集名/版本/引用框架/计数  */
/*    - DetectObfuscation: 10 类混淆器指纹           */
/*    - ClassifyAPICalls: 托管 API 危险分类          */
/*    - ExtractPInvokes: ImplMap → P/Invoke          */
/*    - DetectPayloadEmbedding: COR20 资源 blob +     */
/*      FieldRVA 高熵载荷探测                        */
/*    - ComputeThreatScore: 加权评分                 */
/*                                                  */
/*  简化迁移说明 (未全量, 均注释标注):               */
/*    - MSIL 反汇编 + 解释执行 (.cctor 字符串解密)    */
/*      → 依赖模拟器轨, 不迁移 (本模块仅静态)        */
/*    - 26 类托管 API: 实现核心危险子集 (反射/进程/   */
/*      文件/网络/加密/注册表/WMI/反分析)            */
/*    - 字符串解密提取 (extractedStrings) 不填充      */
/*                                                  */
/*  编码: UTF-8 with BOM                             */
/**************************************************/

#pragma once

#include "IocTypes.h"
#include "PEAnalyzer/PeAnalyzer.h"   /* PE_INFO (几何/COR20 目录/Sections) */

/**************************************************/
/*       混淆标志位 (对齐 SS DotNetObfuscation)     */
/**************************************************/
#define IOC_DN_OBF_NONE              0x0000
#define IOC_DN_OBF_STRING_ENC        0x0001
#define IOC_DN_OBF_CFLATTEN          0x0002
#define IOC_DN_OBF_METHOD_PROXY      0x0004
#define IOC_DN_OBF_ANTI_TAMPER       0x0008
#define IOC_DN_OBF_ANTI_DECOMPILE    0x0010
#define IOC_DN_OBF_NAME              0x0020
#define IOC_DN_OBF_RESOURCE_ENC      0x0040
#define IOC_DN_OBF_VIRTUALIZE        0x0080
#define IOC_DN_OBF_MIXED_MODE        0x0100
#define IOC_DN_OBF_BODY_ENC          0x0200

/**************************************************/
/*        托管 API 危险分类 (对齐 SS 核心子集)       */
/**************************************************/
typedef enum _IOC_DN_API_CATEGORY {
    IocDnApi_None = 0,
    IocDnApi_AssemblyLoad,      /* 反射加载 */
    IocDnApi_ReflectionInvoke,  /* MethodInfo.Invoke / Activator */
    IocDnApi_DynamicCompile,    /* 动态编译 */
    IocDnApi_ProcessStart,      /* 进程创建 */
    IocDnApi_FileRead, IocDnApi_FileWrite, IocDnApi_FileDelete,
    IocDnApi_WebDownload, IocDnApi_SocketConnect, IocDnApi_DnsResolve,
    IocDnApi_SymmetricEncrypt, IocDnApi_AsymmetricEncrypt, IocDnApi_HashCompute,
    IocDnApi_RegistryRead, IocDnApi_RegistryWrite, IocDnApi_WmiQuery,
    IocDnApi_MarshalCopy, IocDnApi_UnsafeCode, IocDnApi_SleepDelay,
    IocDnApi_AntiDebug, IocDnApi_AntiVM,
    IocDnApi_Count
} IOC_DN_API_CATEGORY;

/**************************************************/
/*               函数声明                          */
/**************************************************/

/* 对 .NET 镜像做静态深度分析 (元数据解析 + 混淆/API/PInvoke/载荷)。
 * PeInfo - 构建期 PE_INFO 几何 (DataDirectories[COM] 定位 COR20,
 *          Sections 供 RVA→文件偏移)。须 .NET (PeInfo->IsDotNet)。
 * Data   - 文件字节缓冲 (RVA 换算后的文件偏移读取)。
 * Size   - 缓冲字节数。
 * Agg    - IOC_SCAN_RESULT 聚合 (填 Net* 字段组)。
 * 非 .NET 或无 COR20 返回 STATUS_NOT_SUPPORTED (Agg 不置 NetAnalyzed)。
 * Return: STATUS_SUCCESS / STATUS_NOT_SUPPORTED。 */
NTSTATUS
IocDotNetAnalyze(
    _In_      const PE_INFO*       PeInfo,
    _In_      const BYTE*          Data,
    _In_      SIZE_T               Size,
    _Inout_   IOC_SCAN_RESULT*     Agg
    );
