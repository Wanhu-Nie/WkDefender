/**************************************************/
/*  WkDefender IOC — 地址→(DLL名,函数名) 惰性缓存   */
/*                                                  */
/*  职责: 将给定地址解析为所属 DLL 和导出函数名。     */
/*        不预设关注名单，纯惰性——只有查询未命中时    */
/*        才会远程读取 DLL 镜像、本地 PE 解析后缓存。 */
/*                                                  */
/*  缓存策略:                                       */
/*    - x64/x32 两条链表，同一位数全局共享           */
/*    - 惰性填充：只有在查询中用到且解析成功才缓存    */
/*    - 无预填充、无关注名单                         */
/*    - 后续可升级为哈希表                           */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*           地址解析结果                           */
/**************************************************/

typedef struct _IOC_FUNC_INFO {
    PVOID   Address;
    PCWSTR  DllName;         /* 如 L"kernel32"           */
    PCWSTR  FuncName;        /* 如 L"LoadLibraryA"       */
} IOC_FUNC_INFO, *PIOC_FUNC_INFO;

/**************************************************/
/*               初始化与查询                       */
/**************************************************/

/*
 * 初始化（惰性模式下仅初始化锁）。
 * 启动时由 IocEngine_Initialize 调用。
 */
VOID
IocInitKnownDllAddresses(
    VOID
    );

/*
 * 将地址解析为 (DLL名, 函数名)。
 *
 * 流程:
 *   1. 判断目标进程位数（IsWow64Process）
 *   2. 遍历对应缓存链表（x64/x32）
 *   3. 命中 → 直接返回
 *   4. 未命中 → 惰性解析：
 *      a. EnumProcessModulesEx 获取模块列表
 *      b. 遍历模块，找 Address 所属模块
 *      c. 一次性 ReadProcessMemory 读入整个模块镜像
 *      d. 本地 PE 解析导出表，反查函数名
 *      e. 创建节点追加到缓存链表
 *      f. 填充 OutInfo 返回
 *
 * 参数:
 *   Address   — 待解析地址
 *   TargetProcessId — 目标进程 PID（用于判断位数 + 跨进程读取）
 *   OutInfo   — [可选] 输出解析结果
 */
NTSTATUS
IocMatchSensitiveFunc(
    _In_  ULONG64           Address,
    _In_  ULONG             TargetProcessId,
    _Out_ PIOC_FUNC_INFO    OutInfo
    );
