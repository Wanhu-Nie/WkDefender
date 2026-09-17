/**************************************************/
/*  WkDefender IOA — ROP 模式检测器宿主接线        */
/*  实现 (RopWiring.cpp)                   */
/*                                                  */
/*  迁移自 ShadowStrike RopWiring.cpp               */
/*  (RopWiring.cpp/.hpp, v3.0.0)                    */
/*  功能重实现 (C 重写), 非源码复制。                */
/**************************************************/

#include "RopPatternDetectorHost.h"
#include "RopPatternDetector.h"

/*++ RpdHostInitialize — 初始化并启动 ROP 模式检测器
 *
 * InitROPProtection:
 *   1. ROPProtection::Instance()      → C 静态全局 g_Rpd 天然存在
 *   2. IsInitialized() == false 时 Initialize()
 *      (失败: SS Logger::Warn + return false → 本实现返回 FALSE)
 *   3. Start()                        → RpdInitialize 成功即置
 *      RpdStatus_Running, 此处保留启动就绪断言维持 fail-closed
 *   4. SS catch(...) 吞异常返回 false → C 无异常语义, Rpd 模块
 *      API 均为内存安全实现, fail-safe 由返回值表达
 *
 * 返回值: TRUE = 已就绪; FALSE = 初始化失败或未达 Running。
 * 重复调用幂等 (对齐 SS: 已初始化则跳过 Initialize)。
 * --*/
BOOLEAN
RpdHostInitialize(VOID)
{
    /* SS: ROPProtection::Instance() —— 无需对应物 */
    if (!RpdIsInitialized()) {
        /* SS: Initialize() 失败 → Warn 日志 + return false */
        if (!NT_SUCCESS(RpdInitialize(NULL))) {
            return FALSE;
        }
    }

    /* SS: Start() 显式置 Running (未初始化时 Start 直接失败);
     * Rpd 侧 RpdInitialize 成功即 Running, 断言保持等价语义. */
    if (RpdGetStatus() != RpdStatus_Running) {
        return FALSE;
    }

    return TRUE;
}

/*++ RpdHostShutdown — 关闭 ROP 模式检测器
 *
 * ShutdownROPProtection:
 *   1. HasInstance() 守卫: SS 不存在单例则直接返回, 绝不创建
 *      单例仅为关闭; C 侧对应"模块从未初始化" (静态全局永远
 *      "存在", 故以 IsInitialized 表达同一语义)
 *   2. IsInitialized() == false 则直接返回
 *   3. Shutdown() (SS catch 吞异常 → C 无异常语义)
 * --*/
VOID
RpdHostShutdown(VOID)
{
    if (!RpdIsInitialized()) {
        return;
    }

    RpdShutdown();
}