/**************************************************/
/*  WkDefender L2 — 主入口                          */
/*  初始化因果图引擎 + 阻塞等待用户退出              */
/*  作者: WkDefender Team                           */
/*  版本: 3.0.0                                     */
/**************************************************/

#include "./CausalityGraph/Engine.h"

/**************************************************/
/*                   主函数                         */
/**************************************************/

int main(void)
/*++
Routine Description:
    WkDefender L2 Agent 主入口。
    1. 加载默认配置
    2. 初始化因果图引擎（存储/事件/谱系/图/ALPC）
    3. 启动引擎
    4. 等待用户输入退出
    5. 清理并关闭

Return Value:
    0 = 正常退出, -1 = 初始化失败。
--*/
{
    NTSTATUS            status;
    ORC_ENGINE_CONFIG    config = CG_DEFAULT_CONFIG;

    /* 初始化引擎 */
    status = OrcEngineInitialize(&WkdOrchestratorEngine, &config);
    if (!NT_SUCCESS(status)) {
        printf("[FATAL] Engine initialization failed: 0x%X\n", status);
        return -1;
    }

    /* 启动引擎 */
    status = CgEngineStart(&WkdOrchestratorEngine);
    if (!NT_SUCCESS(status)) {
        printf("[FATAL] Engine start failed: 0x%X\n", status);
        CgEngineCleanup(&WkdOrchestratorEngine);
        return -1;
    }

    printf("[Agent] Engine is running. Press Enter to shutdown...\n\n");

    /* 阻塞等待用户输入 */
    getchar();

    /* 清理 */
    printf("[Agent] Shutting down...\n");
    CgEngineCleanup(&WkdOrchestratorEngine);

    printf("[Agent] Shutdown complete. Goodbye.\n");
    return 0;
}
