/**************************************************/
/*  WkDefender — 排除子系统进程身份豁免               */
/*                                                   */
/*  2026-08-20 新增。进程维度豁免判定（无镜像内核    */
/*  假进程名单）。                                    */
/*                                                   */
/*  职责:                                            */
/*    - 判定进程名是否为"无镜像假进程"：System /      */
/*      Registry / Secure System / Memory             */
/*      Compression。这些进程是内核假进程，没有真实   */
/*      可执行文件（PsQueryFullProcessImageFileName   */
/*      语义下无文件），磁盘上不存在对应镜像。        */
/*                                                   */
/*  安全要点（红线，改动前必读）:                     */
/*    - 本名单只允许收录"无镜像内核假进程"。          */
/*      System/Registry 等名字用户态进程无法伪装      */
/*      （内核假进程无文件，进程创建回调/快照拿不到   */
/*      用户态可伪造的镜像名），豁免无绕过面。        */
/*    - 严禁扩展为通用进程名豁免：svchost.exe 等有    */
/*      真实文件的进程若按名豁免，恶意程序改名即可    */
/*      绕过（对齐 process_manager.c 禁杀名单"须位   */
/*      于系统二进制目录才生效"的防伪装设计）。        */
/*    - 有文件的进程豁免必须走文件四维                */
/*      ExemptsEvaluate（Hash>Cert>Publisher>Path）。 */
/*                                                   */
/*  与 ExemptInjection.c 同型：静态名单 + 纯函数，    */
/*  零全局状态、不依赖 Engine、不进 Manager、不持久化。*/
/**************************************************/

#include "ExemptsInternal.h"
#include <wchar.h>

/**************************************************/
/*           无镜像内核假进程名单                    */
/**************************************************/

/* 只允许添加"无镜像内核假进程"（见文件头安全要点红线） */
static const PCWSTR g_ExemptPseudoProcesses[] = {
    L"System",
    L"Registry",
    L"Secure System",
    L"MemCompression"
};

/**************************************************/
/*               判定实现                           */
/**************************************************/

BOOLEAN
CopExemptPseudoSystemProcessInternal(
    _In_ PCWSTR ProcessName
    )
/*++
Routine Description:
    判定进程名是否为无镜像内核假进程（精确匹配，不区分大小写）。

    调用方须知（职责边界）:
      - 仅用于 ProcessCreate 前置快速通道：假进程无文件可析，
        深度静态分析无输入意义，跳过防资源浪费与低质信号。
      - 本判定是"进程身份"豁免，与 ExemptsEvaluate（文件四维：
        Hash>Cert>Publisher>Path）互补且前置；有真实文件的进程
        一律走 ExemptsEvaluate，禁止按名豁免。

Arguments:
    ProcessName - 进程文件名（如 L"System"）。

Return Value:
    TRUE = 无镜像内核假进程（豁免）；FALSE = 非假进程。
--*/
{
    if (!CoCheckStringValidity(ProcessName)) return FALSE;

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_ExemptPseudoProcesses); i++) {
        if (_wcsicmp(ProcessName, g_ExemptPseudoProcesses[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}
