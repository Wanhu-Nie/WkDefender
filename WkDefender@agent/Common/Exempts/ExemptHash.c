/**************************************************/
/*  WkDefender — 排除子系统哈希判定                 */
/*                                                   */
/*  职责：文件哈希豁免判定。规则数据由                */
/*  ExemptsManager 存储仓库持有，本组件仅做判定      */
/*  转发（对齐驱动侧 ExemptHash 组件职责划分）。      */
/**************************************************/

#include "ExemptsInternal.h"

_Use_decl_annotations_
BOOLEAN
ExemptHash_IsWhitelisted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PDEF_SHA256_HASH Hash
    )
/*++
Routine Description:
    哈希规则命中判定：查 Manager 哈希规则表。

Arguments:
    Engine - 子系统全局。
    Hash   - 文件 SHA256。

Return Value:
    TRUE 命中哈希规则（豁免）。
--*/
{
    return ExemptsMgr_FindHashRule(Engine, Hash, NULL);
}
