/**************************************************/
/*  WkDefender 内存签名 — 机制 B 核心实现 (纯 C YARA 解析器 + AC) */
/**************************************************/

#include "MemorySignature.h"
#include "../WkDefenderHeader.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* sqlite3 为 agent 既有依赖（StorageEngine 使用），此处直接引用。
 * 若编译环境无 sqlite3.h，需将 sqlite3 头加入 include 路径（与 StorageEngine.c 一致）。 */
#include <sqlite3.h>

/* 编译上限（DoS 防护，参考 CompilePattern 行 146/2051；MS_MAX_PATTERN_BYTES 已上移 .h） */
#define MS_MAX_PATTERN_STRING_LEN  10000
#define MS_MAX_RULE_TEXT_LEN       (4 * 1024 * 1024)
#define MS_MAX_RULE_NAME_LEN       256

/*====================================================================*/
/*  AC 节点 / 索引 管理                                  */
/*====================================================================*/

static MS_AC_NODE* MsAcNodeAlloc(VOID)
{
    MS_AC_NODE* n = (MS_AC_NODE*)calloc(1, sizeof(MS_AC_NODE));
    return n;   /* Child/WildcardChild/Failure 均为 NULL，OutputCount=0 */
}

static VOID MsAcNodeFree(_In_ MS_AC_NODE* Node)
{
    if (!Node) return;
    for (int i = 0; i < 256; i++) {
        if (Node->Child[i]) MsAcNodeFree(Node->Child[i]);
    }
    if (Node->WildcardChild) MsAcNodeFree(Node->WildcardChild);
    if (Node->OutputPatternIds) free(Node->OutputPatternIds);
    free(Node);
}

PMS_PATTERN_INDEX MsPatternIndexCreate(VOID)
{
    PMS_PATTERN_INDEX idx = (PMS_PATTERN_INDEX)calloc(1, sizeof(MS_PATTERN_INDEX));
    if (!idx) return NULL;
    idx->Root = MsAcNodeAlloc();
    if (!idx->Root) { free(idx); return NULL; }
    idx->NextPatternId = 1;
    idx->PatternCapacity = 64;
    idx->Patterns = (MS_PATTERN*)calloc(idx->PatternCapacity, sizeof(MS_PATTERN));
    if (!idx->Patterns) { MsAcNodeFree(idx->Root); free(idx); return NULL; }
    return idx;
}

VOID MsPatternIndexDestroy(_In_ PMS_PATTERN_INDEX Index)
{
    if (!Index) return;
    if (Index->Root) MsAcNodeFree(Index->Root);
    if (Index->Patterns) {
        for (UINT i = 0; i < Index->PatternCount; i++) {
            if (Index->Patterns[i].Bytes) free(Index->Patterns[i].Bytes);
            if (Index->Patterns[i].Mask) free(Index->Patterns[i].Mask);
            if (Index->Patterns[i].RuleName) free(Index->Patterns[i].RuleName);
        }
        free(Index->Patterns);
    }
    free(Index);
}

VOID MsFreePatternBuffer(_In_ BYTE* Bytes, _In_ BYTE* Mask)
{
    if (Bytes) free(Bytes);
    if (Mask) free(Mask);
}

/*====================================================================*/
/*  CompilePattern — YARA 模式 → (bytes, mask)            */
/*  参考 PatternCompiler::CompilePattern（行 110）            */
/*====================================================================*/

/* 把文本串（含转义）转为 hex 文本（便于复用 hex 解析分支） */
static BOOL MsTextToHex(_In_ const char* Text, _Out_ char* Out, _In_ size_t OutCap)
{
    size_t o = 0;
    for (size_t i = 0; Text[i]; i++) {
        char c = Text[i];
        unsigned char b = 0;
        if (c == '\\') {
            char n = Text[i + 1];
            if (n == 'n') b = 0x0A;
            else if (n == 'r') b = 0x0D;
            else if (n == 't') b = 0x09;
            else if (n == '\\') b = 0x5C;
            else if (n == '"') b = 0x22;
            else if (n == '0') b = 0x00;
            else if (n == 'x' && Text[i + 2] && Text[i + 3]) {
                unsigned int v = 0;
                if (sscanf_s(&Text[i + 2], "%2x", &v) == 1) b = (unsigned char)v;
                else b = 0;
                i += 3;
            } else { b = (unsigned char)n; i += 1; }
            i += 1; /* 跳过转义后的字符 */
        } else {
            b = (unsigned char)c;
        }
        /* 输出为两位 hex + 空格 */
        if (o + 3 >= OutCap) return FALSE;
        sprintf_s(&Out[o], OutCap - o, "%02X ", b);
        o += 3;
    }
    if (o > 0 && Out[o - 1] == ' ') Out[o - 1] = '\0';
    else Out[o] = '\0';
    return TRUE;
}

/* 单 hex token 解析：两字符 hex（如 "48"）或四字符紧凑（如 "8B05"） */
static int MsParseHexToken(_In_ const char* tok, _Out_ BYTE* outBytes, _Inout_ UINT* outLen)
{
    size_t L = strlen(tok);
    if (L == 2) {
        unsigned int v = 0;
        if (sscanf_s(tok, "%2x", &v) != 1) return -1;
        outBytes[(*outLen)] = (BYTE)v; (*outLen)++;
        return 1;
    }
    if (L == 4) { /* 紧凑写法 8B05 → 两字节 */
        unsigned int v = 0;
        if (sscanf_s(tok, "%4x", &v) != 1) return -1;
        outBytes[(*outLen)] = (BYTE)((v >> 8) & 0xFF); (*outLen)++;
        outBytes[(*outLen)] = (BYTE)(v & 0xFF); (*outLen)++;
        return 1;
    }
    return -1;
}

BOOL MsCompilePattern(
    _In_  LPCSTR PatternStr,
    _Out_ BYTE** OutBytes,
    _Out_ BYTE** OutMask,
    _Out_ UINT*  OutLength)
{
    *OutBytes = NULL; *OutMask = NULL; *OutLength = 0;
    if (!PatternStr) return FALSE;

    size_t len = strlen(PatternStr);
    if (len == 0 || len > MS_MAX_PATTERN_STRING_LEN) return FALSE;

    /* 正则 /.../ 范围外（ImportFromYaraFile 行 2031 跳过） */
    if (PatternStr[0] == '/') return FALSE;

    /* 文本串（双引号）→ 转 hex 后走 hex 分支 */
    char hexBuf[MS_MAX_PATTERN_STRING_LEN * 3 + 1];
    const char* work = PatternStr;
    if (PatternStr[0] == '"') {
        /* 去首尾引号，取内部 */
        size_t s = 1, e = len - 1;
        if (e < s) return FALSE;
        char inner[MS_MAX_PATTERN_STRING_LEN + 1];
        memcpy(inner, &PatternStr[s], e - s);
        inner[e - s] = '\0';
        if (!MsTextToHex(inner, hexBuf, sizeof(hexBuf))) return FALSE;
        work = hexBuf;
    }

    BYTE* bytes = (BYTE*)malloc(MS_MAX_PATTERN_BYTES);
    BYTE* mask  = (BYTE*)malloc(MS_MAX_PATTERN_BYTES);
    if (!bytes || !mask) { if (bytes) free(bytes); if (mask) free(mask); return FALSE; }

    UINT outLen = 0;
    const char* p = work;
    while (*p) {
        /* 跳空白 */
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (*p == '{') {
            /* 可能 hex 块开始，或 [min-max] 之外不应有 {；此处处理 hex 块结束前的内容 */
            p++; continue;
        }
        if (*p == '}') { p++; continue; }
        if (*p == '[') {
            /* (a-b) 字节范围 → 取下限（范围外多选，简化取下限） */
            p++;
            unsigned int lo = 0, hi = 0;
            if (sscanf_s(p, "%x-%x", &lo, &hi) < 1) { free(bytes); free(mask); return FALSE; }
            if (outLen >= MS_MAX_PATTERN_BYTES) { free(bytes); free(mask); return FALSE; }
            bytes[outLen] = (BYTE)lo; mask[outLen] = 0xFF; outLen++;
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
            continue;
        }
        if (*p == '(') {
            /* (a-b) 圆括号字节范围（YARA hex 语法）→ 取下限 */
            p++;
            unsigned int lo = 0, hi = 0;
            if (sscanf_s(p, "%x-%x", &lo, &hi) < 1) { free(bytes); free(mask); return FALSE; }
            if (outLen >= MS_MAX_PATTERN_BYTES) { free(bytes); free(mask); return FALSE; }
            bytes[outLen] = (BYTE)lo; mask[outLen] = 0xFF; outLen++;
            while (*p && *p != ')') p++;
            if (*p == ')') p++;
            continue;
        }
        if (*p == '{') { p++; continue; }

        /* 读取一个 token（到空白或括号/花括号） */
        char tok[16];
        size_t ti = 0;
        while (*p && !isspace((unsigned char)*p) && *p != '[' && *p != '(' &&
               *p != '{' && *p != '}' && *p != ']' && *p != ')') {
            if (ti < sizeof(tok) - 1) tok[ti++] = *p;
            p++;
        }
        tok[ti] = '\0';
        if (ti == 0) continue;

        if (strcmp(tok, "??") == 0) {
            /* 通配位：mask=0x00 */
            if (outLen >= MS_MAX_PATTERN_BYTES) { free(bytes); free(mask); return FALSE; }
            bytes[outLen] = 0x00; mask[outLen] = 0x00; outLen++;
        } else if (tok[0] == '{') {
            /* 应不会出现：{min-max} 在 tokenizer 中作为整体，此处兜底跳过 */
            while (*p && *p != '}') p++;
            if (*p == '}') p++;
        } else {
            /* hex token（2 或 4 字符） */
            if (MsParseHexToken(tok, bytes, &outLen) < 0) { free(bytes); free(mask); return FALSE; }
        }
    }

    if (outLen == 0) { free(bytes); free(mask); return FALSE; }
    if (outLen > MS_MAX_PATTERN_BYTES) { free(bytes); free(mask); return FALSE; }

    *OutBytes = bytes;
    *OutMask = mask;
    *OutLength = outLen;
    return TRUE;
}

/*====================================================================*/
/*  YARA 文本解析（替代 ImportFromYaraFile 文件读取）           */
/*  参考 ImportFromYaraFile（行 1660-2090）状态机               */
/*====================================================================*/

/* 取威胁级（meta 段内 threat_level/severity/level → MS_THREAT_LEVEL） */
static INT MsParseThreatLevel(_In_ const char* metaText)
{
    /* 依次查找 threat_level / severity / level 关键字 */
    const char* keys[] = { "threat_level", "severity", "level" };
    for (int k = 0; k < 3; k++) {
        const char* p = strstr(metaText, keys[k]);
        if (!p) continue;
        p += strlen(keys[k]);
        while (*p && (*p == ' ' || *p == '\t' || *p == '=' || *p == ':')) p++;
        if (*p == '"') {
            /* 字符串值：critical/high/medium/low/info */
            p++;
            char word[32]; size_t i = 0;
            while (*p && *p != '"' && i < sizeof(word) - 1) word[i++] = *p++;
            word[i] = '\0';
            if (_stricmp(word, "critical") == 0) return MsThreat_Critical;
            if (_stricmp(word, "high") == 0) return MsThreat_High;
            if (_stricmp(word, "medium") == 0) return MsThreat_Medium;
            if (_stricmp(word, "low") == 0) return MsThreat_Low;
            if (_stricmp(word, "info") == 0) return MsThreat_Info;
        } else {
            /* 数值：4/3/2/1/0 或 100/75/50/25/0 */
            int v = atoi(p);
            if (v >= 75 || v == 4) return MsThreat_Critical;
            if (v >= 50 || v == 3) return MsThreat_High;
            if (v >= 25 || v == 2) return MsThreat_Medium;
            if (v > 0   || v == 1) return MsThreat_Low;
            return MsThreat_Info;
        }
    }
    return MsThreat_Medium;   /* 默认中危（ImportFromYaraFile 行 1905） */
}

/* 跳过空白与注释 */
static const char* MsSkipWsComment(_In_ const char* p, _In_ const char* end)
{
    while (p < end) {
        if (isspace((unsigned char)*p)) { p++; continue; }
        if (p[0] == '/' && p + 1 < end && p[1] == '/') {
            while (p < end && *p != '\n') p++;
            continue;
        }
        if (p[0] == '/' && p + 1 < end && p[1] == '*') {
            p += 2;
            while (p < end && !(p[0] == '*' && p + 1 < end && p[1] == '/')) p++;
            if (p < end) p += 2;
            continue;
        }
        break;
    }
    return p;
}

/* 提取 rule body（从 '{' 到匹配 '}'） */
static const char* MsFindClosingBrace(_In_ const char* p, _In_ const char* end, _Out_ const char** bodyEnd)
{
    int depth = 0;
    BOOL inStr = FALSE;
    for (; p < end; p++) {
        if (*p == '"') inStr = !inStr;
        else if (!inStr && *p == '{') depth++;
        else if (!inStr && *p == '}') {
            depth--;
            if (depth == 0) { *bodyEnd = p; return p + 1; }
        }
    }
    *bodyEnd = end;
    return end;
}

UINT MsImportFromYaraRules(
    _In_ void* Db,
    _In_ PMS_PATTERN_INDEX Index)
{
    if (!Db || !Index) return 0;
    sqlite3* db = (sqlite3*)Db;

    const char* sql = "SELECT rule_text, rule_name FROM yara_rules WHERE enabled=1";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("[MsSig] prepare yara_rules failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    UINT importedRules = 0;
    UINT importedPatterns = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* ruleText = (const char*)sqlite3_column_text(stmt, 0);
        const char* ruleName = (const char*)sqlite3_column_text(stmt, 1);
        if (!ruleText) continue;
        size_t textLen = strlen(ruleText);
        if (textLen == 0 || textLen > MS_MAX_RULE_TEXT_LEN) continue;

        /* 定位 strings: 与 condition: 之间文本 */
        const char* stringsKw = strstr(ruleText, "strings:");
        const char* conditionKw = strstr(ruleText, "condition:");
        if (!stringsKw || !conditionKw || conditionKw <= stringsKw) continue;

        /* meta 段取威胁级 */
        const char* metaKw = strstr(ruleText, "meta:");
        char metaBuf[1024] = {0};
        if (metaKw && metaKw < stringsKw) {
            size_t ml = (size_t)(stringsKw - metaKw);
            if (ml >= sizeof(metaBuf)) ml = sizeof(metaBuf) - 1;
            memcpy(metaBuf, metaKw, ml);
        }
        INT threat = MsParseThreatLevel(metaBuf);

        /* 遍历 strings 段中每个 $var */
        const char* p = stringsKw + strlen("strings:");
        const char* stringsEnd = conditionKw;
        importedRules++;

        while (p < stringsEnd) {
            p = MsSkipWsComment(p, stringsEnd);
            if (p >= stringsEnd) break;
            if (*p != '$') { p++; continue; }

            /* 读变量名 */
            const char* vname = p + 1;
            const char* vnEnd = vname;
            while (vnEnd < stringsEnd && *vnEnd && *vnEnd != '=' && !isspace((unsigned char)*vnEnd)) vnEnd++;
            char varName[128];
            size_t vnl = (size_t)(vnEnd - vname);
            if (vnl >= sizeof(varName)) vnl = sizeof(varName) - 1;
            memcpy(varName, vname, vnl); varName[vnl] = '\0';

            /* 跳到 = 之后 */
            p = vnEnd;
            while (p < stringsEnd && *p != '=') p++;
            if (p >= stringsEnd) break;
            p++; /* 越过 = */
            p = MsSkipWsComment(p, stringsEnd);
            if (p >= stringsEnd) break;

            /* 分支：{ hex / " text / / regex(跳过) */
            if (*p == '/') {
                /* 正则范围外，跳过整条 */
                while (p < stringsEnd && *p != '\n') p++;
                continue;
            }

            char patStr[MS_MAX_PATTERN_STRING_LEN + 1];
            size_t pl = 0;
            BOOL ok = FALSE;
            if (*p == '{') {
                /* hex 块：读到匹配 } */
                p++;
                int depth = 1;
                while (p < stringsEnd && depth > 0 && pl < MS_MAX_PATTERN_STRING_LEN) {
                    if (*p == '{') depth++;
                    else if (*p == '}') { depth--; if (depth == 0) break; }
                    patStr[pl++] = *p; p++;
                }
                if (p < stringsEnd) p++; /* 越过 } */
                ok = TRUE;
            } else if (*p == '"') {
                /* 文本串：复制内部（含转义），交给 MsCompilePattern 处理 */
                p++;
                while (p < stringsEnd && *p != '"' && pl < MS_MAX_PATTERN_STRING_LEN) {
                    patStr[pl++] = *p; p++;
                }
                if (p < stringsEnd) p++;
                ok = TRUE;
            }
            if (!ok) { p++; continue; }
            patStr[pl] = '\0';

            /* 编译 */
            BYTE* bytes = NULL; BYTE* mask = NULL; UINT blen = 0;
            if (!MsCompilePattern(patStr, &bytes, &mask, &blen)) continue;
            if (blen < 2) { MsFreePatternBuffer(bytes, mask); continue; }  /* 至少 2 字节 */

            /* 构造签名名 ruleName.$var */
            char sigName[MS_MAX_RULE_NAME_LEN + 128];
            _snprintf_s(sigName, sizeof(sigName), _TRUNCATE, "%s.%s",
                        ruleName ? ruleName : "unknown", varName);

            if (MsPatternIndexAddPattern(Index, bytes, mask, blen, sigName, threat)) {
                importedPatterns++;
            } else {
                MsFreePatternBuffer(bytes, mask);
            }
        }
    }
    sqlite3_finalize(stmt);

    printf("[MsSig] Imported %u rules, %u patterns (threat-level default=Medium)\n",
           importedRules, importedPatterns);
    return importedRules;
}

/*====================================================================*/
/*  AC 构建与搜索                                       */
/*====================================================================*/

BOOL MsPatternIndexAddPattern(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ BYTE*  Bytes,
    _In_ BYTE*  Mask,
    _In_ UINT   Length,
    _In_opt_ LPCSTR RuleName,
    _In_ INT    ThreatLevel)
{
    if (!Index || !Index->Root || !Bytes || !Mask || Length == 0) return FALSE;

    /* 扩容 Patterns 数组 */
    if (Index->PatternCount >= Index->PatternCapacity) {
        UINT newCap = Index->PatternCapacity * 2;
        MS_PATTERN* np = (MS_PATTERN*)realloc(Index->Patterns, newCap * sizeof(MS_PATTERN));
        if (!np) return FALSE;
        Index->Patterns = np;
        ZeroMemory(&Index->Patterns[Index->PatternCapacity],
                   (newCap - Index->PatternCapacity) * sizeof(MS_PATTERN));
        Index->PatternCapacity = newCap;
    }

    UINT pid = Index->NextPatternId++;
    MS_PATTERN* pat = &Index->Patterns[Index->PatternCount];
    pat->Bytes = Bytes;
    pat->Mask = Mask;
    pat->Length = Length;
    pat->PatternId = pid;
    pat->RuleName = RuleName ? _strdup(RuleName) : NULL;
    pat->ThreatLevel = ThreatLevel;
    Index->PatternCount++;

    /* 建 Trie：仅 mask==0xFF 的字节走 Child[byte]，mask==0x00 走 WildcardChild */
    MS_AC_NODE* cur = Index->Root;
    for (UINT i = 0; i < Length; i++) {
        MS_AC_NODE** edge;
        if (Mask[i] == 0xFF) edge = &cur->Child[Bytes[i]];
        else                 edge = &cur->WildcardChild;

        if (*edge == NULL) {
            *edge = MsAcNodeAlloc();
            if (!*edge) return FALSE;
        }
        cur = *edge;
    }
    /* 终止节点挂 PatternId */
    UINT* no = (UINT*)realloc(cur->OutputPatternIds, (cur->OutputCount + 1) * sizeof(UINT));
    if (!no) return FALSE;
    cur->OutputPatternIds = no;
    cur->OutputPatternIds[cur->OutputCount++] = pid;

    Index->Built = FALSE;
    return TRUE;
}

BOOL MsPatternIndexBuild(_In_ PMS_PATTERN_INDEX Index)
{
    if (!Index || !Index->Root) return FALSE;
    MS_AC_NODE* root = Index->Root;

    /* BFS 构建失败链（标准 Aho-Corasick） */
    MS_AC_NODE** queue = (MS_AC_NODE**)malloc(sizeof(MS_AC_NODE*) * (Index->PatternCount * 256 + 256));
    if (!queue) return FALSE;
    INT qh = 0, qt = 0;

    for (int c = 0; c < 256; c++) {
        if (root->Child[c]) {
            root->Child[c]->Failure = root;
            queue[qt++] = root->Child[c];
        }
    }
    /* 根的通配子边失败链指向自身 */
    if (root->WildcardChild) {
        root->WildcardChild->Failure = root;
        queue[qt++] = root->WildcardChild;
    }

    while (qh < qt) {
        MS_AC_NODE* u = queue[qh++];
        for (int c = 0; c < 256; c++) {
            MS_AC_NODE* v = u->Child[c];
            if (v) {
                queue[qt++] = v;
                MS_AC_NODE* f = u->Failure;
                while (f && f != root && f->Child[c] == NULL) f = f->Failure;
                v->Failure = (f && f->Child[c]) ? f->Child[c] : root;
            }
        }
        /* 通配子边失败链 */
        if (u->WildcardChild) {
            MS_AC_NODE* v = u->WildcardChild;
            queue[qt++] = v;
            MS_AC_NODE* f = u->Failure;
            while (f && f != root && !f->WildcardChild) f = f->Failure;
            v->Failure = (f && f->WildcardChild) ? f->WildcardChild : root;
        }
    }
    free(queue);
    Index->Built = TRUE;
    return TRUE;
}

BOOL MsPatternIndexSearch(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ const BYTE* Buffer,
    _In_ SIZE_T Size,
    _In_ MS_MATCH_CALLBACK Callback)
{
    if (!Index || !Index->Root || !Buffer || Size == 0 || !Callback) return FALSE;
    MS_AC_NODE* root = Index->Root;
    MS_AC_NODE* state = root;

    for (SIZE_T pos = 0; pos < Size; pos++) {
        BYTE b = Buffer[pos];

        /* 沿失败链找能接受 b 的节点（精确边优先，其次通配边） */
        MS_AC_NODE* next = NULL;
        MS_AC_NODE* s = state;
        while (s != NULL) {
            if (s->Child[b]) { next = s->Child[b]; break; }
            if (s->WildcardChild) { next = s->WildcardChild; break; }
            s = (s == root) ? NULL : s->Failure;
        }
        state = next ? next : root;

        /* 收集：当前节点 + 沿失败链所有 output（避免后缀模式漏报） */
        MS_AC_NODE* n = state;
        while (n != NULL) {
            for (UINT k = 0; k < n->OutputCount; k++) {
                UINT pid = n->OutputPatternIds[k];
                if (pid == 0 || pid > Index->PatternCount) continue;
                PMS_PATTERN pat = &Index->Patterns[pid - 1];
                if (pat->Disabled) continue;   /* 逻辑禁用/删除模式跳过（SetEnabled/RemovePattern） */
                /* 通配回扫校验：仅 mask==0xFF 位要求与缓冲相等 */
                SIZE_T hitOff = pos - pat->Length + 1;
                BOOL matchOk = TRUE;
                if (hitOff <= Size && pat->Length > 0) {
                    for (UINT i = 0; i < pat->Length; i++) {
                        if (pat->Mask[i] == 0xFF &&
                            Buffer[hitOff + i] != pat->Bytes[i]) {
                            matchOk = FALSE; break;
                        }
                    }
                } else matchOk = FALSE;
                if (matchOk) {
                    Callback(pid, hitOff, pat);
                }
            }
            n = (n == root) ? NULL : n->Failure;
        }
    }
    return TRUE;
}

/*====================================================================*/
/*  模式运行时管理 — SS MemoryScanner 迁移（死代码）         */
/*  对齐 SS MsEnablePattern（L1296-1338）/ MsRemovePattern（L1196-1292）  */
/*====================================================================*/

/* 按 PatternId 定位模式（Patterns 数组下标 = PatternId-1，PatternId 复核防空洞） */
static PMS_PATTERN MsPatternFindById(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ UINT PatternId
    )
{
    if (Index == NULL || PatternId == 0 || PatternId > Index->PatternCount) return NULL;
    PMS_PATTERN p = &Index->Patterns[PatternId - 1];
    return (p->PatternId == PatternId) ? p : NULL;
}

/*++
 * MsPatternIndexSetEnabled
 *   临时启用/禁用模式（对齐 SS MsEnablePattern：Enable=FALSE → Disabled 标记，搜索跳过；
 *   已逻辑删除的模式拒绝恢复）。
 *   ※ 死代码: 运行时规则管理接线（wkd 默认以 yara_rules 表重建覆盖）。
 *--*/
BOOL MsPatternIndexSetEnabled(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ UINT PatternId,
    _In_ BOOLEAN Enable
    )
{
    PMS_PATTERN p = MsPatternFindById(Index, PatternId);
    if (p == NULL || p->Removed) return FALSE;
    p->Disabled = !Enable;
    return TRUE;
}

/*++
 * MsPatternIndexRemovePattern
 *   逻辑删除模式（对齐 SS MsRemovePattern 语义：搜索跳过 + SetEnabled 不可恢复）。
 *   ※ 死代码: wkd 数组实现保持连续性，不释放 Bytes/Mask（归 Index 所有，
 *     由 MsPatternIndexDestroy 统一回收）；下次 MsImportFromYaraRules 整体重建
 *     时自然排除，与 SS 链表删除 + 置 AhoCorasickReady=0 触发重建机制语义等价。
 *--*/
BOOL MsPatternIndexRemovePattern(
    _In_ PMS_PATTERN_INDEX Index,
    _In_ UINT PatternId
    )
{
    PMS_PATTERN p = MsPatternFindById(Index, PatternId);
    if (p == NULL || p->Removed) return FALSE;
    p->Removed = TRUE;
    p->Disabled = TRUE;
    return TRUE;
}
