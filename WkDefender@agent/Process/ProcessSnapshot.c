/**************************************************/
/*  WkDefender Agent — 进程域快照兜底实现           */
/*                                                  */
/*  2026-08-15 迁自 process_manager.c 快照段。       */
/*  只维护进程域树，不产生 IOA 事件。                 */
/*  竞态: Toolhelp 枚举与驱动事件并发，刚创建未枚举   */
/*  到的进程可能被差集误标退出，但进程若仍存活，       */
/*  下次快照/事件会自我修复。                        */
/**************************************************/

#include "ProcessSnapshot.h"
#include "../Process/ProcessTree.h"
#include "../Process/ProcessModule.h"     /* 存量进程模块补挂 (2026-08-15) */
#include "../IOC/IocProcessEnrich.h"    /* IpeCategorizeProcess/IpeCollectUserContext/IpeRecordProcessExit */
#include "../WkDefenderHeader.h"         /* IMG_SIGNATURE_UNEVALUATED */
#include "../tools.h"
#include <tlhelp32.h>

static HANDLE g_SnapshotThread = NULL;
static HANDLE g_SnapshotStopEvent = NULL;

/**************************************************/
/*               内部辅助函数                       */
/**************************************************/

/* 从宽字符串深拷贝为 UNICODE_STRING（借用源缓冲，拷贝期间只读） */
static
VOID
SnapSetWstr(
    _Inout_ PUNICODE_STRING* Out,
    _In_    PCWSTR           Src
    )
{
    UNICODE_STRING tmp;

    if (!Out || !Src || !Src[0]) return;

    tmp.Length = (USHORT)(wcslen(Src) * sizeof(WCHAR));
    tmp.MaximumLength = tmp.Length + sizeof(WCHAR);
    tmp.Buffer = (PWCHAR)Src;
    CoCopyUnicodeString(Out, &tmp);
}

/* 谱系:轻量 PPID 检测 + 孤儿判定（WKD_PROCESS 版，
 * 对齐 SS DetectPPIDSpoofingImpl 三启发式） */
static
VOID
ProcessSnapshot_DetectPpidSpoof(
    _Inout_ PWKD_PROCESS Node
    )
{
    PWKD_PROCESS parent;

    if (Node == NULL) return;

    if (Node->ParentProcessId == 0 || Node->ParentProcessId == 4) {
        return;   /* PID 0 / System 根,无父判定意义 */
    }

    parent = NULL;
    NTSTATUS _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, (HANDLE)(ULONG_PTR)Node->ParentProcessId, NULL, &parent);
    if (!NT_SUCCESS(_status)) return;
    /* 注: IsOrphan 由 PtTreeUpsertSnapshot 的链接逻辑统一负责
     * (父不在时设 TRUE 并挂 PendingOrphans), 此处不双写。 */

    /* 规则1: 父创建时间晚于子(物理上不可能) */
    if (parent->CreateTime.QuadPart > Node->CreateTime.QuadPart) {
        Node->IsPpidSpoofed = TRUE;
        printf("[ProcessSnapshot] PPID spoofing: PID=%lu claims parent %lu created AFTER child\n",
               Node->ProcessId, Node->ParentProcessId);
    }

    /* 规则2: smss.exe 直接生成用户应用 */
    if (parent->ImageFileName && parent->ImageFileName->Buffer &&
        _wcsicmp(parent->ImageFileName->Buffer, L"smss.exe") == 0) {
        if (Node->ProcessCategory != (ULONG)WkdPcSystemCritical &&
            Node->ProcessCategory != (ULONG)WkdPcSystemCore &&
            Node->ProcessCategory != (ULONG)WkdPcSystemService) {
            Node->IsPpidSpoofed = TRUE;
            printf("[ProcessSnapshot] PPID spoofing: PID=%lu claims smss.exe as parent\n",
                   Node->ProcessId);
        }
    }

    PsDereferenceWkdProcess(parent);   /* 归还查找 pin */
}

/* 元数据富化:用户/域/完整性/提权/WoW64/保护
 * (对齐 SS EnrichFromLiveProcess;复用 IpeCollectUserContext) */
static
VOID
ProcessSnapshot_EnrichNode(
    _Inout_ PWKD_PROCESS Node
    )
{
    WKD_USER_CONTEXT ctx;

    if (Node == NULL) return;

    RtlZeroMemory(&ctx, sizeof(ctx));
    if (IpeCollectUserContext(Node->ProcessId, &ctx)) {
        wcsncpy_s(Node->UserName, RTL_NUMBER_OF(Node->UserName), ctx.UserName, _TRUNCATE);
        wcsncpy_s(Node->DomainName, RTL_NUMBER_OF(Node->DomainName), ctx.DomainName, _TRUNCATE);
        if (ctx.IntegrityLevel != 0) Node->IntegrityLevel = ctx.IntegrityLevel;
        Node->IsElevated = ctx.IsElevated;
        Node->IsWow64 = ctx.IsWow64;
    }

    /* IsProtectedProcess: OpenProcess 失败判定（对齐原快照 ACCESS_DENIED 分支；
     * 保护等级查询 WkGetProtectionInfoInternal 为 process_manager 内部 static，此处不依赖） */
    if (Node->IsProtectedProcess == FALSE) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Node->ProcessId);
        if (hProc == NULL) Node->IsProtectedProcess = TRUE;
        else CloseHandle(hProc);
    }

    Node->MetadataComplete = TRUE;
}

/* 快照差集退出回调：记录历史（对齐 IpeRecordProcessExit） */
static
VOID
ProcessSnapshot_OnExit(
    _In_ ULONG   Pid,
    _In_ PCWSTR  ImageFileName
    )
{
    IpeRecordProcessExit(Pid, ImageFileName);
}

/* 存量进程模块补挂（2026-08-15）：快照纳管的进程模块从未经过
 * ImageLoad 事件（agent 上线前已加载），此处一次性 Toolhelp 枚举
 * 补挂 WKD_MODULE + 进程视图，补齐模块域覆盖缺口。
 * 在快照线程内执行（异步，不阻塞事件线程）；与 ImageLoad 事件并发
 * 由 PsModuleInstanceAttachProcess 的 ImageBase 去重幂等兜底。已存在模块走
 * PsFindOrCreateModule 查表复用（O(1)），仅新模块触发 IocAnalyzePeFromFilePath。 */
static
VOID
ProcessSnapshot_AttachModules(
    _In_ PWKD_PROCESS Node
    )
{
    HANDLE hMod;
    MODULEENTRY32W me;

    if (!Node || Node->ProcessId == 0 || Node->ProcessId == 4) {
        return;
    }

    hMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                    Node->ProcessId);
    if (hMod == INVALID_HANDLE_VALUE) return;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hMod, &me)) {
        do {
            PWKD_MODULE module = NULL;

            if (me.szExePath[0] == L'\0') continue;
            if (NT_SUCCESS(PsFindOrCreateModule(me.szExePath,
                                                (ULONG64)me.modBaseSize,
                                                IMG_SIGNATURE_UNEVALUATED,
                                                &module))) {
                PsModuleInstanceAttachProcess(Node, module, me.modBaseAddr, NULL);
                PsDereferenceWkdModule(module);   /* 释放查找 pin */
            }
        } while (Module32NextW(hMod, &me));
    }
    CloseHandle(hMod);
}

/**************************************************/
/*               快照刷新                           */
/**************************************************/

static
NTSTATUS
ProcessSnapshot_RefreshOnce(
    VOID
    )
/*++
Routine Description:
    Toolhelp 快照一轮：枚举当前 PID 集合 → 差集 upsert → 差集 reconcile。
    只维护进程域树（WkdProcessTree），不产生 IOA 事件。
--*/
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    ULONG* currentPids = NULL;
    ULONG pidCount = 0;
    ULONG pidCap = 0;
    PWKD_PROCESS node;
    HANDLE hProc;
    WCHAR path[MAX_PATH];
    DWORD pathSize;
    DWORD sessionId;
    LARGE_INTEGER createTime;
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    ULONG i;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return STATUS_UNSUCCESSFUL;
    }

    do {
        ULONG currentPid = pe.th32ProcessID;

        /* 收集当前 PID(阶段4 差集用) */
        if (pidCount >= pidCap) {
            ULONG newCap = pidCap ? pidCap * 2 : 512;
            ULONG* np = (ULONG*)realloc(currentPids, newCap * sizeof(ULONG));
            if (np == NULL) break;
            currentPids = np;
            pidCap = newCap;
        }
        currentPids[pidCount++] = currentPid;

        /* 构造快照节点（GUID=零、NodeSource=Snapshot）
         * 2026-08-25 堆口径对齐: 节点本体统一 malloc — 入树后与
         * 事件创建节点共用 PspDestroyWkdProcess 的 free 释放,
         * 禁止与 Ut 堆混用 (同型双堆必有一半跨堆)。 */
        node = (PWKD_PROCESS)malloc(sizeof(WKD_PROCESS));
        if (node == NULL) continue;
        RtlZeroMemory(node, sizeof(*node));

        node->ProcessId = currentPid;
        node->ParentProcessId = pe.th32ParentProcessID;
        node->NodeSource = WkdProcessSource_Snapshot;
        SnapSetWstr(&node->ImageFileName, pe.szExeFile);

        /* 路径/创建时间/会话 */
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, currentPid);
        if (hProc != NULL) {
            pathSize = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, path, &pathSize)) {
                SnapSetWstr(&node->ImagePath, path);
            }
            if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                createTime.LowPart = ftCreate.dwLowDateTime;
                createTime.HighPart = ftCreate.dwHighDateTime;
                node->CreateTime = createTime;
            }
            sessionId = 0;
            if (ProcessIdToSessionId(currentPid, &sessionId)) node->SessionId = sessionId;
            CloseHandle(hProc);
        } else {
            node->IsProtectedProcess = TRUE;   /* 无权限访问 → 受保护 */
        }
        if (node->ImagePath == NULL) SnapSetWstr(&node->ImagePath, L"Unknown");

        node->ProcessCategory = (ULONG)IpeCategorizeProcess(
            node->ImageFileName ? node->ImageFileName->Buffer : L"",
            node->ImagePath ? node->ImagePath->Buffer : L"");
        ProcessSnapshot_EnrichNode(node);
        ProcessSnapshot_DetectPpidSpoof(node);
        node->MetadataComplete = TRUE;

        /* upsert 到进程域树（同 PID 存活节点刷新+补富化，不重插）。
         * 插入路径树持有节点；未插入节点由 PtTreeUpsertSnapshot 内部释放。 */
        PtTreeUpsertSnapshot(&WkdProcessTree, node);

        /* 存量进程模块补挂（2026-08-15）：对树中生效的 Snapshot 源节点
         * 枚举模块挂载。Driver 源节点由 ImageLoad 事件流覆盖，不重复枚举；
         * 必须对 upsert 后的 liveNode 操作（临时 node 可能未插入被释放）。 */
        {
            PWKD_PROCESS liveNode = NULL;
            NTSTATUS _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, (HANDLE)(ULONG_PTR)currentPid, NULL, &liveNode);
            if (NT_SUCCESS(_status) && liveNode) {
                if (liveNode->NodeSource == WkdProcessSource_Snapshot) {
                    ProcessSnapshot_AttachModules(liveNode);
                }
                PsDereferenceWkdProcess(liveNode);   /* 归还查找 pin */
            }
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);

    /* 阶段4: 差集删除存活快照节点（Driver 节点由驱动事件控制生命周期） */
    PtTreeReconcileSnapshot(&WkdProcessTree, currentPids, pidCount, ProcessSnapshot_OnExit);

    if (currentPids != NULL) free(currentPids);

    return STATUS_SUCCESS;
}

/**************************************************/
/*               线程生命周期                       */
/**************************************************/

static DWORD WINAPI
ProcessSnapshot_ThreadProc(
    _In_ LPVOID Parameter
    )
{
    UNREFERENCED_PARAMETER(Parameter);

    while (WaitForSingleObject(g_SnapshotStopEvent, 60000) == WAIT_TIMEOUT) {
        ProcessSnapshot_RefreshOnce();
    }
    return 0;
}

NTSTATUS
ProcessSnapshot_Start(
    VOID
    )
{
    if (g_SnapshotThread != NULL) return STATUS_SUCCESS;

    g_SnapshotStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_SnapshotStopEvent == NULL) return STATUS_UNSUCCESSFUL;

    /* 启动前先做一次快照,确保进程表有数据(兜底驱动未装) */
    ProcessSnapshot_RefreshOnce();

    g_SnapshotThread = CreateThread(NULL, 0, ProcessSnapshot_ThreadProc, NULL, 0, NULL);
    if (g_SnapshotThread == NULL) {
        CloseHandle(g_SnapshotStopEvent);
        g_SnapshotStopEvent = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

VOID
ProcessSnapshot_Stop(
    VOID
    )
{
    if (g_SnapshotStopEvent != NULL) {
        SetEvent(g_SnapshotStopEvent);
        if (g_SnapshotThread != NULL) {
            WaitForSingleObject(g_SnapshotThread, 5000);
            CloseHandle(g_SnapshotThread);
            g_SnapshotThread = NULL;
        }
        CloseHandle(g_SnapshotStopEvent);
        g_SnapshotStopEvent = NULL;
    }
}
