/**************************************************/
/*  WkDefender IOA — Tier3 分析器回调实现             */
/*                                                  */
/*  每个分析器注册一组 T3_ANALYZER_CALLBACKS:         */
/*    ScoreCand   — 提取参数+深化内容+评分            */
/*    TryFuse     — 融合尝试 (可选)                  */
/*    FulfillCheck — 满足检查 (标记 Active=FALSE)     */
/*    DeriveNeeds  — 需求推导                        */
/*    UpdateMitreProbs — 概率更新                    */
/*                                                  */
/*  公共骨架 T3pProcessCore 自动编排上述回调。        */
/**************************************************/

#include "CausalAnalyzer.h"
#include "CausalInference.h"
#include "../IoaEngine.h"
#include "../IoaEdgeAggregate.h"
#include "../../Common/Utils.h"
#include "../../Storage/StorageEngine.h"
#include "../../IOC/IocKnownDll.h"
#include <string.h>

/*
 * 某些 Windows SDK 版本未导出 NtCreateThreadEx 的 CreateFlags 常量，
 * 此处显式定义以确保兼容。
 */
#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED    0x00000001
#endif

/**************************************************/
/*           公共辅助                               */
/**************************************************/

static
PEVENT_PAYLOAD_SYSCALL
T3pLoadSyscallParams(
    _In_ PWKD_EVENT_HEADER Event
    )
/*++
Routine Description:
    从 WKD_EVENT_HEADER 提取 syscall 参数。
    返回 Payload 指针，或 NULL (类型不匹配或 Payload 过小)。
--*/
{
    if (!Event) return NULL;
    if (Event->PayloadSize < sizeof(EVENT_PAYLOAD_SYSCALL)) return NULL;
    return (PEVENT_PAYLOAD_SYSCALL)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
}

static
HANDLE
T3pOpenTargetProcess(
    _In_ GUID TargetNodeId
    )
/*++
Routine Description:
    通过进程 NodeId 获取目标进程句柄 (PROCESS_VM_READ)。
    失败返回 NULL。
--*/
{
    PWKD_PROCESS tgtNode;

    tgtNode = PtTreeLookupByNodeId(
        &WkdProcessTree, TargetNodeId);
    if (!tgtNode || !tgtNode->Alive) return NULL;

    return OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        (DWORD)(ULONG_PTR)tgtNode->ProcessId);
}

static
VOID
T3pReadTargetMemory(
    _In_    ULONG64  RemoteAddr,
    _In_    GUID     TargetNodeId,
    _Out_   UCHAR*   Buffer,
    _In_    ULONG    BufferSize,
    _Out_   PSIZE_T  BytesRead,
    _Out_   PBOOLEAN OutHasMZ,
    _Out_   PBOOLEAN OutHasDllPath
    )
/*++
Routine Description:
    读取目标进程内存，分析内容特征。
    设置 HasMZ / HasDllPath 标记。
    若 ReadProcessMemory 失败则标记 ContentConfidence=0。
--*/
{
    HANDLE hTarget;
    SIZE_T actualRead = 0;

    if (OutHasMZ) *OutHasMZ = FALSE;
    if (OutHasDllPath) *OutHasDllPath = FALSE;
    if (BytesRead) *BytesRead = 0;

    hTarget = T3pOpenTargetProcess(TargetNodeId);
    if (!hTarget || hTarget == INVALID_HANDLE_VALUE) {
        return;
    }

    if (!ReadProcessMemory(hTarget,
                           (LPCVOID)(ULONG_PTR)RemoteAddr,
                           Buffer, BufferSize, &actualRead) ||
        actualRead == 0) {
        CloseHandle(hTarget);
        return;
    }

    CloseHandle(hTarget);

    if (BytesRead) *BytesRead = actualRead;

    /* MZ 魔数 */
    if (actualRead >= 2 && Buffer[0] == 0x4D && Buffer[1] == 0x5A) {
        if (OutHasMZ) *OutHasMZ = TRUE;
    }

    /* DLL 路径检测 */
    if (actualRead >= 4 && OutHasDllPath) {
        BOOLEAN allPrintable = TRUE;
        ULONG strLen = 0;
        for (ULONG i = 0; i < min(actualRead, (SIZE_T)BufferSize); i++) {
            if (Buffer[i] == 0) { strLen = i; break; }
            if (Buffer[i] < 0x20 || Buffer[i] > 0x7E) {
                if (Buffer[i] != '\\' && Buffer[i] != ':') {
                    allPrintable = FALSE;
                    break;
                }
            }
        }
        if (allPrintable && strLen > 4) {
            if ((Buffer[strLen-4] == '.' || Buffer[strLen-4] == 'd') &&
                (Buffer[strLen-3] == 'd' || Buffer[strLen-3] == 'l') &&
                (Buffer[strLen-2] == 'l' || Buffer[strLen-2] == 'l')) {
                *OutHasDllPath = TRUE;
            }
            if (Buffer[0] >= 'A' && Buffer[0] <= 'Z' && Buffer[1] == ':') {
                *OutHasDllPath = TRUE;
            }
        }
    }
}

/**************************************************/
/*           通用概率更新辅助                       */
/**************************************************/

static
VOID
T3pProbAdd(
    _Inout_ PT3_MITRE_PROB_DIST Probs,
    _In_    PCWSTR              TechniqueId,
    _In_    DOUBLE              Delta,
    _In_    PCWSTR              Rationale
    )
/*++
Routine Description:
    在概率组中增加某技术的概率 (带裁剪 [0.0, 1.0])。
--*/
{
    ULONG i;

    if (!Probs) return;

    for (i = 0; i < Probs->Count; i++) {
        if (Probs->Entries[i].TechniqueId == NULL) {
            /* 空槽位 */
            Probs->Entries[i].TechniqueId = TechniqueId;
            Probs->Entries[i].Probability = max(0.0, min(1.0, Delta));
            Probs->Entries[i].Rationale = Rationale;
            return;
        }
        if (wcscmp(Probs->Entries[i].TechniqueId, TechniqueId) == 0) {
            Probs->Entries[i].Probability = max(0.0, min(1.0,
                Probs->Entries[i].Probability + Delta));
            if (Rationale) Probs->Entries[i].Rationale = Rationale;
            return;
        }
    }
}

/**************************************************/
/*           ThreadCreate 分析器                    */
/**************************************************/

static
ULONG
T3pScoreCand_ThreadCreate(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
/*++
Routine Description:
    ScoreCand — ThreadCreate 分析器。
    提取 StartRoutine / Parameter / CreateFlags 等参数，
    通过对比 LoadLibrary 函数地址判断注入类型（不再依赖 BehaviorFlags），
    参照 Wishlist 评分。

    注入类型推断（优先级从高到低）:
      1. StartRoutine == LoadLibraryA/W/ExA/ExW → DLL 注入, 置信度 95
      2. CREATE_SUSPENDED → Process Hollowing, 置信度 90
      3. 其他 → Shellcode/PE 注入, 置信度 90

    评分逻辑:
      DLL 注入 → 100
      Hollowing → 60
      Shellcode/PE → 60

    说明:
      LoadLibrary 地址通过本进程的 kernel32.dll 获取（KnownDLLs 跨进程共享，
      同一会话中所有进程映射地址相同），无需 ReadProcessMemory。MemoryWrite
      侧只需地址匹配即可确认依赖，无需重复读取内容。
--*/
{
    PEVENT_PAYLOAD_THREAD_CREATE payload = NULL;
    PWKD_EVENT_HEADER event = NULL;
    ULONG score = 30;

    UNREFERENCED_PARAMETER(Wishlist);

    if (!Candidate || !OutItem) return 0;

    /* 加载事件 → 提取参数 */
    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event))) {
        OutItem->EventType     = event->Type;
        OutItem->EventClass    = event->Class;
        OutItem->BehaviorFlags = event->BehaviorFlags;

        if (event->PayloadSize == sizeof(EVENT_PAYLOAD_THREAD_CREATE)) {
            payload = (PEVENT_PAYLOAD_THREAD_CREATE)
                ((PUCHAR)event + sizeof(WKD_EVENT_HEADER));

            if (payload) {
                OutItem->Params.ThreadCreate.StartRoutine       = (ULONG64)payload->StartRoutine;
                OutItem->Params.ThreadCreate.Parameter          = (ULONG64)payload->Argument;
                OutItem->Params.ThreadCreate.SyscallCreateFlags = payload->CreateFlags;
                OutItem->Params.ThreadCreate.DesiredAccess      = payload->DesiredAccess;
                OutItem->Params.ThreadCreate.CreationFlags      = payload->Flags;
            }
        }
        UtHeapFree(event);
    }

    /* 初始默认值 */
    OutItem->Params.ThreadCreate.IsApc          = FALSE;
    OutItem->Params.ThreadCreate.IsLoadLibrary  = FALSE;

    /*
     * 内容深化 — 注入类型推断
     *
     * 不再依赖 BehaviorFlags（不可靠，假设为空）。
     * 委托给 IOC 模块（IocIsKnownLoadLibrary）做 LoadLibrary 地址判断。
     * IOC 模块内部维护 x64/x32 两套全局缓存，按目标进程位数自动选择。
     * 相同位数的所有进程地址一致，不按 PID 缓存。
     */
    {
        ULONG64 startRoutine = OutItem->Params.ThreadCreate.StartRoutine;

        /* 从候选信息中获取目标进程 PID */
        ULONG targetPid = 0;
        if (Candidate) {
            PWKD_PROCESS tgtNode = PtTreeLookupByNodeId(
                &WkdProcessTree, Candidate->TargetNodeId);
            if (tgtNode) {
                targetPid = (ULONG)(ULONG_PTR)tgtNode->ProcessId;
            }
        }

        IOC_FUNC_INFO funcInfo;
        const WCHAR funcName[] = L"LoadLibrary";
        if (NT_SUCCESS(IocMatchSensitiveFunc(startRoutine, targetPid, &funcInfo)) &&
            wcsncmp(funcInfo.FuncName, funcName, wcslen(funcName)) == 0) {
            OutItem->Params.ThreadCreate.IsLoadLibrary = TRUE;
            OutItem->ContentConfidence = 95;
            score = 100;
        } else if (OutItem->Params.ThreadCreate.SyscallCreateFlags &
                   THREAD_CREATE_FLAGS_CREATE_SUSPENDED) {
            /* 挂起创建 → Process Hollowing 特征 */
            OutItem->ContentConfidence = 90;
            score = 60;
        } else {
            /* 默认: Shellcode / PE 注入 */
            OutItem->ContentConfidence = 90;
            score = 60;
        }
    }

    OutItem->Description = L"CreateRemoteThread/QueueUserApc";
    return score;
}

static
VOID
T3pFulfillCheck_ThreadCreate(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    FulfillCheck — ThreadCreate 作为最后一步，通常 Wishlist 为空。
    若有后序需求（如 Hollowing 链中后接 ResumeThread），检查线程创建是否满足。
--*/
{
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Wishlist);
    /* 当前无后序需求逻辑 */
}

static
VOID
T3pDeriveNeeds_ThreadCreate(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    DeriveNeeds — ThreadCreate 推导前序依赖:
      DLL 注入: 需要在 Parameter 地址写入 DLL 路径
      Shellcode: 需要在 StartRoutine 地址写入代码
      公共: 需要 PROCESS_CREATE_THREAD|VM_WRITE|VM_OP 句柄
--*/
{
    TIRE3_WISH_ENTRY wish;

    if (OutItem->Params.ThreadCreate.IsLoadLibrary) {
        /* DLL 注入 */
        RtlZeroMemory(&wish, sizeof(wish));
        wish.NeedWriteAt        = TRUE;
        wish.RequiredWriteAddr  = OutItem->Params.ThreadCreate.Parameter;
        wish.RequiredWriteSize  = (ULONG)-1;    // 到底写了多少？不确定
        wish.NeedDllPath        = TRUE;
        WishAppend(Wishlist, &wish);

        RtlZeroMemory(&wish, sizeof(wish));
        wish.NeedAllocCover     = TRUE;
        wish.RequiredAllocMin   = OutItem->Params.ThreadCreate.Parameter;
        wish.RequiredAllocMax   = OutItem->Params.ThreadCreate.Parameter + 260;
        WishAppend(Wishlist, &wish);

    } else {
        /* Shellcode / PE 注入 */
        RtlZeroMemory(&wish, sizeof(wish));
        wish.NeedWriteAt        = TRUE;
        wish.RequiredWriteAddr  = OutItem->Params.ThreadCreate.StartRoutine;
        wish.RequiredWriteSize  = 0x1000;     /* 默认 4KB shellcode */
        wish.NeedPeImage        = TRUE;
        WishAppend(Wishlist, &wish);

        RtlZeroMemory(&wish, sizeof(wish));
        wish.NeedAllocCover     = TRUE;
        wish.RequiredAllocMin   = OutItem->Params.ThreadCreate.StartRoutine;
        wish.RequiredAllocMax   = OutItem->Params.ThreadCreate.StartRoutine + 0x1000;
        WishAppend(Wishlist, &wish);

        RtlZeroMemory(&wish, sizeof(wish));
        wish.NeedExeMemory      = TRUE;
        WishAppend(Wishlist, &wish);
    }

    /* 公共: 句柄权限 */
    RtlZeroMemory(&wish, sizeof(wish));
    wish.NeedAccessMask = TRUE;
    wish.RequiredAccessMask = PROCESS_CREATE_THREAD |
                               PROCESS_VM_WRITE |
                               PROCESS_VM_OPERATION;
    WishAppend(Wishlist, &wish);
}

static
VOID
T3pUpdateProbs_ThreadCreate(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
/*++
Routine Description:
    UpdateMitreProbs — ThreadCreate 证据更新概率。
--*/
{
    if (OutItem->Params.ThreadCreate.IsApc) {
        T3pProbAdd(Probs, L"T1055.004", 0.5, L"APC注入确认");
    } else if (OutItem->Params.ThreadCreate.IsLoadLibrary) {
        T3pProbAdd(Probs, L"T1055.001", 0.6, L"LoadLibrary远程线程");
        T3pProbAdd(Probs, L"T1055.012", -0.1, L"非Hollowing(有Parameter)");
        T3pProbAdd(Probs, L"T1055.004", 0.1, L"备选:可能是APC");
    } else if (OutItem->Params.ThreadCreate.SyscallCreateFlags &
               THREAD_CREATE_FLAGS_CREATE_SUSPENDED) {
        T3pProbAdd(Probs, L"T1055.012", 0.4, L"挂起远程线程(Hollowing特征)");
    } else {
        T3pProbAdd(Probs, L"T1055.002", 0.3, L"Shellcode/PE注入");
        T3pProbAdd(Probs, L"T1620", 0.3, L"反射加载或shellcode");
    }
}

/**************************************************/
/*           MemoryWrite 分析器                    */
/**************************************************/

static
ULONG
T3pScoreCand_MemoryWrite(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
/*++
Routine Description:
    ScoreCand — MemoryWrite 分析器。
    提取 BaseAddress / Size，ReadProcessMemory 读内容，
    参照 Wishlist 计算写地址覆盖和内容匹配分。
--*/
{
    PWKD_EVENT_HEADER event = NULL;
    PEVENT_PAYLOAD_SYSCALL payload;
    ULONG score = 0;
    ULONG addrScore = 0;
    ULONG contentScore = 0;

    if (!Candidate || !OutItem) return 0;
    UNREFERENCED_PARAMETER(Wishlist);

    /* 加载事件 → 提取参数 */
    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event)) && event) {
        OutItem->EventType     = event->Type;
        OutItem->EventClass    = event->Class;
        OutItem->BehaviorFlags = event->BehaviorFlags;

        payload = T3pLoadSyscallParams(event);
        if (payload) {
            OutItem->Params.MemoryWrite.BaseAddress          = payload->ParameterBase[1];
            OutItem->Params.MemoryWrite.NumberOfBytesWritten = payload->ParameterBase[3];
        }
        UtHeapFree(event);
    }

    OutItem->Description = L"WriteProcessMemory";
    OutItem->ContentConfidence = 0;

    /* 内容深化: 读取目标进程内存 */
    {
        UCHAR buffer[64];
        SIZE_T actualRead = 0;
        BOOLEAN hasMZ = FALSE, hasDllPath = FALSE;

        T3pReadTargetMemory(
            OutItem->Params.MemoryWrite.BaseAddress,
            Candidate->TargetNodeId,
            buffer, 64,
            &actualRead, &hasMZ, &hasDllPath);

        if (actualRead > 0) {
            OutItem->ContentConfidence = 100;
            memcpy(OutItem->Params.MemoryWrite.BufferHead, buffer,
                   min(actualRead, sizeof(OutItem->Params.MemoryWrite.BufferHead)));
            OutItem->Params.MemoryWrite.HasMZ      = hasMZ;
            OutItem->Params.MemoryWrite.HasDllPath  = hasDllPath;

            /* 写地址覆盖度评分 */
            for (ULONG i = 0; i < Wishlist->Count; i++) {
                if (!Wishlist->Entries[i].Active) continue;
                if (Wishlist->Entries[i].NeedWriteAt) {
                    addrScore = Score_WriteAddressCoverage(
                        OutItem->Params.MemoryWrite.BaseAddress,
                        OutItem->Params.MemoryWrite.NumberOfBytesWritten,
                        Wishlist->Entries[i].RequiredWriteAddr);
                }
            }

            /* 内容匹配评分 */
            for (ULONG i = 0; i < Wishlist->Count; i++) {
                if (!Wishlist->Entries[i].Active) continue;
                if (Wishlist->Entries[i].NeedDllPath) {
                    contentScore = Score_ContentMatch(hasDllPath, TRUE);
                } else if (Wishlist->Entries[i].NeedPeImage) {
                    contentScore = Score_ContentMatch(hasMZ, TRUE);
                }
            }

            score = (ULONG)(addrScore * 0.6 + contentScore * 0.4);
        }
    }

    return score;
}

static
BOOLEAN
T3pTryFuse_MemoryWrite(
    _In_    PT3_CANDIDATE_INFO      Candidates,
    _In_    ULONG                   Count,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    FusedItem
    )
/*++
Routine Description:
    TryFuse — MemoryWrite 分段写入融合。
    检查多条地址连续的 Write 是否能合并后覆盖 RequiredWriteAddr。
    融合条件: gap ≤ 4KB 且总范围能覆盖需求地址。
--*/
{
    TIRE3_EVIDENCE_ITEM items[8];
    ULONG itemCount = 0;
    ULONG64 fullStart, fullEnd;
    ULONG64 reqAddr = 0;
    BOOLEAN hasReqAddr = FALSE;
    BOOLEAN hasMZ = FALSE, hasDllPath = FALSE;
    ULONG64 totalSize = 0;

    if (!Candidates || Count < 2 || !FusedItem || !Wishlist) return FALSE;
    RtlZeroMemory(FusedItem, sizeof(TIRE3_EVIDENCE_ITEM));

    /* 从 Wishlist 获取需求地址 */
    for (ULONG w = 0; w < Wishlist->Count; w++) {
        if (Wishlist->Entries[w].Active && Wishlist->Entries[w].NeedWriteAt) {
            reqAddr = Wishlist->Entries[w].RequiredWriteAddr;
            hasReqAddr = TRUE;
            break;
        }
    }
    if (!hasReqAddr) return FALSE;

    /* 提取所有候选的参数（简化: 只用 T3pScoreCand_MemoryWrite 内部逻辑） */
    for (ULONG i = 0; i < Count && i < 8; i++) {
        PWKD_EVENT_HEADER event = NULL;
        PEVENT_PAYLOAD_SYSCALL payload;

        RtlZeroMemory(&items[itemCount], sizeof(TIRE3_EVIDENCE_ITEM));

        if (NT_SUCCESS(StLoadEventByGuid(Candidates[i].EdgeId, &event)) && event) {
            payload = T3pLoadSyscallParams(event);
            if (payload) {
                items[itemCount].Params.MemoryWrite.BaseAddress = payload->ParameterBase[0];
                items[itemCount].Params.MemoryWrite.NumberOfBytesWritten = payload->ParameterBase[1];
            }
            items[itemCount].Timestamp = Candidates[i].Timestamp;
            UtHeapFree(event);
        }
        itemCount++;
    }

    if (itemCount < 2) return FALSE;

    /* 按地址排序 */
    for (ULONG i = 1; i < itemCount; i++) {
        TIRE3_EVIDENCE_ITEM temp = items[i];
        LONG j = (LONG)i - 1;
        while (j >= 0 && items[j].Params.MemoryWrite.BaseAddress > temp.Params.MemoryWrite.BaseAddress) {
            items[j + 1] = items[j];
            j--;
        }
        items[j + 1] = temp;
    }

    /* 尝试融合 */
    fullStart = items[0].Params.MemoryWrite.BaseAddress;
    fullEnd   = fullStart + items[0].Params.MemoryWrite.NumberOfBytesWritten;
    totalSize = items[0].Params.MemoryWrite.NumberOfBytesWritten;

    for (ULONG i = 1; i < itemCount; i++) {
        ULONG64 thisStart = items[i].Params.MemoryWrite.BaseAddress;
        ULONG64 thisEnd   = thisStart + items[i].Params.MemoryWrite.NumberOfBytesWritten;
        ULONG64 gap       = thisStart - fullEnd;

        if (gap <= 0x1000) {
            fullEnd = thisEnd;
            totalSize += items[i].Params.MemoryWrite.NumberOfBytesWritten + gap;
            if (items[i].Timestamp.QuadPart > FusedItem->Timestamp.QuadPart) {
                FusedItem->Timestamp = items[i].Timestamp;
            }
        } else {
            break;
        }
    }

    /* 融合后的范围覆盖需求地址？ */
    if (fullStart <= reqAddr && fullEnd > reqAddr) {
        FusedItem->EdgeType = DefEdge_WritesTo;
        FusedItem->Params.MemoryWrite.BaseAddress = fullStart;
        FusedItem->Params.MemoryWrite.NumberOfBytesWritten = totalSize;
        FusedItem->ContentConfidence = 100;

        /* 内容深化: 读需求地址前64字节 */
        {
            UCHAR buffer[64];
            SIZE_T actualRead = 0;
            T3pReadTargetMemory(reqAddr, Candidates[0].TargetNodeId,
                                 buffer, 64, &actualRead, &hasMZ, &hasDllPath);
            FusedItem->Params.MemoryWrite.HasMZ      = hasMZ;
            FusedItem->Params.MemoryWrite.HasDllPath  = hasDllPath;
            if (actualRead > 0) {
                memcpy(FusedItem->Params.MemoryWrite.BufferHead, buffer,
                       min(actualRead, sizeof(FusedItem->Params.MemoryWrite.BufferHead)));
            }
        }

        printf("[T3Analyzer] Write fused: [0x%llX-0x%llX) covers reqAddr=0x%llX "
               "hasMZ=%d hasDllPath=%d\n",
               fullStart, fullEnd, reqAddr, hasMZ, hasDllPath);

        return TRUE;
    }

    return FALSE;
}

static
VOID
T3pFulfillCheck_MemoryWrite(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    FulfillCheck — MemoryWrite 检查写地址覆盖和内容匹配。
--*/
{
    ULONG i;
    ULONG64 base = OutItem->Params.MemoryWrite.BaseAddress;
    ULONG64 size = OutItem->Params.MemoryWrite.NumberOfBytesWritten;

    for (i = 0; i < Wishlist->Count; i++) {
        PTIRE3_WISH_ENTRY w = &Wishlist->Entries[i];
        if (!w->Active) continue;

        if (w->NeedWriteAt) {
            WishFulfillWriteAt(w, base, size);
        }
        if (w->NeedDllPath && OutItem->Params.MemoryWrite.HasDllPath) {
            w->Active = FALSE;
        }
        if (w->NeedPeImage && OutItem->Params.MemoryWrite.HasMZ) {
            w->Active = FALSE;
        }
    }
}

static
VOID
T3pDeriveNeeds_MemoryWrite(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    DeriveNeeds — MemoryWrite 需要前序 Allocates 分配写入区域，
    以及 PROCESS_VM_WRITE|VM_OP 句柄。
--*/
{
    TIRE3_WISH_ENTRY wish;
    ULONG64 base = OutItem->Params.MemoryWrite.BaseAddress;
    ULONG64 size = OutItem->Params.MemoryWrite.NumberOfBytesWritten;

    RtlZeroMemory(&wish, sizeof(wish));
    wish.NeedAllocCover = TRUE;
    wish.RequiredAllocMin = base;
    wish.RequiredAllocMax = base + size;
    WishAppend(Wishlist, &wish);

    RtlZeroMemory(&wish, sizeof(wish));
    wish.NeedAccessMask = TRUE;
    wish.RequiredAccessMask = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    WishAppend(Wishlist, &wish);
}

static
VOID
T3pUpdateProbs_MemoryWrite(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
/*++
Routine Description:
    UpdateMitreProbs — MemoryWrite 内容特征影响概率。
--*/
{
    if (OutItem->Params.MemoryWrite.HasMZ) {
        T3pProbAdd(Probs, L"T1055.002", 0.4, L"PE写入(内存中)");
        T3pProbAdd(Probs, L"T1055.012", 0.2, L"PE写入(Hollowing候选)");
        T3pProbAdd(Probs, L"T1620", -0.2, L"非反射加载(有MZ)");
    }
    if (OutItem->Params.MemoryWrite.HasDllPath) {
        T3pProbAdd(Probs, L"T1055.001", 0.5, L"DLL路径写入确认");
    }
}

/**************************************************/
/*           MemoryAlloc 分析器                    */
/**************************************************/

static
ULONG
T3pScoreCand_MemoryAlloc(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
/*++
Routine Description:
    ScoreCand — MemoryAlloc 分析器。
    提取 BaseAddress / RegionSize / Protect，
    参照 Wishlist 计算分配范围覆盖和可执行标志匹配分。
--*/
{
    PWKD_EVENT_HEADER event = NULL;
    PEVENT_PAYLOAD_SYSCALL payload;
    ULONG score = 0, allocScore = 0, exeScore = 0;

    if (!Candidate || !OutItem) return 0;

    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event)) && event) {
        OutItem->EventType  = event->Type;
        OutItem->EventClass = event->Class;
        OutItem->BehaviorFlags = event->BehaviorFlags;

        payload = T3pLoadSyscallParams(event);
        if (payload) {
            OutItem->Params.MemoryAlloc.BaseAddress = payload->ParameterBase[1];
            OutItem->Params.MemoryAlloc.RegionSize  = payload->ParameterBase[3];
            OutItem->Params.MemoryAlloc.Protect     = (ULONG)(payload->ParameterBase[4] >> 32);
        }
        UtHeapFree(event);
    }
    OutItem->ContentConfidence = 100;
    OutItem->Description = L"VirtualAllocEx";

    /* 评分 */
    for (ULONG i = 0; i < Wishlist->Count; i++) {
        if (!Wishlist->Entries[i].Active) continue;

        if (Wishlist->Entries[i].NeedAllocCover) {
            ULONG64 base    = OutItem->Params.MemoryAlloc.BaseAddress;
            ULONG64 size    = OutItem->Params.MemoryAlloc.RegionSize;
            ULONG64 rMin    = Wishlist->Entries[i].RequiredAllocMin;
            ULONG64 rMax    = Wishlist->Entries[i].RequiredAllocMax;

            if (base <= rMin && base + size >= rMax) {
                allocScore = 100;
            } else if (base <= rMax && base + size >= rMin) {
                /* 部分覆盖 */
                ULONG64 overlapStart = max(base, rMin);
                ULONG64 overlapEnd   = min(base + size, rMax);
                allocScore = (ULONG)((overlapEnd - overlapStart) * 100 /
                                     max(rMax - rMin, 1));
            }
        }

        if (Wishlist->Entries[i].NeedExeMemory) {
            ULONG protect = OutItem->Params.MemoryAlloc.Protect;
            if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE)) {
                exeScore = 100;
            }
        }
    }

    score = (ULONG)(allocScore * 0.7 + exeScore * 0.3);
    return score;
}

static
BOOLEAN
T3pTryFuse_MemoryAlloc(
    _In_    PT3_CANDIDATE_INFO      Candidates,
    _In_    ULONG                   Count,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    FusedItem
    )
/*++
Routine Description:
    TryFuse — MemoryAlloc 分配区域融合。
    检查多条分配是否能合并后覆盖 RequiredAllocCover 范围。
--*/
{
    ULONG64 fullMin = (ULONG64)-1, fullMax = 0;
    ULONG64 rMin = 0, rMax = 0;
    BOOLEAN hasReq = FALSE;

    if (!Candidates || Count < 2 || !FusedItem || !Wishlist) return FALSE;
    RtlZeroMemory(FusedItem, sizeof(TIRE3_EVIDENCE_ITEM));

    for (ULONG w = 0; w < Wishlist->Count; w++) {
        if (Wishlist->Entries[w].Active && Wishlist->Entries[w].NeedAllocCover) {
            rMin = Wishlist->Entries[w].RequiredAllocMin;
            rMax = Wishlist->Entries[w].RequiredAllocMax;
            hasReq = TRUE;
            break;
        }
    }
    if (!hasReq) return FALSE;

    for (ULONG i = 0; i < Count; i++) {
        PWKD_EVENT_HEADER event = NULL;
        PEVENT_PAYLOAD_SYSCALL payload;

        if (NT_SUCCESS(StLoadEventByGuid(Candidates[i].EdgeId, &event)) && event) {
            payload = T3pLoadSyscallParams(event);
            if (payload) {
                ULONG64 base = payload->ParameterBase[0];
                ULONG64 size = payload->ParameterBase[1];
                if (base < fullMin) fullMin = base;
                if (base + size > fullMax) fullMax = base + size;
            }
            UtHeapFree(event);
        }
    }

    if (fullMin <= rMin && fullMax >= rMax) {
        FusedItem->EdgeType = DefEdge_Allocates;
        FusedItem->Params.MemoryAlloc.BaseAddress = fullMin;
        FusedItem->Params.MemoryAlloc.RegionSize  = fullMax - fullMin;
        FusedItem->ContentConfidence = 100;
        return TRUE;
    }

    return FALSE;
}

static
VOID
T3pFulfillCheck_MemoryAlloc(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    FulfillCheck — MemoryAlloc 检查分配范围覆盖 + 可执行内存满足。
--*/
{
    ULONG i;
    ULONG64 base = OutItem->Params.MemoryAlloc.BaseAddress;
    ULONG64 size = OutItem->Params.MemoryAlloc.RegionSize;
    ULONG protect = OutItem->Params.MemoryAlloc.Protect;

    for (i = 0; i < Wishlist->Count; i++) {
        PTIRE3_WISH_ENTRY w = &Wishlist->Entries[i];
        if (!w->Active) continue;

        if (w->NeedAllocCover) {
            WishFulfillAllocCover(w, base, size);
        }
        if (w->NeedExeMemory &&
            (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE))) {
            w->Active = FALSE;
        }
    }
}

static
VOID
T3pDeriveNeeds_MemoryAlloc(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    DeriveNeeds — MemoryAlloc 需要句柄权限。
    若分配可执行内存则需 CREATE_THREAD 权限。
--*/
{
    TIRE3_WISH_ENTRY wish;
    ULONG protect = OutItem->Params.MemoryAlloc.Protect;

    RtlZeroMemory(&wish, sizeof(wish));
    wish.NeedAccessMask = TRUE;
    wish.RequiredAccessMask = PROCESS_VM_OPERATION;
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        wish.RequiredAccessMask |= PROCESS_CREATE_THREAD;
    }
    WishAppend(Wishlist, &wish);
}

static
VOID
T3pUpdateProbs_MemoryAlloc(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
/*++
Routine Description:
    UpdateMitreProbs — 可执行分配提升注入概率。
--*/
{
    ULONG protect = OutItem->Params.MemoryAlloc.Protect;
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        T3pProbAdd(Probs, L"T1055.002", 0.3, L"可执行内存分配");
        T3pProbAdd(Probs, L"T1055.012", 0.2, L"可执行内存(Hollowing候选)");
    }
}

/**************************************************/
/*           MemoryProtect 分析器                  */
/**************************************************/

static
ULONG
T3pScoreCand_MemoryProtect(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
/*++
Routine Description:
    ScoreCand — MemoryProtect 分析器。
    提取 BaseAddress / NewProtect，检查是否与需求匹配。
--*/
{
    PWKD_EVENT_HEADER event = NULL;
    PEVENT_PAYLOAD_SYSCALL payload;
    ULONG score = 0;

    if (!Candidate || !OutItem) return 0;

    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event)) && event) {
        OutItem->EventType  = event->Type;
        OutItem->EventClass = event->Class;
        OutItem->BehaviorFlags = event->BehaviorFlags;

        payload = T3pLoadSyscallParams(event);
        if (payload) {
            OutItem->Params.MemoryProtect.BaseAddress = payload->ParameterBase[0];
            OutItem->Params.MemoryProtect.RegionSize  = payload->ParameterBase[1];
            OutItem->Params.MemoryProtect.NewProtect  = (ULONG)payload->ParameterBase[2];
            OutItem->Params.MemoryProtect.OldProtect  = (ULONG)payload->ParameterBase[3];
        }
        UtHeapFree(event);
    }
    OutItem->ContentConfidence = 100;
    OutItem->Description = L"VirtualProtectEx";

    /* 评分: 如果 NewProtect 含 EXECUTE 且 Wishlist 需要可执行 → 高分 */
    for (ULONG i = 0; i < Wishlist->Count; i++) {
        if (!Wishlist->Entries[i].Active) continue;
        if (Wishlist->Entries[i].NeedExeMemory) {
            if (OutItem->Params.MemoryProtect.NewProtect &
                (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                score = 100;
            }
        }
    }

    return max(score, 30);  /* 基础分 30 */
}

static
VOID
T3pFulfillCheck_MemoryProtect(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    FulfillCheck — MemoryProtect 检查是否满足可执行内存需求。
--*/
{
    ULONG i;
    ULONG protect = OutItem->Params.MemoryProtect.NewProtect;

    for (i = 0; i < Wishlist->Count; i++) {
        PTIRE3_WISH_ENTRY w = &Wishlist->Entries[i];
        if (!w->Active) continue;
        if (w->NeedExeMemory &&
            (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE))) {
            w->Active = FALSE;
        }
    }
}

static
VOID
T3pDeriveNeeds_MemoryProtect(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    DeriveNeeds — MemoryProtect 需要前序分配覆盖地址范围。
--*/
{
    TIRE3_WISH_ENTRY wish;
    ULONG64 base = OutItem->Params.MemoryProtect.BaseAddress;
    ULONG64 size = OutItem->Params.MemoryProtect.RegionSize;

    RtlZeroMemory(&wish, sizeof(wish));
    wish.NeedAllocCover = TRUE;
    wish.RequiredAllocMin = base;
    wish.RequiredAllocMax = base + size;
    WishAppend(Wishlist, &wish);

    RtlZeroMemory(&wish, sizeof(wish));
    wish.NeedAccessMask = TRUE;
    wish.RequiredAccessMask = PROCESS_VM_OPERATION;
    WishAppend(Wishlist, &wish);
}

static
VOID
T3pUpdateProbs_MemoryProtect(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
{
    /* MemoryProtect 本身对概率影响小，保留占位 */
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Probs);
}

/**************************************************/
/*           ProcessOpen 分析器                    */
/**************************************************/

static
ULONG
T3pScoreCand_ProcessOpen(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
/*++
Routine Description:
    ScoreCand — ProcessOpen 分析器。
    提取 DesiredAccess，参照 Wishlist 计算权限覆盖度评分。
--*/
{
    PWKD_EVENT_HEADER event = NULL;
    PEVENT_PAYLOAD_SYSCALL payload;
    ULONG bestScore = 0;

    if (!Candidate || !OutItem) return 0;

    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event)) && event) {
        OutItem->EventType  = event->Type;
        OutItem->EventClass = event->Class;
        OutItem->BehaviorFlags = event->BehaviorFlags;

        payload = T3pLoadSyscallParams(event);
        if (payload) {
            OutItem->Params.ProcessOpen.DesiredAccess = payload->ParameterBase[1];
        }
        UtHeapFree(event);
    }
    OutItem->ContentConfidence = 100;
    OutItem->Description = L"OpenProcess";

    /* 权限覆盖度评分 */
    ACCESS_MASK access = OutItem->Params.ProcessOpen.DesiredAccess;
    for (ULONG i = 0; i < Wishlist->Count; i++) {
        if (!Wishlist->Entries[i].Active) continue;
        if (Wishlist->Entries[i].NeedAccessMask) {
            ULONG s = Score_AccessMaskCoverage(
                access, Wishlist->Entries[i].RequiredAccessMask);
            if (s > bestScore) bestScore = s;
        }
    }

    return bestScore > 0 ? bestScore : 30;
}

static
BOOLEAN
T3pTryFuse_ProcessOpen(
    _In_    PT3_CANDIDATE_INFO      Candidates,
    _In_    ULONG                   Count,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    FusedItem
    )
/*++
Routine Description:
    TryFuse — ProcessOpen 分阶段权限融合。
    多条 OpenProcess 的 DesiredAccess 按位或，检查是否满足需求。
--*/
{
    ULONG64 mergedAccess = 0;
    ULONG reqAccess = 0;
    BOOLEAN hasReq = FALSE;
    LARGE_INTEGER earliestTime = {0};

    if (!Candidates || Count < 2 || !FusedItem || !Wishlist) return FALSE;
    RtlZeroMemory(FusedItem, sizeof(TIRE3_EVIDENCE_ITEM));

    for (ULONG w = 0; w < Wishlist->Count; w++) {
        if (Wishlist->Entries[w].Active && Wishlist->Entries[w].NeedAccessMask) {
            reqAccess |= Wishlist->Entries[w].RequiredAccessMask;
            hasReq = TRUE;
        }
    }
    if (!hasReq) return FALSE;

    for (ULONG i = 0; i < Count; i++) {
        PWKD_EVENT_HEADER event = NULL;
        PEVENT_PAYLOAD_SYSCALL payload;

        if (NT_SUCCESS(StLoadEventByGuid(Candidates[i].EdgeId, &event)) && event) {
            payload = T3pLoadSyscallParams(event);
            if (payload) {
                mergedAccess |= payload->ParameterBase[3];
            }
            if (earliestTime.QuadPart == 0 ||
                Candidates[i].Timestamp.QuadPart < earliestTime.QuadPart) {
                earliestTime = Candidates[i].Timestamp;
            }
            UtHeapFree(event);
        }
    }

    if ((mergedAccess & reqAccess) == reqAccess) {
        FusedItem->EdgeType = DefEdge_Opens;
        FusedItem->Params.ProcessOpen.DesiredAccess = mergedAccess;
        FusedItem->Timestamp = earliestTime;
        FusedItem->ContentConfidence = 100;
        printf("[T3Analyzer] Open fused: mergedAccess=0x%lX covers req=0x%lX\n",
               (ULONG)mergedAccess, reqAccess);
        return TRUE;
    }

    return FALSE;
}

static
VOID
T3pFulfillCheck_ProcessOpen(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    FulfillCheck — ProcessOpen 检查权限覆盖。
--*/
{
    ULONG access = (ULONG)OutItem->Params.ProcessOpen.DesiredAccess;
    for (ULONG i = 0; i < Wishlist->Count; i++) {
        PTIRE3_WISH_ENTRY w = &Wishlist->Entries[i];
        if (!w->Active) continue;
        if (w->NeedAccessMask) {
            WishFulfillAccessMask(w, access);
        }
    }
}

static
VOID
T3pDeriveNeeds_ProcessOpen(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
{
    /* 链首 — 无前序依赖 */
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Wishlist);
}

static
VOID
T3pUpdateProbs_ProcessOpen(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
{
    /* ProcessOpen 本身对概率影响小 */
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Probs);
}

/**************************************************/
/*           ProcessCreate 分析器                  */
/**************************************************/

static
ULONG
T3pScoreCand_ProcessCreate(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
/*++
Routine Description:
    ScoreCand — ProcessCreate 分析器。
    提取 ImagePath / CommandLine / CreationFlags。
    SUSPENDED 创建 → Hollowing 高分。
--*/
{
    PWKD_EVENT_HEADER event = NULL;
    ULONG score = 30;

    if (!Candidate || !OutItem) return 0;
    UNREFERENCED_PARAMETER(Wishlist);

    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event)) && event) {
        if (event->PayloadSize >= sizeof(EVENT_PAYLOAD_PROCESS_CREATE)) {
            PEVENT_PAYLOAD_PROCESS_CREATE payload = (PEVENT_PAYLOAD_PROCESS_CREATE)
                ((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
            wcsncpy_s(OutItem->Params.ProcessCreate.ImagePath, 256,
                      payload->ImagePath.Buffer ? payload->ImagePath.Buffer : L"", _TRUNCATE);
            wcsncpy_s(OutItem->Params.ProcessCreate.CommandLine, 1024,
                      payload->CommandLine.Buffer ? payload->CommandLine.Buffer : L"", _TRUNCATE);
            OutItem->Params.ProcessCreate.ParentProcessId = payload->ParentProcessId;
        }
        UtHeapFree(event);
    }

    OutItem->ContentConfidence = 100;
    OutItem->Description = L"CreateProcess";

    OutItem->Params.ProcessCreate.CreationFlags =
        (OutItem->BehaviorFlags & DEF_BEHAVIOR_FLAG_HOLLOWING) ? 1 : 0;

    if (OutItem->Params.ProcessCreate.CreationFlags) {
        score = 70;     /* SUSPENDED 创建 → Hollowing */
    }

    return score;
}

static
VOID
T3pFulfillCheck_ProcessCreate(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
{
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Wishlist);
}

static
VOID
T3pDeriveNeeds_ProcessCreate(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    DeriveNeeds — ProcessCreate SUSPENDED 需要句柄权限。
--*/
{
    if (OutItem->Params.ProcessCreate.CreationFlags) {
        TIRE3_WISH_ENTRY wish;
        RtlZeroMemory(&wish, sizeof(wish));
        wish.NeedAccessMask = TRUE;
        wish.RequiredAccessMask = PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
        WishAppend(Wishlist, &wish);
    }
}

static
VOID
T3pUpdateProbs_ProcessCreate(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
/*++
Routine Description:
    UpdateMitreProbs — SUSPENDED 创建提升 Hollowing 概率。
--*/
{
    if (OutItem->Params.ProcessCreate.CreationFlags) {
        T3pProbAdd(Probs, L"T1055.012", 0.5, L"挂起进程创建(Hollowing)");
        T3pProbAdd(Probs, L"T1055.002", -0.1, L"非PE注入(有独立进程)");
    }
}

/**************************************************/
/*           NetworkConnect 分析器                 */
/**************************************************/

static
ULONG
T3pScoreCand_NetworkConnect(
    _In_    PT3_CANDIDATE_INFO      Candidate,
    _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
    )
{
    PWKD_EVENT_HEADER event = NULL;
    PEVENT_PAYLOAD_SYSCALL payload;

    if (!Candidate || !OutItem) return 0;
    UNREFERENCED_PARAMETER(Wishlist);

    if (NT_SUCCESS(StLoadEventByGuid(Candidate->EdgeId, &event)) && event) {
        payload = T3pLoadSyscallParams(event);
        if (payload) {
            OutItem->Params.NetworkConnect.DestIP   = payload->ParameterBase[0];
            OutItem->Params.NetworkConnect.DestPort = (USHORT)payload->ParameterBase[1];
        }
        UtHeapFree(event);
    }
    OutItem->ContentConfidence = 100;
    OutItem->Description = L"NetworkConnection";

    return 50;  /* 默认分 */
}

static
VOID
T3pDeriveNeeds_NetworkConnect(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
{
    /* 网络连接通常是链末端 */
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Wishlist);
}

static
VOID
T3pUpdateProbs_NetworkConnect(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PT3_MITRE_PROB_DIST     Probs
    )
{
    UNREFERENCED_PARAMETER(OutItem);
    UNREFERENCED_PARAMETER(Probs);
}

/**************************************************/
/*           内置分析器回调集 (全局实例)              */
/**************************************************/

T3_ANALYZER_CALLBACKS g_T3A_ProcessOpen = {
    L"ProcessOpen",
    NULL,                               /* Collect */
    T3pScoreCand_ProcessOpen,
    T3pTryFuse_ProcessOpen,
    T3pFulfillCheck_ProcessOpen,
    T3pDeriveNeeds_ProcessOpen,
    T3pUpdateProbs_ProcessOpen
};

T3_ANALYZER_CALLBACKS g_T3A_MemoryAlloc = {
    L"MemoryAlloc",
    NULL,                               /* Collect */
    T3pScoreCand_MemoryAlloc,
    T3pTryFuse_MemoryAlloc,
    T3pFulfillCheck_MemoryAlloc,
    T3pDeriveNeeds_MemoryAlloc,
    T3pUpdateProbs_MemoryAlloc
};

T3_ANALYZER_CALLBACKS g_T3A_MemoryWrite = {
    L"MemoryWrite",
    NULL,                               /* Collect */
    T3pScoreCand_MemoryWrite,
    T3pTryFuse_MemoryWrite,
    T3pFulfillCheck_MemoryWrite,
    T3pDeriveNeeds_MemoryWrite,
    T3pUpdateProbs_MemoryWrite
};

T3_ANALYZER_CALLBACKS g_T3A_MemoryProtect = {
    L"MemoryProtect",
    NULL,                               /* Collect */
    T3pScoreCand_MemoryProtect,
    NULL,                               /* TryFuse */
    T3pFulfillCheck_MemoryProtect,
    T3pDeriveNeeds_MemoryProtect,
    T3pUpdateProbs_MemoryProtect
};

T3_ANALYZER_CALLBACKS g_T3A_ThreadCreate = {
    L"ThreadCreate",
    NULL,                               /* Collect */
    T3pScoreCand_ThreadCreate,
    NULL,                               /* TryFuse */
    T3pFulfillCheck_ThreadCreate,
    T3pDeriveNeeds_ThreadCreate,
    T3pUpdateProbs_ThreadCreate
};

T3_ANALYZER_CALLBACKS g_T3A_ProcessCreate = {
    L"ProcessCreate",
    NULL,                               /* Collect */
    T3pScoreCand_ProcessCreate,
    NULL,                               /* TryFuse */
    T3pFulfillCheck_ProcessCreate,
    T3pDeriveNeeds_ProcessCreate,
    T3pUpdateProbs_ProcessCreate
};

T3_ANALYZER_CALLBACKS g_T3A_NetworkConnect = {
    L"NetworkConnect",
    NULL,                               /* Collect */
    T3pScoreCand_NetworkConnect,
    NULL,                               /* TryFuse */
    NULL,                               /* FulfillCheck */
    T3pDeriveNeeds_NetworkConnect,
    T3pUpdateProbs_NetworkConnect
};

/**************************************************/
/*           注册表内部                             */
/**************************************************/

#define T3_MAX_REGISTERED    32

static T3_ANALYZER_REG g_Registry[T3_MAX_REGISTERED];
static ULONG g_RegCount = 0;
static BOOLEAN g_Initialized = FALSE;

/**************************************************/
/*           公共接口                               */
/**************************************************/

VOID
T3Registry_Initialize(VOID)
{
    if (g_Initialized) return;

    /* 进程注入类 */
    T3Registry_Register(FsmClass_ProcessInjection, DefEdge_Opens,       &g_T3A_ProcessOpen,   L"Inject:ProcessOpen");
    T3Registry_Register(FsmClass_ProcessInjection, DefEdge_Allocates,   &g_T3A_MemoryAlloc,   L"Inject:MemoryAlloc");
    T3Registry_Register(FsmClass_ProcessInjection, DefEdge_WritesTo,    &g_T3A_MemoryWrite,   L"Inject:MemoryWrite");
    T3Registry_Register(FsmClass_ProcessInjection, DefEdge_Protects,    &g_T3A_MemoryProtect, L"Inject:MemoryProtect");
    T3Registry_Register(FsmClass_ProcessInjection, DefEdge_InjectsInto, &g_T3A_ThreadCreate,  L"Inject:ThreadCreate");

    /* ProcessHollowing 类 */
    T3Registry_Register(FsmClass_ProcessHollowing, DefEdge_Creates,    &g_T3A_ProcessCreate, L"Hollow:ProcessCreate");
    T3Registry_Register(FsmClass_ProcessHollowing, DefEdge_Allocates,  &g_T3A_MemoryAlloc,   L"Hollow:MemoryAlloc");
    T3Registry_Register(FsmClass_ProcessHollowing, DefEdge_WritesTo,   &g_T3A_MemoryWrite,   L"Hollow:MemoryWrite");
    T3Registry_Register(FsmClass_ProcessHollowing, DefEdge_Protects,   &g_T3A_MemoryProtect, L"Hollow:MemoryProtect");
    T3Registry_Register(FsmClass_ProcessHollowing, DefEdge_InjectsInto, &g_T3A_ThreadCreate, L"Hollow:ThreadCreate");

    /* 凭据访问类 */
    T3Registry_Register(FsmClass_CredentialAccess, DefEdge_Opens,      &g_T3A_ProcessOpen,   L"Cred:ProcessOpen");
    T3Registry_Register(FsmClass_CredentialAccess, DefEdge_ReadsFrom,  &g_T3A_MemoryWrite,   L"Cred:MemoryRead");

    /* 通用 */
    T3Registry_Register(FsmClass_None,            DefEdge_Creates,     &g_T3A_ProcessCreate, L"General:ProcessCreate");
    T3Registry_Register(FsmClass_None,            DefEdge_ConnectsTo,  &g_T3A_NetworkConnect,L"General:NetworkConnect");

    g_Initialized = TRUE;
    printf("[T3Registry] Initialized: %lu analyzers registered\n", g_RegCount);
}

PT3_ANALYZER_CALLBACKS
T3CausalAnalyzerRoute(
    _In_ FSM_ATTACK_CLASS    FsmClass,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    )
{
    /* 先精确匹配 FsmClass + EdgeType */
    for (ULONG i = 0; i < g_RegCount; i++) {
        if (g_Registry[i].FsmClass == FsmClass &&
            g_Registry[i].EdgeType == EdgeType) {
            return &g_Registry[i].Callbacks;
        }
    }
    /* 然后尝试通用 (FsmClass_None) */
    for (ULONG i = 0; i < g_RegCount; i++) {
        if (g_Registry[i].FsmClass == FsmClass_None &&
            g_Registry[i].EdgeType == EdgeType) {
            return &g_Registry[i].Callbacks;
        }
    }
    return NULL;
}

VOID
T3Registry_Register(
    _In_ FSM_ATTACK_CLASS        FsmClass,
    _In_ IOA_GRAPH_EDGE_TYPE     EdgeType,
    _In_ PT3_ANALYZER_CALLBACKS  Callbacks,
    _In_ PCWSTR                  Name
    )
{
    if (g_RegCount >= T3_MAX_REGISTERED) return;

    g_Registry[g_RegCount].FsmClass = FsmClass;
    g_Registry[g_RegCount].EdgeType = EdgeType;
    g_Registry[g_RegCount].Callbacks = *Callbacks;  /* 值拷贝 */
    g_RegCount++;
    UNREFERENCED_PARAMETER(Name);
}
