/**************************************************/
/*  WkDefender PEAnalyzer — 安全读取器实现          */
/*  统一分段 LRU:Buffer/File/Process 三模式对称。    */
/*  IocpReaderRead 返回指针(下一次读取前保持有效);   */
/*  _IocpReaderCopy 拷入调用方缓冲(用于 Uxx/         */
/*  String/Compare/Array,修复旧 BUFFER 模式失效)。   */
/**************************************************/

#include "PeInternal.h"

/**************************************************/
/*             静态辅助:分段 LRU 加载               */
/**************************************************/

/*
 * IocpGetReaderSegment — 取覆盖 Offset 的 4KB 段。
 * 命中则刷新 LRU 序号;未命中按 LRU 淘汰最久段并重载。
 * 返回段指针;加载失败返回 NULL。
 */
static
PPE_SEGMENT
IocpGetReaderSegment(
    _Inout_ PPE_READER Reader,
    _In_ SIZE_T Offset
    )
{
    ULONG victim = 0;
    ULONG64 oldest = MAXULONG64;
    SIZE_T segmentBase;
    PPE_SEGMENT segment;
    SIZE_T got = 0;

    if (!Reader) return NULL;
    segmentBase = Offset & ~(SIZE_T)(PE_SEGMENT_SIZE - 1);

    /* 1) 命中:直接刷新 LRU */
    for (ULONG i = 0; i < PE_SEGMENT_COUNT; i++) {
        if (Reader->Segments[i].Valid &&
            Reader->Segments[i].Offset == segmentBase) {
            Reader->Segments[i].LruSeq = ++Reader->LruClock;
            return &Reader->Segments[i];
        }
    }

    /* 2) 受害者:优先空槽,否则 LRU 序号最小者 */
    for (ULONG i = 0; i < PE_SEGMENT_COUNT; i++) {
        if (!Reader->Segments[i].Valid) {
            victim = i;
            goto load;
        }
        if (Reader->Segments[i].LruSeq < oldest) {
            oldest = Reader->Segments[i].LruSeq;
            victim = i;
        }
    }

load:
    segment = &Reader->Segments[victim];
    if (segment->Data == NULL) {
        segment->Data = (PBYTE)malloc(PE_SEGMENT_SIZE);
        if (segment->Data == NULL) return NULL;
    }

    switch (Reader->Mode) {
    case  PeReader_File: {
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)segmentBase;
        if (!SetFilePointerEx(Reader->FileHandle, li, NULL, FILE_BEGIN)) {
            goto Cleanup;
        }
        if (!ReadFile(Reader->FileHandle, segment->Data,
            PE_SEGMENT_SIZE, &got, NULL) || got == 0) {
            goto Cleanup;
        }
        break;
    }
    case PeReader_Process: {
        if (!ReadProcessMemory(Reader->ProcessHandle,
            (LPCVOID)(Reader->BaseAddress + segmentBase),
            segment->Data, PE_SEGMENT_SIZE, &got) || got == 0) {
            goto Cleanup;
        }
        break;
    }
    default:
        return NULL;
    }
  
    segment->Offset = segmentBase;
    segment->Valid = TRUE;
    segment->LruSeq = ++Reader->LruClock;

    return segment;

Cleanup:
    /* 段更新失败，清除段字段 */
    free(segment->Data);
    RtlZeroMemory(segment, sizeof(PE_SEGMENT));
    return NULL;
}

/**************************************************/
/*             构造与属性                           */
/**************************************************/

NTSTATUS
IocInitializeBufferReader(
    _Out_ PPE_READER Reader,
    _In_ const BYTE* Buffer,
    _In_ SIZE_T BufferSize
    )
/*++
Routine Description:
    构造 Buffer 模式读取器。Buffer 为 NULL 或 Size 为 0 时返回失败
    (对齐 SS: 非零 m_size 必伴非空 m_data 不变式)。

Arguments:
    Reader     - 输出读取器。
    Buffer     - 外部整块缓冲（内存流/已 map view）。
    BufferSize - 数据大小。

Return Value:
    NTSTATUS。
--*/
{
    if (!Reader || !Buffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Reader, sizeof(PE_READER));
    Reader->Mode = PeReader_Buffer;
    Reader->Data = Buffer;
    Reader->Size = BufferSize;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PepCreateFileReader(
    _Out_ PPE_READER Reader,
    _In_ HANDLE FileHandle,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    构造 File 模式读取器。读取器不拥有 FileHandle,调用方负责关闭。
    适用于大文件扫描:无需整文件 mapview,段式 ReadFile 按需加载。

Arguments:
    Reader     - 输出读取器。
    FileHandle - 文件句柄 (GENERIC_READ, 已定位至文件头)。
    Size       - 文件大小（解析域）。

Return Value:
    无。
--*/
{
    if (!Reader || !HandleToULong(FileHandle) || Size == 0) return;
    RtlZeroMemory(Reader, sizeof(PE_READER));
    Reader->Mode = PeReader_File;
    Reader->FileHandle = FileHandle;
    Reader->Size = Size;
}

VOID
IocReaderDestroy(
    _Inout_ PPE_READER Reader
    )
/*++
Routine Description:
    释放读取器持有的堆资源:跨段拼接缓冲 Scratch,以及 File/Process
    模式下各段本地 4KB 缓冲。Buffer 模式段 Base 指向外部、Data 为
    NULL,无需释放。幂等,可重复调用。

Arguments:
    Reader - 读取器。

Return Value:
    无。
--*/
{
    ULONG i;

    if (!Reader) return;

    if (Reader->Scratch) {
        free(Reader->Scratch);
        Reader->Scratch = NULL;
        Reader->ScratchCap = 0;
    }

    /* BUFFER 模式段 Data 为 NULL,不释放;仅释放 File/Process 段堆 */
    if (Reader->Mode != PeReader_Buffer) {
        for (i = 0; i < PE_SEGMENT_COUNT; i++) {
            if (Reader->Segments[i].Data) {
                free(Reader->Segments[i].Data);
                Reader->Segments[i].Data = NULL;
            }
            Reader->Segments[i].Valid = FALSE;
        }
    }
}

PE_READER
PepCreateProcessReader(
    _In_ HANDLE    ProcessHandle,
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T    Size
    )
/*++
Routine Description:
    构造 Process 模式读取器。offset 语义 = RVA,实际地址 = BaseAddress + offset。
    读取器不拥有 ProcessHandle,调用方负责关闭。

Arguments:
    ProcessHandle - 目标进程句柄 (PROCESS_VM_READ)。
    BaseAddress   - 映像基址。
    Size          - 解析域大小 (通常为 SizeOfImage 或 4096 头区)。

Return Value:
    读取器 (按值返回, 结构体较小)。
--*/
{
    PE_READER r;

    RtlZeroMemory(&r, sizeof(r));
    r.Mode = PeReader_Process;
    r.ProcessHandle = ProcessHandle;
    r.BaseAddress = BaseAddress;
    r.Size = Size;
    return r;
}

VOID
WpeReaderSetSize(
    _Out_ PPE_READER R,
    _In_  SIZE_T      Size
    )
/*++
Routine Description:
    更新解析域大小 (学到 SizeOfImage 后扩域)。同步使既有段缓存失效,
    迫使后续读取按新域重新加载 (避免旧域边界遗留脏段)。

Arguments:
    R    - 读取器。
    Size - 新解析域大小。

Return Value:
    无。
--*/
{
    ULONG i;

    if (!R) return;
    R->Size = Size;
    for (i = 0; i < PE_SEGMENT_COUNT; i++) {
        R->Segments[i].Valid = FALSE;
    }
}

/**************************************************/
/*             范围校验                             */
/**************************************************/

NTSTATUS
CopValidateReadingRange(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T Offset,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    校验 [Offset, Offset+Size) 在解析域内, 溢出返回失败。

Arguments:
    Reader - 读取器。
    Offset - 起始偏移。
    Size   - 范围大小。

Return Value:
    STATUS_SUCCESS / 失败状态。
--*/
{
    SIZE_T end;

    if (!Reader || Size == 0) return STATUS_INVALID_PARAMETER;
    if ((ULONG64)Offset + (ULONG64)Size > ULONG_MAX) return STATUS_INTEGER_OVERFLOW;   /* 溢出 */
    end = Offset + Size;
    return end <= Reader->Size ?
        STATUS_SUCCESS :
        STATUS_BUFFER_OVERFLOW;
}

/**************************************************/
/*             读取原语                             */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
IocpReaderReadBytes(
    _In_ PPE_READER Reader,
    _In_ SIZE_T Offset,
    _Out_ PVOID Out,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    读取 Size 字节, 经边界校验后真正拷贝到 Out 指向的调用方缓冲。
    内部统一封装底层分段 / 进程内存读取与跨段拼接, 调用方无需
    感知当前读取模式 (BUFFER / File / Process)。返回 BOOLEAN,
    成功 = TRUE。
    注: 解析结果位于调用方拥有的内存中, 与读取器内部缓存生命周期
    解耦, 可在任意后续读取之间安全持有。

Arguments:
    Reader - 读取器。
    Offset - 偏移。
    Out    - 输出缓冲 (调用方拥有)。
    Size   - 字节数。

Return Value:
    NTSTATUS。
--*/
{
    SIZE_T remain = Size;

    if (!Reader || !Out || Size == 0) return FALSE;
    if (Offset + Size > CopGetReaderSize(Reader)) return FALSE;
    
    if (Reader->Mode == PeReader_Buffer) {
        RtlCopyMemory(Out, Reader->Data + Offset, Size);
        return TRUE;
    }

    while (remain > 0) {
        SIZE_T segmentBase = Offset & ~(SIZE_T)(PE_SEGMENT_SIZE - 1);
        SIZE_T segmentOffset = Offset - segmentBase;
        /* 段内真正可读取的有效字节数 */
        SIZE_T chunk = PE_SEGMENT_SIZE - segmentOffset;
        PPE_SEGMENT segment = IocpGetReaderSegment(Reader, Offset);
        if (segment == NULL) return FALSE;

        /* 若段内剩余大于总需求，则截断为本轮实际需拷贝的长度 */
        if (chunk > remain) chunk = remain;
        RtlCopyMemory(Out, segment->Data + segmentOffset, chunk);
        Out = (PVOID)((PBYTE)Out + chunk);
        Offset += chunk;
        remain -= chunk;
    }
    return TRUE;
}

BOOLEAN
IocpReaderReadArray(
    _In_  PPE_READER R,
    _In_  ULONGLONG   Offset,
    _In_  SIZE_T      Count,
    _In_  SIZE_T      ElemSize,
    _Out_ void*       Out
    )
/*++
Routine Description:
    读 Count×ElemSize 字节到 Out, SafeMul 防乘法溢出 (对齐 SS ReadArray)。
    数据经 _IocpReaderCopy 真正拷入 Out (支持跨段)。

Arguments:
    R        - 读取器。
    Offset   - 偏移。
    Count    - 元素个数。
    ElemSize - 元素字节数。
    Out      - 输出缓冲。

Return Value:
    TRUE=成功。
--*/
{
    SIZE_T totalSize;

    if (Out == NULL) return FALSE;
    if (!WpeSafeMulSz(Count, ElemSize, &totalSize)) return FALSE;
    return IocpReaderReadBytes(R, (SIZE_T)Offset, Out, totalSize);
}

BOOLEAN
IocpReaderReadString(
    _In_  PPE_READER Reader,
    _In_  ULONGLONG   Offset,
    _In_  ULONG       MaxLen,
    _Out_writes_(OutCap) PCHAR Out,
    _In_  ULONG       OutCap,
    _Out_opt_ PULONG  Len
    )
/*++
Routine Description:
    读 NUL 终止字符串。在 [Offset, Offset+MaxLen) 内找 NUL,
    拷贝(不含 NUL)到 Out 并补终止符。找不到 NUL 返回 FALSE
    (对齐 SS ReadString 语义)。OutCap 应 >= MaxLen+1。
    数据经 _IocpReaderCopy 真正拷入 Out (支持跨段)。

Arguments:
    Reader - 读取器。
    Offset - 偏移。
    MaxLen - 最大查找长度 (含 NUL 搜索窗口)。
    Out    - 输出缓冲。
    OutCap - 输出容量。
    Len    - [可选] 输出字符串长度 (不含 NUL)。

Return Value:
    TRUE=找到 NUL。
--*/
{
    ULONGLONG remaining;
    ULONGLONG searchLen;
    void* nul;
    SIZE_T strLen;

    if (Reader == NULL || Out == NULL || OutCap == 0) return FALSE;
    if (Offset >= (ULONGLONG)Reader->Size) return FALSE;

    remaining = (ULONGLONG)Reader->Size - Offset;
    searchLen = (MaxLen < remaining) ? MaxLen : remaining;
    if (searchLen >= OutCap) searchLen = OutCap - 1;

    if (!IocpReaderReadBytes(Reader, (SIZE_T)Offset, Out, (SIZE_T)searchLen)) {
        return FALSE;
    }

    nul = memchr(Out, 0, (SIZE_T)searchLen);
    if (nul == NULL) {
        if (Len) *Len = (ULONG)searchLen;
        return FALSE;
    }
    strLen = (SIZE_T)((PBYTE)nul - (PBYTE)Out);
    Out[strLen] = 0;
    if (Len) *Len = (ULONG)strLen;
    return TRUE;
}

BOOLEAN
WpeReaderCompareBytes(
    _In_  PPE_READER  Reader,
    _In_  ULONGLONG    Offset,
    _In_  const void*  Expected,
    _In_  SIZE_T       Length
    )
/*++
Routine Description:
    比对 Offset 处字节与 Expected (分块比较, 避免大栈缓冲)。
    经 _IocpReaderCopy 真正读入临时缓冲 (修复旧 BUFFER 模式失效)。

Arguments:
    Reader   - 读取器。
    Offset   - 偏移。
    Expected - 期望字节。
    Length   - 比对长度。

Return Value:
    TRUE=全部匹配。
--*/
{
    BYTE tmp[256];

    if (Reader == NULL || Expected == NULL) return FALSE;
    if (!CopValidateReadingRange(Reader, Offset, Length)) return FALSE;
    if (Length == 0) return TRUE;

    while (Length > 0) {
        SIZE_T chunk = (Length > sizeof(tmp)) ? sizeof(tmp) : Length;
        if (!IocpReaderReadBytes(Reader, (SIZE_T)Offset, tmp, chunk)) return FALSE;
        if (memcmp(tmp, Expected, chunk) != 0) return FALSE;
        Offset += chunk;
        Expected = (const BYTE*)Expected + chunk;
        Length -= chunk;
    }
    return TRUE;
}
