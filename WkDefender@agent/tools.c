#include "tools.h"

// 辅助函数：获取当前系统时间
VOID WkQuerySystemTime(PLARGE_INTEGER CurrentTime)
{
    FILETIME fileTime;
    GetSystemTimeAsFileTime(&fileTime);
    CurrentTime->LowPart = fileTime.dwLowDateTime;
    CurrentTime->HighPart = fileTime.dwHighDateTime;
}

// 内存分配辅助函数（使用 UtHeapAlloc）
LPVOID Tools_AllocHeapMemory(SIZE_T Size)
{
    return UtHeapAlloc(Size);
}

void Tools_FreeHeapMemory(LPVOID lpMem)
{
    UtHeapFree(lpMem);
}

// 链表操作函数
VOID Tools_InitListHead(PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

VOID Tools_InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    Entry->Flink = ListHead->Flink;
    Entry->Blink = ListHead;
    ListHead->Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

PLIST_ENTRY Tools_RemoveEntryList(PLIST_ENTRY Entry)
{
    Entry->Flink->Blink = Entry->Blink;
    Entry->Blink->Flink = Entry->Flink;
    Entry->Flink = Entry->Blink = Entry;
    return Entry;
}

BOOLEAN Tools_IsListEmpty(PLIST_ENTRY ListHead)
{
    return ListHead->Flink == ListHead;
}

// 在链表尾部插入节点
VOID Tools_InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}
