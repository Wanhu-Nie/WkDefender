#pragma once

#include "WkDefenderHeader.h"

// 辅助函数：获取当前系统时间
VOID WkQuerySystemTime(PLARGE_INTEGER CurrentTime);
LPVOID Tools_AllocHeapMemory(SIZE_T Size);
void Tools_FreeHeapMemory(LPVOID lpMem);

VOID Tools_InitListHead(PLIST_ENTRY ListHead);
VOID Tools_InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry);
VOID Tools_InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry);
PLIST_ENTRY Tools_RemoveEntryList(PLIST_ENTRY Entry);
BOOLEAN Tools_IsListEmpty(PLIST_ENTRY ListHead);
