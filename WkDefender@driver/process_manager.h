#pragma once
#include "framework.h"


NTSTATUS InitializeProcessManager();

typedef struct _PROCESS_SCANNER
{
	KTIMER Timer;
	KDPC Dpc;
	WORK_QUEUE_ITEM WorkItem;
	KEVENT InitEvent;   // 确保定期扫描(完成进程摘要链初始化)发生在事件回调之前
	BOOLEAN InitDone;
	BOOLEAN IsScanning;		// 是否正在扫描? 防重入
	
} PROCESS_SCANNER, * PROCESS_SCANNER_PTR;

typedef struct _PROCESS_MANAGER
{
	FAST_MUTEX Lock;	// 避免周期扫描与主动更新相冲突
	ULONG ProcessCounter;	// 进程计数
	PLIST_ENTRY PsActiveProcessHead;	// 内核活动进程链表头
	LIST_ENTRY ActiveProcessAbstractHead;
	PVOID PspCidTable;	// 全局句柄表

	PROCESS_SCANNER ProcessScanner;
	RTL_BITMAP ActiveProcessBitmap;
	RTL_BITMAP ActiveProcessBitmapShadow;	// 用于进程遍历时进行差分计算, 获取退出进程

} PROCESS_MANAGER, * PROCESS_MANAGER_PTR;

typedef struct _PROCESS_ABSTRACT
{
	LIST_ENTRY ActiveProcessLinks;
	PEPROCESS EProcess;
	ULONG Pid;	// 0x2e8
	ULONG64 DirectoryTableBase;	// 0x28
	ULONG64 UserDirectoryTableBase;	// 0x280
	PULONG64 VadRoot;	// 0x658
	UCHAR ImageFileName[15];	// 0x450
} PROCESS_ABSTRACT, * PROCESS_ABSTRACT_PTR;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;  // 对象的类型名称（例如 "Process", "File", "Directory"）
} OBJECT_DIRECTORY_INFORMATION, * OBJECT_DIRECTORY_INFORMATION_PTR;