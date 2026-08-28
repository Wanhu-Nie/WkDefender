/**************************************************/
/*  WkDefender IOC 引擎 — 编排层                    */
/*  独立运作: 文件扫描 + 内存扫描 + YARA 集成       */
/*                                                  */
/*  可被事件驱动 (ProcessCreate → ScanProcess)      */
/*  也可主动调用 (ScanFile / ScanMemoryRegion)       */
/**************************************************/

#pragma once

#include "IocScanner.h"
#include "IocYaraScanner.h"
#include "IocKnownDll.h"

/**************************************************/
/*               IOC 引擎上下文                    */
/**************************************************/

typedef struct _IOC_ENGINE {
    BOOLEAN             Initialized;
    IOC_YARA_SCANNER    YaraScanner;
    IOC_ENGINE_STATS    Stats;
} IOC_ENGINE, *PIOC_ENGINE;

/**************************************************/
/*               全局实例                          */
/**************************************************/

extern IOC_ENGINE g_IocEngine;

/**************************************************/
/*               函数声明                          */
/**************************************************/

NTSTATUS IocEngine_Initialize(VOID);
VOID     IocEngine_Cleanup(VOID);

/* 事件驱动: 进程创建时调用 */
NTSTATUS IocObserveProcess(_Inout_ PWKD_PROCESS WkdProcess);

/* 事件驱动: 线程创建时调用 (写回 WKD_THREAD IOC 区域) */
NTSTATUS IocObserveThread(
    _In_ PWKD_THREAD WkdThread,
    _In_ const EVENT_PAYLOAD_THREAD_CREATE* Payload
    );

/* 主动扫描: 独立于事件 */
NTSTATUS IocEngine_ScanFile(_In_ PCWSTR FilePath, _Out_ IOC_SCAN_RESULT* Result);
NTSTATUS IocEngine_ScanMemory(_In_ PWKD_PROCESS Node);

VOID     IocEngine_PrintStats(VOID);
