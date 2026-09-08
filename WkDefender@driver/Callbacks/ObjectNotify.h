#pragma once

#include "../Common/Constants.h"
/**************************************************/
/*                   结构体声明                    */
/**************************************************/

//
// 对象回调管理器全局状态
//
typedef struct _WKD_OBJECT_CALLBACK_MANAGER {
    BOOLEAN Initialized;
    BOOLEAN ShutdownRequested;

    HANDLE CallbackHandle;              // ObRegisterCallbacks 返回的句柄
    FAST_MUTEX Lock;                    // 初始化/清理同步锁

    //
    // 统计信息
    //
    struct {
        volatile LONG64 TotalPreOps;    // 总 PreOperation 调用次数
        volatile LONG64 SensitiveAccess;// 敏感权限访问次数
        volatile LONG64 ProcessOps;     // 进程对象操作次数
        volatile LONG64 ThreadOps;      // 线程对象操作次数
    } Statistics;
} WKD_OBJECT_CALLBACK_MANAGER, *PWKD_OBJECT_CALLBACK_MANAGER;

/**************************************************/
/*                   函数声明                      */
/**************************************************/

//
// 初始化对象回调模块（注册 ObRegisterCallbacks）
// 仅注册 PreOperation 回调，不处理 PostOperation
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbInitializeObjectNotify(
    VOID
    );

//
// 清理对象回调模块（注销 ObUnRegisterCallbacks）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbObjectNotifyCleanup(
    VOID
    );
