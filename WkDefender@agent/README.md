# WkDefender Agent - 模块化架构文档

## 📋 概述

本文档说明WkDefender Agent的模块化架构设计，包括ALPC服务模块、消息处理机制和主动通知接口。

## 🏗️ 架构设计

### 模块划分

```
WkDefender Agent
├── alpc_server.h          # ALPC服务接口定义
├── alpc_server.c          # ALPC服务核心实现
└── main.c                # 业务逻辑和消息处理
```

### 模块职责

| 模块 | 职责 | 说明 |
|------|------|------|
| **alpc_server.h** | 接口定义 | 定义ALPC服务的所有接口和数据结构 |
| **alpc_server.c** | 通信服务 | 实现ALPC服务器、消息循环、主动通知 |
| **main.c** | 业务逻辑 | 实现消息处理回调、业务功能、进程监控 |

### 架构特点

1. **关注点分离**：ALPC通信逻辑与业务逻辑分离
2. **可重用性**：ALPC服务模块可被其他项目重用
3. **可维护性**：模块化设计便于维护和扩展
4. **线程安全**：使用临界区保护共享资源
5. **双向通信**：支持被动接收请求和主动发送通知

## 🔌 ALPC服务模块

### 核心接口

#### 1. 初始化和启动

```c
// 初始化ALPC服务
NTSTATUS AlpcServer_Initialize(
    PALPC_SERVER_CONTEXT pContext,
    LPCWSTR PortName,
    ULONG MaxMessageLength
);

// 启动ALPC服务器
NTSTATUS AlpcServer_Start(
    PALPC_SERVER_CONTEXT pContext,
    ALPC_MESSAGE_HANDLER MessageHandler,
    PVOID pHandlerContext
);
```

**使用示例：**

```c
ALPC_SERVER_CONTEXT context;
NTSTATUS status;

// 初始化
status = AlpcServer_Initialize(
    &context,
    L"\\RPC Control\\WkDefenderServerPort",
    0x500  // 最大消息长度
);

if (!NT_SUCCESS(status)) {
    printf("初始化失败: 0x%X\n", status);
    return;
}

// 启动服务器
status = AlpcServer_Start(
    &context,
    MyMessageHandler,  // 消息处理回调
    NULL              // 用户上下文
);
```

#### 2. 停止和清理

```c
// 停止ALPC服务器
NTSTATUS AlpcServer_Stop(PALPC_SERVER_CONTEXT pContext);

// 清理ALPC服务资源
VOID AlpcServer_Cleanup(PALPC_SERVER_CONTEXT pContext);
```

**使用示例：**

```c
// 停止服务器
AlpcServer_Stop(&context);

// 清理资源
AlpcServer_Cleanup(&context);
```

#### 3. 主动通知接口

这是Agent向UI推送消息的核心接口，支持三种数据格式：

```c
// 通用通知接口
NTSTATUS AlpcServer_SendNotification(
    PALPC_SERVER_CONTEXT pContext,
    WKDEFENDER_MESSAGE_TYPE MessageType,
    PVOID pData,
    ULONG DataLength
);

// 字符串通知
NTSTATUS AlpcServer_SendNotificationString(
    PALPC_SERVER_CONTEXT pContext,
    WKDEFENDER_MESSAGE_TYPE MessageType,
    LPCSTR pStringData
);

// 整数通知
NTSTATUS AlpcServer_SendNotificationInt(
    PALPC_SERVER_CONTEXT pContext,
    WKDEFENDER_MESSAGE_TYPE MessageType,
    UINT32 Value
);
```

**使用示例：**

```c
// 发送进程终止通知
AlpcServer_SendNotificationInt(
    &context,
    WKDEFENDER_MSG_PROCESS_TERMINATED_NOTIFICATION,
    1234  // PID
);

// 发送威胁检测通知
AlpcServer_SendNotificationString(
    &context,
    WKDEFENDER_MSG_THREAT_DETECTED_NOTIFICATION,
    "trojan.exe|Trojan.Win32.Agent|C:\\Temp\\trojan.exe"
);

// 发送扫描进度通知
UINT32 progress = 50;
AlpcServer_SendNotification(
    &context,
    WKDEFENDER_MSG_SCAN_PROGRESS_NOTIFICATION,
    &progress,
    sizeof(UINT32)
);
```

## 📨 消息处理机制

### 消息处理回调

Agent通过实现消息处理回调函数来处理UI的请求：

```c
typedef NTSTATUS (*ALPC_MESSAGE_HANDLER)(
    PWKDEFENDER_MESSAGE pRequest,
    PWKDEFENDER_MESSAGE pResponse,
    PVOID pContext
);
```

**回调函数实现示例：**

```c
NTSTATUS MyMessageHandler(
    PWKDEFENDER_MESSAGE pRequest,
    PWKDEFENDER_MESSAGE pResponse,
    PVOID pContext)
{
    // 根据消息类型分发处理
    switch (pRequest->MessageType)
    {
        case WKDEFENDER_MSG_GET_SYSTEM_STATUS_REQUEST:
            return HandleGetSystemStatus(pRequest, pResponse);
        
        case WKDEFENDER_MSG_GET_PROCESS_LIST_REQUEST:
            return HandleGetProcessList(pRequest, pResponse);
        
        // ... 其他消息类型
        
        default:
            printf("未知消息类型: 0x%X\n", pRequest->MessageType);
            return STATUS_INVALID_PARAMETER;
    }
}
```

### 消息处理流程

```
UI客户端
    ↓ 发送请求
ALPC服务器（alpc_server.c）
    ↓ 接收消息
消息处理回调（main.c）
    ↓ 处理请求
构建响应消息
    ↓ 返回响应
ALPC服务器
    ↓ 发送响应
UI客户端
```

## 🔔 主动通知机制

### 通知类型

| 消息类型 | 说明 | 数据格式 |
|---------|------|---------|
| `WKDEFENDER_MSG_PROCESS_TERMINATED_NOTIFICATION` | 进程终止通知 | UINT32 (PID) |
| `WKDEFENDER_MSG_THREAT_DETECTED_NOTIFICATION` | 威胁检测通知 | 字符串 |
| `WKDEFENDER_MSG_SCAN_COMPLETED_NOTIFICATION` | 扫描完成通知 | 自定义 |
| `WKDEFENDER_MSG_SCAN_PROGRESS_NOTIFICATION` | 扫描进度通知 | UINT32 (进度百分比) |

### 通知发送流程

```
Agent业务逻辑
    ↓ 触发通知
主动通知接口（AlpcServer_SendNotification*）
    ↓ 线程安全检查
ALPC服务器
    ↓ 发送通知消息
UI客户端
    ↓ 接收通知
UI事件处理
```

### 线程安全

主动通知接口使用临界区（CRITICAL_SECTION）确保线程安全：

```c
// 进入临界区
EnterCriticalSection(&g_NotificationLock);

// 发送通知
ntRet = NtAlpcSendWaitReceivePort(...);

// 离开临界区
LeaveCriticalSection(&g_NotificationLock);
```

## 📝 完整使用示例

### 示例1：启动Agent服务器

```c
#include "alpc_server.h"

ALPC_SERVER_CONTEXT g_Context;

void main()
{
    NTSTATUS status;
    
    // 初始化ALPC服务
    status = AlpcServer_Initialize(
        &g_Context,
        L"\\RPC Control\\WkDefenderServerPort",
        0x500
    );
    
    if (!NT_SUCCESS(status)) {
        return;
    }
    
    // 启动服务器
    status = AlpcServer_Start(
        &g_Context,
        MessageHandlerCallback,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        AlpcServer_Cleanup(&g_Context);
        return;
    }
    
    // 等待退出
    getchar();
    
    // 清理
    AlpcServer_Stop(&g_Context);
    AlpcServer_Cleanup(&g_Context);
}
```

### 示例2：发送进程终止通知

```c
void OnProcessTerminated(DWORD pid)
{
    printf("进程 %d 已终止，发送通知到UI\n", pid);
    
    // 使用主动通知接口发送通知
    NTSTATUS status = AlpcServer_SendNotificationInt(
        &g_Context,
        WKDEFENDER_MSG_PROCESS_TERMINATED_NOTIFICATION,
        pid
    );
    
    if (NT_SUCCESS(status)) {
        printf("通知发送成功\n");
    } else {
        printf("通知发送失败: 0x%X\n", status);
    }
}
```

### 示例3：发送扫描进度通知

```c
void OnScanProgress(int progress)
{
    printf("扫描进度: %d%%\n", progress);
    
    // 发送进度通知
    UINT32 progressValue = (UINT32)progress;
    AlpcServer_SendNotification(
        &g_Context,
        WKDEFENDER_MSG_SCAN_PROGRESS_NOTIFICATION,
        &progressValue,
        sizeof(UINT32)
    );
}
```

## 🔧 编译说明

### 编译命令

```bash
# 编译ALPC服务模块
cl /c alpc_server.c

# 编译主程序
cl main.c alpc_server.obj /link ntdll.lib

# 或者使用Visual Studio项目文件
```

### 依赖项

- **Windows SDK**: 提供Windows API和Native API
- **ntdll.lib**: 提供ALPC Native API函数

## 📂 文件说明

| 文件 | 说明 |
|------|------|
| `alpc_server.h` | ALPC服务接口定义，包含所有公共接口和数据结构 |
| `alpc_server.c` | ALPC服务实现，包含服务器逻辑和通知机制 |
| `main.c` | 主程序，实现业务逻辑和消息处理回调 |
| `main_old.c` | 旧版本的main.c（已备份） |

## 🎯 下一步工作

1. **完善消息处理函数**：将预填充数据替换为真实的Windows API调用
2. **实现进程监控**：完善ProcessMonitorThread中的真实监控逻辑
3. **错误处理**：添加更完善的错误处理和日志记录
4. **性能优化**：优化消息处理和通知发送的性能
5. **单元测试**：为ALPC服务模块编写单元测试

## 📞 技术支持

如有问题或建议，请联系开发团队。

---

**文档版本**: 1.0.0  
**最后更新**: 2026-04-04  
**作者**: WkDefender Team
