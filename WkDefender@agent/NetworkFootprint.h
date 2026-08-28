/**************************************************/
/*  WkDefender 网络足迹分析                         */
/*  迁移自 ShadowStrike ProcessAnalyzer            */
/*  AnalyzeNetworkFootprintInternal (L2073)        */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winnt.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

//
// 单条网络连接
//
typedef struct _WKD_NET_CONNECTION {
    WCHAR   LocalAddress[48];
    USHORT  LocalPort;
    WCHAR   RemoteAddress[48];
    USHORT  RemotePort;
    WCHAR   State[16];       // LISTENING / ESTABLISHED / SYN_SENT / OTHER
} WKD_NET_CONNECTION, *PWKD_NET_CONNECTION;

//
// 网络行为分级（对齐 PS NetworkBehavior）
//
typedef enum _WKD_NET_BEHAVIOR {
    WkdNet_None         = 0,
    WkdNet_NoNetwork    = 1,    // 未加载网络模块
    WkdNet_BasicNetwork = 2,    // 常规网络使用
    WkdNet_UnusualPorts = 3,    // 非标准端口
} WKD_NET_BEHAVIOR, *PWKD_NET_BEHAVIOR;

//
// 网络足迹结果
//
#define WKD_NET_MAX_CONNECTIONS    128
#define WKD_NET_MAX_LISTEN_PORTS   64

typedef struct _WKD_NETWORK_FOOTPRINT {
    /* 网络模块 */
    BOOLEAN     HasNetworkModules;
    BOOLEAN     HasWs2_32;
    BOOLEAN     HasWinInet;
    BOOLEAN     HasWinHttp;
    BOOLEAN     HasWinsock;

    /* 连接计数 */
    ULONG       TcpConnectionCount;
    ULONG       UdpEndpointCount;
    ULONG       ListeningPortCount;

    /* 连接明细（固定数组，超限截断） */
    ULONG               ConnectionCount;
    WKD_NET_CONNECTION  Connections[WKD_NET_MAX_CONNECTIONS];
    ULONG               ListeningPortCountStored;
    USHORT              ListeningPorts[WKD_NET_MAX_LISTEN_PORTS];

    /* 行为判定 */
    BOOLEAN         HasExternalConnections;
    BOOLEAN         HasUnusualPorts;
    WKD_NET_BEHAVIOR Behavior;
} WKD_NETWORK_FOOTPRINT, *PWKD_NETWORK_FOOTPRINT;

//
// 分析指定进程的网络足迹（TCP/UDP IPv4+IPv6 + 监听端口 + 异常端口）
// 需要 iphlpapi.lib
//
NTSTATUS
WnfAnalyzeNetworkFootprint(
    _In_  DWORD                   ProcessId,
    _Out_ PWKD_NETWORK_FOOTPRINT  Footprint
    );
