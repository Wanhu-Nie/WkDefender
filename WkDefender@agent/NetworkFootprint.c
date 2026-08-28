/**************************************************/
/*  WkDefender 网络足迹分析实现                     */
/*  迁移自 ShadowStrike ProcessAnalyzer            */
/*  AnalyzeNetworkFootprintInternal (L2073)        */
/**************************************************/

#include <winsock2.h>   /* 必须先于 windows.h/NetworkFootprint.h*/
#include "NetworkFootprint.h"
#include <ws2tcpip.h>   /* 须先于 tcpmib.h: _WS2IPDEF_ 守卫 IPv6 表类型 */
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/**************************************************/
/*             辅助: 网络模块检测                   */
/**************************************************/

static BOOL
WnfProcessHasModule(
    _In_ DWORD  ProcessId,
    _In_ PCWSTR ModuleName
    )
{
    HANDLE hSnapshot;
    MODULEENTRY32W me;
    BOOL found = FALSE;

    hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (_wcsicmp(me.szModule, ModuleName) == 0) {
                found = TRUE;
                break;
            }
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return found;
}

/**************************************************/
/*           TCP 连接枚举（IPv4 / IPv6）           */
/**************************************************/

static VOID
WnfAppendConnection(
    _Inout_ PWKD_NETWORK_FOOTPRINT Fp,
    _In_    PCWSTR LocalAddr,
    _In_    USHORT LocalPort,
    _In_    PCWSTR RemoteAddr,
    _In_    USHORT RemotePort,
    _In_    DWORD  State
    )
{
    if (Fp->ConnectionCount >= WKD_NET_MAX_CONNECTIONS) return;

    PWKD_NET_CONNECTION c = &Fp->Connections[Fp->ConnectionCount];

    wcsncpy_s(c->LocalAddress, RTL_NUMBER_OF(c->LocalAddress),
              LocalAddr, _TRUNCATE);
    c->LocalPort = LocalPort;
    wcsncpy_s(c->RemoteAddress, RTL_NUMBER_OF(c->RemoteAddress), RemoteAddr, _TRUNCATE);
    c->RemotePort = RemotePort;

    switch (State) {
        case MIB_TCP_STATE_LISTEN:
            wcscpy_s(c->State, RTL_NUMBER_OF(c->State), L"LISTENING");
            if (Fp->ListeningPortCountStored < WKD_NET_MAX_LISTEN_PORTS) {
                Fp->ListeningPorts[Fp->ListeningPortCountStored++] = LocalPort;
            }
            Fp->ListeningPortCount++;
            break;
        case MIB_TCP_STATE_ESTAB:
            wcscpy_s(c->State, RTL_NUMBER_OF(c->State), L"ESTABLISHED");
            Fp->HasExternalConnections = TRUE;
            break;
        case MIB_TCP_STATE_SYN_SENT:
            wcscpy_s(c->State, RTL_NUMBER_OF(c->State), L"SYN_SENT");
            break;
        default:
            wcscpy_s(c->State, RTL_NUMBER_OF(c->State), L"OTHER");
            break;
    }

    Fp->ConnectionCount++;
    Fp->TcpConnectionCount++;
}

static VOID
WnfEnumTcp(
    _In_  DWORD                  ProcessId,
    _Inout_ PWKD_NETWORK_FOOTPRINT Fp,
    _In_  BOOL                   IPv6
    )
{
    DWORD size = 0;
    BOOL v6 = IPv6;

    if (GetExtendedTcpTable(NULL, &size, FALSE,
            v6 ? AF_INET6 : AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER ||
        size == 0 || size > 16 * 1024 * 1024) {
        return;
    }

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) return;

    if (GetExtendedTcpTable(buf, &size, FALSE,
            v6 ? AF_INET6 : AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        if (!v6) {
            PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)buf;
            for (DWORD i = 0; i < table->dwNumEntries && Fp->ConnectionCount < WKD_NET_MAX_CONNECTIONS; i++) {
                const MIB_TCPROW_OWNER_PID* row = &table->table[i];
                if (row->dwOwningPid != ProcessId) continue;

                IN_ADDR localAddr, remoteAddr;
                WCHAR localBuf[INET6_ADDRSTRLEN] = { 0 };
                WCHAR remoteBuf[INET6_ADDRSTRLEN] = { 0 };
                localAddr.S_un.S_addr = row->dwLocalAddr;
                remoteAddr.S_un.S_addr = row->dwRemoteAddr;
                InetNtopW(AF_INET, &localAddr, localBuf, INET6_ADDRSTRLEN);
                InetNtopW(AF_INET, &remoteAddr, remoteBuf, INET6_ADDRSTRLEN);

                WnfAppendConnection(Fp,
                    localBuf, (USHORT)ntohs((USHORT)(row->dwLocalPort & 0xFFFF)),
                    remoteBuf, (USHORT)ntohs((USHORT)(row->dwRemotePort & 0xFFFF)),
                    row->dwState);
            }
        } else {
            PMIB_TCP6TABLE_OWNER_PID table = (PMIB_TCP6TABLE_OWNER_PID)buf;
            for (DWORD i = 0; i < table->dwNumEntries && Fp->ConnectionCount < WKD_NET_MAX_CONNECTIONS; i++) {
                const MIB_TCP6ROW_OWNER_PID* row = &table->table[i];
                if (row->dwOwningPid != ProcessId) continue;

                IN6_ADDR localAddr, remoteAddr;
                WCHAR localBuf[INET6_ADDRSTRLEN] = { 0 };
                WCHAR remoteBuf[INET6_ADDRSTRLEN] = { 0 };
                memcpy(&localAddr, row->ucLocalAddr, sizeof(localAddr));
                memcpy(&remoteAddr, row->ucRemoteAddr, sizeof(remoteAddr));
                InetNtopW(AF_INET6, &localAddr, localBuf, INET6_ADDRSTRLEN);
                InetNtopW(AF_INET6, &remoteAddr, remoteBuf, INET6_ADDRSTRLEN);

                WnfAppendConnection(Fp,
                    localBuf, (USHORT)ntohs((USHORT)(row->dwLocalPort & 0xFFFF)),
                    remoteBuf, (USHORT)ntohs((USHORT)(row->dwRemotePort & 0xFFFF)),
                    row->dwState);
            }
        }
    }

    free(buf);
}

/**************************************************/
/*           UDP 端点枚举（IPv4 / IPv6）           */
/**************************************************/

static VOID
WnfEnumUdp(
    _In_  DWORD                  ProcessId,
    _Inout_ PWKD_NETWORK_FOOTPRINT Fp,
    _In_  BOOL                   IPv6
    )
{
    DWORD size = 0;
    BOOL v6 = IPv6;

    if (GetExtendedUdpTable(NULL, &size, FALSE,
            v6 ? AF_INET6 : AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER ||
        size == 0 || size > 16 * 1024 * 1024) {
        return;
    }

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) return;

    if (GetExtendedUdpTable(buf, &size, FALSE,
            v6 ? AF_INET6 : AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        if (!v6) {
            PMIB_UDPTABLE_OWNER_PID table = (PMIB_UDPTABLE_OWNER_PID)buf;
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                if (table->table[i].dwOwningPid == ProcessId) {
                    Fp->UdpEndpointCount++;
                }
            }
        } else {
            PMIB_UDP6TABLE_OWNER_PID table = (PMIB_UDP6TABLE_OWNER_PID)buf;
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                if (table->table[i].dwOwningPid == ProcessId) {
                    Fp->UdpEndpointCount++;
                }
            }
        }
    }

    free(buf);
}

/**************************************************/
/*               主入口                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WnfAnalyzeNetworkFootprint(
    DWORD                  ProcessId,
    PWKD_NETWORK_FOOTPRINT Footprint
    )
/*++
Routine Description:
    分析指定进程的网络足迹：网络模块、TCP/UDP 连接（IPv4+IPv6）、
    监听端口、异常端口判定、行为分级。

Arguments:
    ProcessId - 目标进程 PID。
    Footprint - 输出网络足迹结果。

Return Value:
    NTSTATUS。
--*/
{
    ULONG i;

    if (!Footprint) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Footprint, sizeof(*Footprint));

    if (ProcessId == 0 || ProcessId == 4) return STATUS_SUCCESS;

    /* 网络模块检测（对齐 PS: ws2_32/wininet/winhttp/wsock32） */
    if (WnfProcessHasModule(ProcessId, L"ws2_32.dll")) Footprint->HasWs2_32 = TRUE;
    if (WnfProcessHasModule(ProcessId, L"wininet.dll")) Footprint->HasWinInet = TRUE;
    if (WnfProcessHasModule(ProcessId, L"winhttp.dll")) Footprint->HasWinHttp = TRUE;
    if (WnfProcessHasModule(ProcessId, L"wsock32.dll")) Footprint->HasWinsock = TRUE;

    Footprint->HasNetworkModules = Footprint->HasWs2_32 || Footprint->HasWinInet ||
                                   Footprint->HasWinHttp || Footprint->HasWinsock;

    /* TCP 连接（IPv4 + IPv6，对齐 PS 双栈枚举） */
    WnfEnumTcp(ProcessId, Footprint, FALSE);
    if (Footprint->ConnectionCount < WKD_NET_MAX_CONNECTIONS) {
        WnfEnumTcp(ProcessId, Footprint, TRUE);
    }

    /* UDP 端点（IPv4 + IPv6） */
    WnfEnumUdp(ProcessId, Footprint, FALSE);
    WnfEnumUdp(ProcessId, Footprint, TRUE);

    /* 异常端口判定（对齐 PS: 非 80/443/53/8080/8443 即异常） */
    for (i = 0; i < Footprint->ConnectionCount; i++) {
        USHORT rp = Footprint->Connections[i].RemotePort;
        if (rp != 0 && rp != 80 && rp != 443 && rp != 53 &&
            rp != 8080 && rp != 8443) {
            Footprint->HasUnusualPorts = TRUE;
            break;
        }
    }

    /* 行为分级（对齐 PS NetworkBehavior 判定） */
    if (!Footprint->HasNetworkModules) {
        Footprint->Behavior = WkdNet_NoNetwork;
    } else if (Footprint->HasUnusualPorts) {
        Footprint->Behavior = WkdNet_UnusualPorts;
    } else if (Footprint->TcpConnectionCount > 0 || Footprint->UdpEndpointCount > 0) {
        Footprint->Behavior = WkdNet_BasicNetwork;
    } else {
        Footprint->Behavior = WkdNet_None;
    }

    return STATUS_SUCCESS;
}
