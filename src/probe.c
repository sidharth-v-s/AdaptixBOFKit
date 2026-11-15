/*
 * probe <host> <port> - single TCP port check.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host, *ports;
    int hlen, plen, port;
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in addr;
    struct hostent *he;
    u_long nb = 1;
    fd_set wf;
    struct timeval tv;
    int rc;
    char ip[64];

    BeaconDataParse(&parser, args, alen);
    host  = BeaconDataExtract(&parser, &hlen);
    ports = BeaconDataExtract(&parser, &plen);
    port  = bof_atoi(ports);
    if (!host || !host[0] || port <= 0 || port > 65535) {
        BeaconPrintf(CALLBACK_ERROR, "usage: probe <host> <port>\n");
        return;
    }

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        return;
    }

    bof_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons((u_short)port);
    addr.sin_addr.s_addr = WS2_32$inet_addr(host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        he = WS2_32$gethostbyname(host);
        if (!he || !he->h_addr_list[0]) {
            BeaconPrintf(CALLBACK_ERROR, "cannot resolve %s\n", host);
            WS2_32$WSACleanup();
            return;
        }
        bof_memcpy(&addr.sin_addr, he->h_addr_list[0], 4);
    }
    bof_ipv4(bof_ntohl(addr.sin_addr.s_addr), ip);

    s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "socket failed: %d\n", WS2_32$WSAGetLastError());
        WS2_32$WSACleanup();
        return;
    }

    WS2_32$ioctlsocket(s, FIONBIO, &nb);
    rc = WS2_32$connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == SOCKET_ERROR) {
        int err = WS2_32$WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            rc = WS2_32$select(0, NULL, &wf, NULL, &tv);
            if (rc > 0 && wf.fd_count > 0) {
                int soerr = 0;
                int slen = sizeof(soerr);
                WS2_32$getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &slen);
                rc = soerr ? SOCKET_ERROR : 0;
            } else {
                rc = SOCKET_ERROR;
            }
        }
    }

    if (rc == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "%s:%d open\n", ip, port);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "%s:%d closed/filtered\n", ip, port);

    WS2_32$closesocket(s);
    WS2_32$WSACleanup();
}
