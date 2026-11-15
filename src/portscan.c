/*
 * portscan <target> <ports>
 *
 * TCP connect scan.  Ports accepts comma separated values and ranges,
 * e.g. "80,443,22-25,3389".
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define SCAN_TIMEOUT_MS 500

static int try_port(DWORD addr, int port)
{
    SOCKET s;
    struct sockaddr_in sa;
    u_long nonblock = 1;
    int rc;

    s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    WS2_32$ioctlsocket(s, FIONBIO, &nonblock);

    bof_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = WS2_32$htons((unsigned short)port);
    sa.sin_addr.S_un.S_addr = addr;

    rc = WS2_32$connect(s, (const struct sockaddr *)&sa, sizeof(sa));
    if (rc == SOCKET_ERROR) {
        int err = WS2_32$WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            fd_set wf;
            struct timeval tv;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            tv.tv_sec = 0;
            tv.tv_usec = SCAN_TIMEOUT_MS * 1000;
            rc = WS2_32$select(0, NULL, &wf, NULL, &tv);
            if (rc > 0 && wf.fd_count > 0 && wf.fd_array[0] == s) {
                int soerr = 0, solen = sizeof(soerr);
                if (WS2_32$getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &solen) == 0 && soerr == 0)
                    rc = 0;
                else
                    rc = -1;
            } else {
                rc = -1;
            }
        } else {
            rc = -1;
        }
    }

    WS2_32$closesocket(s);
    return rc == 0;
}

static int scan_range(DWORD addr, int start, int end, int *found)
{
    int p;
    for (p = start; p <= end; p++) {
        if (p < 1 || p > 65535) continue;
        if (try_port(addr, p)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [open] %d/tcp\n", p);
            (*found)++;
        }
    }
    return 0;
}

void go(char *args, int alen)
{
    datap parser;
    char *target, *ports;
    int tlen = 0, plen = 0;
    DWORD addr;
    char *p;
    int found = 0;
    WSADATA wsa;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: portscan <target> <ports>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    target = BeaconDataExtract(&parser, &tlen);
    ports  = BeaconDataExtract(&parser, &plen);
    if (!target || !ports) {
        BeaconPrintf(CALLBACK_ERROR, "invalid arguments\n");
        return;
    }

    addr = WS2_32$inet_addr(target);
    if (addr == INADDR_NONE) {
        BeaconPrintf(CALLBACK_ERROR, "only IPv4 addresses are supported: %s\n", target);
        return;
    }

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Scanning %s ...\n", target);

    p = ports;
    while (*p) {
        int start = 0, end = 0;
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        if (*p < '0' || *p > '9') { p++; continue; }
        while (*p >= '0' && *p <= '9') start = start * 10 + (*p++ - '0');
        end = start;
        if (*p == '-') {
            p++;
            end = 0;
            while (*p >= '0' && *p <= '9') end = end * 10 + (*p++ - '0');
        }
        scan_range(addr, start, end, &found);
        while (*p && *p != ',') p++;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\nOpen ports: %d\n", found);
    WS2_32$WSACleanup();
}
