/*
 * nbtscan <host[,host...]> - NetBIOS node status (NBNS) name enumeration.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int skip_name(const unsigned char *p, const unsigned char *end)
{
    if (p >= end) return -1;
    if (*p == 0) return 1;
    if (*p & 0xC0) return 2;          /* compression pointer */
    if (p + 1 + *p > end) return -1;
    return 1 + *p;
}

static void query_host(const char *host, unsigned char *pkt)
{
    SOCKET s;
    struct sockaddr_in addr;
    struct hostent *he;
    unsigned char buf[2048];
    const unsigned char *p, *end;
    int n, timeout = 1500, off, answers, i;
    char ip[64];

    bof_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons(137);
    addr.sin_addr.s_addr = WS2_32$inet_addr(host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        he = WS2_32$gethostbyname(host);
        if (!he || !he->h_addr_list[0]) {
            BeaconPrintf(CALLBACK_ERROR, "%s: cannot resolve\n", host);
            return;
        }
        bof_memcpy(&addr.sin_addr, he->h_addr_list[0], 4);
    }
    bof_ipv4(bof_ntohl(addr.sin_addr.s_addr), ip);

    s = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "socket failed: %d\n", WS2_32$WSAGetLastError());
        return;
    }
    WS2_32$setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    n = WS2_32$sendto(s, (const char *)pkt, 50, 0,
                      (const struct sockaddr *)&addr, sizeof(addr));
    if (n <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "%s: sendto failed: %d\n", host, WS2_32$WSAGetLastError());
        WS2_32$closesocket(s);
        return;
    }

    n = WS2_32$recvfrom(s, (char *)buf, sizeof(buf), 0, NULL, NULL);
    WS2_32$closesocket(s);
    if (n < 57) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s (%s): no NetBIOS response\n", host, ip);
        return;
    }

    p = buf + 12;
    end = buf + n;
    off = skip_name(p, end);
    if (off < 0 || p + off + 4 > end) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s (%s): malformed response\n", host, ip);
        return;
    }
    p += off + 4;
    answers = (buf[6] << 8) | buf[7];

    BeaconPrintf(CALLBACK_OUTPUT, "%s (%s)\n", host, ip);
    for (i = 0; i < answers && p < end; i++) {
        int t, rdlen;
        off = skip_name(p, end);
        if (off < 0 || p + off + 10 > end) break;
        p += off;
        t = (p[0] << 8) | p[1];
        rdlen = (p[8] << 8) | p[9];
        p += 10;
        if (p + rdlen > end) break;
        if (t == 0x21 && rdlen >= 1) {
            int count = p[0], j;
            const unsigned char *q = p + 1;
            for (j = 0; j < count && q + 18 <= p + rdlen; j++, q += 18) {
                char name[17];
                int k;
                bof_memzero(name, sizeof(name));
                for (k = 0; k < 15; k++)
                    name[k] = (q[k] >= 0x20 && q[k] < 0x7f) ? (char)q[k] : '.';
                bof_trim(name);
                BeaconPrintf(CALLBACK_OUTPUT, "  %-16s <%02x> %s\n",
                             name, q[15],
                             ((q[16] << 8) | q[17]) & 0x8000 ? "GROUP" : "UNIQUE");
            }
        }
        p += rdlen;
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *hosts;
    int hlen;
    unsigned char pkt[50];
    char list[1024];
    char *p;
    int i;
    WSADATA wsa;

    BeaconDataParse(&parser, args, alen);
    hosts = BeaconDataExtract(&parser, &hlen);
    if (!hosts || !hosts[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: nbtscan <host[,host...]>\n");
        return;
    }

    bof_memzero(pkt, sizeof(pkt));
    pkt[0] = 0x82;
    pkt[1] = 0x28;
    pkt[5] = 0x01;               /* one question */
    pkt[12] = 0x20;              /* encoded wildcard name */
    pkt[13] = 'C';
    pkt[14] = 'K';
    for (i = 15; i < 45; i++) pkt[i] = 'A';
    pkt[45] = 0x00;
    pkt[47] = 0x21;              /* NBSTAT */
    pkt[49] = 0x01;              /* IN */

    bof_memzero(&wsa, sizeof(wsa));
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        return;
    }

    bof_strncpy(list, hosts, sizeof(list));
    p = list;
    while (p && *p) {
        char *comma = p;
        while (*comma && *comma != ',') comma++;
        if (*comma) *comma++ = 0;
        bof_trim(p);
        if (*p) query_host(p, pkt);
        p = comma;
    }
    WS2_32$WSACleanup();
}
