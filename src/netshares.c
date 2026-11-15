/*
 * netshares [host] - enumerate SMB shares on a host.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *share_type(DWORD t)
{
    DWORD base = t & 0x000000ff;
    if (t & STYPE_SPECIAL) return "special";
    switch (base) {
    case STYPE_DISKTREE: return "disk";
    case STYPE_PRINTQ:   return "print";
    case STYPE_DEVICE:   return "device";
    case STYPE_IPC:      return "ipc";
    }
    return "other";
}

void go(char *args, int alen)
{
    datap parser;
    char *host = "";
    int hlen = 0;
    wchar_t whost[256];
    LPWSTR server = NULL;
    PSHARE_INFO_1 buf = NULL;
    DWORD read = 0, total = 0, i;
    NET_API_STATUS st;
    char tmp[512];

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        host = BeaconDataExtract(&parser, &hlen);
        if (!host) host = "";
    }

    if (host[0]) {
        bof_a2w(host, whost, 256);
        server = whost;
    }

    st = NETAPI32$NetShareEnum(server, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                               &read, &total, NULL);
    if (st != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "NetShareEnum failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Shares on %s (%lu)\n", host[0] ? host : "localhost", (unsigned long)read);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-24s %-10s %s\n", "Name", "Type", "Remark");

    for (i = 0; i < read; i++) {
        bof_w2a(buf[i].shi1_netname, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-24s %-10s ", tmp, share_type(buf[i].shi1_type));
        if (buf[i].shi1_remark) {
            bof_w2a(buf[i].shi1_remark, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", tmp);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
        }
    }

    NETAPI32$NetApiBufferFree(buf);
}
