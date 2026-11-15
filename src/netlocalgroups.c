/*
 * netlocalgroups [host] - enumerate local groups.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host = "";
    int hlen = 0;
    wchar_t whost[256];
    LPCWSTR server = NULL;
    PLOCALGROUP_INFO_1 buf = NULL;
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

    st = NETAPI32$NetLocalGroupEnum(server, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                                    &read, &total, NULL);
    if (st != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "NetLocalGroupEnum failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Local groups on %s (%lu)\n", host[0] ? host : "localhost", (unsigned long)read);
    for (i = 0; i < read; i++) {
        bof_w2a(buf[i].lgrpi1_name, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s", tmp);
        if (buf[i].lgrpi1_comment && buf[i].lgrpi1_comment[0]) {
            bof_w2a(buf[i].lgrpi1_comment, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "  - %s", tmp);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    NETAPI32$NetApiBufferFree(buf);
}
