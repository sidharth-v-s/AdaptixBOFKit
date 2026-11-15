/*
 * netloggedon [host] - users logged on to a local or remote machine.
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
    PWKSTA_USER_INFO_1 buf = NULL;
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

    st = NETAPI32$NetWkstaUserEnum(server, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                                   &read, &total, NULL);
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "NetWkstaUserEnum failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Logged-on users on %s (%lu)\n",
                 host[0] ? host : "localhost", (unsigned long)read);
    for (i = 0; i < read; i++) {
        if (buf[i].wkui1_username) {
            bof_w2a(buf[i].wkui1_username, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "  %-32s", tmp);
        }
        if (buf[i].wkui1_logon_domain) {
            bof_w2a(buf[i].wkui1_logon_domain, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, " domain=%s", tmp);
        }
        if (buf[i].wkui1_logon_server) {
            bof_w2a(buf[i].wkui1_logon_server, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, " server=%s", tmp);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    NETAPI32$NetApiBufferFree(buf);
}
