/*
 * netsession [host] - enumerate SMB sessions on a machine.
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
    PSESSION_INFO_10 buf = NULL;
    DWORD read = 0, total = 0, i;
    NET_API_STATUS st;
    char client[512], user[512];

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        host = BeaconDataExtract(&parser, &hlen);
        if (!host) host = "";
    }
    if (host[0]) {
        bof_a2w(host, whost, 256);
        server = whost;
    }

    st = NETAPI32$NetSessionEnum(server, NULL, NULL, 10, (LPBYTE *)&buf,
                                 MAX_PREFERRED_LENGTH, &read, &total, NULL);
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "NetSessionEnum failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Sessions on %s (%lu)\n", host[0] ? host : "localhost", (unsigned long)read);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-24s %-24s %-8s %s\n", "Client", "User", "Idle", "Connected");
    for (i = 0; i < read; i++) {
        client[0] = user[0] = 0;
        if (buf[i].sesi10_cname) bof_w2a(buf[i].sesi10_cname, client, sizeof(client));
        if (buf[i].sesi10_username) bof_w2a(buf[i].sesi10_username, user, sizeof(user));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-24s %-24s %-8lu %lu\n",
                     client, user,
                     (unsigned long)buf[i].sesi10_idle_time,
                     (unsigned long)buf[i].sesi10_time);
    }

    NETAPI32$NetApiBufferFree(buf);
}
