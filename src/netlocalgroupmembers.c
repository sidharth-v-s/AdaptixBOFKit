/*
 * netlocalgroupmembers <group> [host] - enumerate members of a local group.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *group, *host = "";
    int glen = 0, hlen = 0;
    wchar_t wgroup[256], whost[256];
    LPCWSTR server = NULL;
    PLOCALGROUP_MEMBERS_INFO_1 buf = NULL;
    DWORD read = 0, total = 0, i;
    NET_API_STATUS st;
    char tmp[512];

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: netlocalgroupmembers <group> [host]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    group = BeaconDataExtract(&parser, &glen);
    host = BeaconDataExtract(&parser, &hlen);
    if (!host) host = "";

    bof_a2w(group, wgroup, 256);
    if (host[0]) {
        bof_a2w(host, whost, 256);
        server = whost;
    }

    st = NETAPI32$NetLocalGroupGetMembers(server, wgroup, 1, (LPBYTE *)&buf,
                                          MAX_PREFERRED_LENGTH, &read, &total, NULL);
    if (st != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "NetLocalGroupGetMembers failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Members of %s (%lu)\n", group, (unsigned long)read);
    for (i = 0; i < read; i++) {
        if (buf[i].lgrmi1_name && buf[i].lgrmi1_name[0]) {
            bof_w2a(buf[i].lgrmi1_name, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "  %-40s", tmp);
        } else {
            LPSTR sid = NULL;
            if (buf[i].lgrmi1_sid && ADVAPI32$ConvertSidToStringSidA(buf[i].lgrmi1_sid, &sid)) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-40s", sid);
                KERNEL32$LocalFree(sid);
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT, " (usage=%lu)\n", (unsigned long)buf[i].lgrmi1_sidusage);
    }

    NETAPI32$NetApiBufferFree(buf);
}
