/*
 * netgroupmembers <group> [domain] - members of a domain global group.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *group, *domain = "";
    int glen = 0, dlen = 0;
    wchar_t wgroup[256], wdomain[256];
    LPCWSTR server = NULL;
    PGROUP_USERS_INFO_1 buf = NULL;
    DWORD read = 0, total = 0, i;
    NET_API_STATUS st;
    char tmp[512];

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: netgroupmembers <group> [domain]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    group = BeaconDataExtract(&parser, &glen);
    domain = BeaconDataExtract(&parser, &dlen);
    if (!domain) domain = "";
    if (!group) return;

    bof_a2w(group, wgroup, 256);
    if (domain[0]) {
        bof_a2w(domain, wdomain, 256);
        server = wdomain;
    }

    st = NETAPI32$NetGroupGetUsers(server, wgroup, 1, (LPBYTE *)&buf,
                                   MAX_PREFERRED_LENGTH, &read, &total, NULL);
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "NetGroupGetUsers failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Members of %s (%lu)\n", group, (unsigned long)read);
    for (i = 0; i < read; i++) {
        if (buf[i].grui1_name) {
            bof_w2a(buf[i].grui1_name, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "  %-48s attrs=0x%lx\n", tmp,
                         (unsigned long)buf[i].grui1_attributes);
        }
    }

    NETAPI32$NetApiBufferFree(buf);
}
