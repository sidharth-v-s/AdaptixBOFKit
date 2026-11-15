/*
 * domaingroups [domain] - enumerate global domain groups.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *domain = "";
    int dlen = 0;
    wchar_t wdomain[256];
    LPCWSTR server = NULL;
    PGROUP_INFO_1 buf = NULL;
    DWORD read = 0, total = 0, i;
    NET_API_STATUS st;
    char tmp[512];

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        domain = BeaconDataExtract(&parser, &dlen);
        if (!domain) domain = "";
    }
    if (domain[0]) {
        bof_a2w(domain, wdomain, 256);
        server = wdomain;
    }

    st = NETAPI32$NetGroupEnum(server, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                               &read, &total, NULL);
    if (st != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "NetGroupEnum failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Domain groups in %s (%lu)\n", domain[0] ? domain : "current", (unsigned long)read);
    for (i = 0; i < read; i++) {
        bof_w2a(buf[i].grpi1_name, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s", tmp);
        if (buf[i].grpi1_comment && buf[i].grpi1_comment[0]) {
            bof_w2a(buf[i].grpi1_comment, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "  - %s", tmp);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    NETAPI32$NetApiBufferFree(buf);
}
