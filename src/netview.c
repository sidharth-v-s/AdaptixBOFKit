/*
 * netview [domain] - list computers visible in a domain.
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
    LPCWSTR dom = NULL;
    PSERVER_INFO_101 buf = NULL;
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
        dom = wdomain;
    }

    st = NETAPI32$NetServerEnum(NULL, 101, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                                &read, &total, SV_TYPE_ALL, dom, NULL);
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "NetServerEnum failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Computers in %s (%lu)\n", domain[0] ? domain : "domain", (unsigned long)read);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-24s %-10s %s\n", "Name", "Version", "Comment");

    for (i = 0; i < read; i++) {
        bof_w2a(buf[i].sv101_name, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-24s %u.%-6u ", tmp,
                     (unsigned)buf[i].sv101_version_major,
                     (unsigned)buf[i].sv101_version_minor);
        if (buf[i].sv101_comment) {
            bof_w2a(buf[i].sv101_comment, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", tmp);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
        }
    }

    NETAPI32$NetApiBufferFree(buf);
}
