/*
 * smbinfo [host] - SMB/workstation info via NetWkstaGetInfo.
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
    PWKSTA_INFO_100 i100 = NULL;
    PWKSTA_INFO_101 i101 = NULL;
    NET_API_STATUS st;
    char comp[256], dom[256], root[512];

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        host = BeaconDataExtract(&parser, &hlen);
        if (!host) host = "";
    }
    bof_a2w(host, whost, 256);

    st = NETAPI32$NetWkstaGetInfo(host[0] ? whost : NULL, 100, (LPBYTE *)&i100);
    if (st != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "NetWkstaGetInfo(100) failed: %lu\n", (unsigned long)st);
        return;
    }

    bof_w2a(i100->wki100_computername ? i100->wki100_computername : L"", comp, sizeof(comp));
    bof_w2a(i100->wki100_langroup ? i100->wki100_langroup : L"", dom, sizeof(dom));

    BeaconPrintf(CALLBACK_OUTPUT, "Workstation info for %s\n", host[0] ? host : "local");
    BeaconPrintf(CALLBACK_OUTPUT, "  Computer   : %s\n", comp);
    BeaconPrintf(CALLBACK_OUTPUT, "  Domain     : %s\n", dom);
    BeaconPrintf(CALLBACK_OUTPUT, "  Platform   : %lu\n", (unsigned long)i100->wki100_platform_id);
    BeaconPrintf(CALLBACK_OUTPUT, "  OS version : %lu.%lu\n",
                 (unsigned long)i100->wki100_ver_major,
                 (unsigned long)i100->wki100_ver_minor);
    NETAPI32$NetApiBufferFree(i100);

    st = NETAPI32$NetWkstaGetInfo(host[0] ? whost : NULL, 101, (LPBYTE *)&i101);
    if (st == NERR_Success && i101) {
        bof_w2a(i101->wki101_lanroot ? i101->wki101_lanroot : L"", root, sizeof(root));
        BeaconPrintf(CALLBACK_OUTPUT, "  LAN root   : %s\n", root);
        NETAPI32$NetApiBufferFree(i101);
    }
}
