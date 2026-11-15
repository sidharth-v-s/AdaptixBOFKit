/*
 * netuse-list - list mapped network resources for the current user.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HANDLE hEnum = NULL;
    DWORD rc;
    BYTE buffer[16384];
    int total = 0;
    (void)args; (void)alen;

    rc = MPR$WNetOpenEnumA(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &hEnum);
    if (rc != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "WNetOpenEnum failed: %lu\n", (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-8s %s\n", "Local", "Remote");
    for (;;) {
        DWORD count = (DWORD)-1;
        DWORD size = sizeof(buffer);
        DWORD i;
        NETRESOURCEA *nr;

        rc = MPR$WNetEnumResourceA(hEnum, &count, buffer, &size);
        if (rc != NO_ERROR || count == 0) break;

        nr = (NETRESOURCEA *)buffer;
        for (i = 0; i < count; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %-8s %s\n",
                         nr[i].lpLocalName ? nr[i].lpLocalName : "",
                         nr[i].lpRemoteName ? nr[i].lpRemoteName : "");
            total++;
        }
    }

    MPR$WNetCloseEnum(hEnum);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d mapping(s)\n", total);
}
