/*
 * domaininfo - machine join status, domain/workgroup and DC.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS status;
    LPBYTE dc = NULL;
    char tmp[512];
    (void)args; (void)alen;

    if (NETAPI32$NetGetJoinInformation(NULL, &name, &status) == NERR_Success) {
        bof_w2a(name, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "Join name : %s\n", tmp);
        switch (status) {
        case NetSetupUnknownStatus: BeaconPrintf(CALLBACK_OUTPUT, "Join type : unknown\n"); break;
        case NetSetupUnjoined:      BeaconPrintf(CALLBACK_OUTPUT, "Join type : unjoined\n"); break;
        case NetSetupWorkgroupName: BeaconPrintf(CALLBACK_OUTPUT, "Join type : workgroup\n"); break;
        case NetSetupDomainName:
            BeaconPrintf(CALLBACK_OUTPUT, "Join type : domain\n");
            if (NETAPI32$NetGetDCName(NULL, name, &dc) == NERR_Success && dc) {
                bof_w2a((LPWSTR)dc, tmp, sizeof(tmp));
                BeaconPrintf(CALLBACK_OUTPUT, "DC        : %s\n", tmp);
                NETAPI32$NetApiBufferFree(dc);
            }
            break;
        }
        NETAPI32$NetApiBufferFree(name);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "NetGetJoinInformation failed\n");
    }

    {
        char computer[256];
        DWORD size = sizeof(computer);
        if (KERNEL32$GetComputerNameExA(ComputerNameDnsFullyQualified, computer, &size))
            BeaconPrintf(CALLBACK_OUTPUT, "FQDN      : %s\n", computer);
        size = sizeof(computer);
        if (KERNEL32$GetComputerNameExA(ComputerNameNetBIOS, computer, &size))
            BeaconPrintf(CALLBACK_OUTPUT, "NetBIOS   : %s\n", computer);
    }
}
