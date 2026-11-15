/*
 * arp - dump the IPv4 ARP table.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    DWORD size = 0;
    PMIB_IPNETTABLE table = NULL;
    DWORD i;
    (void)args; (void)alen;

    DWORD rc = IPHLPAPI$GetIpNetTable(NULL, &size, TRUE);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "GetIpNetTable size query failed: %lu\n", (unsigned long)rc);
        return;
    }

    table = (PMIB_IPNETTABLE)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!table) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc failed\n");
        return;
    }

    rc = IPHLPAPI$GetIpNetTable(table, &size, TRUE);
    if (rc != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "GetIpNetTable failed: %lu\n", (unsigned long)rc);
        KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-18s %-10s\n", "Internet Address", "Physical Address", "Type");
    BeaconPrintf(CALLBACK_OUTPUT, "  ----------------   ----------------   ----------\n");

    for (i = 0; i < table->dwNumEntries; i++) {
        PMIB_IPNETROW row = &table->table[i];
        char ip[32], mac[32];
        char *m = mac;
        DWORD j;
        const char *type = "other";

        bof_ipv4(bof_ntohl(row->dwAddr), ip);

        for (j = 0; j < row->dwPhysAddrLen && j < 8; j++) {
            char h[3];
            bof_hex(row->bPhysAddr[j], 2, h);
            m[0] = h[0]; m[1] = h[1]; m += 2;
            if (j + 1 < row->dwPhysAddrLen) *m++ = '-';
        }
        *m = 0;

        if (row->dwType == MIB_IPNET_TYPE_DYNAMIC) type = "dynamic";
        else if (row->dwType == MIB_IPNET_TYPE_STATIC) type = "static";
        else if (row->dwType == MIB_IPNET_TYPE_INVALID) type = "invalid";

        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-18s %-10s\n", ip, mac, type);
    }

    KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
}
