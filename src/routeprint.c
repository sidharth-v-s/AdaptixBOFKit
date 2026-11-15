/*
 * routeprint - dump the IPv4 routing table.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    DWORD size = 0, i;
    PMIB_IPFORWARDTABLE table;
    DWORD rc;
    (void)args; (void)alen;

    rc = IPHLPAPI$GetIpForwardTable(NULL, &size, TRUE);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "GetIpForwardTable size query failed: %lu\n", (unsigned long)rc);
        return;
    }

    table = (PMIB_IPFORWARDTABLE)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!table) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc failed\n");
        return;
    }

    rc = IPHLPAPI$GetIpForwardTable(table, &size, TRUE);
    if (rc != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "GetIpForwardTable failed: %lu\n", (unsigned long)rc);
        KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-16s %-16s %-6s %s\n",
                 "Destination", "Netmask", "Gateway", "Iface", "Metric");
    BeaconPrintf(CALLBACK_OUTPUT, "  ---------------- ---------------- ---------------- ------ ------\n");

    for (i = 0; i < table->dwNumEntries; i++) {
        PMIB_IPFORWARDROW r = &table->table[i];
        char dst[32], mask[32], gw[32];
        bof_ipv4(bof_ntohl(r->dwForwardDest), dst);
        bof_ipv4(bof_ntohl(r->dwForwardMask), mask);
        bof_ipv4(bof_ntohl(r->dwForwardNextHop), gw);
        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-16s %-16s %-6lu %lu\n",
                     dst, mask, gw,
                     (unsigned long)r->dwForwardIfIndex,
                     (unsigned long)r->dwForwardMetric1);
    }

    KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
}
