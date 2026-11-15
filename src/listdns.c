/*
 * listdns - dump the DNS client resolver cache.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *rtype(WORD t)
{
    switch (t) {
    case 1:  return "A";
    case 2:  return "NS";
    case 5:  return "CNAME";
    case 6:  return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    }
    return "?";
}

void go(char *args, int alen)
{
    PDNS_CACHE_ENTRY e = NULL;
    int count = 0;
    char name[512];

    (void)args; (void)alen;

    if (DNSAPI$DnsGetCacheDataTable(&e) != 0 || !e) {
        BeaconPrintf(CALLBACK_ERROR, "DnsGetCacheDataTable failed\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "DNS client cache\n");
    for (; e; e = e->pNext) {
        bof_w2a(e->pszName ? e->pszName : L"", name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-48s %-6s len=%u\n",
                     name, rtype(e->wType), (unsigned)e->wDataLength);
        count++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d entries\n", count);
}
