/*
 * nslookup <name> [type] [server]
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static WORD type_from_string(const char *s)
{
    if (bof_stricmp(s, "A") == 0)     return DNS_TYPE_A;
    if (bof_stricmp(s, "AAAA") == 0)  return DNS_TYPE_AAAA;
    if (bof_stricmp(s, "CNAME") == 0) return DNS_TYPE_CNAME;
    if (bof_stricmp(s, "MX") == 0)    return DNS_TYPE_MX;
    if (bof_stricmp(s, "NS") == 0)    return DNS_TYPE_NS;
    if (bof_stricmp(s, "PTR") == 0)   return DNS_TYPE_PTR;
    if (bof_stricmp(s, "TXT") == 0)   return DNS_TYPE_TEXT;
    if (bof_stricmp(s, "SRV") == 0)   return DNS_TYPE_SRV;
    if (bof_stricmp(s, "SOA") == 0)   return DNS_TYPE_SOA;
    if (bof_stricmp(s, "ANY") == 0)   return DNS_TYPE_ANY;
    return DNS_TYPE_A;
}

static void print_record(PDNS_RECORD r)
{
    char buf[512];
    switch (r->wType) {
    case DNS_TYPE_A: {
        char ip[32];
        bof_ipv4(bof_ntohl(r->Data.A.IpAddress), ip);
        BeaconPrintf(CALLBACK_OUTPUT, "  A      %s\n", ip);
        break;
    }
    case DNS_TYPE_AAAA: {
        char out[64];
        char *q = out;
        int i;
        for (i = 0; i < 8; i++) {
            bof_hex(r->Data.AAAA.Ip6Address.IP6Word[i], 4, q);
            q += 4;
            if (i != 7) *q++ = ':';
        }
        *q = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "  AAAA   %s\n", out);
        break;
    }
    case DNS_TYPE_CNAME:
        bof_strncpy(buf, r->Data.CNAME.pNameHost, sizeof(buf));
        BeaconPrintf(CALLBACK_OUTPUT, "  CNAME  %s\n", buf);
        break;
    case DNS_TYPE_PTR:
        bof_strncpy(buf, r->Data.PTR.pNameHost, sizeof(buf));
        BeaconPrintf(CALLBACK_OUTPUT, "  PTR    %s\n", buf);
        break;
    case DNS_TYPE_NS:
        bof_strncpy(buf, r->Data.NS.pNameHost, sizeof(buf));
        BeaconPrintf(CALLBACK_OUTPUT, "  NS     %s\n", buf);
        break;
    case DNS_TYPE_MX:
        bof_strncpy(buf, r->Data.MX.pNameExchange, sizeof(buf));
        BeaconPrintf(CALLBACK_OUTPUT, "  MX     %u %s\n", (unsigned)r->Data.MX.wPreference, buf);
        break;
    case DNS_TYPE_SRV:
        bof_strncpy(buf, r->Data.SRV.pNameTarget, sizeof(buf));
        BeaconPrintf(CALLBACK_OUTPUT, "  SRV    %u %u %u %s\n",
                     (unsigned)r->Data.SRV.wPriority,
                     (unsigned)r->Data.SRV.wWeight,
                     (unsigned)r->Data.SRV.wPort, buf);
        break;
    case DNS_TYPE_TEXT: {
        DWORD i;
        for (i = 0; i < r->Data.TXT.dwStringCount; i++) {
            bof_strncpy(buf, r->Data.TXT.pStringArray[i], sizeof(buf));
            BeaconPrintf(CALLBACK_OUTPUT, "  TXT    %s\n", buf);
        }
        break;
    }
    case DNS_TYPE_SOA:
        bof_strncpy(buf, r->Data.SOA.pNamePrimaryServer, sizeof(buf));
        BeaconPrintf(CALLBACK_OUTPUT, "  SOA    %s\n", buf);
        break;
    default:
        BeaconPrintf(CALLBACK_OUTPUT, "  type=%u\n", (unsigned)r->wType);
        break;
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *name, *type = "A", *server = "";
    int nlen = 0, tlen = 0, slen = 0;
    IP4_ARRAY server_array;
    PDNS_RECORD rec = NULL;
    PDNS_RECORD r;
    DNS_STATUS status;
    WORD qtype;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: nslookup <name> [type] [server]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    name = BeaconDataExtract(&parser, &nlen);
    type = BeaconDataExtract(&parser, &tlen);
    if (tlen <= 0) type = "A";
    server = BeaconDataExtract(&parser, &slen);
    if (slen <= 0) server = "";

    qtype = type_from_string(type);
    BeaconPrintf(CALLBACK_OUTPUT, "Query: %s type=%s server=%s\n", name, type,
                 server[0] ? server : "(default)");

    bof_memzero(&server_array, sizeof(server_array));
    if (server[0]) {
        server_array.AddrCount = 1;
        server_array.AddrArray[0] = WS2_32$inet_addr(server);
        if (server_array.AddrArray[0] == INADDR_NONE) {
            BeaconPrintf(CALLBACK_ERROR, "invalid DNS server: %s\n", server);
            return;
        }
    }

    status = DNSAPI$DnsQuery_A(name, qtype, DNS_QUERY_STANDARD,
                               server[0] ? &server_array : NULL, &rec, NULL);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "DnsQuery failed: %lu\n", (unsigned long)status);
        return;
    }

    for (r = rec; r; r = r->pNext)
        print_record(r);

    DNSAPI$DnsRecordListFree(rec, DnsFreeRecordList);
}
