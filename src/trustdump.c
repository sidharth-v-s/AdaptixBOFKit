/*
 * bof-trustdump [domain]
 *
 * Map domain trusts with DsEnumerateDomainTrustsA.  Prints each trusted
 * DNS/NetBIOS name, trust direction, type, attributes and domain SID.
 * With no argument the local domain is queried; with a domain name that
 * domain is queried (requires access).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_flags(ULONG f)
{
    BeaconPrintf(CALLBACK_OUTPUT, "  flags   :");
    if (f & DS_DOMAIN_IN_FOREST)      BeaconPrintf(CALLBACK_OUTPUT, " IN_FOREST");
    if (f & DS_DOMAIN_DIRECT_OUTBOUND) BeaconPrintf(CALLBACK_OUTPUT, " OUTBOUND");
    if (f & DS_DOMAIN_TREE_ROOT)      BeaconPrintf(CALLBACK_OUTPUT, " TREE_ROOT");
    if (f & DS_DOMAIN_PRIMARY)        BeaconPrintf(CALLBACK_OUTPUT, " PRIMARY");
    if (f & DS_DOMAIN_NATIVE_MODE)    BeaconPrintf(CALLBACK_OUTPUT, " NATIVE");
    if (f & DS_DOMAIN_DIRECT_INBOUND) BeaconPrintf(CALLBACK_OUTPUT, " INBOUND");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

static const char *trust_type(DWORD t)
{
    switch (t) {
    case 1: return "DOWNLEVEL";
    case 2: return "UPLEVEL";
    case 3: return "MIT";
    case 4: return "DCE";
    }
    return "UNKNOWN";
}

static void print_attrs(DWORD a)
{
    BeaconPrintf(CALLBACK_OUTPUT, "  attrs   : 0x%08lx", (unsigned long)a);
    if (a & 0x00000001) BeaconPrintf(CALLBACK_OUTPUT, " NON_TRANSITIVE");
    if (a & 0x00000002) BeaconPrintf(CALLBACK_OUTPUT, " UPLEVEL_ONLY");
    if (a & 0x00000004) BeaconPrintf(CALLBACK_OUTPUT, " QUARANTINED");
    if (a & 0x00000008) BeaconPrintf(CALLBACK_OUTPUT, " FOREST_TRANSITIVE");
    if (a & 0x00000010) BeaconPrintf(CALLBACK_OUTPUT, " CROSS_ORGANIZATION");
    if (a & 0x00000020) BeaconPrintf(CALLBACK_OUTPUT, " WITHIN_ORGANIZATION");
    if (a & 0x00000040) BeaconPrintf(CALLBACK_OUTPUT, " TREAT_AS_EXTERNAL");
    if (a & 0x00000080) BeaconPrintf(CALLBACK_OUTPUT, " USES_RC4");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void go(char *args, int alen)
{
    datap parser;
    char *domain = "";
    int dlen = 0;
    PDS_DOMAIN_TRUSTSA trusts = NULL;
    ULONG count = 0, i;
    DWORD rc;

    BeaconDataParse(&parser, args, alen);
    domain = BeaconDataExtract(&parser, &dlen);
    if (!domain) domain = "";

    rc = NETAPI32$DsEnumerateDomainTrustsA(domain[0] ? domain : NULL,
                                           DS_DOMAIN_VALID_FLAGS,
                                           &trusts, &count);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "DsEnumerateDomainTrusts failed: %lu\n",
                     (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================ domain trusts ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] %lu trust(s)%s%s\n", (unsigned long)count,
                 domain[0] ? " for " : "", domain[0] ? domain : "");

    for (i = 0; i < count; i++) {
        PDS_DOMAIN_TRUSTSA t = &trusts[i];
        char sid[128];

        sid[0] = 0;
        if (t->DomainSid) {
            LPSTR s = NULL;
            if (ADVAPI32$ConvertSidToStringSidA(t->DomainSid, &s)) {
                bof_strncpy(sid, s, sizeof(sid));
                KERNEL32$LocalFree(s);
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n[%lu] %s\n", (unsigned long)i + 1,
                     t->DnsDomainName ? t->DnsDomainName : "(?)");
        BeaconPrintf(CALLBACK_OUTPUT, "  netbios : %s\n",
                     t->NetbiosDomainName ? t->NetbiosDomainName : "(?)");
        BeaconPrintf(CALLBACK_OUTPUT, "  parent  : %lu\n",
                     (unsigned long)t->ParentIndex);
        print_flags(t->Flags);
        BeaconPrintf(CALLBACK_OUTPUT, "  type    : %s\n", trust_type(t->TrustType));
        print_attrs(t->TrustAttributes);
        if (sid[0]) BeaconPrintf(CALLBACK_OUTPUT, "  sid     : %s\n", sid);
    }

    NETAPI32$NetApiBufferFree(trusts);
}
