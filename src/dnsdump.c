/*
 * bof-dnsdump [domain-dn]
 *
 * Dump AD-integrated DNS records over LDAP from DC=DomainDnsZones and
 * DC=ForestDnsZones.  Every dnsNode is printed with its dnsRecord values
 * decoded for A, AAAA, CNAME, PTR, NS, MX, TXT and SRV.
 *
 * No DNS server access is required; this uses the same LDAP bind as the other
 * AD BOFs.  The optional argument overrides the naming context used to build
 * the DNS partition DNs.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

static unsigned int dns_le16(const unsigned char *p)
{
    return p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int dns_le32(const unsigned char *p)
{
    return p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static void dns_name(const unsigned char *p, unsigned int n, unsigned int off,
                     char *out, int outsz)
{
    unsigned int o = 0;
    out[0] = 0;
    while (off < n && o < (unsigned int)outsz - 1 && p[off] &&
           p[off] >= 0x20) {
        out[o++] = (char)p[off++];
    }
    out[o] = 0;
}

static void print_record(const unsigned char *p, unsigned int n,
                         const char *owner)
{
    unsigned int type, ttl, dlen;
    char addr[64], name[512];

    if (n < 26) return;
    dlen = dns_le32(p);
    type = dns_le16(p + 4);
    ttl = dns_le32(p + 14);

    switch (type) {
    case 1: /* A */
        if (n >= 30) {
            bof_ipv4(bof_ntohl(dns_le32(p + 26)), addr);
            BeaconPrintf(CALLBACK_OUTPUT, "  A      %-40s %s (ttl %u)\n",
                         owner, addr, ttl);
        }
        break;
    case 28: /* AAAA */
        if (n >= 42) {
            char *q = addr;
            int i;
            for (i = 0; i < 8; i++) {
                char t[8];
                unsigned int w = (dns_le16(p + 26 + i * 2));
                bof_hex(w, 4, t);
                bof_strcpy(q, t);
                q += 4;
                if (i != 7) *q++ = ':';
            }
            *q = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "  AAAA   %-40s %s (ttl %u)\n",
                         owner, addr, ttl);
        }
        break;
    case 2:  /* NS */
    case 5:  /* CNAME */
    case 12: /* PTR */
        dns_name(p, n, 26, name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-40s %s (ttl %u)\n",
                     type == 2 ? "NS" : type == 5 ? "CNAME" : "PTR",
                     owner, name, ttl);
        break;
    case 15: /* MX */
        dns_name(p, n, 28, name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT, "  MX     %-40s %u %s (ttl %u)\n",
                     owner, dns_le16(p + 26), name, ttl);
        break;
    case 16: /* TXT */
        if (n > 27 && p[26] && 27u + p[26] <= n) {
            unsigned int l = p[26];
            unsigned int i;
            for (i = 0; i < l && i < sizeof(name) - 1; i++)
                name[i] = (char)p[27 + i];
            name[i] = 0;
        } else if (n >= 30) {
            dns_name(p, n, 30, name, sizeof(name));
        } else {
            bof_strcpy(name, "<binary>");
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  TXT    %-40s %s (ttl %u)\n",
                     owner, name, ttl);
        break;
    case 33: /* SRV */
        dns_name(p, n, 32, name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  SRV    %-40s priority=%u weight=%u port=%u %s (ttl %u)\n",
                     owner, dns_le16(p + 26), dns_le16(p + 28),
                     dns_le16(p + 30), name, ttl);
        break;
    case 6: /* SOA */
        BeaconPrintf(CALLBACK_OUTPUT, "  SOA    %-40s <soa, ttl %u>\n",
                     owner, ttl);
        break;
    default:
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  type%-3u %-40s <binary %u bytes, ttl %u>\n",
                     type, owner, dlen, ttl);
        break;
    }
}

static int dump_partition(LDAP *ld, const char *base)
{
    PCHAR attrs[4];
    LDAPMessage *res = NULL, *e;
    ULONG rc;
    int count = 0;

    attrs[0] = "dc";
    attrs[1] = "name";
    attrs[2] = "dnsRecord";
    attrs[3] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, (PCHAR)base, LDAP_SCOPE_SUBTREE,
                                    "(objectClass=dnsNode)", attrs, 0,
                                    NULL, NULL, NULL, 0, &res);
    if (rc != LDAP_SUCCESS || !res) {
        WLDAP32$ldap_msgfree(res);
        return -1;
    }

    for (e = WLDAP32$ldap_first_entry(ld, res); e;
         e = WLDAP32$ldap_next_entry(ld, e)) {
        char owner[512] = "";
        struct berval **vals;

        if (bof_ldap_get_str(ld, e, "dc", owner, sizeof(owner)) != 0)
            bof_ldap_get_str(ld, e, "name", owner, sizeof(owner));
        vals = WLDAP32$ldap_get_values_lenA(ld, e, "dnsRecord");
        if (!vals || !vals[0]) {
            if (vals) WLDAP32$ldap_value_free_len(vals);
            continue;
        }
        for (unsigned int i = 0; vals[i]; i++) {
            print_record((const unsigned char *)vals[i]->bv_val,
                         (unsigned int)vals[i]->bv_len,
                         owner[0] ? owner : "(root)");
            count++;
        }
        WLDAP32$ldap_value_free_len(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return count;
}

static void try_partition(LDAP *ld, const char *label, const char *base)
{
    int n;
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s ===\n[*] %s\n", label, base);
    n = dump_partition(ld, base);
    if (n < 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  partition not present or not readable\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  %d record(s)\n", n);
}

void go(char *args, int alen)
{
    datap parser;
    char *nc = NULL;
    int nclen = 0;
    char base[512], part[768];
    LDAP *ld;
    ULONG rc;

    BeaconDataParse(&parser, args, alen);
    nc = BeaconDataExtract(&parser, &nclen);
    if (!nc) nc = "";

    ld = bof_ldap_open_ex(&rc);
    if (!ld) {
        bof_error_ldap("ldap_init/bind", rc,
                       "cannot reach or authenticate to a domain controller");
        return;
    }
    if (nc[0]) {
        bof_strncpy(base, nc, sizeof(base));
    } else if (bof_ldap_default_nc_ex(ld, base, sizeof(base), &rc) != 0) {
        bof_error_ldap("rootDSE defaultNamingContext", rc,
                       "cannot read the domain naming context");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================ AD DNS dump ================\n");
    bof_strncpy(part, "DC=DomainDnsZones,", sizeof(part));
    bof_strncat(part, base, sizeof(part) - bof_strlen(part) - 1);
    try_partition(ld, "DomainDnsZones", part);

    bof_strncpy(part, "DC=ForestDnsZones,", sizeof(part));
    bof_strncat(part, base, sizeof(part) - bof_strlen(part) - 1);
    try_partition(ld, "ForestDnsZones", part);

    WLDAP32$ldap_unbind(ld);
}
