/*
 * netview [domain] - list computers visible in a domain.
 *
 * NetServerEnum relies on the Computer Browser service, which is disabled on
 * most modern domains (error 6118, ERROR_NO_BROWSER_SERVERS_FOUND).  When it
 * fails this command falls back to an LDAP query for computer objects on the
 * domain controller.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

static LDAP *open_ldap_for(const char *domain)
{
    LDAP *ld;
    DOMAIN_CONTROLLER_INFOA *dci = NULL;
    char host[256];
    char *h = NULL;
    DWORD rc;
    ULONG lrc;

    if (domain && domain[0]) {
        rc = NETAPI32$DsGetDcNameA(NULL, domain, NULL, NULL,
                DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dci);
        if (rc == ERROR_SUCCESS && dci && dci->DomainControllerName) {
            h = dci->DomainControllerName;
            if (h[0] == '\\' && h[1] == '\\') h += 2;
            bof_strncpy(host, h, sizeof(host));
            h = host;
        } else {
            bof_error_win32("DsGetDcName", rc,
                            "domain lookup failed; falling back to the local DC");
            bof_error_context("domain", domain);
        }
    }

    ld = WLDAP32$ldap_initA(h, 389);
    if (dci) NETAPI32$NetApiBufferFree(dci);
    if (!ld) {
        bof_error_text("ldap_init", h ? h : "local domain controller");
        return NULL;
    }
    lrc = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (lrc != LDAP_SUCCESS) {
        bof_error_ldap("ldap_bind_s", lrc,
                       "the current token could not bind to LDAP");
        WLDAP32$ldap_unbind(ld);
        return NULL;
    }
    return ld;
}

static int ldap_list_computers(const char *domain)
{
    LDAP *ld;
    char base[512];
    PCHAR attrs[5];
    LDAPMessage *res = NULL, *e;
    ULONG rc = LDAP_SUCCESS;
    int count = 0;
    char name[256], dns[256], os[256], ver[128];

    ld = open_ldap_for(domain);
    if (!ld) {
        bof_error_text("LDAP fallback", "connect or bind failed (see errors above)");
        return -1;
    }
    if (bof_ldap_default_nc_ex(ld, base, sizeof(base), &rc) != 0) {
        bof_error_ldap("rootDSE defaultNamingContext", rc,
                       "cannot determine the domain naming context");
        WLDAP32$ldap_unbind(ld);
        return -1;
    }

    attrs[0] = "name";
    attrs[1] = "dNSHostName";
    attrs[2] = "operatingSystem";
    attrs[3] = "operatingSystemVersion";
    attrs[4] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
             "(objectCategory=computer)", attrs, 0, NULL, NULL, NULL, 0,
             &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        bof_error_ldap("ldap_search(objectCategory=computer)", rc,
                       "LDAP search failed; verify the DC is reachable and the "
                       "token can read the domain");
        bof_error_context("base", base);
        bof_error_context("filter", "(objectCategory=computer)");
        WLDAP32$ldap_unbind(ld);
        return -1;
    }
    if (rc == LDAP_SIZELIMIT_EXCEEDED)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] LDAP size limit reached; list is truncated\n");

    BeaconPrintf(CALLBACK_OUTPUT, "Computers in %s (LDAP)\n",
                 domain[0] ? domain : base);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %-28s %s\n",
                 "Name", "Operating system", "Version");

    for (e = WLDAP32$ldap_first_entry(ld, res); e;
         e = WLDAP32$ldap_next_entry(ld, e)) {
        name[0] = dns[0] = os[0] = ver[0] = 0;
        bof_ldap_get_str(ld, e, "name", name, sizeof(name));
        bof_ldap_get_str(ld, e, "dNSHostName", dns, sizeof(dns));
        bof_ldap_get_str(ld, e, "operatingSystem", os, sizeof(os));
        bof_ldap_get_str(ld, e, "operatingSystemVersion", ver, sizeof(ver));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %-28s %s\n",
                     dns[0] ? dns : name, os[0] ? os : "-", ver);
        count++;
    }

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d computer(s) via LDAP\n", count);
    return 0;
}

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
        bof_error_netapi("NetServerEnum", (DWORD)st,
                         st == ERROR_NO_BROWSER_SERVERS_FOUND
                             ? "Computer Browser service is disabled; trying LDAP"
                             : "browser enumeration failed; trying LDAP");
        bof_error_context("domain", domain[0] ? domain : "(local)");
        if (ldap_list_computers(domain) == 0)
            return;
        bof_error_text("netview", "both NetServerEnum and the LDAP fallback failed");
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
