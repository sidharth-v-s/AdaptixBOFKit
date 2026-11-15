/*
 * ldapsecuritycheck - report LDAP signing and channel-binding hardening.
 *
 * Checks the local NTDS registry (only meaningful on a DC) and the
 * Directory Service object in AD, then prints a weak/OK verdict for each
 * setting.  Read-only.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

#define NTDS_KEY "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"

static int reg_dword(HKEY root, const char *sub, const char *val,
                     DWORD *out, int *found)
{
    HKEY h;
    DWORD size = sizeof(DWORD), type = 0;
    LONG rc;

    *found = 0;
    rc = ADVAPI32$RegOpenKeyExA(root, sub, 0, KEY_READ | 0x0100, &h);
    if (rc != ERROR_SUCCESS) return -1;
    rc = ADVAPI32$RegQueryValueExA(h, val, NULL, &type, (LPBYTE)out, &size);
    ADVAPI32$RegCloseKey(h);
    if (rc != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD))
        return -1;
    *found = 1;
    return 0;
}

static int has_supported_control(LDAP *ld, LDAPMessage *e, const char *oid)
{
    struct berval **vals = WLDAP32$ldap_get_values_lenA(ld, e, "supportedControl");
    int found = 0;
    ULONG i;

    if (!vals) return 0;
    for (i = 0; vals[i]; i++) {
        if ((int)vals[i]->bv_len == bof_strlen(oid) &&
            bof_strncmp(vals[i]->bv_val, oid, vals[i]->bv_len) == 0) {
            found = 1;
            break;
        }
    }
    WLDAP32$ldap_value_free_len(vals);
    return found;
}

static const char *dc_level(DWORD v)
{
    switch (v) {
    case 0: return "Windows 2000";
    case 1: return "Windows 2003 (interim)";
    case 2: return "Windows Server 2003";
    case 3: return "Windows Server 2008";
    case 4: return "Windows Server 2008 R2";
    case 5: return "Windows Server 2012";
    case 6: return "Windows Server 2012 R2";
    case 7: return "Windows Server 2016+";
    case 8: return "Windows Server 2019+";
    }
    return "unknown";
}

void go(char *args, int alen)
{
    LDAP *ld;
    LDAPMessage *res = NULL, *e;
    PCHAR attrs[5];
    ULONG rc;
    DWORD integrity = 0, cbinding = 0;
    int have_integrity = 0, have_cbinding = 0;
    char config[1024], base[1200];
    char host[256] = "", func[32] = "", policy_cb[32] = "";
    DWORD funcv = 0;
    int signing_ok, cbinding_ok;

    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "LDAP security check\n");

    reg_dword(HKEY_LOCAL_MACHINE, NTDS_KEY, "LDAPServerIntegrity",
              &integrity, &have_integrity);
    reg_dword(HKEY_LOCAL_MACHINE, NTDS_KEY, "LdapEnforceChannelBinding",
              &cbinding, &have_cbinding);

    ld = bof_ldap_open();
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP connect/bind failed\n");
        goto verdict;
    }

    attrs[0] = "dnsHostName";
    attrs[1] = "domainControllerFunctionality";
    attrs[2] = "supportedControl";
    attrs[3] = "ldapServiceName";
    attrs[4] = NULL;
    rc = WLDAP32$ldap_search_ext_sA(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)",
                                    attrs, 0, NULL, NULL, NULL, 1, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "rootDSE query failed: %lu\n",
                     (unsigned long)rc);
        WLDAP32$ldap_unbind(ld);
        goto verdict;
    }

    e = WLDAP32$ldap_first_entry(ld, res);
    if (e) {
        bof_ldap_get_str(ld, e, "dnsHostName", host, sizeof(host));
        bof_ldap_get_str(ld, e, "domainControllerFunctionality", func, sizeof(func));
        funcv = (DWORD)bof_atoi(func);
        BeaconPrintf(CALLBACK_OUTPUT, "  DC              : %s\n",
                     host[0] ? host : "(not a domain controller)");
        if (func[0])
            BeaconPrintf(CALLBACK_OUTPUT, "  Functional level: %lu (%s)\n",
                         (unsigned long)funcv, dc_level(funcv));
        BeaconPrintf(CALLBACK_OUTPUT, "  Signing control : %s\n",
                     has_supported_control(ld, e, "1.2.840.113556.1.4.619")
                         ? "advertised" : "not advertised");
    }
    WLDAP32$ldap_msgfree(res);
    res = NULL;

    if (bof_ldap_config_nc(ld, config, sizeof(config)) == 0) {
        bof_strcpy(base, "CN=Directory Service,CN=Windows NT,CN=Services,");
        bof_strncat(base, config, sizeof(base) - bof_strlen(base) - 1);
        attrs[0] = "ldapEnforceChannelBinding";
        attrs[1] = NULL;
        rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_BASE,
                                        "(objectClass=*)", attrs, 0, NULL, NULL,
                                        NULL, 1, &res);
        if (rc == LDAP_SUCCESS) {
            e = WLDAP32$ldap_first_entry(ld, res);
            if (e) bof_ldap_get_str(ld, e, "ldapEnforceChannelBinding",
                                    policy_cb, sizeof(policy_cb));
            WLDAP32$ldap_msgfree(res);
            res = NULL;
        }
    }

    WLDAP32$ldap_unbind(ld);

verdict:
    BeaconPrintf(CALLBACK_OUTPUT, "\n  Local NTDS registry\n");
    if (have_integrity) {
        BeaconPrintf(CALLBACK_OUTPUT, "    LDAPServerIntegrity       : %lu (%s)\n",
                     (unsigned long)integrity,
                     integrity >= 2 ? "require signing" :
                     (integrity == 1 ? "none" : "unknown"));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    LDAPServerIntegrity       : not set (none)\n");
    }
    if (have_cbinding) {
        BeaconPrintf(CALLBACK_OUTPUT, "    LdapEnforceChannelBinding : %lu (%s)\n",
                     (unsigned long)cbinding,
                     cbinding == 2 ? "always" :
                     (cbinding == 1 ? "when supported" : "never"));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    LdapEnforceChannelBinding : not set (never)\n");
    }
    if (policy_cb[0])
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  AD policy ldapEnforceChannelBinding: %s\n", policy_cb);

    signing_ok = have_integrity && integrity >= 2;
    cbinding_ok = (have_cbinding && cbinding == 2) ||
                  (policy_cb[0] && bof_atoi(policy_cb) == 2);

    BeaconPrintf(CALLBACK_OUTPUT, "\n  Verdict\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    LDAP signing    : %s\n",
                 signing_ok ? "OK" : "WEAK (relay possible)");
    BeaconPrintf(CALLBACK_OUTPUT, "    Channel binding : %s\n",
                 cbinding_ok ? "OK" : "WEAK (relay possible)");

    if (!have_integrity && !have_cbinding)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "\n  Note: NTDS parameters absent - host is probably not a DC.\n");
}
