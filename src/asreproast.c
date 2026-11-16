/*
 * bof-asreproast [filter]
 *
 * Find AS-REP roastable accounts over LDAP: enabled user objects whose
 * userAccountControl has DONT_REQ_PREAUTH (0x400000) set.  Prints account
 * details and password age; requesting the actual AS-REP is left to
 * Rubeus / GetNPUsers / Impacket.
 *
 * Optional filter text is appended to the search (for example a
 * sAMAccountName substring) to narrow the result.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

static void pwd_age(const char *raw)
{
    unsigned long long v = 0;
    char s[32];

    if (!raw || !raw[0] || bof_strcmp(raw, "0") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  pwdLastSet: never");
        return;
    }
    while (*raw >= '0' && *raw <= '9') {
        v = v * 10 + (unsigned long long)(*raw - '0');
        raw++;
    }
    bof_ft_str(v, s, sizeof(s));
    BeaconPrintf(CALLBACK_OUTPUT, "  pwdLastSet: %s", s);
}

void go(char *args, int alen)
{
    datap parser;
    char *extra = "";
    int elen = 0;
    char base[512], filter[1024];
    LDAP *ld;
    PCHAR attrs[6];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int count = 0;

    BeaconDataParse(&parser, args, alen);
    extra = BeaconDataExtract(&parser, &elen);
    if (!extra) extra = "";

    ld = bof_ldap_open();
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP connect/bind failed\n");
        return;
    }
    if (bof_ldap_default_nc(ld, base, sizeof(base)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "could not read defaultNamingContext\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (extra[0]) {
        bof_strncpy(filter, "(&(objectClass=user)"
                     "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                     "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                     "(|(sAMAccountName=*", sizeof(filter));
        bof_strncat(filter, extra, sizeof(filter) - bof_strlen(filter) - 1);
        bof_strncat(filter, "*)(userPrincipalName=*",
                    sizeof(filter) - bof_strlen(filter) - 1);
        bof_strncat(filter, extra, sizeof(filter) - bof_strlen(filter) - 1);
        bof_strncat(filter, "*)))", sizeof(filter) - bof_strlen(filter) - 1);
    } else {
        bof_strncpy(filter, "(&(objectClass=user)"
                     "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                     "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                     sizeof(filter));
    }

    attrs[0] = "sAMAccountName";
    attrs[1] = "userPrincipalName";
    attrs[2] = "pwdLastSet";
    attrs[3] = "distinguishedName";
    attrs[4] = "lastLogonTimestamp";
    attrs[5] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE, filter,
                                    attrs, 0, NULL, NULL, NULL, 1000, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "================ AS-REP roastable accounts ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] base: %s\n", base);

    for (e = WLDAP32$ldap_first_entry(ld, res); e;
         e = WLDAP32$ldap_next_entry(ld, e)) {
        char sam[256], upn[320], pwd[64], dn[512];

        if (bof_ldap_get_str(ld, e, "sAMAccountName", sam, sizeof(sam)) != 0)
            bof_strcpy(sam, "?");
        if (bof_ldap_get_str(ld, e, "userPrincipalName", upn, sizeof(upn)) != 0)
            upn[0] = 0;
        if (bof_ldap_get_str(ld, e, "pwdLastSet", pwd, sizeof(pwd)) != 0)
            pwd[0] = 0;
        if (bof_ldap_get_str(ld, e, "distinguishedName", dn, sizeof(dn)) != 0)
            dn[0] = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "\n  %s\n", sam);
        if (upn[0]) BeaconPrintf(CALLBACK_OUTPUT, "  upn: %s\n", upn);
        if (dn[0])  BeaconPrintf(CALLBACK_OUTPUT, "  dn : %s\n", dn);
        pwd_age(pwd);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        count++;
    }

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);

    BeaconPrintf(CALLBACK_OUTPUT,
                 "\n[*] %d account(s). Request AS-REPs offline (Rubeus asreproast, "
                 "GetNPUsers.py) to crack them.\n", count);
}
