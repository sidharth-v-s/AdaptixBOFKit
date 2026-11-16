/*
 * kerberoast [spn|asrep|all]
 *
 * Enumerate accounts that are worth roasting, over LDAP:
 *   spn   - enabled users with a servicePrincipalName (Kerberoast targets)
 *   asrep - enabled users with DONT_REQ_PREAUTH (AS-REP roast targets)
 *   all   - both lists (default)
 *
 * This lists targets and their password age; it does not request tickets.
 * Request the actual TGS/AS-REP with Rubeus, Kerbeus or Impacket.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

static unsigned long long parse_u64(const char *s)
{
    unsigned long long v = 0;
    if (!s) return 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned long long)(*s - '0');
        s++;
    }
    return v;
}

static int is_zero(const char *s)
{
    if (!s || !s[0]) return 1;
    while (*s == '0') s++;
    return *s == 0;
}

static void print_pwd(const char *raw)
{
    unsigned long long v;
    FILETIME ft;
    SYSTEMTIME st;

    if (is_zero(raw)) {
        BeaconPrintf(CALLBACK_OUTPUT, "pwd=never");
        return;
    }
    v = parse_u64(raw);
    ft.dwLowDateTime = (DWORD)(v & 0xffffffffULL);
    ft.dwHighDateTime = (DWORD)(v >> 32);
    if (!KERNEL32$FileTimeToSystemTime(&ft, &st)) {
        BeaconPrintf(CALLBACK_OUTPUT, "pwd=?");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "pwd=%04u-%02u-%02u %02u:%02u",
                 (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
                 (unsigned)st.wHour, (unsigned)st.wMinute);
}

static void print_account(LDAP *ld, LDAPMessage *e)
{
    char sam[256], pwd[64], admin[32];

    if (bof_ldap_get_str(ld, e, "sAMAccountName", sam, sizeof(sam)) != 0)
        bof_strcpy(sam, "?");
    if (bof_ldap_get_str(ld, e, "pwdLastSet", pwd, sizeof(pwd)) != 0)
        pwd[0] = 0;
    if (bof_ldap_get_str(ld, e, "adminCount", admin, sizeof(admin)) != 0)
        admin[0] = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "  %-28.28s ", sam);
    print_pwd(pwd);
    if (admin[0] && !is_zero(admin))
        BeaconPrintf(CALLBACK_OUTPUT, "  adminCount=%s", admin);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

static int roast_spn(LDAP *ld, char *base)
{
    PCHAR attrs[5];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int count = 0;

    attrs[0] = "sAMAccountName";
    attrs[1] = "servicePrincipalName";
    attrs[2] = "pwdLastSet";
    attrs[3] = "adminCount";
    attrs[4] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
            "(&(objectClass=user)(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attrs, 0, NULL, NULL, NULL, 500, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "SPN search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Kerberoastable accounts (SPN set)\n");
    for (e = WLDAP32$ldap_first_entry(ld, res); e; e = WLDAP32$ldap_next_entry(ld, e)) {
        struct berval **spns;
        print_account(ld, e);
        spns = WLDAP32$ldap_get_values_lenA(ld, e, "servicePrincipalName");
        if (spns) {
            ULONG i;
            for (i = 0; spns[i]; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "      spn: ");
                bof_ldap_print_value(spns[i]);
                BeaconPrintf(CALLBACK_OUTPUT, "\n");
            }
            WLDAP32$ldap_value_free_len(spns);
        }
        count++;
    }
    WLDAP32$ldap_msgfree(res);
    BeaconPrintf(CALLBACK_OUTPUT, "Total: %d\n\n", count);
    return count;
}

static int roast_asrep(LDAP *ld, char *base)
{
    PCHAR attrs[4];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int count = 0;

    attrs[0] = "sAMAccountName";
    attrs[1] = "pwdLastSet";
    attrs[2] = "adminCount";
    attrs[3] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
            "(&(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attrs, 0, NULL, NULL, NULL, 500, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "AS-REP search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "AS-REP roastable accounts (pre-auth disabled)\n");
    for (e = WLDAP32$ldap_first_entry(ld, res); e; e = WLDAP32$ldap_next_entry(ld, e)) {
        print_account(ld, e);
        count++;
    }
    WLDAP32$ldap_msgfree(res);
    BeaconPrintf(CALLBACK_OUTPUT, "Total: %d\n", count);
    return count;
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0;
    char base[512];
    LDAP *ld;
    int do_spn, do_asrep;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!mode) mode = "";

    do_spn = (!mode[0] || bof_stricmp(mode, "spn") == 0 ||
              bof_stricmp(mode, "all") == 0);
    do_asrep = (!mode[0] || bof_stricmp(mode, "asrep") == 0 ||
                bof_stricmp(mode, "all") == 0);
    if (!do_spn && !do_asrep) {
        BeaconPrintf(CALLBACK_ERROR, "usage: kerberoast [spn|asrep|all]\n");
        return;
    }

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

    BeaconPrintf(CALLBACK_OUTPUT, "LDAP base: %s\n\n", base);
    if (do_spn) roast_spn(ld, base);
    if (do_asrep) roast_asrep(ld, base);

    WLDAP32$ldap_unbind(ld);
}
