/*
 * ldapsearch <filter> [attrs] [base]
 * Generic LDAP search against the local domain controller.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *filter, *attrarg = "", *basearg = "";
    int flen, alen2, blen;
    char base[512] = "";
    char attr_copy[512];
    PCHAR attrs[33];
    int nattrs = 0;
    LDAP *ld;
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;

    BeaconDataParse(&parser, args, alen);
    filter  = BeaconDataExtract(&parser, &flen);
    attrarg = BeaconDataExtract(&parser, &alen2);
    basearg = BeaconDataExtract(&parser, &blen);
    if (!filter || !filter[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: ldapsearch <filter> [attr1,attr2,...] [base-dn]\n");
        return;
    }
    if (!attrarg) attrarg = "";
    if (!basearg) basearg = "";

    ld = bof_ldap_open_ex(&rc);
    if (!ld) {
        bof_error_ldap("ldap_init/bind", rc,
                       "cannot reach or authenticate to a domain controller");
        return;
    }

    if (basearg[0]) {
        bof_strncpy(base, basearg, sizeof(base));
    } else if (bof_ldap_default_nc_ex(ld, base, sizeof(base), &rc) != 0) {
        bof_error_ldap("rootDSE defaultNamingContext", rc,
                       "cannot read the domain naming context");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (attrarg[0]) {
        char *p;
        bof_strncpy(attr_copy, attrarg, sizeof(attr_copy));
        p = attr_copy;
        while (*p && nattrs < 32) {
            char *comma;
            while (*p == ' ') p++;
            comma = p;
            while (*comma && *comma != ',') comma++;
            if (*comma) *comma++ = 0;
            if (*p) attrs[nattrs++] = p;
            p = comma;
        }
    }
    attrs[nattrs] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "LDAP search base=%s filter=%s\n\n", base, filter);
    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE, filter,
                                    nattrs ? attrs : NULL, 0, NULL, NULL, NULL,
                                    500, &res);
    if (rc != LDAP_SUCCESS) {
        bof_error_ldap("ldap_search", rc,
                       "directory query failed");
        bof_error_context("base", base);
        bof_error_context("filter", filter);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    for (e = WLDAP32$ldap_first_entry(ld, res); e; e = WLDAP32$ldap_next_entry(ld, e)) {
        PCHAR dn = WLDAP32$ldap_get_dnA(ld, e);
        int i;
        BeaconPrintf(CALLBACK_OUTPUT, "dn: %s\n", dn ? dn : "(null)");
        if (dn) WLDAP32$ldap_memfreeA(dn);

        for (i = 0; i < nattrs; i++) {
            struct berval **vals = WLDAP32$ldap_get_values_lenA(ld, e, attrs[i]);
            ULONG v;
            if (!vals) continue;
            for (v = 0; vals[v]; v++) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %s: ", attrs[i]);
                bof_ldap_print_value(vals[v]);
                BeaconPrintf(CALLBACK_OUTPUT, "\n");
            }
            WLDAP32$ldap_value_free_len(vals);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);
}
