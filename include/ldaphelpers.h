/*
 * AdaptixBOFKit - minimal LDAP helpers (current user, negotiate auth).
 */
#ifndef ADAPTIX_LDAPHELPERS_H
#define ADAPTIX_LDAPHELPERS_H

#include <windows.h>

/* Connect to the local domain controller and bind with the current token. */
static inline LDAP *bof_ldap_open(void)
{
    LDAP *ld = WLDAP32$ldap_initA(NULL, 389);
    ULONG rc;
    if (!ld) return NULL;
    rc = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        WLDAP32$ldap_unbind(ld);
        return NULL;
    }
    return ld;
}

/* Read defaultNamingContext from the rootDSE. Returns 0 on success. */
static inline int bof_ldap_default_nc(LDAP *ld, char *out, int outsz)
{
    PCHAR attrs[2];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    struct berval **vals;
    ULONG rc;
    int ok = -1;

    attrs[0] = "defaultNamingContext";
    attrs[1] = NULL;
    rc = WLDAP32$ldap_search_ext_sA(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)",
                                    attrs, 0, NULL, NULL, NULL, 1, &res);
    if (rc != LDAP_SUCCESS || !res) return -1;

    e = WLDAP32$ldap_first_entry(ld, res);
    if (e) {
        vals = WLDAP32$ldap_get_values_lenA(ld, e, "defaultNamingContext");
        if (vals && vals[0] && (int)vals[0]->bv_len < outsz) {
            bof_memcpy(out, vals[0]->bv_val, vals[0]->bv_len);
            out[vals[0]->bv_len] = 0;
            ok = 0;
        }
        if (vals) WLDAP32$ldap_value_free_len(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return ok;
}

/* Copy the first value of attr for entry e into out. Returns 0 on success. */
static inline int bof_ldap_get_str(LDAP *ld, LDAPMessage *e, const char *attr,
                                   char *out, int outsz)
{
    struct berval **vals = WLDAP32$ldap_get_values_lenA(ld, e, (PCHAR)attr);
    int ok = -1;
    if (vals && vals[0] && (int)vals[0]->bv_len < outsz) {
        bof_memcpy(out, vals[0]->bv_val, vals[0]->bv_len);
        out[vals[0]->bv_len] = 0;
        ok = 0;
    }
    if (vals) WLDAP32$ldap_value_free_len(vals);
    return ok;
}

/* Read configurationNamingContext from the rootDSE. */
static inline int bof_ldap_config_nc(LDAP *ld, char *out, int outsz)
{
    PCHAR attrs[2];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int ok = -1;

    attrs[0] = "configurationNamingContext";
    attrs[1] = NULL;
    rc = WLDAP32$ldap_search_ext_sA(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)",
                                    attrs, 0, NULL, NULL, NULL, 1, &res);
    if (rc != LDAP_SUCCESS || !res) return -1;
    e = WLDAP32$ldap_first_entry(ld, res);
    if (e) ok = bof_ldap_get_str(ld, e, "configurationNamingContext", out, outsz);
    WLDAP32$ldap_msgfree(res);
    return ok;
}

static inline void bof_ldap_print_value(const struct berval *bv)
{
    ULONG i, printable = 1;
    if (!bv || !bv->bv_val) return;
    for (i = 0; i < bv->bv_len; i++) {
        unsigned char c = (unsigned char)bv->bv_val[i];
        if (c < 0x20 && c != '\t') { printable = 0; break; }
    }
    if (printable) {
        char tmp[512];
        ULONG n = bv->bv_len < sizeof(tmp) - 1 ? bv->bv_len : sizeof(tmp) - 1;
        bof_memcpy(tmp, bv->bv_val, n);
        tmp[n] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "%s", tmp);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "<binary %lu bytes>", (unsigned long)bv->bv_len);
    }
}

#endif /* ADAPTIX_LDAPHELPERS_H */
