/*
 * addlocalcert [user|machine] [subject]
 *
 * Create a self-signed certificate and add it to the MY store.  Defaults:
 * LocalMachine and CN=AdaptixBOFKit.  Writing to LocalMachine needs admin.
 * The private key is not persisted; the stored certificate is suitable for
 * trust-style use, not for TLS server authentication.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void add_years(SYSTEMTIME *st, WORD years)
{
    st->wYear = (WORD)(st->wYear + years);
}

void go(char *args, int alen)
{
    datap parser;
    char *which = "", *subject = "";
    char whichbuf[32], subjbuf[256];
    int len, machine = 1;
    char container[64];
    HCRYPTPROV prov = 0;
    HCRYPTKEY key = 0;
    DWORD cbName = 0;
    BYTE *name = NULL;
    CERT_NAME_BLOB nb;
    SYSTEMTIME start, end;
    PCCERT_CONTEXT cert = NULL;
    HCERTSTORE store = NULL;
    DWORD flags;
    char label[64], thumb[64];
    int ok = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        which = BeaconDataExtract(&parser, &len);
        if (which) bof_strncpy(whichbuf, which, sizeof(whichbuf)); else whichbuf[0] = 0;
        subject = BeaconDataExtract(&parser, &len);
        if (subject) bof_strncpy(subjbuf, subject, sizeof(subjbuf)); else subjbuf[0] = 0;
        which = whichbuf; subject = subjbuf;
    }

    if (which[0] && bof_stricmp(which, "user") == 0) machine = 0;
    if (!subject[0]) subject = "CN=AdaptixBOFKit";

    /* A named key container avoids clinging to the default container. */
    bof_strcpy(container, "AdaptixBOFKit-");
    {
        char num[16];
        bof_itoa(KERNEL32$GetCurrentProcessId(), num);
        bof_strncat(container, num, sizeof(container) - bof_strlen(container) - 1);
    }

    if (!ADVAPI32$CryptAcquireContextA(&prov, container, MS_ENHANCED_PROV_A,
                                        PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        if (!ADVAPI32$CryptAcquireContextA(&prov, NULL, MS_ENHANCED_PROV_A,
                                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            BeaconPrintf(CALLBACK_ERROR, "CryptAcquireContext failed: %lu\n",
                         (unsigned long)KERNEL32$GetLastError());
            return;
        }
    }

    if (!ADVAPI32$CryptGenKey(prov, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &key)) {
        BeaconPrintf(CALLBACK_ERROR, "CryptGenKey failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CryptReleaseContext(prov, 0);
        return;
    }

    if (!CRYPT32$CertStrToNameA(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR,
                                NULL, NULL, &cbName, NULL) || !cbName) {
        BeaconPrintf(CALLBACK_ERROR, "bad subject name: %s\n", subject);
        goto cleanup;
    }
    name = (BYTE *)KERNEL32$VirtualAlloc(NULL, cbName, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!name) goto cleanup;
    if (!CRYPT32$CertStrToNameA(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR,
                                NULL, name, &cbName, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "CertStrToName failed\n");
        goto cleanup;
    }

    nb.cbData = cbName;
    nb.pbData = name;

    bof_memzero(&start, sizeof(start));
    KERNEL32$GetSystemTime(&start);
    end = start;
    add_years(&end, 10);

    cert = CRYPT32$CertCreateSelfSignCertificate(
               (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)prov, &nb, 0, NULL, NULL,
               &start, &end, NULL);
    if (!cert) {
        BeaconPrintf(CALLBACK_ERROR, "CertCreateSelfSignCertificate failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        goto cleanup;
    }

    flags = machine ? CERT_SYSTEM_STORE_LOCAL_MACHINE
                    : CERT_SYSTEM_STORE_CURRENT_USER;
    bof_strcpy(label, machine ? "LocalMachine" : "CurrentUser");
    store = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, flags, L"MY");
    if (!store) {
        BeaconPrintf(CALLBACK_ERROR,
                     "CertOpenStore(%s\\MY) failed: %lu (admin required?)\n",
                     label, (unsigned long)KERNEL32$GetLastError());
        goto cleanup;
    }

    if (!CRYPT32$CertAddCertificateContextToStore(store, cert,
                                                  CERT_STORE_ADD_REPLACE_EXISTING,
                                                  NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "CertAddCertificateContextToStore failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        goto cleanup;
    }

    {
        BYTE hash[32];
        DWORD hlen = sizeof(hash), i;
        bof_memzero(hash, sizeof(hash));
        if (CRYPT32$CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID,
                                                      hash, &hlen)) {
            for (i = 0; i < hlen && i < 20; i++)
                bof_hex(hash[i], 2, thumb + i * 2);
            thumb[(hlen < 20 ? hlen : 20) * 2] = 0;
        } else {
            bof_strcpy(thumb, "-");
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Added certificate to %s\\MY\n", label);
    BeaconPrintf(CALLBACK_OUTPUT, "  Subject : %s\n", subject);
    BeaconPrintf(CALLBACK_OUTPUT, "  SHA1    : %s\n", thumb);
    BeaconPrintf(CALLBACK_OUTPUT, "  Expires : %04u-%02u-%02u\n",
                 end.wYear, end.wMonth, end.wDay);
    ok = 1;

cleanup:
    if (store) CRYPT32$CertCloseStore(store, 0);
    if (cert) CRYPT32$CertFreeCertificateContext(cert);
    if (name) KERNEL32$VirtualFree(name, 0, MEM_RELEASE);
    if (key) ADVAPI32$CryptDestroyKey(key);
    if (prov) ADVAPI32$CryptReleaseContext(prov, 0);
    if (!ok) BeaconPrintf(CALLBACK_ERROR, "certificate was not added\n");
}
