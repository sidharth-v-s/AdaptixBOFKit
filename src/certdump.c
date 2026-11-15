/*
 * certdump [user|machine] - list certificates and SHA1 thumbprints.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void dump_store(const char *label, const char *store)
{
    HCERTSTORE h;
    PCCERT_CONTEXT c = NULL;
    int count = 0;

    h = CRYPT32$CertOpenSystemStoreA(0, store);
    if (!h) {
        BeaconPrintf(CALLBACK_ERROR, "%s: CertOpenSystemStore(%s) failed: %lu\n",
                     label, store, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\n", label, store);
    while ((c = CRYPT32$CertEnumCertificatesInStore(h, c)) != NULL) {
        char subject[512], thumb[64];
        BYTE hash[32];
        DWORD hlen = sizeof(hash), i;
        SYSTEMTIME st;

        CRYPT32$CertGetNameStringA(c, 4 /* CERT_NAME_SIMPLE_DISPLAY_TYPE */,
                                   0, NULL, subject, sizeof(subject));
        bof_memzero(hash, sizeof(hash));
        if (CRYPT32$CertGetCertificateContextProperty(c, CERT_HASH_PROP_ID,
                                                      hash, &hlen)) {
            for (i = 0; i < hlen && i < 20; i++)
                bof_hex(hash[i], 2, thumb + i * 2);
            thumb[(hlen < 20 ? hlen : 20) * 2] = 0;
        } else {
            bof_strcpy(thumb, "-");
        }

        bof_memzero(&st, sizeof(st));
        KERNEL32$FileTimeToSystemTime(&c->pCertInfo->NotAfter, &st);
        BeaconPrintf(CALLBACK_OUTPUT, "  %-40s  sha1=%s  expires=%04u-%02u-%02u\n",
                     subject, thumb, st.wYear, st.wMonth, st.wDay);
        count++;
    }

    CRYPT32$CertCloseStore(h, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "  %d certificate(s)\n", count);
}

void go(char *args, int alen)
{
    datap parser;
    char *which = "";
    int wlen = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        which = BeaconDataExtract(&parser, &wlen);
        if (!which) which = "";
    }

    if (!which[0] || bof_stricmp(which, "user") == 0)
        dump_store("CurrentUser", "MY");
    if (!which[0] || bof_stricmp(which, "machine") == 0)
        dump_store("LocalMachine", "MY");
}
