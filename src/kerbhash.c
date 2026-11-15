/*
 * kerbhash <password> [user] [realm]
 * Derive RC4-HMAC (NT), AES128 and AES256 Kerberos keys.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void hexline(const char *label, const BYTE *b, int n)
{
    int i;
    BeaconPrintf(CALLBACK_OUTPUT, "  %-8s ", label);
    for (i = 0; i < n; i++) BeaconPrintf(CALLBACK_OUTPUT, "%02x", b[i]);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

static void md4(const BYTE *data, ULONG len, BYTE out[16])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    DWORD objlen = 0, got = 0;
    PUCHAR obj = NULL;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD4_ALGORITHM, NULL, 0) != 0) return;
    BCRYPT$BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, sizeof(objlen), &got, 0);
    obj = (PUCHAR)KERNEL32$VirtualAlloc(NULL, objlen ? objlen : 1,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!obj) { BCRYPT$BCryptCloseAlgorithmProvider(alg, 0); return; }
    if (BCRYPT$BCryptCreateHash(alg, &h, obj, objlen, NULL, 0, 0) == 0) {
        BCRYPT$BCryptHashData(h, (PUCHAR)data, len, 0);
        BCRYPT$BCryptFinishHash(h, out, 16, 0);
        BCRYPT$BCryptDestroyHash(h);
    }
    KERNEL32$VirtualFree(obj, 0, MEM_RELEASE);
    BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
}

void go(char *args, int alen)
{
    datap parser;
    char *password, *user = "", *realm = "";
    int plen, ulen = 0, rlen = 0;
    wchar_t wpass[512];
    BYTE nt[16];
    BYTE aes128[16], aes192[24], aes256[32];
    char salt[512];
    int i, n;
    BCRYPT_ALG_HANDLE sha1 = NULL;

    BeaconDataParse(&parser, args, alen);
    password = BeaconDataExtract(&parser, &plen);
    user     = BeaconDataExtract(&parser, &ulen);
    realm    = BeaconDataExtract(&parser, &rlen);
    if (!password) {
        BeaconPrintf(CALLBACK_ERROR, "usage: kerbhash <password> [user] [realm]\n");
        return;
    }
    if (!user) user = "";
    if (!realm) realm = "";

    bof_a2w(password, wpass, 512);
    bof_memzero(nt, sizeof(nt));
    md4((BYTE *)wpass, (ULONG)(bof_wcslen(wpass) * sizeof(WCHAR)), nt);

    BeaconPrintf(CALLBACK_OUTPUT, "Kerberos keys\n");
    hexline("RC4/NT", nt, 16);

    /* AES salt = uppercase(realm) + username */
    n = 0;
    for (i = 0; realm[i] && n < (int)sizeof(salt) - 1; i++) {
        char c = realm[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        salt[n++] = c;
    }
    for (i = 0; user[i] && n < (int)sizeof(salt) - 1; i++) salt[n++] = user[i];
    salt[n] = 0;

    if (!n) {
        BeaconPrintf(CALLBACK_OUTPUT, "  (AES keys need user and realm)\n");
        return;
    }

    if (BCRYPT$BCryptOpenAlgorithmProvider(&sha1, BCRYPT_SHA1_ALGORITHM, NULL,
                                           BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "BCrypt SHA1 provider failed\n");
        return;
    }

    bof_memzero(aes128, sizeof(aes128));
    bof_memzero(aes192, sizeof(aes192));
    bof_memzero(aes256, sizeof(aes256));

    BCRYPT$BCryptDeriveKeyPBKDF2(sha1, (PUCHAR)password, (ULONG)plen,
                                 (PUCHAR)salt, (ULONG)n, 4096, aes128, 16, 0);
    BCRYPT$BCryptDeriveKeyPBKDF2(sha1, (PUCHAR)password, (ULONG)plen,
                                 (PUCHAR)salt, (ULONG)n, 4096, aes192, 24, 0);
    BCRYPT$BCryptDeriveKeyPBKDF2(sha1, (PUCHAR)password, (ULONG)plen,
                                 (PUCHAR)salt, (ULONG)n, 4096, aes256, 32, 0);

    hexline("AES128", aes128, 16);
    hexline("AES192", aes192, 24);
    hexline("AES256", aes256, 32);
    BeaconPrintf(CALLBACK_OUTPUT, "  salt     %s\n", salt);

    BCRYPT$BCryptCloseAlgorithmProvider(sha1, 0);
}
