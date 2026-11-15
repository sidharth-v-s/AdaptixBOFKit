/*
 * hashfile <path> [md5|sha1|sha256] - hash a file with BCrypt.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define HASH_CHUNK 16384

void go(char *args, int alen)
{
    datap parser;
    char *path, *algo = "sha256";
    int plen = 0, alen2 = 0;
    const wchar_t *algid = BCRYPT_SHA256_ALGORITHM;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR obj = NULL, digest = NULL;
    DWORD objlen = 0, hashlen = 0, cb = 0;
    HANDLE file;
    BYTE *buf = NULL;
    DWORD read = 0, i;
    NTSTATUS st;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: hashfile <path> [md5|sha1|sha256]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, &plen);
    algo = BeaconDataExtract(&parser, &alen2);
    if (!path) return;
    if (!algo) algo = "sha256";

    if (bof_stricmp(algo, "md5") == 0) algid = BCRYPT_MD5_ALGORITHM;
    else if (bof_stricmp(algo, "sha1") == 0) algid = BCRYPT_SHA1_ALGORITHM;
    else if (bof_stricmp(algo, "sha256") == 0) algid = BCRYPT_SHA256_ALGORITHM;
    else {
        BeaconPrintf(CALLBACK_ERROR, "unsupported algorithm: %s\n", algo);
        return;
    }

    file = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    st = BCRYPT$BCryptOpenAlgorithmProvider(&alg, algid, NULL, 0);
    if (st < 0) goto cleanup;

    BCRYPT$BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, sizeof(objlen), &cb, 0);
    BCRYPT$BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashlen, sizeof(hashlen), &cb, 0);

    obj = (PUCHAR)KERNEL32$VirtualAlloc(NULL, objlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    digest = (PUCHAR)KERNEL32$VirtualAlloc(NULL, hashlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    buf = (BYTE *)KERNEL32$VirtualAlloc(NULL, HASH_CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!obj || !digest || !buf) goto cleanup;

    st = BCRYPT$BCryptCreateHash(alg, &hash, obj, objlen, NULL, 0, 0);
    if (st < 0) goto cleanup;

    while (KERNEL32$ReadFile(file, buf, HASH_CHUNK, &read, NULL) && read > 0) {
        st = BCRYPT$BCryptHashData(hash, buf, read, 0);
        if (st < 0) goto cleanup;
    }

    st = BCRYPT$BCryptFinishHash(hash, digest, hashlen, 0);
    if (st < 0) goto cleanup;

    BeaconPrintf(CALLBACK_OUTPUT, "%s  %s\n", algo, path);
    BeaconPrintf(CALLBACK_OUTPUT, "  ");
    for (i = 0; i < hashlen; i++) {
        char hex[3];
        bof_hex(digest[i], 2, hex);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", hex);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

cleanup:
    if (hash) BCRYPT$BCryptDestroyHash(hash);
    if (alg) BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
    if (obj) KERNEL32$VirtualFree(obj, 0, MEM_RELEASE);
    if (digest) KERNEL32$VirtualFree(digest, 0, MEM_RELEASE);
    if (buf) KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(file);
}
