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
    HANDLE file = INVALID_HANDLE_VALUE;
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
    if (!path || !path[0]) {
        bof_error_text("hashfile", "missing file path");
        BeaconPrintf(CALLBACK_OUTPUT,
                     "usage: hashfile <path> [md5|sha1|sha256]\n");
        return;
    }
    if (!algo || !algo[0]) algo = "sha256";

    if (bof_stricmp(algo, "md5") == 0) algid = BCRYPT_MD5_ALGORITHM;
    else if (bof_stricmp(algo, "sha1") == 0) algid = BCRYPT_SHA1_ALGORITHM;
    else if (bof_stricmp(algo, "sha256") == 0) algid = BCRYPT_SHA256_ALGORITHM;
    else {
        bof_error_text("unsupported hash algorithm", algo);
        bof_error_context("supported", "md5, sha1, sha256");
        return;
    }

    file = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD err = KERNEL32$GetLastError();
        bof_error_win32("CreateFile", err,
                        err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND
                            ? "the file does not exist"
                            : err == ERROR_ACCESS_DENIED
                                ? "the current token cannot read this file"
                                : err == ERROR_SHARING_VIOLATION
                                    ? "the file is locked by another process"
                                    : "could not open the file for reading");
        bof_error_context("path", path);
        return;
    }

    st = BCRYPT$BCryptOpenAlgorithmProvider(&alg, algid, NULL, 0);
    if (st < 0) {
        bof_error_ntstatus("BCryptOpenAlgorithmProvider", st,
                           "the CNG algorithm provider is unavailable");
        bof_error_context("algorithm", algo);
        goto cleanup;
    }

    st = BCRYPT$BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                                  (PUCHAR)&objlen, sizeof(objlen), &cb, 0);
    if (st < 0) {
        bof_error_ntstatus("BCryptGetProperty(BCRYPT_OBJECT_LENGTH)", st,
                           "cannot determine the hash object size");
        goto cleanup;
    }
    st = BCRYPT$BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                                  (PUCHAR)&hashlen, sizeof(hashlen), &cb, 0);
    if (st < 0) {
        bof_error_ntstatus("BCryptGetProperty(BCRYPT_HASH_LENGTH)", st,
                           "cannot determine the digest size");
        goto cleanup;
    }
    if (!objlen || !hashlen || hashlen > 64) {
        bof_error_text("BCryptGetProperty", "unexpected hash sizes");
        bof_error_num("object_len", (unsigned long long)objlen);
        bof_error_num("hash_len", (unsigned long long)hashlen);
        goto cleanup;
    }

    obj = (PUCHAR)KERNEL32$VirtualAlloc(NULL, objlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    digest = (PUCHAR)KERNEL32$VirtualAlloc(NULL, hashlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    buf = (BYTE *)KERNEL32$VirtualAlloc(NULL, HASH_CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!obj || !digest || !buf) {
        bof_error_win32("VirtualAlloc", KERNEL32$GetLastError(),
                        "not enough memory for the hash buffers");
        bof_error_num("object_len", (unsigned long long)objlen);
        bof_error_num("hash_len", (unsigned long long)hashlen);
        bof_error_num("chunk", (unsigned long long)HASH_CHUNK);
        goto cleanup;
    }

    st = BCRYPT$BCryptCreateHash(alg, &hash, obj, objlen, NULL, 0, 0);
    if (st < 0) {
        bof_error_ntstatus("BCryptCreateHash", st,
                           "cannot create the CNG hash object");
        goto cleanup;
    }

    for (;;) {
        if (!KERNEL32$ReadFile(file, buf, HASH_CHUNK, &read, NULL)) {
            DWORD err = KERNEL32$GetLastError();
            if (err == ERROR_HANDLE_EOF) break;
            bof_error_win32("ReadFile", err, "error while reading the file");
            bof_error_context("path", path);
            goto cleanup;
        }
        if (read == 0) break;
        st = BCRYPT$BCryptHashData(hash, buf, read, 0);
        if (st < 0) {
            bof_error_ntstatus("BCryptHashData", st,
                               "cannot feed data into the hash object");
            bof_error_num("chunk_bytes", (unsigned long long)read);
            goto cleanup;
        }
    }

    st = BCRYPT$BCryptFinishHash(hash, digest, hashlen, 0);
    if (st < 0) {
        bof_error_ntstatus("BCryptFinishHash", st,
                           "cannot finalize the hash");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s  %s\n", algo, path);
    {
        static const char hd[] = "0123456789abcdef";
        char hex[2 * 64 + 4];
        int o = 0;
        for (i = 0; i < hashlen; i++) {
            hex[o++] = hd[(digest[i] >> 4) & 0xf];
            hex[o++] = hd[digest[i] & 0xf];
        }
        hex[o] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", hex);
    }

cleanup:
    if (hash) BCRYPT$BCryptDestroyHash(hash);
    if (alg) BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
    if (obj) KERNEL32$VirtualFree(obj, 0, MEM_RELEASE);
    if (digest) KERNEL32$VirtualFree(digest, 0, MEM_RELEASE);
    if (buf) KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    if (file != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(file);
}
