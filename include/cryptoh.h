/*
 * AdaptixBOFKit - small self-contained crypto helpers.
 *
 * MD4 is implemented locally (it is needed for NTLM hashes and is not
 * guaranteed to be enabled in every CNG configuration).  SHA-1, HMAC-SHA1,
 * PBKDF2 and AES are thin wrappers around bcrypt.dll.
 */
#ifndef ADAPTIX_CRYPTOH_H
#define ADAPTIX_CRYPTOH_H

#include <windows.h>
#include <bcrypt.h>
#include "bofdefs.h"
#include "helpers.h"

/* ------------------------------------------------------------------ */
/* MD4                                                                 */
/* ------------------------------------------------------------------ */
#define BOF_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline void bof_md4_block(unsigned int st[4], const unsigned char *p)
{
    unsigned int a = st[0], b = st[1], c = st[2], d = st[3];
    unsigned int x[16];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = (unsigned int)p[i * 4] |
               ((unsigned int)p[i * 4 + 1] << 8) |
               ((unsigned int)p[i * 4 + 2] << 16) |
               ((unsigned int)p[i * 4 + 3] << 24);

#define F(x_, y_, z_) (((x_) & (y_)) | (~(x_) & (z_)))
#define G(x_, y_, z_) (((x_) & (y_)) | ((x_) & (z_)) | ((y_) & (z_)))
#define H(x_, y_, z_) ((x_) ^ (y_) ^ (z_))
#define R1(a_, b_, c_, d_, k_, s_) a_ = BOF_ROTL32(a_ + F(b_, c_, d_) + x[k_], s_)
#define R2(a_, b_, c_, d_, k_, s_) a_ = BOF_ROTL32(a_ + G(b_, c_, d_) + x[k_] + 0x5a827999U, s_)
#define R3(a_, b_, c_, d_, k_, s_) a_ = BOF_ROTL32(a_ + H(b_, c_, d_) + x[k_] + 0x6ed9eba1U, s_)

    R1(a, b, c, d, 0, 3);  R1(d, a, b, c, 1, 7);
    R1(c, d, a, b, 2, 11); R1(b, c, d, a, 3, 19);
    R1(a, b, c, d, 4, 3);  R1(d, a, b, c, 5, 7);
    R1(c, d, a, b, 6, 11); R1(b, c, d, a, 7, 19);
    R1(a, b, c, d, 8, 3);  R1(d, a, b, c, 9, 7);
    R1(c, d, a, b, 10, 11);R1(b, c, d, a, 11, 19);
    R1(a, b, c, d, 12, 3); R1(d, a, b, c, 13, 7);
    R1(c, d, a, b, 14, 11);R1(b, c, d, a, 15, 19);

    R2(a, b, c, d, 0, 3);  R2(d, a, b, c, 4, 5);
    R2(c, d, a, b, 8, 9);  R2(b, c, d, a, 12, 13);
    R2(a, b, c, d, 1, 3);  R2(d, a, b, c, 5, 5);
    R2(c, d, a, b, 9, 9);  R2(b, c, d, a, 13, 13);
    R2(a, b, c, d, 2, 3);  R2(d, a, b, c, 6, 5);
    R2(c, d, a, b, 10, 9); R2(b, c, d, a, 14, 13);
    R2(a, b, c, d, 3, 3);  R2(d, a, b, c, 7, 5);
    R2(c, d, a, b, 11, 9); R2(b, c, d, a, 15, 13);

    R3(a, b, c, d, 0, 3);  R3(d, a, b, c, 8, 9);
    R3(c, d, a, b, 4, 11); R3(b, c, d, a, 12, 15);
    R3(a, b, c, d, 2, 3);  R3(d, a, b, c, 10, 9);
    R3(c, d, a, b, 6, 11); R3(b, c, d, a, 14, 15);
    R3(a, b, c, d, 1, 3);  R3(d, a, b, c, 9, 9);
    R3(c, d, a, b, 5, 11); R3(b, c, d, a, 13, 15);
    R3(a, b, c, d, 3, 3);  R3(d, a, b, c, 11, 9);
    R3(c, d, a, b, 7, 11); R3(b, c, d, a, 15, 15);

#undef F
#undef G
#undef H
#undef R1
#undef R2
#undef R3

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

static inline void bof_md4(const void *data, unsigned int len, unsigned char out[16])
{
    unsigned int st[4] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U};
    const unsigned char *p = (const unsigned char *)data;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8;
    unsigned int i, rem;

    while (len >= 64) {
        bof_md4_block(st, p);
        p += 64;
        len -= 64;
    }

    rem = len;
    bof_memzero(tail, sizeof(tail));
    if (rem) bof_memcpy(tail, p, rem);
    tail[rem] = 0x80;
    i = (rem < 56) ? 56 : 120;
    tail[i++] = (unsigned char)(bits & 0xff);
    tail[i++] = (unsigned char)((bits >> 8) & 0xff);
    tail[i++] = (unsigned char)((bits >> 16) & 0xff);
    tail[i++] = (unsigned char)((bits >> 24) & 0xff);
    tail[i++] = (unsigned char)((bits >> 32) & 0xff);
    tail[i++] = (unsigned char)((bits >> 40) & 0xff);
    tail[i++] = (unsigned char)((bits >> 48) & 0xff);
    tail[i++] = (unsigned char)((bits >> 56) & 0xff);

    bof_md4_block(st, tail);
    if (rem >= 56) bof_md4_block(st, tail + 64);

    for (i = 0; i < 4; i++) {
        out[i * 4]     = (unsigned char)(st[i] & 0xff);
        out[i * 4 + 1] = (unsigned char)((st[i] >> 8) & 0xff);
        out[i * 4 + 2] = (unsigned char)((st[i] >> 16) & 0xff);
        out[i * 4 + 3] = (unsigned char)((st[i] >> 24) & 0xff);
    }
}

static inline void bof_hex16(const unsigned char *b, char *out)
{
    const char *h = "0123456789abcdef";
    int i;
    for (i = 0; i < 16; i++) {
        out[i * 2] = h[(b[i] >> 4) & 0xf];
        out[i * 2 + 1] = h[b[i] & 0xf];
    }
    out[32] = 0;
}

/* ------------------------------------------------------------------ */
/* SHA-1 / HMAC-SHA1 / PBKDF2-SHA1                                     */
/* ------------------------------------------------------------------ */
static inline int bof_bcrypt_hash(const wchar_t *alg, const void *data,
                                  unsigned int len, unsigned char *out,
                                  unsigned int outlen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    int ok = -1;

    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, alg, NULL, 0);
    if (st < 0 || !hAlg) return -1;
    st = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (st < 0 || !hHash) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    if (len && BCRYPT$BCryptHashData(hHash, (PUCHAR)data, len, 0) >= 0 &&
        BCRYPT$BCryptFinishHash(hHash, out, outlen, 0) >= 0)
        ok = 0;

    BCRYPT$BCryptDestroyHash(hHash);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static inline int bof_sha1(const void *data, unsigned int len, unsigned char out[20])
{
    return bof_bcrypt_hash(BCRYPT_SHA1_ALGORITHM, data, len, out, 20);
}

static inline int bof_sha512(const void *data, unsigned int len, unsigned char out[64])
{
    return bof_bcrypt_hash(BCRYPT_SHA512_ALGORITHM, data, len, out, 64);
}

static inline int bof_hmac(const wchar_t *alg, const void *key,
                           unsigned int keylen, const void *data,
                           unsigned int len, unsigned char *out,
                           unsigned int outlen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    int ok = -1;

    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, alg, NULL,
                                            BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0 || !hAlg) return -1;
    st = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0,
                                 (PUCHAR)key, keylen, 0);
    if (st < 0 || !hHash) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    if (len && BCRYPT$BCryptHashData(hHash, (PUCHAR)data, len, 0) >= 0 &&
        BCRYPT$BCryptFinishHash(hHash, out, outlen, 0) >= 0)
        ok = 0;

    BCRYPT$BCryptDestroyHash(hHash);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static inline int bof_hmac_sha1(const void *key, unsigned int keylen,
                                const void *data, unsigned int len,
                                unsigned char out[20])
{
    return bof_hmac(BCRYPT_SHA1_ALGORITHM, key, keylen, data, len, out, 20);
}

static inline int bof_hmac_sha512(const void *key, unsigned int keylen,
                                  const void *data, unsigned int len,
                                  unsigned char out[64])
{
    return bof_hmac(BCRYPT_SHA512_ALGORITHM, key, keylen, data, len, out, 64);
}

static inline int bof_pbkdf2_sha1(const void *pass, unsigned int passlen,
                                  const void *salt, unsigned int saltlen,
                                  unsigned long long iterations,
                                  unsigned char *out, unsigned int outlen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS st;
    int ok = -1;

    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL,
                                            BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0 || !hAlg) return -1;
    st = BCRYPT$BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pass, passlen,
                                      (PUCHAR)salt, saltlen, iterations,
                                      out, outlen, 0);
    if (st >= 0) ok = 0;
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ------------------------------------------------------------------ */
/* AES-CBC / AES-GCM                                                   */
/* ------------------------------------------------------------------ */
static inline int bof_aes_cbc_decrypt(const unsigned char *key, int keylen,
                                      const unsigned char *iv,
                                      const unsigned char *in, int inlen,
                                      unsigned char *out, int outcap)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;
    ULONG done = 0;
    int ok = -1;

    if (inlen <= 0 || outcap < inlen) return -1;
    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0 || !hAlg) return -1;
    st = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                           (PUCHAR)key, keylen, 0);
    if (st < 0 || !hKey) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    st = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)in, inlen, NULL, (PUCHAR)iv,
                              (ULONG)(iv ? 16 : 0), out, outcap, &done, 0);
    if (st >= 0) ok = (int)done;
    BCRYPT$BCryptDestroyKey(hKey);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static inline int bof_aes_gcm_decrypt(const unsigned char *key, int keylen,
                                      const unsigned char *nonce, int noncelen,
                                      const unsigned char *in, int inlen,
                                      const unsigned char *tag, int taglen,
                                      unsigned char *out, int outcap)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS st;
    ULONG done = 0;
    int ok = -1;

    if (inlen < 0 || outcap < inlen) return -1;
    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0 || !hAlg) return -1;
    st = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                  (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                  sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st < 0) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    st = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                           (PUCHAR)key, keylen, 0);
    if (st < 0 || !hKey) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    bof_memzero(&info, sizeof(info));
    info.cbSize = sizeof(info);
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = (ULONG)noncelen;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = (ULONG)taglen;

    st = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)in, inlen, &info, NULL, 0,
                              out, outcap, &done, 0);
    if (st >= 0) ok = (int)done;
    BCRYPT$BCryptDestroyKey(hKey);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ------------------------------------------------------------------ */
/* GUID helpers                                                        */
/* ------------------------------------------------------------------ */
static inline void bof_guid_to_str(const GUID *g, char *out, int outsz)
{
    char t[16];
    bof_strncpy(out, "{", outsz);
    bof_hex(g->Data1, 8, t);
    bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data2, 4, t);
    bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data3, 4, t);
    bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[0], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[1], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[2], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[3], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[4], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[5], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[6], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[7], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "}", outsz - bof_strlen(out) - 1);
}

/* Parse "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" (braces optional). */
static inline int bof_str_to_guid(const char *s, GUID *g)
{
    unsigned char b[16];
    int i = 0;
    unsigned int v;
    int n = 0;
    if (!s) return -1;
    if (*s == '{') s++;
    for (i = 0; i < 36 && s[i]; i++) {
        if (s[i] == '}' || s[i] == 0) break;
    }
    if (i < 32) return -1;
    {
        char hex[33];
        int o = 0;
        for (i = 0; s[i] && s[i] != '}' && o < 32; i++) {
            if (s[i] == '-' || s[i] == '{') continue;
            hex[o++] = s[i];
        }
        hex[o] = 0;
        if (o != 32) return -1;
        for (i = 0; i < 16; i++) {
            int hi = bof_hexval((unsigned char)hex[i * 2]);
            int lo = bof_hexval((unsigned char)hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return -1;
            b[i] = (unsigned char)((hi << 4) | lo);
        }
    }
    (void)v; (void)n;
    bof_memcpy(g, b, 16);
    return 0;
}

#endif /* ADAPTIX_CRYPTOH_H */
