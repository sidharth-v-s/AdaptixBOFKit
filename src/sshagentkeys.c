/*
 * bof-sshagentkeys
 *
 * Ask a running Windows OpenSSH agent for the identities it holds, over its
 * named pipe (\\.\pipe\openssh-ssh-agent).  Prints the key type, comment,
 * base64 wire blob and SHA256 fingerprint for every key.
 *
 * The agent protocol never exposes private keys, so this lists usable public
 * identities (which is what you need for pivot/agent-forwarding decisions),
 * not the private key material itself.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define SSH_AGENTC_REQUEST_IDENTITIES 11
#define SSH_AGENT_IDENTITIES_ANSWER   12

static unsigned int be32(const unsigned char *p)
{
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | p[3];
}

static int read_full(HANDLE h, unsigned char *buf, unsigned int n)
{
    unsigned int got = 0;
    while (got < n) {
        DWORD r = 0;
        if (!KERNEL32$ReadFile(h, buf + got, n - got, &r, NULL) || !r) return -1;
        got += r;
    }
    return 0;
}

static int sha256_b64(const unsigned char *data, unsigned int len,
                      char *out, int outsz)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char digest[32];
    unsigned char obj[256];
    DWORD objlen = 0, got = 0;
    char b64[64];
    int n, i, o = 0;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&alg, L"SHA256", NULL, 0) < 0)
        return -1;
    if (BCRYPT$BCryptGetProperty(alg, L"ObjectLength", obj, sizeof(obj),
                                 (PULONG)&objlen, 0) < 0) {
        BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }
    if (objlen > sizeof(obj)) objlen = sizeof(obj);
    if (BCRYPT$BCryptCreateHash(alg, &hash, obj, objlen, NULL, 0, 0) < 0) {
        BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }
    BCRYPT$BCryptHashData(hash, (PUCHAR)data, len, 0);
    BCRYPT$BCryptFinishHash(hash, digest, sizeof(digest), 0);
    BCRYPT$BCryptDestroyHash(hash);
    BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);

    n = bof_b64_encode(digest, sizeof(digest), b64, sizeof(b64));
    if (n <= 0) return -1;
    for (i = 0; i < n && i < outsz - 1; i++) {
        if (b64[i] == '=') break;
        out[o++] = b64[i];
    }
    out[o] = 0;
    (void)got;
    return 0;
}

/* SSH wire string -> pointer + length. */
static int ssh_str(const unsigned char *p, unsigned int len, unsigned int *used,
                   const unsigned char **val, unsigned int *vlen)
{
    if (len < 4) return -1;
    *vlen = be32(p);
    if (*vlen > len - 4) return -1;
    *val = p + 4;
    *used = 4 + *vlen;
    return 0;
}

void go(char *args, int alen)
{
    HANDLE pipe;
    unsigned char req[5], hdr[4];
    unsigned int plen, off = 0, count, i;
    unsigned char *buf;
    (void)args; (void)alen;

    pipe = KERNEL32$CreateFileA("\\\\.\\pipe\\openssh-ssh-agent",
                                GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "cannot open \\\\.\\pipe\\openssh-ssh-agent: %lu "
                     "(agent not running?)\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    req[0] = 0; req[1] = 0; req[2] = 0; req[3] = 1;
    req[4] = SSH_AGENTC_REQUEST_IDENTITIES;
    {
        DWORD wr = 0;
        if (!KERNEL32$WriteFile(pipe, req, sizeof(req), &wr, NULL) ||
            wr != sizeof(req)) {
            BeaconPrintf(CALLBACK_ERROR, "agent write failed: %lu\n",
                         (unsigned long)KERNEL32$GetLastError());
            KERNEL32$CloseHandle(pipe);
            return;
        }
    }

    if (read_full(pipe, hdr, 4) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "agent read failed\n");
        KERNEL32$CloseHandle(pipe);
        return;
    }
    plen = be32(hdr);
    if (plen < 5 || plen > 1024 * 1024) {
        BeaconPrintf(CALLBACK_ERROR, "unexpected agent reply length %u\n", plen);
        KERNEL32$CloseHandle(pipe);
        return;
    }
    buf = (unsigned char *)KERNEL32$VirtualAlloc(NULL, plen, MEM_COMMIT | MEM_RESERVE,
                                                 PAGE_READWRITE);
    if (!buf) {
        KERNEL32$CloseHandle(pipe);
        return;
    }
    if (read_full(pipe, buf, plen) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "short agent reply\n");
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(pipe);
        return;
    }
    KERNEL32$CloseHandle(pipe);

    if (buf[0] != SSH_AGENT_IDENTITIES_ANSWER) {
        BeaconPrintf(CALLBACK_ERROR, "agent replied type %u\n", buf[0]);
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }
    if (plen < 5) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }
    count = be32(buf + 1);
    off = 5;
    BeaconPrintf(CALLBACK_OUTPUT, "================ ssh-agent identities ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] %u key(s)\n", count);

    for (i = 0; i < count && off < plen; i++) {
        const unsigned char *blob = NULL, *comment = NULL, *type = NULL;
        unsigned int blen = 0, clen = 0, tlen = 0, used = 0;
        char type_s[64], comment_s[256], b64[4096], fp[128];

        if (ssh_str(buf + off, plen - off, &used, &blob, &blen) != 0) break;
        off += used;
        if (ssh_str(buf + off, plen - off, &used, &comment, &clen) != 0) break;
        off += used;

        type_s[0] = 0;
        if (ssh_str(blob, blen, &used, &type, &tlen) == 0 && tlen < sizeof(type_s)) {
            bof_memcpy(type_s, type, tlen);
            type_s[tlen] = 0;
        }
        if (clen >= sizeof(comment_s)) clen = sizeof(comment_s) - 1;
        bof_memcpy(comment_s, comment, clen);
        comment_s[clen] = 0;

        bof_b64_encode(blob, (int)blen, b64, sizeof(b64));
        if (sha256_b64(blob, blen, fp, sizeof(fp)) != 0)
            bof_strncpy(fp, "?", sizeof(fp));

        BeaconPrintf(CALLBACK_OUTPUT, "\n[%u] %s\n", i + 1, type_s[0] ? type_s : "?");
        BeaconPrintf(CALLBACK_OUTPUT, "  comment : %s\n", comment_s);
        BeaconPrintf(CALLBACK_OUTPUT, "  sha256  : SHA256:%s\n", fp);
        BeaconPrintf(CALLBACK_OUTPUT, "  blob    : %s\n", b64);
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}
