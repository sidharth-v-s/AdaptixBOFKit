/*
 * bof-reverttoken
 *
 * Drop thread impersonation with RevertToSelf and print the token that is
 * back in effect (the process primary token).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "tokenhelpers.h"

void go(char *args, int alen)
{
    HANDLE tok = NULL;
    char before[512], after[512];
    int had_impersonation = 0;
    (void)args; (void)alen;

    if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY,
                                 TRUE, &tok)) {
        had_impersonation = 1;
        bof_token_line(tok, before, sizeof(before));
        KERNEL32$CloseHandle(tok);
        tok = NULL;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] dropping: %s\n", before);
    }

    if (!ADVAPI32$RevertToSelf()) {
        BeaconPrintf(CALLBACK_ERROR, "RevertToSelf failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        bof_token_line(tok, after, sizeof(after));
        KERNEL32$CloseHandle(tok);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] current token: %s\n", after);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] RevertToSelf done (token query failed: %lu)\n",
                     (unsigned long)KERNEL32$GetLastError());
    }

    if (!had_impersonation)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] no thread impersonation token was present\n");
}
