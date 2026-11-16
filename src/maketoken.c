/*
 * bof-maketoken <user> <password> [domain]
 *
 * Create an impersonation token from plaintext credentials with LogonUser
 * and impersonate it on the current thread.  Use bof-reverttoken to drop it.
 *
 * Tries LOGON32_LOGON_INTERACTIVE first (local + network access); if that
 * fails, falls back to LOGON32_LOGON_NEW_CREDENTIALS, which only affects
 * outbound network authentication.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "tokenhelpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *user, *pass, *domain = "";
    int ulen, plen, dlen;
    HANDLE tok = NULL;
    char line[512];
    DWORD err;
    int type = 0;

    BeaconDataParse(&parser, args, alen);
    user   = BeaconDataExtract(&parser, &ulen);
    pass   = BeaconDataExtract(&parser, &plen);
    domain = BeaconDataExtract(&parser, &dlen);
    if (!user || !user[0] || !pass) {
        BeaconPrintf(CALLBACK_ERROR, "usage: maketoken <user> <password> [domain]\n");
        return;
    }
    if (!domain || !domain[0]) domain = ".";

    if (!ADVAPI32$LogonUserA(user, domain, pass, LOGON32_LOGON_INTERACTIVE,
                             LOGON32_PROVIDER_DEFAULT, &tok)) {
        err = KERNEL32$GetLastError();
        if (!ADVAPI32$LogonUserA(user, domain, pass, LOGON32_LOGON_NEW_CREDENTIALS,
                                 LOGON32_PROVIDER_DEFAULT, &tok)) {
            BeaconPrintf(CALLBACK_ERROR, "LogonUser(%s\\%s) failed: %lu (interactive: %lu)\n",
                         domain, user, (unsigned long)KERNEL32$GetLastError(),
                         (unsigned long)err);
            return;
        }
        type = 1;
    }

    if (!ADVAPI32$ImpersonateLoggedOnUser(tok)) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tok);
        return;
    }

    bof_token_line(tok, line, sizeof(line));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] impersonating: %s\n", line);
    if (type)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] used NEW_CREDENTIALS: outbound network only, local access unchanged\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] run bof-reverttoken to drop the impersonation\n");

    KERNEL32$CloseHandle(tok);
}
