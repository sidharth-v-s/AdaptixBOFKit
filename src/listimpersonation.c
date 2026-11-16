/*
 * bof-listimpersonation
 *
 * Show the thread impersonation token (if any) next to the process primary
 * token, so you can tell whether the agent is currently impersonating.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "tokenhelpers.h"

void go(char *args, int alen)
{
    HANDLE tok = NULL;
    char line[512], tsid[128], psid[128];
    int have_thread = 0;
    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "================ impersonation ================\n");

    if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY,
                                 FALSE, &tok)) {
        have_thread = 1;
        bof_token_line(tok, line, sizeof(line));
        bof_token_sid(tok, tsid, sizeof(tsid));
        BeaconPrintf(CALLBACK_OUTPUT, "thread : %s\n", line);
        KERNEL32$CloseHandle(tok);
        tok = NULL;
    } else {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_NO_TOKEN)
            BeaconPrintf(CALLBACK_OUTPUT, "thread : (no impersonation token)\n");
        else
            BeaconPrintf(CALLBACK_OUTPUT, "thread : (query failed: %lu)\n",
                         (unsigned long)err);
        tsid[0] = 0;
    }

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        bof_token_line(tok, line, sizeof(line));
        bof_token_sid(tok, psid, sizeof(psid));
        BeaconPrintf(CALLBACK_OUTPUT, "process: %s\n", line);
        KERNEL32$CloseHandle(tok);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "process: (query failed: %lu)\n",
                     (unsigned long)KERNEL32$GetLastError());
        psid[0] = 0;
    }

    if (have_thread)
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] impersonating: %s\n",
                     (tsid[0] && psid[0] && bof_strcmp(tsid, psid) != 0)
                         ? "yes (thread token differs from process token)"
                         : "yes (thread token present)");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] impersonating: no\n");
}
