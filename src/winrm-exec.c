/*
 * bof-winrm-exec <host> <command> [user] [password]
 *
 * Remote execution over WinRM.  Drives the native `winrs.exe` client (WinRM
 * over HTTP/HTTPS with Kerberos/NTLM or explicit credentials) and captures
 * its stdout/stderr through an anonymous pipe.
 *
 * `host` may be a hostname, or `host:port` / a full WS-Man URL passed as-is.
 * Explicit user/password are optional; by default the current logon is used.
 * Requires the WinRM client components and a listener on the target.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host, *command, *user = "", *pass = "";
    int hlen, clen, ulen, plen;
    char cmdline[4096];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE rd = NULL, wr = NULL;
    DWORD exitcode = 0;
    int started;

    BeaconDataParse(&parser, args, alen);
    host    = BeaconDataExtract(&parser, &hlen);
    command = BeaconDataExtract(&parser, &clen);
    user    = BeaconDataExtract(&parser, &ulen);
    pass    = BeaconDataExtract(&parser, &plen);
    if (!host || !host[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: winrm-exec <host> <command> [user] [password]\n");
        return;
    }
    if (!user) user = "";
    if (!pass) pass = "";

    cmdline[0] = 0;
    bof_strncpy(cmdline, "winrs.exe -r:", sizeof(cmdline));
    bof_strncat(cmdline, host, sizeof(cmdline) - bof_strlen(cmdline) - 1);
    if (user[0]) {
        bof_strncat(cmdline, " -u:", sizeof(cmdline) - bof_strlen(cmdline) - 1);
        bof_strncat(cmdline, user, sizeof(cmdline) - bof_strlen(cmdline) - 1);
    }
    if (pass[0]) {
        bof_strncat(cmdline, " -p:", sizeof(cmdline) - bof_strlen(cmdline) - 1);
        bof_strncat(cmdline, pass, sizeof(cmdline) - bof_strlen(cmdline) - 1);
    }
    bof_strncat(cmdline, " cmd.exe /c \"", sizeof(cmdline) - bof_strlen(cmdline) - 1);
    bof_strncat(cmdline, command, sizeof(cmdline) - bof_strlen(cmdline) - 1);
    bof_strncat(cmdline, "\"", sizeof(cmdline) - bof_strlen(cmdline) - 1);

    if (bof_strlen(cmdline) >= (int)sizeof(cmdline) - 1) {
        BeaconPrintf(CALLBACK_ERROR, "command line too long\n");
        return;
    }

    bof_memzero(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!KERNEL32$CreatePipe(&rd, &wr, &sa, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "CreatePipe failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&si, sizeof(si));
    bof_memzero(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s\n", cmdline);
    started = KERNEL32$CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    KERNEL32$CloseHandle(wr);
    wr = NULL;

    if (!started) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess(winrs) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(rd);
        return;
    }

    for (;;) {
        DWORD avail = 0, got = 0;
        char buf[1024];
        DWORD wait;

        if (!KERNEL32$PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail) {
            if (!KERNEL32$ReadFile(rd, buf, sizeof(buf) - 1, &got, NULL) || !got)
                break;
            buf[got] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "%s", buf);
            continue;
        }
        wait = KERNEL32$WaitForSingleObject(pi.hProcess, 100);
        if (wait == WAIT_OBJECT_0) {
            DWORD left = 0;
            if (!KERNEL32$PeekNamedPipe(rd, NULL, 0, NULL, &left, NULL) || !left)
                break;
        }
    }

    KERNEL32$GetExitCodeProcess(pi.hProcess, &exitcode);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] winrs exit code: %lu\n",
                 (unsigned long)exitcode);

    KERNEL32$CloseHandle(rd);
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
}
