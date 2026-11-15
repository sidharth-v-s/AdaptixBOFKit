/*
 * svc-create <name> <binary_path> - create and start a Windows service.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *name, *binpath;
    int nlen = 0, blen = 0;
    SC_HANDLE scm, svc;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: svc-create <name> <binary_path>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    name = BeaconDataExtract(&parser, &nlen);
    binpath = BeaconDataExtract(&parser, &blen);
    if (!name || !binpath) return;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    svc = ADVAPI32$CreateServiceA(scm, name, name, SERVICE_ALL_ACCESS,
                                  SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                                  SERVICE_ERROR_NORMAL, binpath, NULL, NULL, NULL,
                                  NULL, NULL);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "CreateService failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Service created: %s -> %s\n", name, binpath);

    if (ADVAPI32$StartServiceA(svc, 0, NULL))
        BeaconPrintf(CALLBACK_OUTPUT, "Service started: %s\n", name);
    else
        BeaconPrintf(CALLBACK_ERROR, "StartService failed: %lu\n", (unsigned long)KERNEL32$GetLastError());

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
