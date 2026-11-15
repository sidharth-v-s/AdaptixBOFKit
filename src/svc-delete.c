/*
 * svc-delete <name> - delete a Windows service.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *name;
    int nlen = 0;
    SC_HANDLE scm, svc;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: svc-delete <name>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    name = BeaconDataExtract(&parser, &nlen);
    if (!name) return;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    svc = ADVAPI32$OpenServiceA(scm, name, DELETE);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenService failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    if (ADVAPI32$DeleteService(svc))
        BeaconPrintf(CALLBACK_OUTPUT, "Service deleted: %s\n", name);
    else
        BeaconPrintf(CALLBACK_ERROR, "DeleteService failed: %lu\n", (unsigned long)KERNEL32$GetLastError());

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
