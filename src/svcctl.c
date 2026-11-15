/*
 * svcctl <config|start|stop> <service> [start-type]
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static DWORD start_type(const char *s)
{
    if (!s) return SERVICE_NO_CHANGE;
    if (bof_stricmp(s, "boot") == 0)     return SERVICE_BOOT_START;
    if (bof_stricmp(s, "system") == 0)   return SERVICE_SYSTEM_START;
    if (bof_stricmp(s, "auto") == 0)     return SERVICE_AUTO_START;
    if (bof_stricmp(s, "demand") == 0)   return SERVICE_DEMAND_START;
    if (bof_stricmp(s, "disabled") == 0) return SERVICE_DISABLED;
    return SERVICE_NO_CHANGE;
}

void go(char *args, int alen)
{
    datap parser;
    char *op, *name, *arg = "";
    int a, b, c;
    SC_HANDLE scm, svc;
    ACCESS_MASK access;
    BOOL ok = FALSE;
    SERVICE_STATUS st;

    BeaconDataParse(&parser, args, alen);
    op   = BeaconDataExtract(&parser, &a);
    name = BeaconDataExtract(&parser, &b);
    arg  = BeaconDataExtract(&parser, &c);
    if (!op || !name) {
        BeaconPrintf(CALLBACK_ERROR, "usage: svcctl <config|start|stop> <service> [start-type]\n");
        return;
    }
    if (!arg) arg = "";

    if (bof_stricmp(op, "start") == 0)      access = SERVICE_START | SERVICE_QUERY_STATUS;
    else if (bof_stricmp(op, "stop") == 0)  access = SERVICE_STOP | SERVICE_QUERY_STATUS;
    else                                    access = SERVICE_CHANGE_CONFIG;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }
    svc = ADVAPI32$OpenServiceA(scm, name, access);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenService(%s) failed: %lu\n",
                     name, (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    if (bof_stricmp(op, "config") == 0) {
        DWORD stype = start_type(arg);
        ok = ADVAPI32$ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, stype, SERVICE_NO_CHANGE,
                                           NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (ok) BeaconPrintf(CALLBACK_OUTPUT, "%s start type set to %lu\n", name, (unsigned long)stype);
    } else if (bof_stricmp(op, "start") == 0) {
        ok = ADVAPI32$StartServiceA(svc, 0, NULL);
        if (ok) BeaconPrintf(CALLBACK_OUTPUT, "Started %s\n", name);
    } else if (bof_stricmp(op, "stop") == 0) {
        bof_memzero(&st, sizeof(st));
        ok = ADVAPI32$ControlService(svc, SERVICE_CONTROL_STOP, &st);
        if (ok) BeaconPrintf(CALLBACK_OUTPUT, "Stop requested for %s\n", name);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "unknown operation: %s\n", op);
    }

    if (!ok)
        BeaconPrintf(CALLBACK_ERROR, "%s failed: %lu\n", op, (unsigned long)KERNEL32$GetLastError());

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
