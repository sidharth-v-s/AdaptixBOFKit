/*
 * drivers - enumerate kernel drivers registered with the SCM.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *svc_state(DWORD s)
{
    switch (s) {
    case SERVICE_STOPPED:       return "STOPPED";
    case SERVICE_START_PENDING: return "START_PENDING";
    case SERVICE_STOP_PENDING:  return "STOP_PENDING";
    case SERVICE_RUNNING:       return "RUNNING";
    case SERVICE_PAUSED:        return "PAUSED";
    }
    return "?";
}

void go(char *args, int alen)
{
    SC_HANDLE scm;
    DWORD needed = 0, returned = 0, resume = 0;
    LPBYTE buf = NULL;
    DWORD total = 0;
    (void)args; (void)alen;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                   SERVICE_STATE_ALL, NULL, 0, &needed, &returned,
                                   &resume, NULL);
    if (!needed) {
        BeaconPrintf(CALLBACK_ERROR, "EnumServicesStatusEx size query failed\n");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    buf = (LPBYTE)KERNEL32$VirtualAlloc(NULL, needed, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %s\n", "Driver", "State");

    resume = 0;
    do {
        DWORD i;
        returned = 0;
        if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                            SERVICE_STATE_ALL, buf, needed, &needed,
                                            &returned, &resume, NULL)) {
            if (KERNEL32$GetLastError() != ERROR_MORE_DATA) break;
        }
        {
            ENUM_SERVICE_STATUS_PROCESSA *svc = (ENUM_SERVICE_STATUS_PROCESSA *)buf;
            for (i = 0; i < returned; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %s\n",
                             svc[i].lpServiceName,
                             svc_state(svc[i].ServiceStatusProcess.dwCurrentState));
                total++;
            }
        }
    } while (returned > 0 && resume != 0);

    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %lu driver(s)\n", (unsigned long)total);
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    ADVAPI32$CloseServiceHandle(scm);
}
