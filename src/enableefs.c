/*
 * enableefs - start the EFS service (useful for EFS-based tradecraft).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS st;
    DWORD slen = sizeof(st);
    BOOL ok;

    (void)args; (void)alen;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    svc = ADVAPI32$OpenServiceA(scm, "EFS", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenService(EFS) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    bof_memzero(&st, sizeof(st));
    ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st, sizeof(st), &slen);
    BeaconPrintf(CALLBACK_OUTPUT, "EFS state before: %lu\n", (unsigned long)st.dwCurrentState);

    ok = ADVAPI32$StartServiceA(svc, 0, NULL);
    if (!ok && KERNEL32$GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        ok = TRUE;

    bof_memzero(&st, sizeof(st));
    ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st, sizeof(st), &slen);

    if (ok)
        BeaconPrintf(CALLBACK_OUTPUT, "EFS started (state=%lu)\n", (unsigned long)st.dwCurrentState);
    else
        BeaconPrintf(CALLBACK_ERROR, "StartService(EFS) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
