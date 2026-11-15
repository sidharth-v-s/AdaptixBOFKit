/*
 * scenum [service] - service query/config/failure details.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *state_name(DWORD s)
{
    switch (s) {
    case SERVICE_STOPPED:          return "stopped";
    case SERVICE_START_PENDING:    return "start-pending";
    case SERVICE_STOP_PENDING:     return "stop-pending";
    case SERVICE_RUNNING:          return "running";
    case SERVICE_CONTINUE_PENDING: return "continue-pending";
    case SERVICE_PAUSE_PENDING:    return "pause-pending";
    case SERVICE_PAUSED:           return "paused";
    }
    return "?";
}

static const char *start_name(DWORD s)
{
    switch (s) {
    case SERVICE_BOOT_START:   return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START:   return "auto";
    case SERVICE_DEMAND_START: return "demand";
    case SERVICE_DISABLED:     return "disabled";
    }
    return "?";
}

static void detail(SC_HANDLE scm, const char *name)
{
    SC_HANDLE svc;
    QUERY_SERVICE_CONFIGA cfg;
    DWORD need = 0;
    SERVICE_STATUS_PROCESS st;
    DWORD slen = sizeof(st);

    svc = ADVAPI32$OpenServiceA(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenService(%s) failed: %lu\n",
                     name, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&cfg, sizeof(cfg));
    if (ADVAPI32$QueryServiceConfigA(svc, &cfg, sizeof(cfg), &need)) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", name);
        BeaconPrintf(CALLBACK_OUTPUT, "  Start type : %s (%lu)\n",
                     start_name(cfg.dwStartType), (unsigned long)cfg.dwStartType);
        BeaconPrintf(CALLBACK_OUTPUT, "  Binary     : %s\n",
                     cfg.lpBinaryPathName ? cfg.lpBinaryPathName : "-");
        BeaconPrintf(CALLBACK_OUTPUT, "  Account    : %s\n",
                     cfg.lpServiceStartName ? cfg.lpServiceStartName : "-");
        BeaconPrintf(CALLBACK_OUTPUT, "  Display    : %s\n",
                     cfg.lpDisplayName ? cfg.lpDisplayName : "-");
    }

    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st,
                                      sizeof(st), &slen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  State      : %s\n", state_name(st.dwCurrentState));
        BeaconPrintf(CALLBACK_OUTPUT, "  PID        : %lu\n", (unsigned long)st.dwProcessId);
    }

    ADVAPI32$CloseServiceHandle(svc);
}

void go(char *args, int alen)
{
    datap parser;
    char *name = "";
    int nlen = 0;
    SC_HANDLE scm;
    LPBYTE buf = NULL;
    DWORD need = 0, returned = 0, resume = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        name = BeaconDataExtract(&parser, &nlen);
        if (!name) name = "";
    }

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (name[0]) {
        detail(scm, name);
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                       SERVICE_STATE_ALL, NULL, 0, &need, &returned,
                                       &resume, NULL) &&
        KERNEL32$GetLastError() == ERROR_MORE_DATA && need) {
        buf = (LPBYTE)KERNEL32$VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR, "buffer allocation failed\n");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    resume = 0;
    if (ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                       SERVICE_STATE_ALL, buf, need, &need, &returned,
                                       &resume, NULL)) {
        DWORD i;
        LPENUM_SERVICE_STATUS_PROCESSA e = (LPENUM_SERVICE_STATUS_PROCESSA)buf;
        BeaconPrintf(CALLBACK_OUTPUT, "%-40s %-16s %s\n", "Service", "State", "PID");
        for (i = 0; i < returned; i++)
            BeaconPrintf(CALLBACK_OUTPUT, "%-40s %-16s %lu\n",
                         e[i].lpServiceName,
                         state_name(e[i].ServiceStatusProcess.dwCurrentState),
                         (unsigned long)e[i].ServiceStatusProcess.dwProcessId);
        BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %lu\n", (unsigned long)returned);
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    ADVAPI32$CloseServiceHandle(scm);
}
