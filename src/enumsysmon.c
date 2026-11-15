/*
 * enumsysmon - detect Sysmon service/driver and its configuration.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void probe(SC_HANDLE scm, const char *name)
{
    SC_HANDLE svc;
    QUERY_SERVICE_CONFIGA cfg;
    DWORD need = 0;
    SERVICE_STATUS_PROCESS st;
    DWORD slen = sizeof(st);

    svc = ADVAPI32$OpenServiceA(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!svc) return;

    bof_memzero(&cfg, sizeof(cfg));
    if (ADVAPI32$QueryServiceConfigA(svc, &cfg, sizeof(cfg), &need)) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", name);
        BeaconPrintf(CALLBACK_OUTPUT, "  Binary : %s\n",
                     cfg.lpBinaryPathName ? cfg.lpBinaryPathName : "-");
        BeaconPrintf(CALLBACK_OUTPUT, "  Start  : %lu\n", (unsigned long)cfg.dwStartType);
    }
    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st,
                                      sizeof(st), &slen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  State  : %lu\n", (unsigned long)st.dwCurrentState);
        BeaconPrintf(CALLBACK_OUTPUT, "  PID    : %lu\n", (unsigned long)st.dwProcessId);
    }
    ADVAPI32$CloseServiceHandle(svc);
}

void go(char *args, int alen)
{
    SC_HANDLE scm;
    HKEY h;
    char cfg[512];
    DWORD size = sizeof(cfg), type = 0;

    (void)args; (void)alen;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        probe(scm, "Sysmon");
        probe(scm, "Sysmon64");
        probe(scm, "SysmonDrv");
        ADVAPI32$CloseServiceHandle(scm);
    }

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters",
            0, KEY_READ, &h) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(h, "ConfigFile", NULL, &type,
                                      (LPBYTE)cfg, &size) == ERROR_SUCCESS) {
            if (size) cfg[size - 1] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "Sysmon config: %s\n", cfg);
        }
        ADVAPI32$RegCloseKey(h);
    }
}
