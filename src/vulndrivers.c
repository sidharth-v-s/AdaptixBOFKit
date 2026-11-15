/*
 * vulndrivers - flag installed drivers with known-vulnerable names (BYOVD).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *vuln[] = {
    "dbutil_2_3", "gdrv", "iqvw64e", "rtcore64", "msio64", "msio32",
    "asio3", "asio2", "aswarkpot", "aswarpot", "winio", "winring0",
    "physmem", "dbgv", "kslk", "gmer", "eedr", "kprocesshacker",
    "cpuz", "nvflash", "atszio", "atszio64", "atszio32",
    "elrawdsk", "mhyprot", "mhyprot2", "mhyprot3", "wsdm",
    "ene", "inpoutx64", "inpout32", "speedfan", "piddrv",
    "sandboxie", "sysmonload", "cpuz154", "msr",
    "ntiolib", "ntiolib_x64", "viragt64", "bs_def64", "bs_rci",
    "kis", "klif", "tmxpflt"
};

static int is_vuln(const char *path)
{
    char low[1024];
    int i;
    bof_strncpy(low, path ? path : "", sizeof(low));
    for (i = 0; low[i]; i++)
        if (low[i] >= 'A' && low[i] <= 'Z') low[i] += 32;
    for (i = 0; i < (int)(sizeof(vuln) / sizeof(vuln[0])); i++)
        if (bof_strstr(low, vuln[i])) return 1;
    return 0;
}

void go(char *args, int alen)
{
    SC_HANDLE scm;
    LPBYTE buf = NULL;
    DWORD need = 0, returned = 0, resume = 0, i;
    int hits = 0;

    (void)args; (void)alen;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                   SERVICE_STATE_ALL, NULL, 0, &need, &returned,
                                   &resume, NULL);
    if (KERNEL32$GetLastError() != ERROR_MORE_DATA || !need) {
        BeaconPrintf(CALLBACK_ERROR, "driver enumeration failed\n");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    buf = (LPBYTE)KERNEL32$VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { ADVAPI32$CloseServiceHandle(scm); return; }

    resume = 0;
    if (ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                       SERVICE_STATE_ALL, buf, need, &need, &returned,
                                       &resume, NULL)) {
        LPENUM_SERVICE_STATUS_PROCESSA e = (LPENUM_SERVICE_STATUS_PROCESSA)buf;
        BeaconPrintf(CALLBACK_OUTPUT, "Potentially vulnerable drivers\n");
        for (i = 0; i < returned; i++) {
            SC_HANDLE svc;
            QUERY_SERVICE_CONFIGA cfg;
            DWORD cneed = 0;
            svc = ADVAPI32$OpenServiceA(scm, e[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (!svc) continue;
            bof_memzero(&cfg, sizeof(cfg));
            if (ADVAPI32$QueryServiceConfigA(svc, &cfg, sizeof(cfg), &cneed) &&
                is_vuln(cfg.lpBinaryPathName)) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %s\n",
                             e[i].lpServiceName,
                             cfg.lpBinaryPathName ? cfg.lpBinaryPathName : "-");
                hits++;
            }
            ADVAPI32$CloseServiceHandle(svc);
        }
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    ADVAPI32$CloseServiceHandle(scm);
    BeaconPrintf(CALLBACK_OUTPUT, "\nMatches: %d (name heuristic)\n", hits);
}
