/*
 * edrrecon - match installed services/drivers against known EDR/AV names.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *known[] = {
    "windefend", "wdfilter", "wdnisdrv", "mpsdrv", "mpssvc",
    "sense", "mssense", "wdav", "defender",
    "csfalcon", "csagent", "csdevicecontrol", "crowdstrike",
    "sentinelone", "sentinelagent", "sentinelstaticengine",
    "cylance", "cyoptics", "cyprotect",
    "carbonblack", "cbdefense", "cbsensor", "parity",
    "tanium", "taniumclient",
    "symantec", "symantecendpoint", "sep",
    "mcafee", "masvc", "macmnsvc", "mfe",
    "trend", "tmccsf", "tmbmsrv", "amsp",
    "elastic", "elasticendpoint",
    "cortex", "traps", "xdr",
    "fireeye", "xagt",
    "qualys", "qualysagent",
    "rapid7", "ir_agent",
    "sophos", "savservice",
    "kaspersky", "avp",
    "bitdefender", "vsserv",
    "eset", "ekrn",
    "cylanced", "gravityzone",
    "huntress", "huntsvc",
    "threatlocker", "s1"
};

static int matches(const char *s)
{
    int i;
    for (i = 0; i < (int)(sizeof(known) / sizeof(known[0])); i++)
        if (bof_strstr(s, known[i])) return 1;
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

    ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
                                   SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                                   NULL, 0, &need, &returned, &resume, NULL);
    if (KERNEL32$GetLastError() != ERROR_MORE_DATA || !need) {
        BeaconPrintf(CALLBACK_ERROR, "service enumeration failed\n");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    buf = (LPBYTE)KERNEL32$VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { ADVAPI32$CloseServiceHandle(scm); return; }

    resume = 0;
    if (ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
                                       SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                                       buf, need, &need, &returned, &resume, NULL)) {
        LPENUM_SERVICE_STATUS_PROCESSA e = (LPENUM_SERVICE_STATUS_PROCESSA)buf;
        BeaconPrintf(CALLBACK_OUTPUT, "EDR/AV service hits\n");
        for (i = 0; i < returned; i++) {
            char low[512];
            int j;
            bof_strncpy(low, e[i].lpServiceName ? e[i].lpServiceName : "", sizeof(low));
            for (j = 0; low[j]; j++)
                if (low[j] >= 'A' && low[j] <= 'Z') low[j] += 32;
            if (matches(low)) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-40s state=%lu pid=%lu\n",
                             e[i].lpServiceName,
                             (unsigned long)e[i].ServiceStatusProcess.dwCurrentState,
                             (unsigned long)e[i].ServiceStatusProcess.dwProcessId);
                hits++;
            }
        }
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    ADVAPI32$CloseServiceHandle(scm);
    BeaconPrintf(CALLBACK_OUTPUT, "\nHits: %d (heuristic name match)\n", hits);
}
