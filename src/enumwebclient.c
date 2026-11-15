/*
 * enumwebclient [host] - check the WebClient (WebDAV) service.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host = "";
    int hlen = 0;
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS st;
    DWORD slen = sizeof(st);
    QUERY_SERVICE_CONFIGA cfg;
    DWORD need = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        host = BeaconDataExtract(&parser, &hlen);
        if (!host) host = "";
    }

    scm = ADVAPI32$OpenSCManagerA(host[0] ? host : NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager(%s) failed: %lu\n",
                     host[0] ? host : "local", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    svc = ADVAPI32$OpenServiceA(scm, "WebClient", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!svc) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s: WebClient not installed\n",
                     host[0] ? host : "local");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st,
                                      sizeof(st), &slen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s: WebClient state=%lu pid=%lu\n",
                     host[0] ? host : "local",
                     (unsigned long)st.dwCurrentState,
                     (unsigned long)st.dwProcessId);
    }

    bof_memzero(&cfg, sizeof(cfg));
    if (ADVAPI32$QueryServiceConfigA(svc, &cfg, sizeof(cfg), &need))
        BeaconPrintf(CALLBACK_OUTPUT, "  start type: %lu\n", (unsigned long)cfg.dwStartType);

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}
