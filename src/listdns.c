/*
 * listdns - dump the DNS client resolver cache.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *rtype(WORD t)
{
    switch (t) {
    case 1:  return "A";
    case 2:  return "NS";
    case 5:  return "CNAME";
    case 6:  return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    }
    return "?";
}

static void show_dnscache_state(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD need = 0;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        bof_error_win32("OpenSCManager", KERNEL32$GetLastError(),
                        "cannot query the Dnscache service state");
        return;
    }

    svc = ADVAPI32$OpenServiceA(scm, "Dnscache", SERVICE_QUERY_STATUS);
    if (!svc) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
            bof_error_text("Dnscache service", "not installed on this host");
        else
            bof_error_win32("OpenService(Dnscache)", err,
                            "cannot query the Dnscache service state");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    if (ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                      (LPBYTE)&ssp, sizeof(ssp), &need)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Dnscache service: %s",
                     bof_service_state_name(ssp.dwCurrentState));
        if (ssp.dwCurrentState == SERVICE_STOPPED)
            BeaconPrintf(CALLBACK_OUTPUT, " (win32 exit code %lu)",
                         (unsigned long)ssp.dwWin32ExitCode);
        else
            BeaconPrintf(CALLBACK_OUTPUT, " (PID %lu)",
                         (unsigned long)ssp.dwProcessId);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    } else {
        bof_error_win32("QueryServiceStatusEx(Dnscache)",
                        KERNEL32$GetLastError(),
                        "cannot read the Dnscache service state");
    }

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
}

void go(char *args, int alen)
{
    PDNS_CACHE_ENTRY e = NULL;
    DNS_STATUS st;
    int count = 0;
    char name[512];

    (void)args; (void)alen;

    st = DNSAPI$DnsGetCacheDataTable(&e);
    if (st != 0) {
        bof_error_dns("DnsGetCacheDataTable", (DWORD)st,
                      st == 9701 /* DNS_ERROR_NO_MORE_ITEMS */
                          ? "the cache is empty; nothing to display"
                          : "the DNS Client (Dnscache) service may be stopped or blocked");
        show_dnscache_state();
        return;
    }
    if (!e) {
        BeaconPrintf(CALLBACK_OUTPUT, "DNS client cache is empty\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "DNS client cache\n");
    for (; e; e = e->pNext) {
        bof_w2a(e->pszName ? e->pszName : L"", name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-48s %-6s len=%u\n",
                     name, rtype(e->wType), (unsigned)e->wDataLength);
        count++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d entries\n", count);
}
