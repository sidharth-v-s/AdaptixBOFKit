/*
 * nettime [host] - read the clock of a remote (or local) machine.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *host = "";
    int hlen = 0;
    wchar_t whost[256];
    LPCWSTR server = NULL;
    PTIME_OF_DAY_INFO tod = NULL;
    NET_API_STATUS st;
    unsigned long long unix_time;
    ULARGE_INTEGER u;
    FILETIME ft;
    SYSTEMTIME stime;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        host = BeaconDataExtract(&parser, &hlen);
        if (!host) host = "";
    }
    if (host[0]) {
        bof_a2w(host, whost, 256);
        server = whost;
    }

    st = NETAPI32$NetRemoteTOD(server, (LPBYTE *)&tod);
    if (st != NERR_Success || !tod) {
        BeaconPrintf(CALLBACK_ERROR, "NetRemoteTOD failed: %lu\n", (unsigned long)st);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Host       : %s\n", host[0] ? host : "localhost");
    BeaconPrintf(CALLBACK_OUTPUT, "Remote time: %02lu:%02lu:%02lu\n",
                 (unsigned long)tod->tod_hours, (unsigned long)tod->tod_mins,
                 (unsigned long)tod->tod_secs);
    BeaconPrintf(CALLBACK_OUTPUT, "Timezone   : %ld minutes from GMT\n", (long)tod->tod_timezone);
    BeaconPrintf(CALLBACK_OUTPUT, "Uptime     : %lu seconds\n", (unsigned long)tod->tod_elapsedt);

    unix_time = (unsigned long long)tod->tod_elapsedt;
    u.QuadPart = (unix_time + 11644473600ULL) * 10000000ULL;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    if (KERNEL32$FileTimeToSystemTime(&ft, &stime))
        BeaconPrintf(CALLBACK_OUTPUT, "Boot (UTC) : %04u-%02u-%02u %02u:%02u:%02u\n",
                     stime.wYear, stime.wMonth, stime.wDay, stime.wHour,
                     stime.wMinute, stime.wSecond);

    NETAPI32$NetApiBufferFree(tod);
}
