/*
 * uptime - system boot time and uptime.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    ULONGLONG ms = KERNEL32$GetTickCount64();
    ULONGLONG sec = ms / 1000ULL;
    ULONGLONG days = sec / 86400ULL;
    ULONGLONG hours = (sec % 86400ULL) / 3600ULL;
    ULONGLONG mins = (sec % 3600ULL) / 60ULL;
    ULONGLONG secs = sec % 60ULL;
    FILETIME ft;
    SYSTEMTIME st, boot, local;
    (void)args; (void)alen;

    KERNEL32$GetSystemTimeAsFileTime(&ft);
    KERNEL32$FileTimeToSystemTime(&ft, &st);

    /* subtract uptime from current UTC time to estimate boot time */
    {
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        u.QuadPart -= ms * 10000ULL;
        ft.dwLowDateTime = u.LowPart;
        ft.dwHighDateTime = u.HighPart;
        KERNEL32$FileTimeToSystemTime(&ft, &boot);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Current UTC : %04u-%02u-%02u %02u:%02u:%02u\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    BeaconPrintf(CALLBACK_OUTPUT, "Boot  UTC   : %04u-%02u-%02u %02u:%02u:%02u\n",
                 boot.wYear, boot.wMonth, boot.wDay, boot.wHour, boot.wMinute, boot.wSecond);
    BeaconPrintf(CALLBACK_OUTPUT, "Uptime      : %llu days, %llu hours, %llu minutes, %llu seconds\n",
                 days, hours, mins, secs);

    (void)local;
}
